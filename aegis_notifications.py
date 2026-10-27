#!/usr/bin/env python3
"""v1.8 operator-only durable, local Unix-socket notification delivery.

At-least-once, idempotency-keyed: sending to a peer does not establish
acknowledged delivery until a correctly bound ack arrives. This module does
not send email/webhooks or grant assessment workers any networking.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time

from aegis_audit import AuditError, verify_rows
from aegis_reporting import ReportingSupervisor, canonical, ID
from aegis_supervisor import ExecutionDenied, deny, open_directory_nofollow, private_directory

NOTICE = re.compile(r"[a-f0-9]{64}\Z")
MAX_POLICY = 8192
MAX_ACK = 512


def notification_policy(path: Path, info: dict, state: Path):
    if not isinstance(path, Path):path=Path(path)
    if not path.is_absolute():deny("notification policy requires trusted absolute path")
    for forbidden in [state,Path(info["report_directory"]),
                      *[Path(p) for p in info["authorized_repositories"]]]:
        if path == forbidden or forbidden in path.parents:
            deny("notification policy overlaps mutable assessment assets")
    with open_directory_nofollow(path.parent) as p:
        st = os.fstat(p)
        if st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022:
            deny("notification policy directory not trusted")
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=p)
        try:
            st=os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid not in (0,os.geteuid()) or
                    st.st_mode & 0o077 or st.st_size>MAX_POLICY):
                deny("notification policy file is not protected")
            raw=os.read(fd,MAX_POLICY+1)
        finally:os.close(fd)
    try:pol=json.loads(raw)
    except (UnicodeError,ValueError) as exc:raise ExecutionDenied("invalid notification policy") from exc
    if (not isinstance(pol,dict) or set(pol)!={"schema_version","configured","socket_path",
          "allowed_peer_uids","max_attempts","timeout_seconds"} or
          pol["schema_version"]!=1 or pol["configured"] is not True or
          type(pol["max_attempts"]) is not int or not 1 <= pol["max_attempts"] <= 10 or
          type(pol["timeout_seconds"]) is not int or not 1 <= pol["timeout_seconds"] <= 5 or
          not isinstance(pol["allowed_peer_uids"],list) or not pol["allowed_peer_uids"] or
          len(pol["allowed_peer_uids"])>8 or any(type(x) is not int or x<0 for x in pol["allowed_peer_uids"])):
        deny("notification endpoint must be positively configured")
    target=pol["socket_path"]
    if (not isinstance(target,str) or len(target)>180 or not target.startswith("/") or
            any(x in (".","..") for x in target.split("/")) or "\x00" in target):
        deny("invalid notification endpoint")
    sock_path=Path(target)
    for forbidden in [state,*[Path(p) for p in info["authorized_repositories"]],
                      Path(info["report_directory"])]:
        if sock_path==forbidden or forbidden in sock_path.parents:
            deny("notification endpoint overlaps mutable assessment assets")
    return pol


def _trusted_socket(path: Path):
    with open_directory_nofollow(path.parent) as directory:
        p=os.fstat(directory)
        if p.st_uid not in (0,os.geteuid()) or p.st_mode & 0o077:
            deny("notification socket directory must be owner private")
        st=os.stat(path.name,dir_fd=directory,follow_symlinks=False)
        if not stat.S_ISSOCK(st.st_mode) or st.st_mode & 0o077:
            deny("notification destination is not a private Unix socket")
        return st.st_dev,st.st_ino


class NotificationSupervisor(ReportingSupervisor):
    def _report_digest(self, info, run_id):
        with open_directory_nofollow(Path(info["report_directory"])/"assessments"/run_id) as fd:
            private_directory(fd)
            x=os.open("findings.json",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
            try:
                st=os.fstat(x)
                if (not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or
                        st.st_mode & 0o077 or st.st_nlink!=1 or st.st_size>65536):
                    deny("notification report artifact invalid")
                raw=os.read(x,65537)
                if len(raw)!=st.st_size:deny("notification report changed during read")
                return hashlib.sha256(raw).hexdigest()
            finally:os.close(x)

    def deliver(self, notice_id: str, policy_file: Path) -> dict:
        if not isinstance(notice_id,str) or not NOTICE.fullmatch(notice_id):deny("invalid notification ID")
        info,_=self._guard()
        policy=notification_policy(Path(policy_file),info,self.state_root)
        eid=info["engagement_id"]
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            try:verify_rows(con.execute("SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq").fetchall())
            except AuditError as exc:raise ExecutionDenied("notification audit chain invalid") from exc
            record=con.execute("SELECT source_run_id,report_sha256,lead_count,status,attempts,lease_until FROM notification_outbox WHERE notice_id=? AND engagement_id=?",(notice_id,eid)).fetchone()
            if not record:deny("unrecognized report notification")
            run_id,digest,count,status,attempts,lease_until=record
            if status=="delivered":return {"status":"DELIVERY_ALREADY_ACKNOWLEDGED","notice_id":notice_id}
            if status=="failed" or attempts>=policy["max_attempts"]:deny("notification retry budget exhausted")
            if status=="leased" and lease_until>time.time():deny("notification delivery in progress")
            if not isinstance(run_id,str) or not ID.fullmatch(run_id):deny("invalid pending notification source")
            if self._report_digest(info,run_id)!=digest:deny("assessment report integrity mismatch")
            con.execute("UPDATE notification_outbox SET status='leased',attempts=attempts+1,lease_until=?,last_failure=NULL WHERE notice_id=?",
                        (time.time()+max(10,policy["timeout_seconds"]*3),notice_id))
            self._event(con,{"type":"notification_delivery_attempt","engagement_id":eid,"notice_id":notice_id,"attempt":attempts+1})
            con.commit()
        challenge=os.urandom(16).hex()
        payload={"type":"aegis_assessment_v1","notice_id":notice_id,"engagement_id":eid,
                 "source_run_id":run_id,"report_sha256":digest,"lead_count":count,
                 "assessment_status":"limited_source_evidence_only","challenge":challenge}
        outcome="DELIVERY_FAILURE"
        try:
            self._guard()
            path=Path(policy["socket_path"])
            identity=_trusted_socket(path)
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                s.settimeout(policy["timeout_seconds"])
                s.connect(str(path))
                if identity!=_trusted_socket(path):deny("notification endpoint identity changed")
                if not hasattr(socket,"SO_PEERCRED"):deny("peer credentials unavailable")
                pid,uid,gid=struct.unpack("3i",s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if uid not in policy["allowed_peer_uids"]:deny("notification peer identity denied")
                s.sendall(canonical(payload)+b"\n")
                buf=b""
                while b"\n" not in buf and len(buf)<=MAX_ACK:
                    part=s.recv(128)
                    if not part:break
                    buf+=part
                if len(buf)>MAX_ACK or buf.count(b"\n")!=1 or not buf.endswith(b"\n"):
                    deny("notification acknowledgement framing invalid")
                try:ack=json.loads(buf)
                except (UnicodeError,ValueError) as exc:raise ExecutionDenied("notification acknowledgement invalid") from exc
                if (not isinstance(ack,dict) or set(ack)!={"received","notice_id","report_sha256","challenge"} or
                        ack["received"] is not True or ack["notice_id"]!=notice_id or
                        ack["report_sha256"]!=digest or ack["challenge"]!=challenge):
                    deny("notification acknowledgement not bound to delivery")
            self._guard()
            outcome="ACKNOWLEDGED"
        except (OSError,ExecutionDenied,ValueError,TypeError):
            outcome="DELIVERY_FAILURE"
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            row=con.execute("SELECT status,attempts FROM notification_outbox WHERE notice_id=? AND engagement_id=?",(notice_id,eid)).fetchone()
            if not row or row[0]!="leased":deny("notification lease changed unexpectedly")
            if outcome=="ACKNOWLEDGED":
                stamp=datetime.now(timezone.utc).isoformat()
                con.execute("UPDATE notification_outbox SET status='delivered',lease_until=0,acknowledged_utc=? WHERE notice_id=?",(stamp,notice_id))
                self._event(con,{"type":"notification_delivery_acknowledged","engagement_id":eid,"notice_id":notice_id})
                con.commit()
                return {"status":"DELIVERY_ACKNOWLEDGED","notice_id":notice_id,"report_sha256":digest}
            state="failed" if row[1]>=policy["max_attempts"] else "pending"
            con.execute("UPDATE notification_outbox SET status=?,lease_until=0,last_failure='DELIVERY_FAILED' WHERE notice_id=?",(state,notice_id))
            self._event(con,{"type":"notification_delivery_failed","engagement_id":eid,"notice_id":notice_id,"permanent":state=="failed"})
            con.commit()
            return {"status":"DELIVERY_FAILED_PERMANENT" if state=="failed" else "DELIVERY_FAILED_PENDING","notice_id":notice_id,
                    "attempts":row[1]}


def main(argv=None):
    ap=argparse.ArgumentParser(description="Operator-only durable local AEGIS notification delivery")
    for n in ("manifest","signature","trust","state-root","notification-policy","notice-id"):
        ap.add_argument("--"+n,required=True)
    a=ap.parse_args(argv)
    try:
        obj=NotificationSupervisor(a.manifest,a.signature,a.trust,a.state_root)
        print(json.dumps(obj.deliver(a.notice_id,Path(a.notification_policy)),sort_keys=True))
        return 0
    except (OSError,ExecutionDenied,ValueError,TypeError):
        print("NOTIFICATION_DENIED",file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
