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
import secrets
import socket
import stat
import struct
import sys
import time

from aegis_audit import AuditError, verify_rows
from aegis_reporting import ReportingSupervisor, canonical, ID, verified_package
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


def _trusted_socket(path: Path, allowed_uids):
    """Group-traversable private socket directory supports distinct service UIDs.

    Modes 0700/0600 support same-UID integrations; modes 0710/0660 support a
    deliberately shared operator/receiver group. World permissions are denied.
    """
    with open_directory_nofollow(path.parent) as directory:
        parent = os.fstat(directory)
        if (parent.st_uid not in (0, os.geteuid(), *allowed_uids) or
                parent.st_mode & 0o007 or parent.st_mode & 0o020 or
                not parent.st_mode & stat.S_IXUSR):
            deny("notification socket directory owner or mode denied")
        st = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISSOCK(st.st_mode) or
                st.st_uid not in allowed_uids or st.st_mode & 0o007):
            deny("notification destination must be an approved private socket")
        return st.st_dev, st.st_ino, st.st_uid


class NotificationSupervisor(ReportingSupervisor):
    def _report_package(self, info, run_id, digest, revision):
        if revision is not None and (not isinstance(revision, str) or
                                    not NOTICE.fullmatch(revision) or revision != digest):
            deny("notification revision reference invalid")
        folder = Path(info["report_directory"]) / "assessments" / run_id
        if revision is not None:
            folder = folder / "revisions" / revision
        document = verified_package(folder, digest)
        if document["engagement_id"] != info["engagement_id"] or document["source_run_id"] != run_id:
            deny("notification report engagement identity mismatch")
        if revision is None and document["assessment_status"] != "limited_source_evidence_only":
            deny("unexpected initial report status")
        if revision is not None and document["assessment_status"] != "independently_reviewed_limited_evidence":
            deny("unexpected reviewed report status")
        return document

    def deliver(self, notice_id: str, policy_file: Path) -> dict:
        if not isinstance(notice_id, str) or not NOTICE.fullmatch(notice_id):
            deny("invalid notification ID")
        info, _ = self._guard()
        policy = notification_policy(Path(policy_file), info, self.state_root)
        eid = info["engagement_id"]
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            try:
                verify_rows(con.execute("SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq").fetchall())
            except AuditError as exc:
                raise ExecutionDenied("notification audit chain invalid") from exc
            record = con.execute("""SELECT source_run_id,report_sha256,lead_count,status,attempts,lease_until,
                report_revision FROM notification_outbox WHERE notice_id=? AND engagement_id=?""",
                (notice_id, eid)).fetchone()
            if not record:
                deny("unrecognized report notification")
            run_id, digest, count, status, attempts, lease_until, revision = record
            if status == "delivered":
                return {"status": "DELIVERY_ALREADY_ACKNOWLEDGED", "notice_id": notice_id}
            if status == "failed" or attempts >= policy["max_attempts"]:
                deny("notification retry budget exhausted")
            if status == "leased" and lease_until > time.time():
                deny("notification delivery in progress")
            if not isinstance(run_id, str) or not ID.fullmatch(run_id):
                deny("invalid pending notification source")
            report = self._report_package(info, run_id, digest, revision)
            if count != len(report["findings"]):
                deny("notification lead count inconsistent with report")
            attempt_token = secrets.token_hex(24)
            attempt = attempts + 1
            con.execute("""UPDATE notification_outbox SET status='leased',attempts=?,
                lease_until=?,lease_token=?,last_failure=NULL,next_attempt_at=0 WHERE notice_id=? AND engagement_id=?""",
                (attempt, time.time() + max(10, policy["timeout_seconds"] * 3), attempt_token, notice_id, eid))
            self._event(con, {"type": "notification_delivery_attempt", "engagement_id": eid,
                              "notice_id": notice_id, "attempt": attempt})
            con.commit()
        challenge = secrets.token_hex(16)
        payload = {"type": "aegis_assessment_v1", "notice_id": notice_id, "engagement_id": eid,
                   "source_run_id": run_id, "report_sha256": digest, "lead_count": count,
                   "assessment_status": report["assessment_status"], "challenge": challenge}
        acknowledged = False
        try:
            self._guard()
            # Verify the *entire* package again immediately before sending.
            if self._report_package(info, run_id, digest, revision) != report:
                deny("notification report changed during dispatch")
            path = Path(policy["socket_path"])
            identity = _trusted_socket(path, policy["allowed_peer_uids"])
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(policy["timeout_seconds"])
                sock.connect(str(path))
                if identity != _trusted_socket(path, policy["allowed_peer_uids"]):
                    deny("notification destination changed")
                if not hasattr(socket, "SO_PEERCRED"):
                    deny("kernel peer credentials unavailable")
                pid, uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid not in policy["allowed_peer_uids"] or uid != identity[2]:
                    deny("notification peer identity denied")
                sock.sendall(canonical(payload) + b"\n")
                received = b""
                while b"\n" not in received and len(received) <= MAX_ACK:
                    chunk = sock.recv(128)
                    if not chunk:
                        break
                    received += chunk
                if (len(received) > MAX_ACK or received.count(b"\n") != 1 or
                        not received.endswith(b"\n")):
                    deny("notification acknowledgment framing invalid")
                try:
                    ack = json.loads(received)
                except (ValueError, UnicodeError) as exc:
                    raise ExecutionDenied("invalid receiver acknowledgment") from exc
                if (not isinstance(ack, dict) or set(ack) != {"received", "notice_id", "report_sha256", "challenge"} or
                        ack["received"] is not True or ack["notice_id"] != notice_id or
                        ack["report_sha256"] != digest or ack["challenge"] != challenge):
                    deny("receiver acknowledgment not bound to report")
            self._guard()
            acknowledged = True
        except (OSError, ExecutionDenied, ValueError, TypeError):
            acknowledged = False
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            owner = con.execute("""SELECT status,attempts,lease_token,lease_until FROM notification_outbox
                WHERE notice_id=? AND engagement_id=?""", (notice_id, eid)).fetchone()
            if not owner or owner[0] != "leased" or owner[1] != attempt or owner[2] != attempt_token:
                # A recovered lease must never be overwritten by its former owner.
                return {"status": "DELIVERY_ATTEMPT_SUPERSEDED", "notice_id": notice_id}
            if owner[3] <= time.time():
                # Even an otherwise matching token loses authority on expiry.
                return {"status": "DELIVERY_ATTEMPT_EXPIRED", "notice_id": notice_id}
            if acknowledged:
                stamp = datetime.now(timezone.utc).isoformat()
                con.execute("""UPDATE notification_outbox SET status='delivered',lease_until=0,
                    lease_token=NULL,next_attempt_at=0,acknowledged_utc=?
                    WHERE notice_id=? AND engagement_id=? AND lease_token=? AND attempts=?""",
                    (stamp, notice_id, eid, attempt_token, attempt))
                self._event(con, {"type": "notification_delivery_acknowledged", "engagement_id": eid,
                                  "notice_id": notice_id, "attempt": attempt})
                con.commit()
                return {"status": "DELIVERY_ACKNOWLEDGED", "notice_id": notice_id, "report_sha256": digest}
            state = "failed" if attempt >= policy["max_attempts"] else "pending"
            # Manual retries remain available immediately; the queue drainer
            # respects exponential backoff to prevent hot-looping failed peers.
            next_attempt = time.time() + min(300, 2 ** min(attempt, 8)) if state == "pending" else 0
            con.execute("""UPDATE notification_outbox SET status=?,lease_until=0,lease_token=NULL,
                next_attempt_at=?,last_failure='DELIVERY_FAILED'
                WHERE notice_id=? AND engagement_id=? AND lease_token=? AND attempts=?""",
                (state, next_attempt, notice_id, eid, attempt_token, attempt))
            self._event(con, {"type": "notification_delivery_failed", "engagement_id": eid,
                              "notice_id": notice_id, "attempt": attempt, "permanent": state == "failed"})
            con.commit()
            return {"status": "DELIVERY_FAILED_PERMANENT" if state == "failed" else "DELIVERY_FAILED_PENDING",
                    "notice_id": notice_id, "attempts": attempt}

    def drain(self, policy_file: Path, max_items: int = 20):
        """Run a bounded queue-drain pass suitable for a service timer."""
        if type(max_items) is not int or not 1 <= max_items <= 50:
            deny("invalid bounded dispatch count")
        info, _ = self._guard()
        policy = notification_policy(Path(policy_file), info, self.state_root)
        now = time.time()
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            expired = con.execute("""SELECT notice_id FROM notification_outbox
                WHERE engagement_id=? AND status='leased' AND lease_until<=? AND attempts>=?""",
                (info["engagement_id"], now, policy["max_attempts"])).fetchall()
            for (notice_id,) in expired:
                con.execute("""UPDATE notification_outbox SET status='failed',lease_until=0,
                    lease_token=NULL,last_failure='EXPIRED_LEASE_RETRY_LIMIT',next_attempt_at=0
                    WHERE notice_id=? AND engagement_id=?""", (notice_id, info["engagement_id"]))
                self._event(con,{"type":"notification_lease_expired_permanent","engagement_id":info["engagement_id"],
                                 "notice_id":notice_id})
            rows = con.execute("""SELECT notice_id FROM notification_outbox
                WHERE engagement_id=? AND attempts<? AND
                 ((status='pending' AND next_attempt_at<=?) OR (status='leased' AND lease_until<=?))
                ORDER BY next_attempt_at,notice_id LIMIT ?""",
                (info["engagement_id"], policy["max_attempts"], now, now, max_items)).fetchall()
            con.commit()
        result = []
        for (notice,) in rows:
            self._guard()
            try:
                result.append(self.deliver(notice, policy_file))
            except (ExecutionDenied, OSError, ValueError) as exc:
                result.append({"status": "DELIVERY_DENIED", "notice_id": notice})
        return {"status": "OUTBOX_DRAINED", "processed": len(result), "results": result}


def main(argv=None):
    ap=argparse.ArgumentParser(description="Operator-only durable local AEGIS notification delivery")
    for n in ("manifest", "signature", "trust", "state-root", "notification-policy"):
        ap.add_argument("--" + n, required=True)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--notice-id")
    group.add_argument("--drain", type=int)
    a=ap.parse_args(argv)
    try:
        obj=NotificationSupervisor(a.manifest,a.signature,a.trust,a.state_root)
        response = (obj.drain(Path(a.notification_policy), a.drain) if a.drain is not None
                    else obj.deliver(a.notice_id, Path(a.notification_policy)))
        print(json.dumps(response,sort_keys=True))
        return 0
    except (OSError,ExecutionDenied,ValueError,TypeError):
        print("NOTIFICATION_DENIED",file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
