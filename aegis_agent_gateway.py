#!/usr/bin/env python3
"""AEGIS v2.0: restricted, signed and replay-protected assessment delegation.

Separate from the privileged operator approval service. This service NEVER holds
operator/delegate private keys and NEVER exposes arbitrary dispatch, paths or
credentials. An agent can inspect a safe workflow summary or propose precisely
its next, already operator-approved action. All actual actions use their
original independently authorizing supervisors.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import struct
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis_integrated_assessment import IntegratedAssessment, HEX, RUN_ID, _operator_path, _audit
from aegis_reporting import canonical
from aegis_supervisor import ExecutionDenied, deny, open_directory_nofollow

GRANT_DOMAIN = b"AEGIS-v2-delegation-v1\x00"
REQUEST_DOMAIN = b"AEGIS-v2-delegate-request-v1\x00"
MAX_ENVELOPE = 16384
MAX_GRANT = 4096
MAX_REQUEST = 2048
MAX_RESPONSE = 4096
NONCE = re.compile(r"[0-9a-f]{32}\Z")
POLICY_FIELDS = {"version", "configured", "socket_path", "signer_public_key_path",
    "allowed_peer_uids", "allowed_engagement_ids", "max_grant_seconds", "max_request_seconds", "shared_gid"}
GRANT_FIELDS = {"version", "grant_id", "engagement_id", "assessment_id", "manifest_sha256",
    "assessment_policy_sha256", "client_public_key_b64", "client_uid", "permissions",
    "not_before_utc", "expires_at_utc"}
REQUEST_FIELDS = {"version", "request_id", "engagement_id", "assessment_id",
    "operation", "step_id", "expected_action", "not_before_utc", "expires_at_utc"}
SAFE_OPS = ("snapshot", "propose")


def _decode(raw, maximum):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= maximum:
        deny("invalid delegated message size")
    try:
        def unique(pairs):
            out = {}
            for key, value in pairs:
                if key in out: raise ValueError("duplicate JSON field")
                out[key] = value
            return out
        obj=json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")))
        if not isinstance(obj,dict) or canonical(obj)!=raw:
            deny("delegation must be canonical JSON")
        return obj
    except (UnicodeError,ValueError,TypeError,RecursionError,OverflowError) as exc:
        raise ExecutionDenied("invalid delegation JSON") from exc


def _b64(value, maximum=12000):
    if not isinstance(value,str) or len(value)>maximum or not value.isascii():
        deny("invalid delegate envelope base64")
    try:
        return base64.b64decode(value,validate=True)
    except (ValueError,base64.binascii.Error) as exc:
        raise ExecutionDenied("invalid delegate envelope base64") from exc


def _utc(value):
    if not isinstance(value,str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",value):
        deny("delegation timestamps must be UTC seconds")
    try:
        stamp=datetime.strptime(value,"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return stamp.timestamp()
    except (ValueError,OverflowError) as exc:
        raise ExecutionDenied("invalid delegation timestamp") from exc


def _protected(path, maximum, info, state):
    path=_operator_path(str(path),info,state)
    with open_directory_nofollow(path.parent) as parent:
        ps=os.fstat(parent)
        if ps.st_uid not in (0,os.geteuid()) or ps.st_mode & 0o022:
            deny("delegation policy directory is not protected")
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
        try:
            st=os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or
                st.st_uid not in (0,os.geteuid()) or st.st_mode & 0o077 or
                not 0<st.st_size<=maximum):
                deny("delegation material must be private and bounded")
            body=os.read(fd, maximum+1)
            after=os.fstat(fd)
            if len(body)!=st.st_size or (st.st_dev,st.st_ino,st.st_size)!=(after.st_dev,after.st_ino,after.st_size):
                deny("delegation material changed during read")
            return body
        finally: os.close(fd)


class DelegatedAssessmentService:
    def __init__(self, controller: IntegratedAssessment, policy_file: Path):
        self.controller=controller
        self.policy_file=Path(policy_file)

    def _policy(self, info):
        raw=_protected(self.policy_file,8192,info,self.controller.state_root)
        policy=_decode(raw,8192)
        if (set(policy)!=POLICY_FIELDS or policy["version"]!=1 or policy["configured"] is not True or
            not isinstance(policy["allowed_peer_uids"],list) or
            not 1<=len(policy["allowed_peer_uids"])<=8 or
            any(type(x) is not int or not 0<x<2**31 for x in policy["allowed_peer_uids"]) or
            len(set(policy["allowed_peer_uids"]))!=len(policy["allowed_peer_uids"]) or
            (policy["shared_gid"] is not None and (type(policy["shared_gid"]) is not int or not 0<=policy["shared_gid"]<2**31)) or
            not isinstance(policy["allowed_engagement_ids"],list) or
            info["engagement_id"] not in policy["allowed_engagement_ids"] or
            not 1<=len(policy["allowed_engagement_ids"])<=16 or
            any(not isinstance(x,str) or len(x)>64 for x in policy["allowed_engagement_ids"]) or
            type(policy["max_grant_seconds"]) is not int or not 1<=policy["max_grant_seconds"]<=900 or
            type(policy["max_request_seconds"]) is not int or not 1<=policy["max_request_seconds"]<=30):
            deny("delegate policy identity and time bounds invalid")
        socket_path=_operator_path(policy["socket_path"],info,self.controller.state_root)
        key_path=_operator_path(policy["signer_public_key_path"],info,self.controller.state_root)
        if socket_path == key_path or self.policy_file in (socket_path,key_path):
            deny("delegate control material must be separated")
        key=load_pem_public_key(_protected(key_path,4096,info,self.controller.state_root))
        if not isinstance(key,Ed25519PublicKey):deny("delegation signer must use Ed25519")
        return policy,key, socket_path

    def _authenticate(self, envelope: bytes, peer_uid: int):
        info,assessment_policy,assessment_sha=self.controller._admit()
        policy,key,_=self._policy(info)
        if peer_uid==0 or peer_uid not in policy["allowed_peer_uids"]: deny("delegate OS peer identity denied")
        envelope=_decode(envelope,MAX_ENVELOPE)
        if set(envelope)!={"grant_b64","grant_signature_b64","request_b64","request_signature_b64"}:
            deny("invalid delegated envelope shape")
        grant_raw=_b64(envelope["grant_b64"])
        grant_sig=_b64(envelope["grant_signature_b64"])
        request_raw=_b64(envelope["request_b64"])
        req_sig=_b64(envelope["request_signature_b64"])
        if len(grant_sig)!=64 or len(req_sig)!=64:deny("invalid delegate signature size")
        try:key.verify(grant_sig,GRANT_DOMAIN+grant_raw)
        except InvalidSignature as exc:raise ExecutionDenied("unauthorized delegation") from exc
        grant=_decode(grant_raw,MAX_GRANT)
        if (set(grant)!=GRANT_FIELDS or grant["version"]!=1 or
            not isinstance(grant["grant_id"],str) or not NONCE.fullmatch(grant["grant_id"]) or
            grant["engagement_id"]!=info["engagement_id"] or
            not isinstance(grant["assessment_id"],str) or not RUN_ID.fullmatch(grant["assessment_id"]) or
            grant["manifest_sha256"]!=info["manifest_sha256"] or
            grant["assessment_policy_sha256"]!=assessment_sha or
            type(grant["client_uid"]) is not int or grant["client_uid"]!=peer_uid or
            not isinstance(grant["permissions"],list) or not grant["permissions"] or
            any(not isinstance(x,str) for x in grant["permissions"]) or
            len(set(grant["permissions"]))!=len(grant["permissions"]) or
            any(x not in SAFE_OPS for x in grant["permissions"])):
            deny("delegate grant is not bound to approved workflow and peer")
        now=time.time()
        begins,ends=_utc(grant["not_before_utc"]),_utc(grant["expires_at_utc"])
        if not begins<=now<ends or not 0<ends-begins<=policy["max_grant_seconds"]:
            deny("delegation expired or exceeds operator cap")
        client=load_pem_public_key(_b64(grant["client_public_key_b64"],1800))
        if not isinstance(client,Ed25519PublicKey):deny("client key must be Ed25519")
        try:client.verify(req_sig,REQUEST_DOMAIN+request_raw)
        except InvalidSignature as exc:raise ExecutionDenied("invalid agent request signature") from exc
        req=_decode(request_raw,MAX_REQUEST)
        if (set(req)!=REQUEST_FIELDS or req["version"]!=1 or
            not isinstance(req["request_id"],str) or not NONCE.fullmatch(req["request_id"]) or
            req["assessment_id"]!=grant["assessment_id"] or
            req["engagement_id"]!=info["engagement_id"] or
            req["operation"] not in grant["permissions"]):
            deny("agent request exceeds signed delegation")
        start,end=_utc(req["not_before_utc"]),_utc(req["expires_at_utc"])
        if not start<=now<end or not 0<end-start<=policy["max_request_seconds"] or end>ends:
            deny("agent request expired or outside grant")
        if req["operation"]=="snapshot":
            if req["step_id"] is not None or req["expected_action"] is not None:
                deny("snapshot cannot choose an action")
        else:
            if (not isinstance(req["step_id"],str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}",req["step_id"]) or
                not isinstance(req["expected_action"],str) or
                req["expected_action"] not in {x["action"] for x in assessment_policy["steps"]}):
                deny("proposal has no approved action shape")
        return info, grant, req, hashlib.sha256(grant_raw).hexdigest(),hashlib.sha256(request_raw).hexdigest()

    def _consume(self, info, grant, req, grant_hash, request_hash):
        # All requests, even read-only snapshots, are single-use. A dropped socket
        # response must be reconciled from a fresh request, never replayed.
        with self.controller._database() as con:
            con.execute("BEGIN IMMEDIATE")
            _audit(con)
            con.execute("""CREATE TABLE IF NOT EXISTS agent_delegated_requests (
                request_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
                assessment_id TEXT NOT NULL, grant_sha256 TEXT NOT NULL,
                request_sha256 TEXT NOT NULL, operation TEXT NOT NULL)""")
            try:
                con.execute("INSERT INTO agent_delegated_requests VALUES(?,?,?,?,?,?)",
                    (req["request_id"],info["engagement_id"],grant["assessment_id"],grant_hash,request_hash,req["operation"]))
            except sqlite3.IntegrityError as exc:
                raise ExecutionDenied("delegated request replay rejected") from exc
            self.controller._event(con,{"type":"agent_delegate_request_consumed",
                "engagement_id":info["engagement_id"],"assessment_id":grant["assessment_id"],
                "request_id":req["request_id"],"operation":req["operation"],
                "grant_sha256":grant_hash,"request_sha256":request_hash})
            con.commit()

    def handle(self, envelope: bytes, peer_uid: int):
        info,grant,req,gh,rh=self._authenticate(envelope,peer_uid)
        # Recheck current protected workflow before consuming a request.
        snap=self.controller.snapshot(grant["assessment_id"])
        if req["operation"]=="propose":
            unfinished=next((x for x in snap["steps"] if x["state"]!="completed"),None)
            if (not unfinished or unfinished["state"]!="pending" or
                unfinished["id"]!=req["step_id"] or unfinished["action"]!=req["expected_action"]):
                deny("proposed step is not the next operator-approved action")
        self._consume(info,grant,req,gh,rh)
        if req["operation"]=="snapshot":
            return {"status":"DELEGATED_WORKFLOW_SNAPSHOT","assessment_id":grant["assessment_id"],
                "workflow_status":snap["status"],"completed":snap["completed"],"total":snap["total"],
                "steps":[{"id":s["id"],"action":s["action"],"state":s["state"]} for s in snap["steps"]]}
        completed=self.controller.advance(grant["assessment_id"])
        if completed.get("step_id")!=req["step_id"]:
            deny("delegated completion did not match approved proposal")
        return {"status":"DELEGATED_STEP_COMPLETED","assessment_id":grant["assessment_id"],
            "step_id":req["step_id"],"action":req["expected_action"],
            "warning":"Results remain local evidence requiring independent review."}

    def process_connection(self, sock):
        if not hasattr(socket,"SO_PEERCRED"):deny("Linux peer credentials required")
        pid,uid,gid=struct.unpack("3i",sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        sock.settimeout(4)
        data=b""
        while b"\n" not in data and len(data)<=MAX_ENVELOPE:
            chunk=sock.recv(4096)
            if not chunk:break
            data+=chunk
        if data.count(b"\n")!=1 or not data.endswith(b"\n") or len(data)>MAX_ENVELOPE+1:
            deny("invalid delegated request framing")
        return self.handle(data[:-1],uid)

    def serve(self, *, stop_event=None):
        if os.geteuid()==0:
            deny("delegated assessment service must run as non-root")
        info,_,_=self.controller._admit()
        policy,_,path=self._policy(info)
        with open_directory_nofollow(path.parent) as fd:
            st=os.fstat(fd)
            # A private service-owned socket directory; optional production
            # cross-UID ACL/group provisioning must be independently reviewed.
            if st.st_uid!=os.geteuid() or st.st_mode & 0o007:
                deny("delegated socket directory must be service-owned and private")
            shared=policy["shared_gid"]
            if shared is None:
                if st.st_mode & 0o077:
                    deny("same-UID delegate socket directory must be mode 0700")
            elif st.st_gid!=shared or st.st_mode & 0o777 != 0o710:
                deny("cross-UID delegate directory must be mode 0710 in configured group")
        if path.exists() or path.is_symlink():deny("delegated socket path already occupied")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
            server.bind(str(path))
            if policy["shared_gid"] is None:
                os.chmod(path,0o600)
            else:
                os.chown(path,-1,policy["shared_gid"])
                os.chmod(path,0o660)
            server.listen(8)
            server.settimeout(.25)
            identity=os.lstat(path)
            try:
                while stop_event is None or not stop_event.is_set():
                    try: client,_=server.accept()
                    except socket.timeout:continue
                    with client:
                        try:
                            outcome=self.process_connection(client)
                        except (ExecutionDenied, OSError, ValueError, TypeError, KeyError, OverflowError):
                            outcome={"status":"DELEGATED_REQUEST_DENIED"}
                        try:
                            body=canonical(outcome)
                            if len(body)>MAX_RESPONSE:body=canonical({"status":"DELEGATED_RESPONSE_TOO_LARGE"})
                            client.sendall(body+b"\n")
                        except OSError:pass
            finally:
                try:
                    stat_after=os.lstat(path)
                    if (stat_after.st_ino,stat_after.st_dev)==(identity.st_ino,identity.st_dev):
                        os.unlink(path)
                except FileNotFoundError:pass


def main(argv=None):
    ap=argparse.ArgumentParser(description="Operator-owned, independently signed AEGIS agent delegation gateway")
    for key in ("manifest","signature","trust","state-root","assessment-policy","delegation-policy"):
        ap.add_argument("--"+key,required=True)
    a=ap.parse_args(argv)
    try:
        controller=IntegratedAssessment(a.manifest,a.signature,a.trust,a.state_root,a.assessment_policy)
        DelegatedAssessmentService(controller,Path(a.delegation_policy)).serve()
        return 0
    except (ExecutionDenied,OSError,ValueError,TypeError,KeyError):
        print("AGENT_GATEWAY_DENIED",file=__import__("sys").stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
