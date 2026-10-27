#!/usr/bin/env python3
"""Operator-only AEGIS credential control service. Never expose to an AI agent.

An independently signed, short-lived command PLUS Linux SO_PEERCRED identity is
required for each request. Replay identifiers are committed before execution.
Only three explicitly named operations are supported; no generic Python/CLI.
This service must run under a dedicated protected non-root Linux identity.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import struct
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from aegis_audit import AuditError, verify_rows
from aegis_credentials import AegisCredentialAuthority, _json_bytes, _protected_bytes, _utc
from aegis_supervisor import ExecutionDenied, deny, open_directory_nofollow

API_CONTEXT = b"AEGIS-operator-command-v1\x00"
API_KEYS = frozenset({"version", "principal", "engagement_id", "request_id",
    "not_before", "expires_at", "operation", "args"})
POLICY_KEYS = frozenset({"version", "configured", "principal", "public_key_pem_path",
    "allowed_peer_uids", "allowed_engagement_ids", "socket_path", "approval_dir",
    "max_request_window_seconds"})
MAX_ENVELOPE = 16384
MAX_COMMAND = 8192
MAX_RESPONSE = 4096
OPS = frozenset({"session.create", "session.revoke", "session.fetch"})
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,96}\.json\Z")


def _parse_canonical(data: bytes):
    if not data or len(data) > MAX_COMMAND:
        deny("invalid operator command length")
    try:
        obj = json.loads(data)
        if not isinstance(obj, dict) or _json_bytes(obj) != data:
            deny("operator commands must use canonical JSON")
        return obj
    except (UnicodeDecodeError, ValueError, TypeError, OverflowError) as exc:
        raise ExecutionDenied("invalid operator command") from exc


def _b64(data):
    if not isinstance(data, str) or len(data) > 12000 or not data.isascii():
        deny("invalid operator envelope")
    try:
        return base64.b64decode(data, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ExecutionDenied("invalid operator envelope encoding") from exc


def encode_signed_command(command: dict, private_key: Ed25519PrivateKey):
    """Private operator signing only; never import/invoke from agent tooling."""
    raw = _json_bytes(command)
    if len(raw) > MAX_COMMAND:
        deny("operator command too long")
    return _json_bytes({"payload_b64": base64.b64encode(raw).decode("ascii"),
        "signature_b64": base64.b64encode(private_key.sign(API_CONTEXT + raw)).decode("ascii")})


def issue_command(key: Ed25519PrivateKey, principal: str, engagement_id: str,
                  operation: str, args: dict, *, expires_seconds: int = 30,
                  request_id: str | None = None) -> bytes:
    if not 1 <= expires_seconds <= 60:
        deny("operator command must expire within one minute")
    import secrets
    now = datetime.now(timezone.utc)
    stamp = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
    obj = {"version": 1, "principal": principal, "engagement_id": engagement_id,
           "request_id": request_id or secrets.token_hex(16),
           "not_before": stamp(now - timedelta(seconds=2)),
           "expires_at": stamp(now + timedelta(seconds=expires_seconds)),
           "operation": operation, "args": args}
    return encode_signed_command(obj, key)


class OperatorService:
    def __init__(self, authority: AegisCredentialAuthority, api_policy_path: Path):
        self.authority = authority
        self.api_policy_path = Path(api_policy_path)

    def _policy(self, info):
        policy = json.loads(_protected_bytes(self.api_policy_path, 16384, private=True))
        if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
            deny("invalid independent operator API policy")
        if policy["version"] != 1 or policy["configured"] is not True:
            deny("operator API not enabled")
        if (not isinstance(policy["principal"], str) or len(policy["principal"]) < 3 or
                not isinstance(policy["allowed_engagement_ids"], list) or
                info["engagement_id"] not in policy["allowed_engagement_ids"] or
                not isinstance(policy["allowed_peer_uids"], list) or
                not 1 <= len(policy["allowed_peer_uids"]) <= 16 or
                any(type(uid) is not int or not 0 <= uid <= 2**31 - 1
                    for uid in policy["allowed_peer_uids"]) or
                type(policy["max_request_window_seconds"]) is not int or
                not 1 <= policy["max_request_window_seconds"] <= 60):
            deny("operator API identity/engagement policy invalid")
        for name in ("public_key_pem_path", "socket_path", "approval_dir"):
            value = policy[name]
            if not isinstance(value, str) or not value.startswith("/") or value.endswith("/."):
                deny("operator API protected path must be absolute")
            p = Path(value)
            if '..' in p.parts or '.' in p.parts or p == Path('/usr') or Path('/usr') in p.parents:
                deny("operator API material overlaps worker-visible runtime")
            if (p == self.authority.state_root or self.authority.state_root in p.parents or
                    any(p == Path(repo) or Path(repo) in p.parents for repo in info["authorized_repositories"])):
                deny("operator API material may not overlap agent-writable assets")
        pub = _protected_bytes(Path(policy["public_key_pem_path"]), 8192)
        key = load_pem_public_key(pub)
        if not isinstance(key, Ed25519PublicKey):
            deny("operator API key must be Ed25519")
        if self.api_policy_path == Path(policy["public_key_pem_path"]):
            deny("operator API policy and key must be separate")
        with open_directory_nofollow(Path(policy["approval_dir"])) as approval_fd:
            st = os.fstat(approval_fd)
            if st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o077:
                deny("approval directory must be service-owned, private and non-symlinked")
        return policy, key

    @staticmethod
    def _args(operation, args):
        if not isinstance(args, dict):
            deny("operator command args must be a fixed JSON object")
        if operation == "session.create":
            if set(args) != {"approval_name"} or not isinstance(args["approval_name"], str):
                deny("invalid session creation command")
            name = args["approval_name"]
            if not NAME_RE.fullmatch(name) or name.startswith(".") or ".." in name:
                deny("approval filename must be a simple JSON basename")
        elif operation == "session.revoke":
            if set(args) != {"session_handle"} or not isinstance(args["session_handle"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", args["session_handle"]):
                deny("invalid session revoke command")
        elif operation == "session.fetch":
            if set(args) != {"session_handle", "url", "method", "budget_seconds"}:
                deny("invalid session fetch shape")
            if (not isinstance(args["session_handle"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", args["session_handle"]) or
                    not isinstance(args["url"], str) or len(args["url"]) > 4096 or
                    args["method"] not in ("GET", "HEAD") or type(args["budget_seconds"]) is not int or
                    not 2 <= args["budget_seconds"] <= 30):
                deny("invalid session fetch command")
        else:
            deny("unsupported operator command")

    def authenticate(self, envelope: bytes, peer_uid: int):
        """Authenticate and durably consume request id before calling any operation."""
        info, _ = self.authority._guard()
        policy, key = self._policy(info)
        if peer_uid not in policy["allowed_peer_uids"]:
            deny("operator peer identity not authorized")
        if not envelope or len(envelope) > MAX_ENVELOPE:
            deny("invalid operator envelope length")
        env = _parse_canonical(envelope)
        if set(env) != {"payload_b64", "signature_b64"}:
            deny("operator envelope has extra or missing fields")
        payload = _b64(env["payload_b64"])
        signature = _b64(env["signature_b64"])
        if len(signature) != 64:
            deny("invalid command signature")
        try:
            key.verify(signature, API_CONTEXT + payload)
        except InvalidSignature as exc:
            raise ExecutionDenied("unauthorized operator signature") from exc
        obj = _parse_canonical(payload)
        if set(obj) != API_KEYS or obj.get("version") != 1:
            deny("incomplete signed operator command")
        now = time.time()
        if (obj["principal"] != policy["principal"] or
                obj["engagement_id"] != info["engagement_id"] or
                not isinstance(obj["request_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", obj["request_id"]) or
                obj["operation"] not in OPS):
            deny("signed operator identity/scope invalid")
        issued, expires = _utc(obj["not_before"]), _utc(obj["expires_at"])
        if not issued <= now < expires or not 0 < expires - issued <= policy["max_request_window_seconds"]:
            deny("operator request expired or outside approved window")
        self._args(obj["operation"], obj["args"])
        with self.authority._database() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                verify_rows(con.execute("SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq").fetchall())
            except AuditError as exc:
                raise ExecutionDenied("operator request audit chain invalid") from exc
            con.execute("""CREATE TABLE IF NOT EXISTS operator_requests
                (request_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
                 request_sha256 TEXT NOT NULL, consumed_epoch REAL NOT NULL)""")
            if con.execute("SELECT 1 FROM operator_requests WHERE request_id=?", (obj["request_id"],)).fetchone():
                deny("operator request replay denied")
            con.execute("INSERT INTO operator_requests VALUES(?,?,?,?)",
                (obj["request_id"], info["engagement_id"], hashlib.sha256(payload).hexdigest(), now))
            self.authority._event(con, {"type": "operator_command_accepted",
                 "engagement_id": info["engagement_id"], "operation": obj["operation"],
                 "request_sha256": hashlib.sha256(payload).hexdigest()})
            con.commit()
        return obj, policy

    def handle(self, envelope: bytes, peer_uid: int):
        obj, policy = self.authenticate(envelope, peer_uid)
        op, args = obj["operation"], obj["args"]
        if op == "session.create":
            path = Path(policy["approval_dir"]) / args["approval_name"]
            result = self.authority.create_session(path, path.with_name(path.name + ".sig"))
        elif op == "session.revoke":
            result = self.authority.revoke_session(args["session_handle"])
        elif op == "session.fetch":
            result = self.authority.authenticated_request(args["session_handle"],
                args["url"], args["method"], args["budget_seconds"])
        else:
            deny("unknown operator action")
        if not isinstance(result, dict) or len(_json_bytes(result)) > MAX_RESPONSE:
            deny("operator result exceeds bounded metadata")
        return result

    def process_connection(self, sock):
        if not hasattr(socket, 'SO_PEERCRED'):
            deny("Linux SO_PEERCRED required")
        ucred = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", ucred)
        sock.settimeout(3)
        data = bytearray()
        while len(data) < MAX_ENVELOPE + 1:
            part = sock.recv(min(4096, MAX_ENVELOPE + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        if not data or len(data) > MAX_ENVELOPE:
            deny("operator command missing or oversized")
        return self.handle(bytes(data), uid)

    def serve(self, *, stop_event=None):
        if sys.platform != "linux" or os.geteuid() == 0:
            deny("operator service must run non-root on Linux")
        info, _ = self.authority._guard()
        policy, _ = self._policy(info)
        path = Path(policy["socket_path"])
        if path.parent == Path("/"):
            deny("operator socket requires dedicated private directory")
        with open_directory_nofollow(path.parent) as dfd:
            st = os.fstat(dfd)
            if st.st_uid != os.geteuid() or st.st_mode & 0o077:
                deny("operator socket directory must be service-owned 0700")
        if os.path.lexists(path):
            deny("operator socket already exists; refusing to replace it")
        oldmask = os.umask(0o077)
        try:
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(4)
            listener.settimeout(1)
        finally:
            os.umask(oldmask)
        try:
            while stop_event is None or not stop_event.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                with client:
                    try:
                        answer = {"ok": True, "result": self.process_connection(client)}
                    except (ExecutionDenied, OSError, ValueError, KeyError, TypeError,
                            sqlite3.Error):
                        answer = {"ok": False, "status": "OPERATOR_DENIED"}
                    payload = _json_bytes(answer)
                    if len(payload) <= MAX_RESPONSE:
                        try:
                            client.sendall(payload)
                        except OSError:
                            pass
        finally:
            identity = os.stat(path, follow_symlinks=False)
            listener.close()
            if os.path.lexists(path) and os.stat(path, follow_symlinks=False).st_ino == identity.st_ino:
                os.unlink(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run protected operator-only AEGIS control service")
    for key in ("manifest", "signature", "trust", "state-root", "credential-policy", "api-policy"):
        parser.add_argument("--" + key, required=True)
    args = parser.parse_args(argv)
    try:
        authority = AegisCredentialAuthority(args.manifest, args.signature, args.trust,
            args.state_root, args.credential_policy)
        OperatorService(authority, Path(args.api_policy)).serve()
        return 0
    except (ExecutionDenied, ValueError, OSError, sqlite3.Error):
        print("OPERATOR_SERVICE_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
