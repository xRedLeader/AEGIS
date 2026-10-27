#!/usr/bin/env python3
"""AEGIS v1.5 operator approvals and credential-session authority.

Trusted-control-plane library ONLY. Never give an agent direct access to this
object, vault references, the approval signing key or the SQLite ledger.

A session is an opaque limited capability, not a copy of a credential. The
signed approval authorizes creation; each operation must recheck live scope,
operator revocation, exact origin/route and its independent rate/use budget.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis_audit import AuditError, verify_rows
from aegis_http_policy import inspect_url, pinned_address, HttpPolicyDenied
from aegis_http_runtime import AegisHttpSupervisor
from aegis_supervisor import ExecutionDenied, deny, open_directory_nofollow, HERE, preexec_limits

APPROVAL_CONTEXT = b"AEGIS-credential-approval-v1\x00"
APPROVAL_KEYS = frozenset({"version", "approval_id", "operator", "engagement_id",
    "manifest_sha256", "role", "secret_ref", "origin", "path_prefix", "not_before",
    "expires_at", "session_seconds", "max_uses"})
CONFIG_KEYS = frozenset({"version", "configured", "operator", "public_key_pem_path",
    "allowed_engagement_ids", "credential_paths", "max_session_seconds", "max_uses"})
SESSION_MAX = 900
MAX_APPROVAL_BYTES = 8192
MAX_POLICY_BYTES = 32768
TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/-]{8,2048}$")


def _json_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _utc(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        deny("credential approval timestamps must be UTC")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset().total_seconds() != 0:
            raise ValueError("not UTC")
        return result.timestamp()
    except (ValueError, OverflowError) as exc:
        raise ExecutionDenied("invalid credential approval timestamp") from exc


def _protected_bytes(path: Path, maximum: int, *, private: bool = False) -> bytes:
    """No symlinks in any parent; service- or root-owned immutable regular file."""
    path = Path(path)
    if not path.is_absolute() or path.name in (".", "..") or not path.name:
        deny("protected credential file path must be absolute")
    try:
        with open_directory_nofollow(path.parent) as parent_fd:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=parent_fd)
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in (0, os.geteuid()):
                    deny("credential material must be operator/service-owned regular file")
                if metadata.st_mode & (0o077 if private else 0o022):
                    deny("credential material has unsafe permissions")
                if metadata.st_size > maximum:
                    deny("credential material exceeds limit")
                content = os.read(fd, maximum + 1)
                if len(content) > maximum:
                    deny("credential material exceeds limit")
                return content
            finally:
                os.close(fd)
    except (OSError, ValueError) as exc:
        raise ExecutionDenied("protected credential material unavailable") from exc


def _prefix(path):
    if not isinstance(path, str) or len(path) > 128 or not path.startswith("/") or not path.isascii():
        deny("invalid session route prefix")
    if ("?" in path or "#" in path or "\\" in path or "%" in path or ";" in path or
        "//" in path or any(part in (".", "..") for part in path.split("/"))):
        deny("ambiguous session route prefix")
    return path.rstrip("/") or "/"


def _in_prefix(path, prefix):
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


def _verify_approval(payload: bytes, signature: bytes, key):
    if len(payload) > MAX_APPROVAL_BYTES or len(signature) != 64:
        deny("invalid signed approval size")
    try:
        key.verify(signature, APPROVAL_CONTEXT + payload)
        obj = json.loads(payload)
    except (InvalidSignature, ValueError, UnicodeError) as exc:
        raise ExecutionDenied("credential approval signature or encoding invalid") from exc
    if (not isinstance(obj, dict) or set(obj) != APPROVAL_KEYS or
            _json_bytes(obj) != payload or obj["version"] != 1):
        deny("credential approval must be canonical and schema-complete")
    return obj


class AegisCredentialAuthority(AegisHttpSupervisor):
    """Private operator service entrypoint. Never expose methods as agent tools."""

    def __init__(self, manifest, signature, trust_policy, state_root, credential_policy):
        super().__init__(manifest, signature, trust_policy, state_root)
        self.credential_policy = Path(credential_policy)

    def _authority(self, info):
        policy = json.loads(_protected_bytes(self.credential_policy, MAX_POLICY_BYTES))
        if (not isinstance(policy, dict) or set(policy) != CONFIG_KEYS or
                policy["version"] != 1 or policy["configured"] is not True or
                not isinstance(policy["operator"], str) or len(policy["operator"]) < 3 or
                info["engagement_id"] not in policy["allowed_engagement_ids"] or
                type(policy["max_session_seconds"]) is not int or
                not 1 <= policy["max_session_seconds"] <= SESSION_MAX or
                type(policy["max_uses"]) is not int or not 1 <= policy["max_uses"] <= 100):
            deny("independent credential authority is not configured for engagement")
        if (not isinstance(policy["allowed_engagement_ids"], list) or
                not isinstance(policy["credential_paths"], dict)):
            deny("invalid credential authorization policy")
        pub = _protected_bytes(Path(policy["public_key_pem_path"]), 8192)
        key = load_pem_public_key(pub)
        if not isinstance(key, Ed25519PublicKey):
            deny("credential approval key must be Ed25519")
        # None of the external policy or secrets may be inside target repos or
        # the mutable result/ledger directory.
        if any(not isinstance(v, str) or not v.startswith("/") for v in policy["credential_paths"].values()):
            deny("credential vault paths must be absolute")
        for p in [self.credential_policy, Path(policy["public_key_pem_path"]),
                  *(Path(v) for v in policy["credential_paths"].values())]:
            if not p.is_absolute() or p == self.state_root or self.state_root in p.parents or any(
                    p == Path(repo) or Path(repo) in p.parents
                    for repo in info["authorized_repositories"]):
                deny("credential authority material overlaps agent-writable assets")
        return policy, key

    @staticmethod
    def _tables(con):
        con.execute("""CREATE TABLE IF NOT EXISTS credential_approvals (
            approval_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
            digest TEXT NOT NULL, consumed_epoch REAL NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS credential_sessions (
            handle_hash TEXT PRIMARY KEY, approval_id TEXT NOT NULL UNIQUE,
            engagement_id TEXT NOT NULL, manifest_sha TEXT NOT NULL,
            role TEXT NOT NULL, secret_ref TEXT NOT NULL,
            origin TEXT NOT NULL, path_prefix TEXT NOT NULL,
            created_epoch REAL NOT NULL, expires_epoch REAL NOT NULL,
            max_uses INTEGER NOT NULL, uses INTEGER NOT NULL DEFAULT 0,
            revoked INTEGER NOT NULL DEFAULT 0)""")

    def validate_grant(self, obj, info, manifest, policy):
        now = time.time()
        if (not isinstance(obj["approval_id"], str) or
            not re.fullmatch(r"[0-9a-f]{32}", obj["approval_id"]) or
            obj["operator"] != policy["operator"] or
            obj["engagement_id"] != info["engagement_id"] or
            obj["manifest_sha256"] != info["manifest_sha256"] or
            not _utc(obj["not_before"]) <= now < _utc(obj["expires_at"]) or
            _utc(obj["expires_at"]) - _utc(obj["not_before"]) > 600 or
            type(obj["session_seconds"]) is not int or
            not 1 <= obj["session_seconds"] <= policy["max_session_seconds"] or
            type(obj["max_uses"]) is not int or
            not 1 <= obj["max_uses"] <= policy["max_uses"]):
            deny("credential approval not valid for current scope and time")
        accounts = [a for a in manifest["accounts"] if
                    a["role"] == obj["role"] and a["secret_ref"] == obj["secret_ref"] and
                    obj["origin"] in a["allowed_origins"]]
        if len(accounts) != 1 or obj["secret_ref"] not in policy["credential_paths"]:
            deny("credential approval does not bind a unique authorized account")
        if obj["origin"] not in info["authorized_origins"] or not obj["origin"].startswith("https://"):
            deny("credential sessions require an explicitly authorized HTTPS origin")
        prefix = _prefix(obj["path_prefix"])
        plan = inspect_url(obj["origin"] + prefix, info["authorized_origins"],
                           manifest["targets"]["excluded_origins"])
        self._operator_route_guard(plan)
        end = min(now + obj["session_seconds"], _utc(manifest["engagement"]["valid_until_utc"]))
        if end <= now:
            deny("credential session cannot outlive signed engagement")
        return prefix, end

    def create_session(self, approval_path: Path, signature_path: Path):
        info, manifest = self._guard()
        policy, key = self._authority(info)
        payload = _protected_bytes(Path(approval_path), MAX_APPROVAL_BYTES)
        signature = _protected_bytes(Path(signature_path), 64)
        obj = _verify_approval(payload, signature, key)
        prefix, end = self.validate_grant(obj, info, manifest, policy)
        now = time.time()
        handle = secrets.token_urlsafe(32)
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            try:
                verify_rows(con.execute("SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq").fetchall())
            except AuditError as exc:
                raise ExecutionDenied("audit verification failed") from exc
            if con.execute("SELECT 1 FROM credential_approvals WHERE approval_id=?",
                           (obj["approval_id"],)).fetchone():
                deny("operator approval replay rejected")
            con.execute("INSERT INTO credential_approvals VALUES(?,?,?,?)",
                        (obj["approval_id"], info["engagement_id"],
                         hashlib.sha256(payload).hexdigest(), now))
            con.execute("""INSERT INTO credential_sessions
                (handle_hash,approval_id,engagement_id,manifest_sha,role,secret_ref,origin,
                 path_prefix,created_epoch,expires_epoch,max_uses) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (hashlib.sha256(handle.encode()).hexdigest(), obj["approval_id"],
                 info["engagement_id"], info["manifest_sha256"], obj["role"], obj["secret_ref"],
                 obj["origin"], prefix, now, end, obj["max_uses"]))
            self._event(con, {"type": "credential_session_created", "engagement_id": info["engagement_id"],
                              "approval_id": obj["approval_id"], "role": obj["role"],
                              "origin": obj["origin"], "expires_epoch": end})
            con.commit()
        return {"status": "SESSION_CREATED", "handle": handle,
                "expires_epoch": end, "max_uses": obj["max_uses"]}

    def _check_session(self, handle, plan, consume=False, allow_exhausted=False):
        info, manifest = self._guard()
        policy, _ = self._authority(info)
        if not isinstance(handle, str) or len(handle) > 128 or len(handle) < 24:
            deny("invalid credential session handle")
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            try:
                verify_rows(con.execute("SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq").fetchall())
            except AuditError as exc:
                raise ExecutionDenied("audit integrity check failed") from exc
            row = con.execute("""SELECT engagement_id, manifest_sha, role, secret_ref,
                origin, path_prefix, expires_epoch, max_uses, uses, revoked
                FROM credential_sessions WHERE handle_hash=?""",
                (hashlib.sha256(handle.encode()).hexdigest(),)).fetchone()
            if not row or row[0] != info["engagement_id"] or row[1] != info["manifest_sha256"]:
                deny("credential session unavailable for this engagement")
            eid, sha, role, ref, origin, prefix, expires, max_uses, uses, revoked = row
            if (revoked or time.time() >= expires or (uses >= max_uses and not allow_exhausted) or
                    origin != plan["origin"] or not _in_prefix(plan["target"].split("?",1)[0], prefix) or
                    ref not in policy["credential_paths"]):
                deny("credential session expired, revoked, exhausted or outside approved route")
            if consume:
                con.execute("UPDATE credential_sessions SET uses=uses+1 WHERE handle_hash=?",
                            (hashlib.sha256(handle.encode()).hexdigest(),))
                self._event(con, {"type": "credential_use_reserved", "engagement_id": eid,
                                  "origin": origin, "role": role})
            con.commit()
        return {"role": role, "secret_ref": ref, "origin": origin,
                "session_expiry": expires, "uses_left": max_uses - uses - (1 if consume else 0)}

    def authorize_operation(self, handle, url, method="GET"):
        """Reserve ONE permitted operation; returns metadata, never credentials."""
        info, manifest = self._guard()
        if method not in ("GET", "HEAD") or "controlled_http_testing" not in info["approved_methods"]:
            deny("credentialed operation not permitted")
        try:
            plan = inspect_url(url, info["authorized_origins"], manifest["targets"]["excluded_origins"])
        except HttpPolicyDenied as exc:
            raise ExecutionDenied("credential URL is outside signed scope") from exc
        self._operator_route_guard(plan)
        if plan["scheme"] != "https":
            deny("credential operation requires HTTPS")
        session = self._check_session(handle, plan, consume=True)
        return {"status": "CREDENTIAL_OPERATION_AUTHORIZED", "origin": plan["origin"],
                "method": method, "session_expiry": session["session_expiry"],
                "remaining_uses": session["uses_left"]}

    def revoke_session(self, handle):
        """Operator-facing command ONLY; never give this to agent principals."""
        info, _ = self._guard()
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            digest = hashlib.sha256(handle.encode()).hexdigest()
            row = con.execute("SELECT engagement_id,revoked FROM credential_sessions WHERE handle_hash=?", (digest,)).fetchone()
            if row is None or row[0] != info["engagement_id"]:
                deny("unknown credential session")
            con.execute("UPDATE credential_sessions SET revoked=1 WHERE handle_hash=?", (digest,))
            self._event(con, {"type": "credential_session_revoked", "engagement_id": info["engagement_id"]})
            con.commit()
        return {"status": "SESSION_REVOKED"}

    def _open_secret_fd(self, handle, plan):
        """Return pinned protected FD only to trusted control-plane code."""
        info, manifest = self._guard()
        policy, _ = self._authority(info)
        session = self._check_session(handle, plan, allow_exhausted=True)
        path = Path(policy["credential_paths"][session["secret_ref"]])
        try:
            with open_directory_nofollow(path.parent) as dirfd:
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dirfd)
        except OSError as exc:
            raise ExecutionDenied("protected credential unavailable") from exc
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid not in (0, os.geteuid()) or
                    meta.st_mode & 0o077 or meta.st_size > 4096):
                deny("protected credential is invalid")
            content = os.read(fd, 4097)
            if not TOKEN_RE.fullmatch(content.decode("ascii", errors="replace")):
                deny("credential vault entry invalid")
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def authenticated_request(self, handle, url, method="GET", budget_seconds=15):
        """Operator-side approved HTTPS metadata request; credentials never enter worker.

        This fixed trusted helper has host networking. It is not the isolated
        assessment worker. Do not expose helper, vault FDs or this Python object
        directly to the agent; only a protected operator service may invoke it.
        """
        import hashlib
        from aegis_http_runtime import HTTP_EVIDENCE_RESERVATION, DNS_TIMEOUT_SECONDS, MAX_REQUEST_SECONDS
        if sys.platform != "linux" or os.geteuid() == 0:
            deny("authenticated requests require non-root Linux service identity")
        info, manifest = self._guard()
        if "controlled_http_testing" not in info["approved_methods"] or method not in ("GET", "HEAD"):
            deny("authenticated requests require approved GET/HEAD capability")
        if type(budget_seconds) is not int or not 2 <= budget_seconds <= MAX_REQUEST_SECONDS:
            deny("authenticated request budget invalid")
        try:
            plan = inspect_url(url, info["authorized_origins"], manifest["targets"]["excluded_origins"])
        except HttpPolicyDenied as exc:
            raise ExecutionDenied("credentialed destination denied") from exc
        if plan["scheme"] != "https" or not manifest["targets"]["networks"]:
            deny("credentialed request requires HTTPS and signed network authorization")
        self._operator_route_guard(plan)
        self._check_session(handle, plan)
        ca = self._operator_tls_ca(info)
        eid = info["engagement_id"]
        request_id = self._reserve_request(info, manifest, plan["origin"], method, budget_seconds)
        start = time.monotonic()
        try:
            self._check_session(handle, plan, consume=True)
            addresses = self._resolve(plan["hostname"], plan["port"],
                                      min(DNS_TIMEOUT_SECONDS, budget_seconds * .4), plan)
            try:
                address = pinned_address(addresses, manifest["targets"]["networks"],
                    manifest["targets"]["excluded_networks"], plan["hostname"])
            except HttpPolicyDenied as exc:
                raise ExecutionDenied("credential destination address denied") from exc
            remaining = budget_seconds - (time.monotonic() - start)
            if remaining <= 1:
                deny("authenticated deadline reached before sending")
            self._guard()
            self._operator_route_guard(plan)
            secret_fd = self._open_secret_fd(handle, plan)
            child = None
            try:
                from aegis_http_broker import parent_death_guard
                parent = os.getpid()
                child = subprocess.Popen(["/usr/bin/python3", "-I", "-S",
                            str(HERE / "aegis_auth_helper.py"), str(secret_fd)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    pass_fds=(secret_fd,), cwd="/", start_new_session=True, env={"PATH": "/usr/bin:/bin",
                        "PYTHONDONTWRITEBYTECODE": "1"},
                    preexec_fn=lambda: (preexec_limits(max(2, budget_seconds)),
                                       parent_death_guard(parent)))
            finally:
                os.close(secret_fd)
            request = {"scheme": "https", "hostname": plan["hostname"],
                       "port": plan["port"], "address": address, "method": method,
                       "target": plan["target"], "timeout": min(10, remaining - .2),
                       "body_limit": min(manifest["limits"]["max_response_body_bytes"], 1048576)}
            if ca:
                request["ca_bundle"] = ca
            raw = _json_bytes(request)
            if len(raw) > 16384:
                deny("trusted credential helper input exceeds cap")
            deadline = time.monotonic() + remaining
            try:
                while True:
                    self._guard()
                    self._operator_route_guard(plan)
                    self._check_session(handle, plan, allow_exhausted=True)
                    seconds_left = deadline - time.monotonic()
                    if seconds_left <= 0:
                        deny("credentialed request exceeded deadline")
                    try:
                        stdout, stderr = child.communicate(
                            input=raw if child.stdin and not child.stdin.closed else None,
                            timeout=min(.2, seconds_left))
                        break
                    except subprocess.TimeoutExpired:
                        # communicate remembers pending input within its internal buffer.
                        raw = None
                        continue
                if child.returncode != 0 or len(stdout) > 2048:
                    deny("authenticated transport rejected request")
                result = json.loads(stdout)
                if (not isinstance(result, dict) or
                    set(result) != {"status", "http_status", "body_bytes", "redirect_not_followed"} or
                    result["status"] != "AUTH_METADATA_ONLY" or
                    type(result["http_status"]) is not int or
                    type(result["body_bytes"]) is not int or
                    type(result["redirect_not_followed"]) is not bool):
                    deny("invalid authenticated transport result")
                self._guard()
                self._check_session(handle, plan, allow_exhausted=True)
                # Never retain query, token, header values, response body or body hash.
                evidence = {"kind": "credentialed_http_metadata_v1",
                    "engagement_id": eid, "request_id": request_id,
                    "origin": plan["origin"], "method": method,
                    "target_sha256": hashlib.sha256(plan["target"].encode()).hexdigest(),
                    "destination_ip": address, "http_status": result["http_status"],
                    "body_bytes": result["body_bytes"], "credential_used": True,
                    "body_retained": False, "redirect_followed": False}
                payload = _json_bytes(evidence)
                if len(payload) > HTTP_EVIDENCE_RESERVATION:
                    deny("credential metadata exceeds evidence reservation")
                artifact = self._write_report(info, request_id, payload, "http-result.json")
                self._finish_request(eid, request_id, "completed")
                return {"status": "AUTHENTICATED_METADATA_COMPLETED",
                    "engagement_id": eid, "request_id": request_id,
                    "http_status": result["http_status"], "body_bytes": result["body_bytes"],
                    "report": artifact}
            finally:
                if child is not None:
                    if child.poll() is None:
                        self._kill_worker(child)
                    child.wait()
                    for stream in (child.stdin, child.stdout, child.stderr):
                        if stream:
                            stream.close()
        except BaseException as exc:
            self._finish_request(eid, request_id, "aborted", type(exc).__name__)
            raise
