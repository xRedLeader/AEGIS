#!/usr/bin/env python3
"""AEGIS v1.4.1 HTTP(S) supervisor: scoped metadata-only GET/HEAD.

Authorization is checked from a signed scope and separate operator trust file;
requests are charged atomically before DNS, connections use verified IP literals,
and a fixed trusted helper is watched for revocation/stop and wall-time limits.

The trusted broker connects the pinned endpoint and confines the HTTP worker
to that socket in offline namespaces with seccomp. Only the operator service
may invoke this class; agents must not receive direct broker or host access.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import stat
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import uuid

from aegis_audit import AuditError, verify_rows
from aegis_preflight import read_protected_trust, PreflightError
from aegis_http_policy import HttpPolicyDenied, inspect_url, pinned_address
from aegis_supervisor import AegisSupervisor, ExecutionDenied, HERE, deny, preexec_limits

MAX_GATEWAY_OUTPUT = 8192
HTTP_EVIDENCE_RESERVATION = 8192
MAX_REQUEST_SECONDS = 30
DNS_TIMEOUT_SECONDS = 5


class AegisHttpSupervisor(AegisSupervisor):
    @staticmethod
    def _ensure_http_tables(con):
        con.execute("""CREATE TABLE IF NOT EXISTS http_requests (
            request_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
            manifest_sha TEXT NOT NULL, origin TEXT NOT NULL, method TEXT NOT NULL,
            started_epoch REAL NOT NULL, deadline_epoch REAL NOT NULL,
            status TEXT NOT NULL, finished_utc TEXT)""")
        con.execute("CREATE INDEX IF NOT EXISTS http_by_engagement ON http_requests(engagement_id,origin,started_epoch)")
        con.execute("""CREATE TABLE IF NOT EXISTS http_body_budget (
            engagement_id TEXT PRIMARY KEY, manifest_sha TEXT NOT NULL,
            reserved_bytes INTEGER NOT NULL)""")

    def _reserve_request(self, info: dict, manifest: dict, origin: str,
                         method: str, seconds: int) -> str:
        eid, sha = info["engagement_id"], info["manifest_sha256"]
        limits = manifest["limits"]
        request_id = str(uuid.uuid4())
        now = time.time()
        with self._database() as con:
            try:
                con.execute("BEGIN IMMEDIATE")
                self._ensure_http_tables(con)
                try:
                    verify_rows(con.execute("SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq").fetchall())
                except AuditError as exc:
                    deny("audit integrity failure: " + str(exc))
                row = con.execute("SELECT manifest_sha,reserved_seconds,reserved_evidence_bytes FROM usage WHERE engagement_id=?", (eid,)).fetchone()
                if row is None:
                    con.execute("INSERT INTO usage VALUES(?,?,0,0)", (eid, sha))
                    row = (sha, 0, 0)
                if row[0] != sha:
                    deny("engagement scope changed; new engagement required")
                # An expired slot may be reaped only after its maximum wall time.
                # Actual helpers are separately killed by the parent watchdog.
                expired = con.execute("UPDATE http_requests SET status='expired', finished_utc=? WHERE engagement_id=? AND status='reserved' AND deadline_epoch<?", (datetime.now(timezone.utc).isoformat(), eid, now)).rowcount
                if expired:
                    self._event(con, {"type": "http_expired_slots", "engagement_id": eid, "count": expired})
                prior_sha = con.execute("SELECT COUNT(*) FROM http_requests WHERE engagement_id=? AND manifest_sha<>?", (eid, sha)).fetchone()[0]
                if prior_sha:
                    deny("HTTP authorization manifest changed within engagement")
                count = con.execute("SELECT COUNT(*) FROM http_requests WHERE engagement_id=?", (eid,)).fetchone()[0]
                recent = con.execute("SELECT COUNT(*) FROM http_requests WHERE engagement_id=? AND origin=? AND started_epoch>?", (eid, origin, now - 60)).fetchone()[0]
                active = con.execute("SELECT COUNT(*) FROM http_requests WHERE engagement_id=? AND status='reserved'", (eid,)).fetchone()[0]
                if count >= limits["max_total_requests"]:
                    deny("cumulative HTTP request limit exhausted")
                if recent >= limits["max_requests_per_minute_per_origin"]:
                    deny("per-origin requests-per-minute limit reached")
                if active >= limits["max_concurrent_requests"]:
                    deny("HTTP concurrency limit reached")
                if row[1] + seconds > limits["engagement_runtime_minutes"] * 60:
                    deny("cumulative runtime budget exhausted")
                if row[2] + HTTP_EVIDENCE_RESERVATION > limits["max_total_evidence_bytes"]:
                    deny("cumulative evidence budget exhausted")
                bodyrow = con.execute("SELECT manifest_sha,reserved_bytes FROM http_body_budget WHERE engagement_id=?", (eid,)).fetchone()
                if bodyrow is None:
                    con.execute("INSERT INTO http_body_budget VALUES(?,?,0)", (eid, sha))
                    bodyrow = (sha, 0)
                if bodyrow[0] != sha:
                    deny("HTTP body-budget scope changed")
                if bodyrow[1] + limits["max_response_body_bytes"] > limits["max_total_response_bytes"]:
                    deny("cumulative HTTP response-body budget exhausted")
                self._check_kill(eid)
                con.execute("UPDATE usage SET reserved_seconds=reserved_seconds+?,reserved_evidence_bytes=reserved_evidence_bytes+? WHERE engagement_id=?", (seconds, HTTP_EVIDENCE_RESERVATION, eid))
                con.execute("UPDATE http_body_budget SET reserved_bytes=reserved_bytes+? WHERE engagement_id=?", (limits["max_response_body_bytes"], eid))
                con.execute("INSERT INTO http_requests VALUES(?,?,?,?,?,?,?,?,NULL)",
                            (request_id, eid, sha, origin, method, now, now + seconds + 3, "reserved"))
                self._event(con, {"type": "http_reserved", "engagement_id": eid,
                                  "request_id": request_id, "origin": origin, "method": method,
                                  "seconds": seconds, "evidence_bytes": HTTP_EVIDENCE_RESERVATION,
                                  "body_bytes_reserved": limits["max_response_body_bytes"]})
                con.commit()
            except BaseException:
                con.rollback()
                raise
        return request_id

    def _finish_request(self, eid: str, request_id: str, status: str, note: str = ""):
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._ensure_http_tables(con)
            con.execute("UPDATE http_requests SET status=?, finished_utc=? WHERE engagement_id=? AND request_id=?",
                        (status, datetime.now(timezone.utc).isoformat(), eid, request_id))
            self._event(con, {"type": "http_" + status, "engagement_id": eid,
                              "request_id": request_id, "note": note[:100]})
            con.commit()

    def _helper(self, request: dict, timeout: float, expected: str,
                route_plan: dict | None = None) -> dict:
        if timeout <= 0:
            deny("HTTP operation timed out")
        active_info, _ = self._guard()
        if route_plan is not None:
            self._operator_route_guard(route_plan)
            if route_plan["scheme"] == "https":
                self._operator_tls_ca(active_info)
        body = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        if len(body) > 16384:
            deny("HTTP helper command exceeds maximum input")
        # Fixed helper. Never shell=True or caller-provided executable arguments.
        worker = subprocess.Popen(["/usr/bin/python3", "-I", "-S",
                                   str(HERE / "aegis_http_broker.py"), str(os.getpid())],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, cwd="/", start_new_session=True,
                                  env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1",
                                       "PYTHONDONTWRITEBYTECODE": "1"},
                                  preexec_fn=lambda: preexec_limits(max(2, int(timeout) + 1)))
        try:
            worker.stdin.write(body)
            worker.stdin.close()
            worker.stdin = None
            deadline = time.monotonic() + timeout
            while True:
                active_info, _ = self._guard()
                if route_plan is not None:
                    self._operator_route_guard(route_plan)
                    if route_plan["scheme"] == "https":
                        self._operator_tls_ca(active_info)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    deny("HTTP helper exceeded wall-time budget")
                try:
                    stdout, stderr = worker.communicate(timeout=min(0.2, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
            if worker.returncode != 0:
                deny("HTTP helper rejected or failed request")
            if len(stdout) > MAX_GATEWAY_OUTPUT:
                deny("HTTP helper output exceeded metadata cap")
            result = json.loads(stdout)
            if not isinstance(result, dict) or result.get("status") != expected:
                deny("unexpected HTTP helper result")
            return result
        finally:
            if worker.poll() is None:
                self._kill_worker(worker)

    def _resolve(self, hostname: str, port: int, timeout: float,
                 route_plan: dict | None = None) -> list[str]:
        result = self._helper({"mode": "resolve", "hostname": hostname,
                               "port": port}, timeout, "RESOLVED", route_plan)
        addresses = result.get("addresses")
        if (not isinstance(addresses, list) or not addresses or len(addresses) > 16 or
            any(not isinstance(address, str) for address in addresses)):
            deny("invalid DNS resolver response")
        return addresses

    def _active_operator_trust(self):
        """Fail closed under concurrently rotated/partially written trust files."""
        try:
            return read_protected_trust(self.trust_path)
        except PreflightError as exc:
            raise ExecutionDenied("independent operator trust policy invalid or unavailable") from exc

    def _operator_route_guard(self, plan: dict):
        """Independent, default-deny operator route gate (not just host allowlist).

        A prefix of '/' authorizes all paths at that origin: use only for
        explicitly disposable staging. GET cannot guarantee a state-free route.
        """
        trust = self._active_operator_trust()
        by_origin = trust.get("allowed_http_path_prefixes", {})
        if not isinstance(by_origin, dict):
            deny("invalid operator HTTP route policy")
        prefixes = by_origin.get(plan["origin"], [])
        if not isinstance(prefixes, list) or len(prefixes) > 64:
            deny("invalid operator route allowlist")
        path = plan["target"].split("?", 1)[0]
        if ("%" in path or ";" in path or "//" in path or
            any(part in {".", ".."} for part in path.split("/"))):
            deny("ambiguous HTTP route cannot be reliably scoped")
        for prefix in prefixes:
            if (not isinstance(prefix, str) or not prefix.isascii() or
                not prefix.startswith("/") or len(prefix) > 128 or
                "?" in prefix or "#" in prefix or "\\" in prefix or "%" in prefix or
                ";" in prefix or "//" in prefix or
                any(part in {".", ".."} for part in prefix.split("/"))):
                deny("invalid operator path prefix")
            prefix = prefix.rstrip("/") or "/"
            if prefix == "/" or path == prefix or path.startswith(prefix + "/"):
                return
        deny("HTTP route not authorized by independent operator policy")

    def _operator_tls_ca(self, info: dict):
        """Optional signed-operator policy CA for private HTTPS staging servers.

        CA is never accepted from agent input. Both parent and helper verify
        fingerprint; helper pins its exact bytes in SSL context before TLS.
        """
        trust = self._active_operator_trust()
        spec = trust.get("tls_custom_ca")
        if spec is None:
            return None
        if not isinstance(spec, dict) or set(spec) != {"path", "sha256"}:
            deny("invalid independently configured TLS CA policy")
        path = Path(spec["path"])
        if not path.is_absolute() or any(x in {"..", "."} for x in path.parts[1:]):
            deny("operator TLS CA path must be absolute and canonical")
        if path == self.trust_path or any(
                path == Path(repo) or Path(repo) in path.parents
                for repo in info["authorized_repositories"]):
            deny("operator TLS CA may not be part of a tested repository")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                st = os.fstat(fd)
                if (not stat.S_ISREG(st.st_mode) or st.st_mode & 0o022 or
                    st.st_uid not in (0, os.geteuid()) or st.st_size > 512 * 1024):
                    deny("operator TLS CA file must be protected regular file")
                contents = os.read(fd, 512 * 1024 + 1)
            finally:
                os.close(fd)
        except OSError as exc:
            raise ExecutionDenied("operator TLS CA unavailable") from exc
        if (len(contents) > 512 * 1024 or
            hashlib.sha256(contents).hexdigest() != spec["sha256"]):
            deny("operator TLS CA fingerprint does not match trusted policy")
        return {"path": str(path), "sha256": spec["sha256"]}

    def request(self, url: str, method: str = "GET", budget_seconds: int = 15) -> dict:
        if sys.platform != "linux" or os.geteuid() == 0:
            deny("scoped HTTP requests require a non-root Linux service identity")
        info, manifest = self._guard()
        if "controlled_http_testing" not in info["approved_methods"]:
            deny("controlled_http_testing is not authorized")
        if method not in {"GET", "HEAD"}:
            deny("v1.4.1 permits only GET and HEAD")
        if (type(budget_seconds) is not int or budget_seconds < 2 or
            budget_seconds > min(MAX_REQUEST_SECONDS, manifest["limits"]["max_single_run_minutes"] * 60)):
            deny("HTTP timeout exceeds per-operation limit")
        try:
            plan = inspect_url(url, info["authorized_origins"], manifest["targets"]["excluded_origins"])
        except HttpPolicyDenied as exc:
            raise ExecutionDenied(str(exc)) from exc
        if not manifest["targets"]["networks"]:
            deny("HTTP destinations require explicit signed and independently approved networks")
        self._operator_route_guard(plan)
        ca_bundle = self._operator_tls_ca(info) if plan["scheme"] == "https" else None
        eid = info["engagement_id"]
        request_id = self._reserve_request(info, manifest, plan["origin"], method, budget_seconds)
        began = time.monotonic()
        try:
            # The resolver is a separately killable fixed process, not a
            # blocking DNS call in the protected supervisor process.
            addresses = self._resolve(plan["hostname"], plan["port"],
                                      min(DNS_TIMEOUT_SECONDS, budget_seconds * 0.4), plan)
            try:
                ip = pinned_address(addresses, manifest["targets"]["networks"],
                                    manifest["targets"]["excluded_networks"], plan["hostname"])
            except HttpPolicyDenied as exc:
                raise ExecutionDenied(str(exc)) from exc
            self._guard()
            self._operator_route_guard(plan)
            remaining = budget_seconds - (time.monotonic() - began)
            if remaining <= 0.5:
                deny("HTTP budget exhausted before connection")
            result = self._helper({
                "mode": "fetch", "scheme": plan["scheme"], "hostname": plan["hostname"],
                "port": plan["port"], "address": ip, "method": method,
                "target": plan["target"],
                "timeout": min(10, remaining - 0.2),
                "body_limit": min(manifest["limits"]["max_response_body_bytes"], 1024 * 1024),
                **({"ca_bundle": ca_bundle} if ca_bundle else {}),
            }, remaining, "SUCCESS", plan)
            info, _ = self._guard()
            self._operator_route_guard(plan)
            evidence = {
                "kind": "controlled_http_metadata_v1", "engagement_id": eid,
                "request_id": request_id, "origin": plan["origin"], "method": method,
                # Do not disclose secret-bearing URL query/target in evidence.
                "target_sha256": hashlib.sha256(plan["target"].encode()).hexdigest(),
                "destination_ip": ip, "result": result,
                "credentials_used": False, "body_retained": False,
                "redirect_followed": False,
            }
            payload = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
            if len(payload) > HTTP_EVIDENCE_RESERVATION:
                deny("metadata result exceeds reserved evidence budget")
            artifact = self._write_report(info, request_id, payload, "http-result.json")
            self._finish_request(eid, request_id, "completed")
            return {"status": "COMPLETED_HTTP_METADATA_ONLY", "engagement_id": eid,
                    "request_id": request_id, "http_status": result["http_status"],
                    "body_bytes": result["body_bytes"],
                    "redirect_not_followed": result["redirect_not_followed"],
                    "report": artifact, "reserved_runtime_seconds": budget_seconds}
        except BaseException as exc:
            self._finish_request(eid, request_id, "aborted", type(exc).__name__)
            raise

    def http_usage(self, eid: str) -> dict:
        self._guard()
        with self._database() as con:
            self._ensure_http_tables(con)
            row = con.execute("SELECT COUNT(*), SUM(status='reserved') FROM http_requests WHERE engagement_id=?", (eid,)).fetchone()
            b = con.execute("SELECT reserved_bytes FROM http_body_budget WHERE engagement_id=?", (eid,)).fetchone()
            return {"engagement_id": eid, "reserved_requests": row[0],
                    "active_slots": row[1] or 0, "reserved_body_bytes": b[0] if b else 0}
