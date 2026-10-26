#!/usr/bin/env python3
"""AEGIS v1.3 local supervisor with a rootless Linux namespace worker.

ONLY supports bounded read-only source review. The fixed worker runs in a
Linux user/mount/network/PID namespace with a sealed filesystem and seccomp.
This protects the worker; it does NOT confine an agent with independent shell
or network access. Launch from a trusted operator-owned service.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import tempfile
import sys
import time
import uuid

import yaml
from aegis_preflight import PreflightError, UniqueKeyLoader, validate

HERE = Path(__file__).resolve().parent
SCAN_RESULT_RESERVATION = 32 * 1024
MAX_RESULT_BYTES = SCAN_RESULT_RESERVATION
O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class ExecutionDenied(Exception):
    pass


def deny(message):
    raise ExecutionDenied(message)


def relative_parts(absolute: Path):
    if not absolute.is_absolute():
        deny("protected output path must be absolute")
    parts = absolute.parts
    if not parts or parts[0] != "/":
        deny("POSIX absolute path required")
    if any(part in {"..", "."} for part in parts[1:]):
        deny("dot components forbidden in protected path")
    return parts[1:]


@contextmanager
def open_directory_nofollow(directory: Path, create: bool = False):
    """Safely walk every POSIX path component without following symlinks."""
    fd = os.open("/", O_DIR)
    try:
        for part in relative_parts(directory):
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            nxt = os.open(part, O_DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
        yield fd
    finally:
        os.close(fd)


def private_directory(fd: int):
    """Reports are not writable/readable by other local identities."""
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        deny("private report directory must be service-owned with mode 0700")


def preexec_limits(seconds: int):
    """Best-effort POSIX limits for the known, trusted static worker."""
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (max(2, seconds), max(3, seconds + 1)))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024, 256 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))


class AegisSupervisor:
    def __init__(self, manifest: Path, signature: Path, trust_policy: Path, state_root: Path):
        self.manifest_path = Path(manifest)
        self.signature_path = Path(signature)
        self.trust_path = Path(trust_policy)
        self.state_root = Path(state_root)
        self.pinned_sha: str | None = None
        self._check_state_root()

    def _check_state_root(self):
        if not self.state_root.is_absolute():
            deny("state root must be an absolute trusted path")
        try:
            with open_directory_nofollow(self.state_root) as fd:
                st = os.fstat(fd)
                if st.st_uid != os.geteuid() or st.st_mode & 0o077:
                    deny("state root must be owned by service identity, mode 0700")
        except OSError as exc:
            raise ExecutionDenied(f"protected state root invalid: {exc}") from exc

    def _check_kill(self, eid: str):
        marker = self.state_root / (eid + ".stop")
        if marker.exists() or marker.is_symlink():
            deny("operator emergency stop active")

    def _guard(self) -> tuple[dict, dict]:
        self._check_state_root()
        try:
            info = validate(self.manifest_path, self.signature_path, self.trust_path)
            raw = self.manifest_path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != info["manifest_sha256"]:
                deny("manifest changed during verification")
            manifest = yaml.load(raw.decode("utf-8"), Loader=UniqueKeyLoader)
        except (PreflightError, ValueError, OSError, yaml.YAMLError) as exc:
            raise ExecutionDenied(f"scope verification failed: {exc}") from exc
        if self.pinned_sha is None:
            self.pinned_sha = info["manifest_sha256"]
        elif self.pinned_sha != info["manifest_sha256"]:
            deny("manifest changed within the same supervisor session")
        self._check_kill(info["engagement_id"])
        # State is separate from reports, repositories and the operator's keys.
        for repo in info["authorized_repositories"]:
            try:
                if self.state_root.resolve() == Path(repo).resolve() or self.state_root.resolve().is_relative_to(Path(repo).resolve()):
                    deny("supervisor state cannot be inside assessed repository")
            except OSError:
                deny("cannot verify supervisor state/repo separation")
        return info, manifest

    @contextmanager
    def _database(self):
        db = self.state_root / "ledger.sqlite3"
        try:
            # No-follow prevents a link to another writable database at opening.
            flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
            fd = os.open(db, flags, 0o600)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                    deny("ledger database must be protected regular file")
            finally:
                os.close(fd)
            con = sqlite3.connect(str(db), timeout=5, isolation_level=None)
            try:
                con.execute("PRAGMA journal_mode=DELETE")
                con.execute("PRAGMA synchronous=FULL")
                con.execute("PRAGMA busy_timeout=5000")
                con.execute("CREATE TABLE IF NOT EXISTS usage (engagement_id TEXT PRIMARY KEY, manifest_sha TEXT NOT NULL, reserved_seconds INTEGER NOT NULL, reserved_evidence_bytes INTEGER NOT NULL)")
                con.execute("CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, status TEXT NOT NULL, budget_seconds INTEGER NOT NULL, started_utc TEXT NOT NULL, ended_utc TEXT)")
                con.execute("CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, previous_hash TEXT NOT NULL, digest TEXT NOT NULL)")
                yield con
            finally:
                con.close()
        except sqlite3.Error as exc:
            raise ExecutionDenied(f"protected ledger unavailable: {exc}") from exc

    @staticmethod
    def _event(con, event: dict):
        previous = con.execute("SELECT digest FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev = previous[0] if previous else "0" * 64
        payload = json.dumps(event, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256((prev + "\n" + payload).encode()).hexdigest()
        con.execute("INSERT INTO audit(event,previous_hash,digest) VALUES (?,?,?)", (payload, prev, digest))

    def reserve(self, seconds: int) -> tuple[dict, dict, str]:
        info, m = self._guard()
        if "source_review" not in info["approved_methods"]:
            deny("source_review is not authorized")
        if type(seconds) is not int or seconds < 1 or seconds > m["limits"]["max_single_run_minutes"] * 60:
            deny("requested run duration exceeds signed single-run limit")
        eid = info["engagement_id"]
        run_id = str(uuid.uuid4())
        with self._database() as con:
            try:
                con.execute("BEGIN IMMEDIATE")
                row = con.execute("SELECT manifest_sha,reserved_seconds,reserved_evidence_bytes FROM usage WHERE engagement_id=?", (eid,)).fetchone()
                if row is None:
                    con.execute("INSERT INTO usage VALUES(?,?,0,0)", (eid, info["manifest_sha256"]))
                    row = (info["manifest_sha256"], 0, 0)
                if row[0] != info["manifest_sha256"]:
                    deny("engagement scope hash changed; new engagement required")
                if row[1] + seconds > m["limits"]["engagement_runtime_minutes"] * 60:
                    deny("engagement cumulative runtime budget exceeded")
                if row[2] + SCAN_RESULT_RESERVATION > m["limits"]["max_total_evidence_bytes"]:
                    deny("engagement cumulative evidence budget exceeded")
                self._check_kill(eid)
                con.execute("UPDATE usage SET reserved_seconds=reserved_seconds+?,reserved_evidence_bytes=reserved_evidence_bytes+? WHERE engagement_id=?", (seconds, SCAN_RESULT_RESERVATION, eid))
                con.execute("INSERT INTO runs VALUES(?,?,?,?,?,NULL)", (run_id, eid, "reserved", seconds, datetime.now(timezone.utc).isoformat()))
                self._event(con, {"type": "reserved", "engagement_id": eid, "run_id": run_id, "scope_sha": info["manifest_sha256"], "runtime_seconds": seconds, "evidence_bytes": SCAN_RESULT_RESERVATION})
                con.commit()
            except BaseException:
                con.rollback()
                raise
        return info, m, run_id

    def _finish(self, eid: str, run_id: str, status: str, notes: str = ""):
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("UPDATE runs SET status=?,ended_utc=? WHERE run_id=? AND engagement_id=?", (status, datetime.now(timezone.utc).isoformat(), run_id, eid))
            self._event(con, {"type": status, "engagement_id": eid, "run_id": run_id, "notes": notes[:160]})
            con.commit()

    def _worker_command(self, repo_fd: int, jail: Path) -> list[str]:
        # Fixed, trusted scan entrypoint: never passes a model-supplied command.
        # No insecure fallback if user namespaces / seccomp are unavailable.
        namespaces = ','.join(str(os.stat('/proc/self/ns/' + name).st_ino)
                              for name in ('user', 'mnt', 'net', 'pid'))
        return ["/usr/bin/unshare", "--user", "--map-root-user", "--mount",
                "--net", "--pid", "--fork", "--kill-child", "--propagation", "private",
                "--", "/usr/bin/python3", "-I", "-S", str(HERE / "aegis_sandbox.py"),
                "--repo-fd", str(repo_fd), "--jail", str(jail), "--mode", "scan",
                "--host-uid", str(os.geteuid()), "--parent-namespaces", namespaces]

    @staticmethod
    def _kill_worker(worker):
        try:
            os.killpg(worker.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            worker.kill()
        worker.communicate()

    def _write_report(self, info: dict, run_id: str, payload: bytes) -> str:
        if len(payload) > MAX_RESULT_BYTES:
            deny("worker evidence exceeds reserved byte budget")
        out = Path(info["report_directory"])
        with open_directory_nofollow(out, create=True) as rootfd:
            private_directory(rootfd)
            try:
                os.mkdir("runs", mode=0o700, dir_fd=rootfd)
            except FileExistsError:
                pass
            runsfd = os.open("runs", O_DIR, dir_fd=rootfd)
            private_directory(runsfd)
            try:
                os.mkdir(run_id, mode=0o700, dir_fd=runsfd)
                runfd = os.open(run_id, O_DIR, dir_fd=runsfd)
                private_directory(runfd)
                try:
                    evidencefd = os.open("source-review.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=runfd)
                    try:
                        os.write(evidencefd, payload)
                        os.fsync(evidencefd)
                    finally:
                        os.close(evidencefd)
                finally:
                    os.close(runfd)
            finally:
                os.close(runsfd)
        return str(out / "runs" / run_id / "source-review.json")

    def scan(self, repo: Path, budget_seconds: int = 15) -> dict:
        if sys.platform != "linux" or not hasattr(os, "O_NOFOLLOW"):
            deny("v1.3 requires Linux with POSIX no-follow support")
        if os.geteuid() == 0:
            deny("v1.3 worker must launch from a non-root service identity")
        info, m = self._guard()
        requested = Path(repo)
        if not requested.is_absolute() or str(requested.resolve()) not in info["authorized_repositories"]:
            deny("repository is outside verified target scope")
        # Pinned authorized descriptor remains open until the sandbox exits;
        # the child verifies its mounted repository's inode against this fd.
        with open_directory_nofollow(requested) as repo_fd:
            if not stat.S_ISDIR(os.fstat(repo_fd).st_mode):
                deny("invalid repo directory")
            info, m, run_id = self.reserve(budget_seconds)
            eid = info["engagement_id"]
            worker = None
            jail = None
            try:
                self._guard()
                jail = Path(tempfile.mkdtemp(prefix="sandbox-", dir=self.state_root))
                worker = subprocess.Popen(self._worker_command(repo_fd, jail),
                                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE, cwd="/", start_new_session=True,
                                          env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1",
                                               "PYTHONDONTWRITEBYTECODE": "1"},
                                          pass_fds=(repo_fd,),
                                          preexec_fn=lambda: preexec_limits(budget_seconds))
                deadline = time.monotonic() + budget_seconds
                while True:
                    self._guard()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        deny("worker exceeded reserved runtime budget")
                    try:
                        stdout, stderr = worker.communicate(timeout=min(0.25, remaining))
                        break
                    except subprocess.TimeoutExpired:
                        continue
                if worker.returncode != 0:
                    deny("isolated worker failed; no result accepted")
                if len(stdout) > MAX_RESULT_BYTES:
                    deny("trusted source reviewer produced excessive evidence")
                result = json.loads(stdout)
                if result.get("status") != "STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES":
                    deny("unexpected worker result")
                self._guard()
                path = self._write_report(info, run_id, stdout)
                self._finish(eid, run_id, "completed")
                return {"status": "COMPLETED_STATIC_REVIEW_ONLY", "engagement_id": eid,
                        "run_id": run_id, "report": path, "summary": result["summary"],
                        "isolation": "LINUX_ROOTLESS_NAMESPACES_READONLY_ROOT_SECCOMP",
                        "unverified_leads": len(result["candidates"]),
                        "reserved_runtime_seconds": budget_seconds}
            except BaseException as exc:
                if worker and worker.poll() is None:
                    self._kill_worker(worker)
                self._finish(eid, run_id, "aborted", str(exc))
                raise
            finally:
                # Namespace mount is invisible in the supervisor's namespace.
                if jail is not None:
                    try:
                        jail.rmdir()
                    except OSError:
                        # A cleanup failure must be visible to the operator.
                        # A protected empty directory is not an escape route.
                        pass

    def usage(self, eid: str) -> dict:
        self._guard()
        with self._database() as con:
            row = con.execute("SELECT manifest_sha,reserved_seconds,reserved_evidence_bytes FROM usage WHERE engagement_id=?", (eid,)).fetchone()
            if not row:
                return {"engagement_id": eid, "reserved_seconds": 0, "reserved_evidence_bytes": 0}
            return {"engagement_id": eid, "scope_sha": row[0], "reserved_seconds": row[1], "reserved_evidence_bytes": row[2]}

    def verify_audit_chain(self) -> bool:
        with self._database() as con:
            rows = con.execute("SELECT event,previous_hash,digest FROM audit ORDER BY seq ASC").fetchall()
            expected = "0" * 64
            for event, prev, digest in rows:
                if prev != expected or hashlib.sha256((prev + "\n" + event).encode()).hexdigest() != digest:
                    return False
                expected = digest
        return True


def operator_stop(state_root: Path, eid: str):
    if not eid or not all(c.islower() or c.isdigit() or c == "-" for c in eid):
        deny("invalid engagement id for stop")
    # Operator-only stop path; do not allow agent writes to the protected root.
    sup = object.__new__(AegisSupervisor)
    sup.state_root = Path(state_root)
    sup._check_state_root()
    with open_directory_nofollow(sup.state_root) as fd:
        try:
            marker = os.open(eid + ".stop", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            os.close(marker)
        except FileExistsError:
            pass


def main(argv=None):
    ap = argparse.ArgumentParser(description="AEGIS v1.3 sandboxed, local-only action supervisor")
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--signature", type=Path)
    cmds = ap.add_subparsers(dest="command", required=True)
    sc = cmds.add_parser("scan", help="Bounded, read-only static lead scan; no target code execution")
    sc.add_argument("--repo", type=Path, required=True)
    sc.add_argument("--seconds", type=int, default=15)
    cmds.add_parser("audit", help="Check chained audit integrity")
    cmds.add_parser("usage", help="Show cumulatively reserved budgets")
    stop = cmds.add_parser("stop", help="Operator-only, irreversible emergency stop marker")
    stop.add_argument("--engagement-id", required=True)
    args = ap.parse_args(argv)
    state_text = os.environ.get("AEGIS_STATE_ROOT")
    trust_text = os.environ.get("AEGIS_TRUST_POLICY")
    if not state_text or not Path(state_text).is_absolute():
        print("DENIED: protected AEGIS_STATE_ROOT must be configured by operator", file=sys.stderr)
        return 2
    try:
        if args.command == "stop":
            operator_stop(Path(state_text), args.engagement_id)
            print(json.dumps({"status": "STOP_SET", "engagement_id": args.engagement_id}))
            return 0
        if not trust_text or not Path(trust_text).is_absolute() or not args.manifest or not args.signature:
            deny("operator-pinned trust policy and signed scope are required")
        s = AegisSupervisor(args.manifest, args.signature, Path(trust_text), Path(state_text))
        if args.command == "scan":
            output = s.scan(args.repo, budget_seconds=args.seconds)
        elif args.command == "usage":
            info, _ = s._guard()
            output = s.usage(info["engagement_id"])
        else:
            s._guard()
            output = {"status": "AUDIT_VALID" if s.verify_audit_chain() else "AUDIT_INVALID"}
        print(json.dumps(output, indent=2))
        return 0 if output.get("status") != "AUDIT_INVALID" else 3
    except (ExecutionDenied, PreflightError, OSError, ValueError, sqlite3.Error) as exc:
        print(f"DENIED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
