#!/usr/bin/env python3
"""AEGIS v1.9: fail-closed operator-side investigation planner and executor.

No agent-controlled shell, network, credentials, policy edits, arbitrary payloads,
or automatic deployed-impact promotion. Decisions derive from authenticated,
completed, immutable v1.8 report packages. The only active assessment action is
an explicitly operator-pinned v1.7 synthetic replay in a fresh Linux sandbox.
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
import sqlite3
import stat
import sys
import time
import uuid

from aegis_audit import AuditError, verify_rows
from aegis_reporting import ReportingSupervisor, canonical, verified_package
from aegis_supervisor import ExecutionDenied, deny, open_directory_nofollow

RUN_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
FINDING_ID = re.compile(r"A18-[0-9a-f]{20}\Z")
PLAN_ID = RUN_ID
HEX = re.compile(r"[0-9a-f]{64}\Z")
MODULE = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_./-]{0,150}\.py\Z")
MAX_POLICY = 16 * 1024
MAX_STEPS = 40
MAX_EDGES = 24


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _safe_path(value):
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 350:
        deny("operator investigation path must be absolute and bounded")
    if any(part in (".", "..", "") for part in value.split("/")[1:]) or "\x00" in value:
        deny("invalid operator investigation path")
    return Path(value)


def _policy(path: Path, info: dict, state: Path) -> tuple[dict, str]:
    """Private positive allowlist; never loaded from target or model output."""
    policy_path = _safe_path(str(path))
    forbidden = [state, Path(info["report_directory"]),
                 *[Path(p) for p in info["authorized_repositories"]]]
    if any(policy_path == p or p in policy_path.parents for p in [*forbidden,Path("/usr")]):
        deny("investigation policy must be outside mutable state and targets")
    with open_directory_nofollow(policy_path.parent) as fd:
        parent = os.fstat(fd)
        if parent.st_uid not in (0, os.geteuid()) or parent.st_mode & 0o022:
            deny("investigation policy parent writable by another principal")
        child = os.open(policy_path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                        os.O_NONBLOCK, dir_fd=fd)
        try:
            st = os.fstat(child)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                    st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o077 or
                    not 0 < st.st_size <= MAX_POLICY):
                deny("investigation policy must be private, regular and bounded")
            raw = os.read(child, MAX_POLICY + 1)
            if len(raw) != st.st_size:
                deny("investigation policy changed during read")
        finally:
            os.close(child)
    try:
        obj = json.loads(raw, object_pairs_hook=_no_duplicates)
        if canonical(obj) != raw:
            deny("investigation policy must be canonical JSON")
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ExecutionDenied("invalid investigation policy") from exc
    required = {"schema_version", "configured", "engagement_ids", "max_steps",
                "max_attempts", "lease_seconds", "allow_local_replay", "replay_targets"}
    if (not isinstance(obj, dict) or set(obj) != required or
            type(obj["schema_version"]) is not int or obj["schema_version"] != 1 or
            obj["configured"] is not True or
            not isinstance(obj["engagement_ids"], list) or
            len(obj["engagement_ids"]) > 20 or
            any(not isinstance(i, str) or len(i) > 64 for i in obj["engagement_ids"]) or
            info["engagement_id"] not in obj["engagement_ids"] or
            type(obj["max_steps"]) is not int or not 1 <= obj["max_steps"] <= MAX_STEPS or
            type(obj["max_attempts"]) is not int or not 1 <= obj["max_attempts"] <= 3 or
            type(obj["lease_seconds"]) is not int or not 60 <= obj["lease_seconds"] <= 300 or
            type(obj["allow_local_replay"]) is not bool or
            not isinstance(obj["replay_targets"], dict) or len(obj["replay_targets"]) > 12):
        deny("investigation policy is not positively configured")
    if obj["replay_targets"] and not obj["allow_local_replay"]:
        deny("local replay target declared while replay is disabled")
    for source, config in obj["replay_targets"].items():
        if not isinstance(source, str) or not RUN_ID.fullmatch(source):
            deny("replay source must be exact run identifier")
        if not isinstance(config, dict) or set(config) != {"repository", "module", "fuzz_policy"}:
            deny("unexpected replay capability")
        repository = _safe_path(config["repository"])
        fuzz = _safe_path(config["fuzz_policy"])
        module = config["module"]
        if (str(repository) not in info["authorized_repositories"] or
                not isinstance(module, str) or not MODULE.fullmatch(module) or
                any(part in (".", "..") for part in module.split("/")) or
                any(fuzz == f or f in fuzz.parents for f in [*forbidden,Path("/usr")])):
            deny("replay capability crosses operator scope")
    return obj, hashlib.sha256(raw).hexdigest()


def _no_duplicates(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate JSON policy field")
        result[k] = v
    return result


def _audit_ok(con):
    try:
        verify_rows(con.execute("SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq").fetchall())
    except AuditError as exc:
        raise ExecutionDenied("investigation audit chain corrupted") from exc


class InvestigationSupervisor(ReportingSupervisor):
    def __init__(self, manifest, signature, trust, state_root, policy_path):
        super().__init__(manifest, signature, trust, state_root)
        self.investigation_policy = Path(policy_path)

    @staticmethod
    def _tables(con):
        ReportingSupervisor._tables(con)
        con.execute("""CREATE TABLE IF NOT EXISTS investigations (
            plan_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
            source_run_id TEXT NOT NULL, manifest_sha TEXT NOT NULL,
            policy_sha TEXT NOT NULL, report_sha TEXT NOT NULL,
            source_sha TEXT NOT NULL, plan_sha TEXT NOT NULL,
            state TEXT NOT NULL, created_utc TEXT NOT NULL,
            UNIQUE(engagement_id,source_run_id,report_sha,policy_sha))""")
        con.execute("""CREATE TABLE IF NOT EXISTS investigation_steps (
            plan_id TEXT NOT NULL, step_id TEXT NOT NULL PRIMARY KEY,
            ordinal INTEGER NOT NULL, kind TEXT NOT NULL,
            finding_id TEXT, state TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            lease_token TEXT, lease_until REAL NOT NULL DEFAULT 0,
            outcome TEXT, outcome_sha TEXT, result_json TEXT,
            UNIQUE(plan_id,ordinal))""")

    def _admit(self):
        info, _ = self._guard()
        policy, digest = _policy(self.investigation_policy, info, self.state_root)
        return info, policy, digest

    def _report(self, info, source_run):
        """Admit latest ledger-bound, complete, unmodified v1.8 package."""
        if not isinstance(source_run, str) or not RUN_ID.fullmatch(source_run):
            deny("investigation source identifier invalid")
        eid = info["engagement_id"]
        with self._database() as con:
            self._tables(con)
            _audit_ok(con)
            row = con.execute("""SELECT source_sha256,report_sha256,latest_sha256
                FROM assessment_reports WHERE source_run_id=? AND engagement_id=?""",
                (source_run, eid)).fetchone()
            run = con.execute("SELECT status FROM runs WHERE run_id=? AND engagement_id=?",
                              (source_run, eid)).fetchone()
            if not row or run != ("completed",):
                deny("investigation requires a completed reported run")
            source_sha, original_sha, latest = row
            digest = latest or original_sha
            if not isinstance(digest, str) or not HEX.fullmatch(digest):
                deny("invalid admitted report digest")
            if digest != original_sha:
                record = con.execute("""SELECT report_sha256 FROM assessment_report_revisions
                    WHERE report_sha256=? AND source_run_id=? AND engagement_id=?""",
                    (digest, source_run, eid)).fetchone()
                if record != (digest,):
                    deny("latest report revision not in protected ledger")
        root = Path(info["report_directory"]) / "assessments" / source_run
        folder = root if digest == original_sha else root / "revisions" / digest
        document = verified_package(folder, digest)
        if (document["engagement_id"] != eid or document["source_run_id"] != source_run or
                document["source_evidence"]["sha256"] != source_sha):
            deny("report identity does not match verified ledger")
        filename = Path(document["source_evidence"]["relative_path"]).name
        raw = self._read_source(info, source_run, filename)
        if hashlib.sha256(raw).hexdigest() != source_sha:
            deny("original assessment bytes changed after report publication")
        return document, digest, source_sha

    @staticmethod
    def _plan_steps(document, policy):
        findings = document["findings"]
        if len(findings) > 150:
            deny("unbounded investigation candidate inventory")
        steps = [{"kind": "verify_report_integrity", "finding_id": None}]
        needs = [x for x in findings if x["verdict"] == "needs_validation"]
        confirmed = [x for x in findings if x["verdict"] == "confirmed"]
        # All decisions are deterministic: independent signed operator policy
        # controls permitted replay, not untrusted finding prose or agent text.
        if (needs and document["source_evidence"]["kind"] == "bounded_fuzz" and
                policy["allow_local_replay"] and
                document["source_run_id"] in policy["replay_targets"]):
            steps.append({"kind": "replay_bounded_local", "finding_id": None})
        for x in sorted(needs, key=lambda y: y["id"]):
            steps.append({"kind": "await_independent_review", "finding_id": x["id"]})
        for x in sorted(confirmed, key=lambda y: y["id"]):
            steps.append({"kind": "await_remediation_retest", "finding_id": x["id"]})
        if len(steps) > policy["max_steps"]:
            deny("planned investigation exceeds operator step ceiling")
        return steps

    @staticmethod
    def _chain_hypotheses(document):
        """Cross-finding correlation is NEVER verified attack-chain evidence."""
        findings = sorted(document["findings"], key=lambda x: x["id"])
        grouped = {}
        for f in findings:
            grouped.setdefault(f["affected_asset"], []).append(f)
        output = []
        for asset, values in sorted(grouped.items()):
            for i in range(len(values)):
                for j in range(i+1, len(values)):
                    if len(output) >= MAX_EDGES:
                        return output
                    output.append({"source": values[i]["id"], "target": values[j]["id"],
                        "asset": asset, "classification": "UNVERIFIED_SHARED_ASSET_ONLY",
                        "observed_transition": False,
                        "warning": "Shared asset is not evidence of a reachable attack chain."})
        return output

    def create(self, source_run):
        info, policy, policy_sha = self._admit()
        document, report_sha, source_sha = self._report(info, source_run)
        steps = self._plan_steps(document, policy)
        eid = info["engagement_id"]
        payload = {"engagement_id": eid, "source_run_id": source_run,
                   "report_sha": report_sha, "source_sha": source_sha,
                   "policy_sha": policy_sha, "manifest_sha": info["manifest_sha256"],
                   "steps": steps, "hypotheses": self._chain_hypotheses(document)}
        digest = hashlib.sha256(canonical(payload)).hexdigest()
        # A stable content-addressed identifier protects idempotent crash retry;
        # it is not an authorization capability or a secret.
        plan_id = str(uuid.UUID(digest[:32], version=4))
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            _audit_ok(con)
            existing = con.execute("SELECT plan_id,plan_sha FROM investigations WHERE engagement_id=? AND source_run_id=? AND report_sha=? AND policy_sha=?",
                                   (eid, source_run, report_sha, policy_sha)).fetchone()
            if existing and existing != (plan_id, digest):
                deny("investigation plan identity collision")
            if not existing:
                con.execute("""INSERT INTO investigations VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (plan_id, eid, source_run, info["manifest_sha256"], policy_sha,
                         report_sha, source_sha, digest, "active", _utc()))
            if not existing:
                for idx, step in enumerate(steps):
                    step_id = hashlib.sha256(canonical([digest, idx, step])).hexdigest()[:32]
                    state = "awaiting_operator" if step["kind"].startswith("await_") else "pending"
                    con.execute("""INSERT INTO investigation_steps
                        (plan_id,step_id,ordinal,kind,finding_id,state)
                        VALUES(?,?,?,?,?,?)""",
                        (plan_id, step_id, idx, step["kind"], step["finding_id"], state))
                self._event(con, {"type": "investigation_plan_created", "engagement_id": eid,
                                  "plan_id": plan_id, "plan_sha": digest, "report_sha": report_sha,
                                  "steps": len(steps)})
            con.commit()
        return self.snapshot(plan_id)

    def _check_plan(self, plan_id, info, policy_sha, *, require_current=True):
        if not isinstance(plan_id, str) or not PLAN_ID.fullmatch(plan_id):
            deny("invalid investigation identifier")
        with self._database() as con:
            self._tables(con)
            _audit_ok(con)
            row = con.execute("""SELECT engagement_id,source_run_id,manifest_sha,policy_sha,
                report_sha,source_sha,plan_sha,state FROM investigations WHERE plan_id=?""",
                (plan_id,)).fetchone()
        if not row or row[0] != info["engagement_id"] or row[2] != info["manifest_sha256"] or row[3] != policy_sha:
            deny("investigation no longer authorized by current operator policy")
        if row[7] != "active":
            deny("investigation is not active")
        if require_current:
            document, digest, source_sha = self._report(info, row[1])
            if digest != row[4] or source_sha != row[5]:
                deny("investigation is stale: report revision/source changed")
        return row

    def snapshot(self, plan_id):
        info, policy, policy_sha = self._admit()
        row = self._check_plan(plan_id, info, policy_sha)
        document, digest, source_sha = self._report(info, row[1])
        steps = self._plan_steps(document, policy)
        plan = {"engagement_id": info["engagement_id"], "source_run_id": row[1],
                "report_sha": digest, "source_sha": source_sha,
                "policy_sha": policy_sha, "manifest_sha": info["manifest_sha256"],
                "steps": steps, "hypotheses": self._chain_hypotheses(document)}
        if hashlib.sha256(canonical(plan)).hexdigest() != row[6]:
            deny("stored investigation step graph differs from canonical plan")
        with self._database() as con:
            self._tables(con)
            recorded = con.execute("""SELECT step_id,ordinal,kind,finding_id,state,attempts,outcome,outcome_sha,result_json
                FROM investigation_steps WHERE plan_id=? ORDER BY ordinal""", (plan_id,)).fetchall()
        if len(recorded) != len(steps) or any(
                (r[1],r[2],r[3]) != (i,s["kind"],s["finding_id"])
                for i,(r,s) in enumerate(zip(recorded,steps))):
            deny("investigation step ledger diverged from plan")
        return {"status": "INVESTIGATION_PLAN", "plan_id": plan_id,
            "source_run_id": row[1], "report_sha256": digest,
            "steps": [{"step_id": r[0], "kind": r[2], "finding_id": r[3],
                       "state": r[4], "attempts": r[5], "outcome": r[6],
                       "outcome_sha256": r[7],
                       "result": self._read_result(r[8],r[7])} for r in recorded],
            "attack_path_hypotheses": plan["hypotheses"],
            "warning": "Correlation is unverified. Operator approval is required for impact claims and retesting deployed systems."}

    @staticmethod
    def _read_result(raw, digest):
        if raw is None:
            return None
        if (not isinstance(raw,str) or len(raw)>2048 or not HEX.fullmatch(digest) or
                hashlib.sha256(raw.encode("ascii")).hexdigest()!=digest):
            deny("investigation result ledger altered")
        try:
            decoded=json.loads(raw)
        except (ValueError,UnicodeError,TypeError) as exc:
            raise ExecutionDenied("investigation result invalid") from exc
        if not isinstance(decoded,dict) or canonical(decoded)!=raw.encode("ascii"):
            deny("noncanonical investigation result")
        return decoded

    def _claim(self, plan_id, info, policy):
        """Claim one deterministic active action; crash recovery is lease-fenced."""
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            _audit_ok(con)
            rows = con.execute("""SELECT step_id,kind,state,attempts,lease_until FROM investigation_steps
                WHERE plan_id=? ORDER BY ordinal""", (plan_id,)).fetchall()
            now = time.time()
            for step_id, kind, state, attempts, lease_until in rows:
                if kind.startswith("await_"):
                    continue
                if state in ("completed", "failed"):
                    continue
                if state == "leased" and lease_until > now:
                    return {"status": "INVESTIGATION_BUSY", "step_id": step_id}
                if state not in ("leased", "pending"):
                    deny("investigation step state tampering")
                if attempts >= policy["max_attempts"]:
                    con.execute("UPDATE investigation_steps SET state='failed',lease_token=NULL,lease_until=0,outcome='ATTEMPTS_EXHAUSTED' WHERE step_id=? AND plan_id=?",(step_id,plan_id))
                    self._event(con, {"type": "investigation_step_exhausted", "plan_id": plan_id,"step_id": step_id})
                    con.commit()
                    return {"status": "INVESTIGATION_ACTION_FAILED", "step_id": step_id}
                token = secrets.token_hex(16)
                con.execute("""UPDATE investigation_steps SET state='leased',attempts=attempts+1,
                    lease_token=?,lease_until=? WHERE step_id=? AND plan_id=?""",
                    (token, now + policy["lease_seconds"], step_id, plan_id))
                self._event(con,{"type":"investigation_step_claimed", "plan_id":plan_id,
                    "step_id":step_id,"kind":kind,"attempt":attempts+1})
                con.commit()
                return {"status":"CLAIMED", "step_id":step_id, "kind":kind,"token":token,
                        "attempt": attempts+1}
        return {"status":"INVESTIGATION_OPERATOR_ACTION_REQUIRED" if any(
            x[2] == "awaiting_operator" for x in rows) else "INVESTIGATION_AUTOMATION_COMPLETE"}

    def _complete(self, plan_id, step_id, token, result, *, success):
        """Fenced finalization: old workers can never acknowledge recovered leases."""
        if not isinstance(result,dict) or not isinstance(result.get("status"),str):
            deny("invalid investigation step result")
        raw=canonical(result)
        if len(raw)>2048:
            deny("investigation result exceeds size ceiling")
        outcome=result["status"]
        if len(outcome)>100 or not outcome.isascii():
            deny("invalid investigation outcome")
        outcome_sha=hashlib.sha256(raw).hexdigest()
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            rec = con.execute("""SELECT state,lease_token,lease_until FROM investigation_steps
                WHERE plan_id=? AND step_id=?""",(plan_id,step_id)).fetchone()
            if not rec or rec[0]!="leased" or rec[1]!=token or rec[2]<=time.time():
                return {"status":"INVESTIGATION_LEASE_SUPERSEDED", "step_id":step_id}
            con.execute("""UPDATE investigation_steps SET state=?,lease_token=NULL,lease_until=0,
                outcome=?,outcome_sha=?,result_json=? WHERE plan_id=? AND step_id=?""",
                ("completed" if success else "pending",outcome,outcome_sha,raw.decode("ascii"),plan_id,step_id))
            self._event(con,{"type":"investigation_step_completed" if success else "investigation_step_failed",
                              "plan_id":plan_id,"step_id":step_id,"outcome":outcome,
                              "outcome_sha256":outcome_sha})
            con.commit()
        return {"status":"INVESTIGATION_ACTION_COMPLETED" if success else "INVESTIGATION_ACTION_RETRY_PENDING",
                "step_id": step_id,"outcome":outcome,"outcome_sha256":outcome_sha}

    def advance(self, plan_id):
        info, policy, policy_sha = self._admit()
        row = self._check_plan(plan_id, info, policy_sha)
        self.snapshot(plan_id)  # verify the stored plan against immutable evidence
        claim = self._claim(plan_id, info, policy)
        if claim["status"] != "CLAIMED":
            return claim
        result = None
        success = False
        try:
            if claim["kind"] == "verify_report_integrity":
                self._report(info, row[1])
                result = {"status":"REPORT_PACKAGE_VERIFIED", "report_sha256":row[4]}
            elif claim["kind"] == "replay_bounded_local":
                if not policy["allow_local_replay"] or row[1] not in policy["replay_targets"]:
                    deny("unapproved local replay action")
                cap = policy["replay_targets"][row[1]]
                from aegis_fuzz_runtime import AegisFuzzSupervisor
                engine = AegisFuzzSupervisor(self.manifest_path, self.signature_path,
                    self.trust_path, self.state_root, Path(cap["fuzz_policy"]))
                result = engine.verify_evidence(Path(cap["repository"]),cap["module"],row[1],seconds=8)
            else:
                deny("unrecognized investigation action kind")
            # Recheck scope/stop, private policy, latest immutable report and
            # source evidence AFTER executing, before acknowledging any effect.
            fresh, _, current_sha = self._admit()
            if current_sha != policy_sha:
                deny("investigation policy changed during action")
            self._check_plan(plan_id,fresh,current_sha)
            result_bytes = canonical(result)
            if len(result_bytes) > 2048:
                deny("investigation step output exceeded budget")
            success=True
        except (OSError, ValueError, TypeError, ExecutionDenied):
            # Do not finalize or requeue when authorization was revoked or
            # policy/report identity changed; leave the lease for recovery.
            fresh, _, current_sha = self._admit()
            if current_sha != policy_sha:
                deny("investigation policy changed before failure handling")
            self._check_plan(plan_id, fresh, current_sha)
            result={"status":"ACTION_DENIED", "kind":claim["kind"]}
        finished = self._complete(plan_id,claim["step_id"],claim["token"],result,success=success)
        if success:
            finished["result"] = result
        return finished

    def run_allowed(self, plan_id, max_steps=10):
        """Bounded one-shot autonomous progression through typed allowed actions.

        Never acts on operator-only checkpoints; each step re-reads all signed
        scope, policy, latest evidence and resource limitations.
        """
        if type(max_steps) is not int or not 1 <= max_steps <= 20:
            deny("invalid autonomous progression ceiling")
        actions = []
        for _ in range(max_steps):
            result = self.advance(plan_id)
            actions.append(result)
            if result["status"] != "INVESTIGATION_ACTION_COMPLETED":
                break
        return {"status":"INVESTIGATION_BOUNDED_PROGRESS", "plan_id":plan_id,
                "executed":sum(x["status"] == "INVESTIGATION_ACTION_COMPLETED" for x in actions),
                "outcomes":actions,
                "warning":"Unverified leads and review/retest checkpoints remain operator-owned."}


def main(argv=None):
    parser=argparse.ArgumentParser(description="Operator-only v1.9 bounded investigation planner")
    for name in ("manifest", "signature", "trust", "state-root", "investigation-policy"):
        parser.add_argument("--"+name,required=True)
    parser.add_argument("action",choices=("plan", "snapshot", "advance", "run"))
    parser.add_argument("--source-run")
    parser.add_argument("--plan-id")
    parser.add_argument("--max-steps", type=int, default=10)
    args=parser.parse_args(argv)
    try:
        sup=InvestigationSupervisor(args.manifest,args.signature,args.trust,
                                     args.state_root,args.investigation_policy)
        if args.action=="plan" and args.source_run and not args.plan_id:
            out=sup.create(args.source_run)
        elif args.action=="snapshot" and args.plan_id and not args.source_run:
            out=sup.snapshot(args.plan_id)
        elif args.action=="advance" and args.plan_id and not args.source_run:
            out=sup.advance(args.plan_id)
        elif args.action=="run" and args.plan_id and not args.source_run:
            out=sup.run_allowed(args.plan_id,args.max_steps)
        else:
            deny("invalid typed investigation operation")
        print(json.dumps(out,sort_keys=True,separators=(",", ":")))
        return 0
    except (ExecutionDenied,OSError,ValueError,TypeError):
        print("INVESTIGATION_DENIED",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
