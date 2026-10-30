"""Operator-scoped source research: plan signed replies, then retain checked evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import uuid

from aegis_agent_gateway import _protected
from aegis_audit_contract import canonical, decode, digest, require, source_snapshot
from aegis_audit_coordinator import AuditCoordinator, validate_policy
from aegis_reporting import ReportingSupervisor
from aegis_supervisor import ExecutionDenied

MAX_AUDIT = 262144
MAX_TRANSCRIPT = 131072


def retained(supervisor, info, run_id):
    """Tie prior evidence to a completed run and its existing chained audit event."""
    require(str(uuid.UUID(run_id)) == run_id, "invalid prior source audit ID")
    require(supervisor.verify_audit_chain(), "source audit chain is invalid")
    raw = supervisor._read_source(info, run_id, "source-audit.json")
    sha = hashlib.sha256(raw).hexdigest()
    with supervisor._database() as con:
        row = con.execute("SELECT status FROM runs WHERE run_id=? AND engagement_id=?",
                          (run_id, info["engagement_id"])).fetchone()
        require(row == ("completed",), "prior research run is incomplete or foreign")
        events = (json.loads(r[0]) for r in con.execute("SELECT event FROM audit"))
        require(any(e.get("type") == "completed" and e.get("run_id") == run_id and
                    e.get("engagement_id") == info["engagement_id"] and
                    e.get("notes") == "source-audit:" + sha for e in events),
                "retained research differs from its audited bytes")
    return decode(raw, MAX_AUDIT)


class SourceAuditSupervisor(ReportingSupervisor):
    def research(self, policy_path, bundle_path=None, *, accept=False, seconds=10, expected_repository=None):
        require(sys.platform == "linux" and os.geteuid() != 0, "source audit requires a non-root Linux identity")
        info, _ = self._guard()
        policy_raw = _protected(policy_path, 32768, info, self.state_root)
        policy = decode(policy_raw, 32768)
        validate_policy(policy)
        require(canonical(policy) == policy_raw, "source audit policy must be canonical JSON")
        repo = Path(policy["repository"])
        require(expected_repository is None or repo == expected_repository, "research repository differs from its assessment")
        require(repo.is_absolute() and str(repo.resolve()) == str(repo) and
                str(repo) in info["authorized_repositories"] and policy["engagement_id"] == info["engagement_id"],
                "research policy escaped signed repository/engagement scope")
        bundle_raw = _protected(bundle_path, MAX_TRANSCRIPT, info, self.state_root) if bundle_path else None
        prior = [retained(self, info, uid)["result"] for uid in policy["prior_run_ids"]]
        info, _, run_id = self.reserve(seconds, evidence_bytes=MAX_AUDIT if accept else 0)
        deadline = time.monotonic() + seconds
        def guard():
            self._guard()
            require(time.monotonic() < deadline, "source audit exceeded reserved runtime")
        try:
            snapshot = source_snapshot(repo, policy["source_paths"], guard)
            engine = AuditCoordinator(policy, snapshot, prior)
            bundle = decode(bundle_raw, MAX_TRANSCRIPT) if bundle_raw else {
                "version": 1, "audit_id": str(uuid.uuid4()), "policy_sha256": engine.policy_sha,
                "source_sha256": engine.source_sha, "records": []}
            outcome = engine.replay(bundle)
            guard()
            after = source_snapshot(repo, policy["source_paths"], guard)
            require(snapshot == after, "source changed during research validation")
            require(policy_raw == _protected(policy_path, 32768, info, self.state_root), "research policy changed during validation")
            if bundle_path:
                require(bundle_raw == _protected(bundle_path, MAX_TRANSCRIPT, info, self.state_root), "research transcript changed during validation")
            if not accept:
                self._finish(info["engagement_id"], run_id, "research_planned", digest(outcome))
                return {"status": "SOURCE_AUDIT_PLAN", "bundle": bundle, **outcome}
            require(outcome["next_assignment"] is None, "research transcript still needs an assigned independent reply")
            artifact = canonical({"version": 1, "policy": policy, "bundle": bundle, "result": outcome["result"]})
            require(len(artifact) <= MAX_AUDIT, "research evidence exceeds reserved byte budget")
            guard()
            sha = hashlib.sha256(artifact).hexdigest()
            with self._database() as con:
                con.execute("CREATE TABLE IF NOT EXISTS source_audit_receipts (engagement_id TEXT NOT NULL, audit_id TEXT NOT NULL, source_run_id TEXT NOT NULL, evidence_sha256 TEXT NOT NULL, PRIMARY KEY(engagement_id,audit_id))")
                con.execute("BEGIN IMMEDIATE")
                require(con.execute("SELECT 1 FROM source_audit_receipts WHERE engagement_id=? AND audit_id=?",
                                    (info["engagement_id"], bundle["audit_id"])).fetchone() is None,
                        "source audit identity was already admitted")
                require(not any(e.get("type") == "completed" and e.get("engagement_id") == info["engagement_id"]
                                and e.get("audit_id") == bundle["audit_id"] for e in
                                (json.loads(row[0]) for row in con.execute("SELECT event FROM audit"))),
                        "source audit identity is already present in the audit chain")
                con.execute("INSERT INTO source_audit_receipts VALUES(?,?,?,?)",
                            (info["engagement_id"], bundle["audit_id"], run_id, sha))
                guard()
                self._write_report(info, run_id, artifact, "source-audit.json")
                con.execute("UPDATE runs SET status='completed',ended_utc=? WHERE run_id=? AND engagement_id=?",
                            (datetime.now(timezone.utc).isoformat(), run_id, info["engagement_id"]))
                self._event(con, {"type": "completed", "engagement_id": info["engagement_id"],
                                  "run_id": run_id, "audit_id": bundle["audit_id"], "notes": "source-audit:" + sha})
                con.commit()
            return {"status": "SOURCE_AUDIT_RECORDED", "run_id": run_id,
                    "research_status": outcome["result"]["status"], "sha256": sha,
                    "deployment_approval": False}
        except BaseException:
            self._finish(info["engagement_id"], run_id, "failed", "source audit validation failed")
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "accept"))
    for name in ("manifest", "signature", "policy"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--seconds", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        require(args.command != "accept" or args.bundle is not None, "accept requires an explicit research transcript")
        state, trust = os.environ.get("AEGIS_STATE_ROOT"), os.environ.get("AEGIS_TRUST_POLICY")
        require(state and trust and Path(state).is_absolute() and Path(trust).is_absolute(),
                "operator-pinned trust policy and state root required")
        sup = SourceAuditSupervisor(args.manifest, args.signature, Path(trust), Path(state))
        result = sup.research(args.policy, args.bundle, accept=args.command == "accept", seconds=args.seconds)
        print(json.dumps(result, indent=2))
        return 0
    except (ExecutionDenied, ValueError, OSError, TypeError, KeyError, sqlite3.Error) as exc:
        print("DENIED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
