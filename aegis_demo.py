#!/usr/bin/env python3
"""Offline, non-production end-to-end supervisor demo with ephemeral authorization.

Creates only a temporary sample repository and credentials. Never sends network
traffic, never targets user software, and leaves no persistent key material.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import tempfile
import yaml

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from aegis_preflight import SIGNING_CONTEXT
from aegis_supervisor import AegisSupervisor, ExecutionDenied

HERE = Path(__file__).resolve().parent


def main():
    with tempfile.TemporaryDirectory(prefix="aegis-local-demo-") as tmp:
        base = Path(tmp)
        repo = base / "authorized" / "demo-repo"
        repo.mkdir(parents=True)
        (repo / "sample.py").write_text('import subprocess\nsubprocess.run("echo demo", shell=True)\n')
        reports, alerts, state = (base / x for x in ("reports", "alerts", "state"))
        for p in (reports, alerts, state):
            p.mkdir(mode=0o700)
        trust = json.loads((HERE / "trust-policy.example.json").read_text())
        scope = yaml.safe_load((HERE / "security-scope.example.yaml").read_text())
        now = datetime.now(timezone.utc)
        stamp = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
        engagement_id = "aegis-demo-001"
        scope["engagement"].update(id=engagement_id,
                                   authorized_by="demo-operator@example.invalid",
                                   signer_id="demo-operator",
                                   valid_from_utc=stamp(now - timedelta(minutes=1)),
                                   valid_until_utc=stamp(now + timedelta(hours=1)))
        scope["targets"].update(repositories=[str(repo)], origins=[], networks=[],
                                excluded_origins=[], excluded_networks=[])
        scope["accounts"] = []
        scope["methods"]["allowed"] = ["source_review"]
        scope["limits"].update(engagement_runtime_minutes=2, max_single_run_minutes=1,
                               deterministic_hypothesis_minutes=1, max_total_requests=0,
                               max_requests_per_minute_per_origin=0, max_concurrent_requests=0)
        scope["reporting"]["output_dir"] = str(reports / engagement_id)
        scope["reporting"]["critical_alert"]["path"] = str(alerts / (engagement_id + ".ndjson"))
        key = Ed25519PrivateKey.generate()
        pub = base / "trusted-signing.pub.pem"
        pub.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        trust["configured"] = True
        trust["operator"].update(principal="demo-operator@example.invalid", signer_id="demo-operator",
                                 public_key_pem_path=str(pub))
        trust["approved_engagement_ids"] = [engagement_id]
        trust["allowed_repository_roots"] = [str(repo.parent)]
        trust["allowed_origins"] = []
        trust["approved_methods"] = ["source_review"]
        trust["allowed_report_roots"] = [str(reports)]
        trust["allowed_alert_roots"] = [str(alerts)]
        trust["revocation"]["last_checked_utc"] = stamp(now)
        manifest = base / "scope.yaml"
        signature = base / "scope.sig"
        policy = base / "trust.json"
        raw = yaml.safe_dump(scope, sort_keys=False).encode()
        manifest.write_bytes(raw)
        signature.write_bytes(key.sign(SIGNING_CONTEXT + raw))
        policy.write_text(json.dumps(trust))
        supervisor = AegisSupervisor(manifest, signature, policy, state)
        result = supervisor.scan(repo, budget_seconds=5)
        findings = json.loads(Path(result["report"]).read_text())
        if not supervisor.verify_audit_chain() or len(findings["candidates"]) != 1:
            raise RuntimeError("demo validation failed")
        # Don't print the temp report path; the temp directory is immediately deleted.
        print(json.dumps({"demo_status": "PASS", "runtime_status": result["status"],
                          "static_review_leads": len(findings["candidates"]),
                          "lead_classification": findings["candidates"][0]["status"],
                          "budget_reserved_seconds": supervisor.usage(engagement_id)["reserved_seconds"],
                          "audit_chain_valid": True, "network_requests": 0}, indent=2))


if __name__ == "__main__":
    main()
