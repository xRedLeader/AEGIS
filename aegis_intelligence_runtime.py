#!/usr/bin/env python3
"""Trusted, authorization-scoped dependency inventory + signed OSV correlation.

Never expose this Python object or bundle signer to an untrusted agent. AEGIS
must independently gate this fixed operation through its trusted operator API.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat

from aegis_intelligence import load_signed_snapshot, correlate, IntelligenceDenied, MAX_INVENTORY
from aegis_preflight import read_protected_trust
from aegis_supervisor import AegisSupervisor, ExecutionDenied, deny, open_directory_nofollow, private_directory, MAX_RESULT_BYTES, SCAN_RESULT_RESERVATION


class AegisIntelligenceSupervisor(AegisSupervisor):
    def assess_dependencies(self, repository: Path, snapshot: Path, signature: Path, budget_seconds: int = 15) -> dict:
        """Runs fixed jail, then correlates verified snapshots outside the jailed worker."""
        info, manifest = self._guard()
        if "dependency_analysis" not in info["approved_methods"]:
            deny("dependency_analysis is not approved")
        trusted = read_protected_trust(self.trust_path)
        public_key_path = Path(trusted["operator"]["public_key_pem_path"])
        # The feed is accepted only when signed by the independent operator
        # key used by the current protected trust policy, not a supplied key.
        bundle, digest = load_signed_snapshot(Path(snapshot), Path(signature), public_key_path)
        for protected in (Path(snapshot), Path(signature)):
            target = protected.resolve()
            if (any(target == Path(repo) or Path(repo) in target.parents
                    for repo in info["authorized_repositories"]) or
                    target == self.state_root or self.state_root in target.parents):
                deny("OSV snapshot must not be supplied from the assessment repository or mutable service state")
        result = self.scan(repository, budget_seconds=budget_seconds, mode="deps")
        report = Path(result["report"])
        with open_directory_nofollow(report.parent) as fd:
            private_directory(fd)
            inventory_fd = os.open(report.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                st = os.fstat(inventory_fd)
                if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_INVENTORY:
                    deny("invalid inventory report")
                raw = os.read(inventory_fd, MAX_INVENTORY + 1)
            finally:
                os.close(inventory_fd)
        try:
            inventory = json.loads(raw)
            candidates = correlate(inventory, bundle, digest=digest)
        except (ValueError, TypeError) as exc:
            raise ExecutionDenied("unusable intelligence or inventory data") from exc
        encoded = json.dumps(candidates, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) + len(encoded) > SCAN_RESULT_RESERVATION or len(encoded) > MAX_RESULT_BYTES:
            deny("advisory correlation exceeds persistent evidence budget reservation")
        self._guard()  # May revoke at any point; do not write another artifact after revoke.
        with open_directory_nofollow(report.parent) as fd:
            private_directory(fd)
            out = os.open("advisory-candidates.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                          os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                data = memoryview(encoded)
                while data:
                    n = os.write(out, data)
                    if n <= 0:
                        raise OSError("partial advisory report write")
                    data = data[n:]
                os.fsync(out)
            finally:
                os.close(out)
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._event(con, {"type": "osv_exact_version_correlation", "engagement_id": info["engagement_id"],
                              "run_id": result["run_id"], "snapshot_sha256": digest,
                              "exact_version_leads": candidates["summary"]["exact_version_leads"]})
            con.commit()
        return {"status": "COMPLETED_SIGNED_OSV_EXACT_VERSION_CORRELATION", "engagement_id": info["engagement_id"],
                "run_id": result["run_id"], "inventory_report": str(report),
                "candidates_report": str(report.parent / "advisory-candidates.json"),
                "summary": candidates["summary"], "snapshot_retrieved_at_utc": bundle["retrieved_at_utc"],
                "snapshot_sha256": digest,
                "warning": "Leads are not verified vulnerabilities; limited snapshot and unsupported ranges prevent clearance."}
