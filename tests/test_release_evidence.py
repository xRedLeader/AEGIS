"""Release reconciliation never manufactures host evidence or human acceptance."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_audit import AUDIT_CONTEXT
from aegis_audit_contract import canonical, digest
from aegis_release_evidence import MACHINE_GATES, ROLES, SIGNOFF_CONTEXT, collect
from aegis_supervisor import ExecutionDenied


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.source, self.bundle, self.trust_root = (root/name for name in ("source", "bundle", "trust"))
        for directory in (self.source, self.bundle, self.trust_root): directory.mkdir(mode=0o700)
        (self.source/"example.py").write_bytes(b"# Synthetic source, never executed.\n")
        (self.source/"SHA256SUMS.txt").write_text(hashlib.sha256((self.source/"example.py").read_bytes()).hexdigest()+"  example.py\n")
        def git(*args):
            return subprocess.check_output(["/usr/bin/git", "-C", str(self.source), *args], stderr=subprocess.DEVNULL).decode().strip()
        git("init", "-q"); git("add", "example.py", "SHA256SUMS.txt")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "Synthetic fixture")
        self.candidate = git("rev-parse", "HEAD")
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.stamp = self.now.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        self.trust = {"schema_version": 1, "role_keys": {}, "checkpoint_key": self.save(self.trust_root, "anchor.pem", pub)}
        self.trust_path = self.trust_root/"trust.json"
        original = self.save(self.bundle, "original.log", b"Ran 12 tests in 0.1s\nOK\n")
        observations = []
        for kind in sorted(MACHINE_GATES):
            if kind.startswith("ci_"):
                details = {"job_url": "https://github.com/example/fixture/actions/runs/1/job/2", "head_sha": self.candidate,
                           "conclusion": "success", "tests": 12, "skipped": 0}
            elif kind == "installed_host":
                details = {"host_identity_sha256": "a"*64, "configuration_sha256": "b"*64,
                    "dependency_inventory_sha256": "c"*64, "installed_commit": self.candidate,
                    "kernel_acceptance": "PASS", "packaged_services": "PASS"}
            else:
                details = {"engagement_scope_sha256": "d"*64, **{k:"PASS" for k in
                    ("proof_admission", "forged_proof_rejected", "remediation_retest", "crash", "expired_lease",
                     "stop", "revocation", "no_silent_rerun", "audited_abandonment", "successful_ack", "failed_delivery", "receiver_restart")}}
            record = {"schema_version": 1, "candidate_sha": self.candidate, "kind": kind, "observed_at_utc": self.stamp,
                      "result": "PASS", "details": details, "artifacts": [original]}
            observations.append(self.save(self.bundle, kind+".json", canonical(record)))
        event = canonical({"type": "synthetic_fixture"}).decode()
        head = hashlib.sha256(("0"*64+"\n"+event).encode()).hexdigest()
        ledger_id = str(uuid.uuid4())
        payload = {"format": "AEGIS-audit-checkpoint-v1", "ledger_id": ledger_id, "sequence": 1,
                   "head_sha256": head, "created_utc": self.stamp}
        self.anchor = {"payload": payload, "signature_hex": self.key.sign(AUDIT_CONTEXT+canonical(payload)).hex()}
        self.manifest = {"schema_version": 1, "candidate_sha": self.candidate, "created_at_utc": self.stamp,
            "max_age_seconds": 3600, "source_manifest_sha256": hashlib.sha256((self.source/"SHA256SUMS.txt").read_bytes()).hexdigest(),
            "observations": observations, "checkpoint": {
                "record": self.save(self.bundle, "checkpoint.json", canonical(self.anchor)),
                "ledger": self.save(self.bundle, "ledger.json", canonical({"ledger_id": ledger_id, "rows": [[1,event,"0"*64,head]]}))},
            "signoffs": []}
        self.persist()

    @staticmethod
    def save(root, name, raw):
        path = root/name; path.write_bytes(raw); path.chmod(0o600)
        return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}

    def persist(self):
        self.save(self.bundle, "bundle.json", canonical(self.manifest))
        self.save(self.trust_root, "trust.json", canonical(self.trust))

    def collect(self):
        return collect(self.bundle, self.source, self.candidate, self.trust_path, now=self.now)

    def test_machine_complete_still_pending_all_humans_and_does_not_write(self):
        before = {p:(p.read_bytes(), p.stat().st_mtime_ns) for p in self.bundle.rglob("*") if p.is_file()}
        result = self.collect()
        self.assertTrue(result["machine_evidence_complete"])
        self.assertEqual(result["status"], "NOT_PRODUCTION_APPROVED")
        self.assertEqual(set(result["pending_roles"]), ROLES)
        self.assertEqual(before, {p:(p.read_bytes(), p.stat().st_mtime_ns) for p in self.bundle.rglob("*") if p.is_file()})
        self.assertNotIn(str(self.tmp.name), json.dumps(result))

    def test_wrong_source_and_manifest_commit(self):
        (self.source/"example.py").write_bytes(b"changed source")
        self.assertFalse(self.collect()["machine_evidence_complete"])
        self.manifest["candidate_sha"] = "0"*40; self.persist()
        with self.assertRaises(ExecutionDenied): self.collect()

    def test_github_timestamped_logs_preserve_bytes_and_enforce_results(self):
        prefix=b"2026-10-30T20:01:02.1234567Z "
        def log(raw):
            artifact=self.save(self.bundle,"original.log",raw)
            for index,ref in enumerate(self.manifest["observations"]):
                record=json.loads((self.bundle/ref["path"]).read_bytes())
                record["artifacts"]=[artifact if item["path"]=="original.log" else item for item in record["artifacts"]]
                self.manifest["observations"][index]=self.save(self.bundle,ref["path"],canonical(record))
            self.persist()
        raw=prefix+b"Ran 12 tests in 0.1s\n"+prefix+b"OK\n"
        log(raw)
        self.assertTrue(self.collect()["machine_evidence_complete"])
        self.assertEqual((self.bundle/"original.log").read_bytes(),raw)
        for invalid in (raw.replace(b"Ran 12",b"Ran 11"),raw+prefix+b"FAILED (failures=1)\n",
                        raw.replace(b"1234567Z ",b"1234567+00:00 ")):
            with self.subTest(log=invalid):
                log(invalid)
                self.assertFalse(self.collect()["machine_evidence_complete"])

    def test_native_scanner_and_packaged_service_jobs_are_required(self):
        original = list(self.manifest["observations"])
        for kind in ("ci_native_scanners_22_04", "ci_native_scanners_24_04",
                     "ci_packaged_services_22_04", "ci_packaged_services_24_04"):
            with self.subTest(kind=kind):
                self.manifest["observations"] = [ref for ref in original
                    if json.loads((self.bundle/ref["path"]).read_bytes())["kind"] != kind]
                self.persist()
                result = self.collect()
                self.assertFalse(result["machine_evidence_complete"])
                self.assertIn({"check": kind, "result": "MISSING_INVALID_OR_STALE"}, result["checks"])

    def test_successful_native_job_cannot_hide_failed_or_missing_test_output(self):
        for kind in ("ci_native_scanners_22_04", "ci_native_scanners_24_04"):
            index = next(i for i, ref in enumerate(self.manifest["observations"])
                         if json.loads((self.bundle/ref["path"]).read_bytes())["kind"] == kind)
            original = self.manifest["observations"][index]
            record = json.loads((self.bundle/original["path"]).read_bytes())
            for raw in (b"2026-10-30T20:01:02.1234567Z Ran 12 tests in 0.1s\n"
                        b"2026-10-30T20:01:02.1234567Z FAILED (failures=1)\n", b"preparation only\n"):
                with self.subTest(kind=kind, output=raw):
                    record["artifacts"] = [self.save(self.bundle, "native.log", raw)]
                    self.manifest["observations"][index] = self.save(self.bundle, "native-record.json", canonical(record))
                    self.persist()
                    self.assertFalse(self.collect()["machine_evidence_complete"])
            self.manifest["observations"][index] = original
        self.persist()

    def test_claimed_counts_cannot_override_retained_regression_output(self):
        for index, ref in enumerate(self.manifest["observations"]):
            record = json.loads((self.bundle/ref["path"]).read_bytes())
            if record["kind"] == "ci_ubuntu_24_04":
                record["details"]["tests"] = 999
                self.manifest["observations"][index] = self.save(self.bundle, ref["path"], canonical(record))
        self.persist()
        self.assertFalse(self.collect()["machine_evidence_complete"])

    def test_missing_tampered_mixed_and_stale_records(self):
        for mutation in ("missing", "tampered", "mixed", "stale"):
            with self.subTest(mutation=mutation):
                ref = self.manifest["observations"][0]; path = self.bundle/ref["path"]; raw = path.read_bytes()
                if mutation == "missing": path.unlink()
                elif mutation == "tampered": path.write_bytes(raw+b" ")
                else:
                    record = json.loads(raw)
                    record["candidate_sha" if mutation == "mixed" else "observed_at_utc"] = "0"*40 if mutation == "mixed" else "2000-01-01T00:00:00Z"
                    self.manifest["observations"][0] = self.save(self.bundle, ref["path"], canonical(record)); self.persist()
                self.assertFalse(self.collect()["machine_evidence_complete"])
                self.manifest["observations"][0] = self.save(self.bundle, ref["path"], raw); self.persist()

    def test_invalid_checkpoint_signature_and_missing_ledger_are_not_repaired(self):
        self.anchor["signature_hex"] = "00"*64
        self.manifest["checkpoint"]["record"] = self.save(self.bundle, "checkpoint.json", canonical(self.anchor)); self.persist()
        self.assertFalse(self.collect()["machine_evidence_complete"])
        (self.bundle/"ledger.json").unlink()
        self.assertFalse(self.collect()["machine_evidence_complete"])
        self.assertFalse((self.bundle/"ledger.json").exists())

    def sign_all_roles(self, schema_version=1):
        observations = {json.loads((self.bundle/ref["path"]).read_bytes())["kind"]:ref["sha256"] for ref in self.manifest["observations"]}
        evidence = digest({"observations": observations, "checkpoint": self.manifest["checkpoint"],
                           "source_manifest_sha256": self.manifest["source_manifest_sha256"],
                           "created_at_utc": self.manifest["created_at_utc"], "max_age_seconds": self.manifest["max_age_seconds"]})
        for role in ROLES:
            self.trust["role_keys"][role] = self.trust["checkpoint_key"]
            payload = {"schema_version":schema_version, "candidate_sha":self.candidate, "role":role,
                "accountable_identity":"Synthetic fixture only", "observed_at_utc":self.stamp,
                "decision":"accepted", "evidence_sha256":evidence}
            envelope = {"payload":payload,"signature_hex":self.key.sign(SIGNOFF_CONTEXT+canonical(payload)).hex()}
            self.manifest["signoffs"].append(self.save(self.bundle, role+".json", canonical(envelope)))
        self.persist()

    def test_pinned_signatures_are_evidence_not_independent_real_world_approval(self):
        self.sign_all_roles()
        result = self.collect()
        self.assertEqual(result["pending_roles"], [])
        self.assertEqual(result["status"], "NOT_PRODUCTION_APPROVED")
        self.assertIn("reviewer independence", result["note"])

    def test_unsigned_freshness_changes_do_not_reuse_old_signatures(self):
        self.sign_all_roles()
        original = {key:self.manifest[key] for key in ("created_at_utc","max_age_seconds")}
        signatures = [reference["sha256"] for reference in self.manifest["signoffs"]]
        self.now += timedelta(seconds=1)
        for key,value in (("created_at_utc",self.now.strftime("%Y-%m-%dT%H:%M:%SZ")),
                          ("max_age_seconds",original["max_age_seconds"]+1)):
            with self.subTest(field=key):
                self.manifest.update(original);self.manifest[key]=value;self.persist()
                result=self.collect()
                self.assertTrue(result["machine_evidence_complete"])
                self.assertEqual(set(result["pending_roles"]),ROLES)
                self.assertEqual(result["signed_roles"],[])
        self.manifest.update(original);self.persist()
        self.now += timedelta(hours=2)
        with self.assertRaises(ExecutionDenied):self.collect()
        self.manifest.update(created_at_utc=self.now.strftime("%Y-%m-%dT%H:%M:%SZ"),max_age_seconds=7202);self.persist()
        result=self.collect()
        self.assertTrue(result["machine_evidence_complete"])
        self.assertEqual([reference["sha256"] for reference in self.manifest["signoffs"]],signatures)
        self.assertEqual(set(result["pending_roles"]),ROLES)
        self.assertEqual(result["signed_roles"],[])
        self.assertEqual(result["status"],"NOT_PRODUCTION_APPROVED")

    def test_boolean_schema_versions_fail_closed(self):
        self.sign_all_roles(schema_version=True)
        result=self.collect()
        self.assertEqual(set(result["pending_roles"]),ROLES)
        self.assertEqual(result["signed_roles"],[])
        self.trust["schema_version"]=True;self.persist()
        with self.assertRaises(ExecutionDenied):self.collect()
