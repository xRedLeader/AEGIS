"""Offline imports bind independently selected source and never retain vendor prose."""
import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import os
import subprocess
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_audit_contract import canonical, digest
from aegis_scanner_contract import ATTESTATION_CONTEXT, MAX_INPUT, attestation, parse_report, report_projection, strict_json
from aegis_scanner_import import ScannerImportSupervisor, retained_import, selected_input
from aegis_supervisor import ExecutionDenied, operator_stop
from test_v18_reporting import ReportFixture


class ScannerAdmissionTests(ReportFixture):
    def setUp(self):
        super().setUp()
        self.fx.fx.manifest["methods"]["allowed"].append("dependency_analysis")
        self.fx.fx.trust["approved_methods"].append("dependency_analysis")
        self.fx.fx.save()
        self.source = self.fx.fx.repo/"requirements.txt"
        self.source.write_bytes(b"requests==2.31.0\n")
        self.canary = "SYNTHETIC_SECRET_NEVER_EXPORT_789012345"
        self.raw_report = {"dependencies": [{"name": "requests", "version": "2.31.0", "vulns": [
            {"id": "CVE-2023-12345", "description": self.canary, "fix_versions": [self.canary]}]}],
            "nested": {"Authorization": self.canary, "Cookie": [self.canary]}}
        self.report_path = self.fx.fx.p/"scanner.json"
        self.config_path = self.fx.fx.p/"scanner-config.json"
        self.config_path.write_bytes(b'{"fixture":true}'); self.config_path.chmod(0o600)
        self.admission_path = self.fx.fx.p/"scanner-policy.json"
        self.admission = {"schema_version": 1, "configured": True,
            "engagement_id": self.fx.fx.manifest["engagement"]["id"],
            "detector": {"name": "pip-audit", "version": "2.9.0", "report_schema": "pip-audit-json"},
            "configuration": {"path": str(self.config_path), "sha256": hashlib.sha256(self.config_path.read_bytes()).hexdigest()},
            "report_sha256": "0"*64, "observed_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "max_age_seconds": 3600, "input": {"kind": "source", "repository": str(self.fx.fx.repo),
                "files": {"requirements.txt": hashlib.sha256(self.source.read_bytes()).hexdigest()}},
            "allowed_rule_ids": ["CVE-2023-12345"], "database": None,
            "provenance": {"mode": "operator_attested_external", "producer": "fixture-operator",
                "attestation_path": None, "signature_path": None, "public_key_path": None, "execution_run_id": None}}
        self.importer = ScannerImportSupervisor(self.fx.fx.manifest_path, self.fx.fx.sig_path,
                                               self.fx.fx.trust_path, self.fx.state)
        self.save_admission()

    def save_admission(self):
        raw = canonical(self.raw_report)
        self.report_path.write_bytes(raw); self.report_path.chmod(0o600)
        self.admission["report_sha256"] = hashlib.sha256(raw).hexdigest()
        self.admission_path.write_bytes(canonical(self.admission)); self.admission_path.chmod(0o600)

    def admit(self):
        return self.importer.admit(self.admission_path, self.report_path, seconds=2)

    def test_readonly_import_canonical_report_and_sensitive_output_absence(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no execution")), patch("socket.create_connection", side_effect=AssertionError("no network")):
            result = self.admit()
        info, _ = self.importer._guard()
        raw = retained_import(self.importer, info, result["run_id"])
        evidence = json.loads(raw)
        self.assertEqual(evidence["provenance"]["mode"], "operator_attested_external")
        self.assertFalse(evidence["independent_corroboration"])
        self.assertEqual(len(evidence["observations"]), 1)
        report = self.sup.generate(result["run_id"], "scanner-import.json")
        root = Path(info["report_directory"])
        for file in root.rglob("*"):
            if file.is_file(): self.assertNotIn(self.canary.encode(), file.read_bytes())
        document = json.loads(Path(report["report"]).read_bytes())
        self.assertEqual(document["findings"][0]["verdict"], "needs_validation")
        self.assertNotIn("severity", document["findings"][0])

    def test_reimport_and_duplicate_records_do_not_create_independent_corroboration(self):
        self.raw_report["dependencies"] *= 2
        self.save_admission()
        first, second = self.admit(), self.admit()
        self.assertEqual(first["run_id"], second["run_id"])
        self.assertEqual(second["status"], "SCANNER_IMPORT_ALREADY_RECORDED")
        info, _ = self.importer._guard()
        self.assertEqual(json.loads(retained_import(self.importer, info, first["run_id"]))["duplicates_removed"], 1)

    def test_new_database_attestation_retained_without_new_finding_or_corroboration(self):
        first=self.admit()
        info,_=self.importer._guard()
        original=retained_import(self.importer,info,first["run_id"])
        self.admission["database"]={"sha256":"a"*64,"built_at_utc":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),"max_age_seconds":3600}
        self.save_admission()
        second=self.admit();repeat=self.admit()
        changed=retained_import(self.importer,info,second["run_id"])
        self.assertNotEqual(first["run_id"],second["run_id"])
        self.assertEqual(second["run_id"],repeat["run_id"])
        self.assertIsNone(json.loads(original)["database"])
        self.assertEqual(json.loads(changed)["database"],self.admission["database"])
        self.assertFalse(json.loads(changed)["independent_corroboration"])
        projections=[report_projection(raw,info["engagement_id"],run,self.admission["observed_at_utc"])
                     for raw,run in ((original,first["run_id"]),(changed,second["run_id"]))]
        self.assertEqual([f["id"] for f in projections[0]["findings"]],[f["id"] for f in projections[1]["findings"]])

    def test_report_and_database_expiry_during_admission_fail_before_acceptance(self):
        import aegis_scanner_import
        baseline=datetime.now(timezone.utc).replace(microsecond=0)
        original_normalize=aegis_scanner_import.normalize
        original_database=self.importer._database
        class Clock(datetime):
            elapsed=0
            @classmethod
            def now(cls,tz=None):return baseline+timedelta(seconds=cls.elapsed)
        for stage in ("normalization","database_lock"):
            for expires in ("report","database"):
                with self.subTest(stage=stage,expires=expires):
                    Clock.elapsed=0
                    stamp=baseline.strftime("%Y-%m-%dT%H:%M:%SZ")
                    self.admission.update(observed_at_utc=stamp,max_age_seconds=1 if expires=="report" else 3600,
                        database={"sha256":"a"*64,"built_at_utc":stamp,"max_age_seconds":1} if expires=="database" else None)
                    self.save_admission()
                    def normalize(*args):
                        result=original_normalize(*args)
                        if stage=="normalization":Clock.elapsed=2
                        return result
                    @contextmanager
                    def database():
                        with original_database() as connection:
                            class DelayedLock:
                                admission=False
                                def execute(self,sql,*args):
                                    if sql.startswith("CREATE TABLE IF NOT EXISTS scanner_imports"):self.admission=True
                                    result=connection.execute(sql,*args)
                                    if stage=="database_lock" and self.admission and sql=="BEGIN IMMEDIATE":Clock.elapsed=2
                                    return result
                                def __getattr__(self,name):return getattr(connection,name)
                            yield DelayedLock()
                    with patch("aegis_scanner_contract.datetime",Clock),patch("aegis_scanner_import.normalize",side_effect=normalize), \
                         patch.object(self.importer,"_database",side_effect=database):
                        with self.assertRaisesRegex(ExecutionDenied,"stale"):
                            self.admit()
                    with original_database() as con:
                        events=[json.loads(row[0]) for row in con.execute("SELECT event FROM audit")]
                    self.assertFalse(any(e.get("type")=="completed" and e.get("notes","").startswith("scanner-import:") for e in events))
    def test_report_source_configuration_and_retained_artifact_tampering_fail_closed(self):
        good = self.report_path.read_bytes()
        self.report_path.write_bytes(good+b" ")
        with self.assertRaises(ExecutionDenied): self.admit()
        self.report_path.write_bytes(good)
        self.source.write_text("requests==2.32.0\n")
        with self.assertRaises(ExecutionDenied): self.admit()
        self.source.write_bytes(b"requests==2.31.0\n")
        self.config_path.write_bytes(b"changed")
        with self.assertRaises(ExecutionDenied): self.admit()
        self.config_path.write_bytes(b'{"fixture":true}')
        result = self.admit()
        info, _ = self.importer._guard()
        evidence = Path(info["report_directory"])/"runs"/result["run_id"]/"scanner-import.json"
        evidence.write_bytes(evidence.read_bytes().replace(b"requests", b"forgeries"))
        with self.assertRaises(ExecutionDenied): self.sup.generate(result["run_id"], "scanner-import.json")

    def test_forbidden_paths_schemas_rules_stale_and_forged_provenance(self):
        original = copy.deepcopy(self.admission)
        mutations = [lambda p:p["input"].update(repository="/etc"),
                     lambda p:p["input"].update(files={"../escape": "0"*64}),
                     lambda p:p["detector"].update(version="999.0.0"),
                     lambda p:p.update(allowed_rule_ids=[]),
                     lambda p:p.update(observed_at_utc="2000-01-01T00:00:00Z"),
                     lambda p:p["provenance"].update(mode="verified_ci"),
                     lambda p:p["provenance"].update(mode="aegis_governed", execution_run_id="00000000-0000-0000-0000-000000000000")]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.admission = copy.deepcopy(original); mutate(self.admission); self.save_admission()
                with self.assertRaises((ExecutionDenied, OSError)): self.admit()

    def test_signed_ci_attestation_must_match_independently_selected_inputs(self):
        key = Ed25519PrivateKey.generate()
        public, statement, signature = (self.fx.fx.p/name for name in ("ci.pem", "ci.json", "ci.sig"))
        public.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)); public.chmod(0o600)
        self.admission["provenance"].update(mode="verified_ci", producer="ci-fixture",
            attestation_path=str(statement), signature_path=str(signature), public_key_path=str(public))
        info, _ = self.importer._guard()
        identity, _ = selected_input(self.admission, info, self.fx.state, lambda: None)
        raw = canonical(attestation(self.admission, identity))
        statement.write_bytes(raw); statement.chmod(0o600)
        signature.write_bytes(key.sign(ATTESTATION_CONTEXT+raw)); signature.chmod(0o600)
        self.save_admission()
        self.assertEqual(self.admit()["status"], "SCANNER_IMPORT_RECORDED")
        signature.write_bytes(b"x"*64)
        with self.assertRaises(ExecutionDenied): self.admit()

    def test_strict_json_bounds_and_stop(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'9'*65, b'['*40+b'0'+b']'*40, b' '* (MAX_INPUT+1)):
            with self.assertRaises(ExecutionDenied): strict_json(raw)
        operator_stop(self.fx.state, self.admission["engagement_id"])
        with self.assertRaises(ExecutionDenied): self.admit()

    def test_legacy_npm_api_remains_supported(self):
        from aegis_security_tool_adapters import import_scanner_report
        raw = canonical({"vulnerabilities": {"example": {"via": [{"name": "CVE-2023-12345"}]}}})
        self.assertEqual(len(import_scanner_report("npm-audit-v2", raw)["leads"]), 1)

    def test_measured_native_coverage_reaches_canonical_and_human_reports(self):
        from aegis_worker import review
        source = self.fx.fx.repo/"unsupported.cs"
        source.write_text("class Unsupported {}\n")
        raw = canonical(review(str(self.fx.fx.repo), 100, 1024*1024))
        result, _ = self.report(raw)
        report = Path(result["report"])
        document = json.loads(report.read_bytes())
        self.assertIn("unsupported=", " ".join(document["coverage"]["tested"]))
        self.assertIn("aegis-regex version 2", (report.parent/"REPORT.md").read_text())
        self.assertIn(json.loads(raw)["coverage"]["source_identity"]["sha256"], report.read_text())

    def test_maven_manifest_provenance_and_inventory_gaps_reach_reports(self):
        record = json.loads(self.osv_raw())
        record["leads"][0].update(ecosystem="Maven", package="org.example:fixture", source="service/pom.xml",
            manifest_sha256="b"*64, evidence_kind="declared", origin="dependencies:1/entry:2")
        record["summary"].update(inventory_entries_unresolved=3, inventory_coverage_status="partial")
        from aegis_reporting import projection
        report = projection(canonical(record), "advisory-candidates.json", self.admission["engagement_id"],
                            "00000000-0000-0000-0000-000000000000", self.admission["observed_at_utc"])
        self.assertIn("org.example:fixture", report["findings"][0]["affected_asset"])
        self.assertIn("service/pom.xml", report["findings"][0]["description"])
        self.assertIn("unresolved coordinates=3", " ".join(report["coverage"]["untested"]))

    def test_history_binds_actual_commit_blobs_not_current_working_tree(self):
        from aegis_scanner_contract import normalize, observation
        def git(*args):
            return subprocess.check_output(["/usr/bin/git", "-C", str(self.fx.fx.repo), *args], stderr=subprocess.DEVNULL).decode().strip()
        git("init", "-q"); git("add", "requirements.txt")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "Fixture history")
        revision = git("rev-parse", "HEAD")
        source_hash = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.source.write_bytes(b"current content changed\n")
        self.admission["input"] = {"kind":"history", "repository":str(self.fx.fx.repo),
                                   "revisions":{revision:{"requirements.txt":source_hash}}}
        info, _ = self.importer._guard()
        identity, context = selected_input(self.admission, info, self.fx.state, lambda:None)
        self.assertEqual(context["history_sources"][revision]["requirements.txt"]["lines"], ["requests==2.31.0"])
        parsed = {"observations":[observation("secret", "CVE-2023-12345", path="requirements.txt", start_line=1, end_line=1, revision=revision)],
                  "coverage":{"assessed_records":1,"unresolved_records":0,"limitations":[]}}
        self.assertEqual(len(normalize(parsed, self.admission, context)["observations"]), 1)
        parsed["observations"][0]["revision"] = None
        with self.assertRaises(ExecutionDenied): normalize(parsed, self.admission, context)
        self.admission["input"]["revisions"][revision]["requirements.txt"] = "0"*64
        with self.assertRaises(ExecutionDenied): selected_input(self.admission, info, self.fx.state, lambda:None)
        self.admission["input"]["revisions"][revision]["requirements.txt"] = source_hash
        git("config", "remote.fixture.promisor", "true")
        with self.assertRaises(ExecutionDenied): selected_input(self.admission, info, self.fx.state, lambda:None)

    def test_internal_governed_handoff_requires_audited_sanitized_bytes(self):
        from aegis_supervisor import open_directory_nofollow
        info, _, execution = self.importer.reserve(2, "dependency_analysis")
        identity, context = selected_input(self.admission, info, self.fx.state, lambda:None)
        sanitized = canonical({"schema_version":1, **parse_report(self.report_path.read_bytes(), self.admission, context)})
        directory = Path(info["report_directory"])/"runs"/execution
        policy = copy.deepcopy(self.admission)
        policy["provenance"].update(mode="aegis_governed", execution_run_id=execution)
        policy["configuration"]["path"] = str(directory/"scanner-config.bin")
        policy["report_sha256"] = hashlib.sha256(sanitized).hexdigest()
        metadata = {"admission":policy, "input_identity":identity, "original_report_sha256":self.admission["report_sha256"]}
        artifacts = {"scanner-execution.json":canonical(metadata), "scanner-report.json":sanitized,
                     "scanner-config.bin":self.config_path.read_bytes()}
        with open_directory_nofollow(directory, create=True) as root:
            for name, raw in artifacts.items():
                fd = os.open(name, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600, dir_fd=root)
                with os.fdopen(fd, "wb") as stream: stream.write(raw)
        with self.assertRaises(ExecutionDenied): self.importer.import_governed_report(execution, seconds=2)
        with self.importer._database() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("UPDATE runs SET status='completed',ended_utc=? WHERE run_id=?", (self.admission["observed_at_utc"], execution))
            self.importer._event(con, {"type":"scanner_execution_completed", "engagement_id":info["engagement_id"], "run_id":execution,
                "attestation":attestation(policy, identity), "artifacts":{n:hashlib.sha256(b).hexdigest() for n,b in artifacts.items()}})
            con.commit()
        with self.assertRaises(ExecutionDenied): self.importer.admit(directory/"scanner-execution.json", directory/"scanner-report.json", seconds=2)
        result = self.importer.import_governed_report(execution, seconds=2)
        document = json.loads(Path(self.sup.generate(result["run_id"], "scanner-import.json")["report"]).read_bytes())
        self.assertIn("Pinned scanner execution", " ".join(document["coverage"]["limitations"]))
        self.assertNotIn(self.canary, json.dumps(document))
        (directory/"scanner-report.json").write_bytes(sanitized+b" ")
        with self.assertRaises(ExecutionDenied): self.importer.import_governed_report(execution, seconds=2)
