"""Pinned vendor exports plus explicitly derived negative/redaction controls."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from aegis_audit_contract import canonical
from aegis_extended_scanner_adapters import _stamp, parse_package_report, parse_staging_report
from aegis_http_policy import HttpPolicyDenied
from aegis_scanner_contract import normalize, strict_json
from aegis_supervisor import ExecutionDenied

FIXTURES = Path(__file__).parent / "fixtures" / "scanner-exports"


class ExtendedScannerAdapterTests(unittest.TestCase):
    def test_rfc3339_nanoseconds_and_offsets_preserve_interval_boundaries(self):
        self.assertEqual(_stamp("2026-10-30T13:53:44.56929556-05:00"), _stamp("2026-10-30T18:53:44.569295560Z"))
        self.assertEqual(_stamp("2026-10-31T00:23:44.56929556+05:30"), _stamp("2026-10-30T18:53:44.569295560Z"))
        self.assertEqual(_stamp("1970-01-01T00:00:00.000000001Z"), 1)
        self.assertEqual(_stamp("1969-12-31T23:59:59.999999999Z"), -1)
        for invalid in ("2026-10-30 18:53:44Z", "2026-10-30T18:53:44", "2026-10-30T18:53:60Z",
                        "2026-10-30T18:53:44.0000000001Z", "2026-10-30T18:53:44+24:00", "2026-10-30T18:53:44+00:60"):
            with self.subTest(timestamp=invalid), self.assertRaises(ExecutionDenied):
                _stamp(invalid)
        for stamp, accepted in (("2026-10-30T18:53:44.999999999Z", True),
                                ("2026-10-30T18:53:45.000000000Z", True),
                                ("2026-10-30T18:53:45.000000001Z", False),
                                ("2026-10-30T18:53:43.999999999Z", False)):
            doc, policy, context = self.staging()
            doc[0]["timestamp"] = stamp
            with self.subTest(timestamp=stamp):
                if accepted:
                    self.assertEqual(len(parse_staging_report(doc, policy, context)["observations"]), 1)
                else:
                    with self.assertRaises(ExecutionDenied):
                        parse_staging_report(doc, policy, context)

    def test_fixture_export_bytes_match_recorded_provenance(self):
        provenance = json.loads((FIXTURES/"provenance.json").read_bytes())
        for fixture in provenance["fixtures"]:
            with self.subTest(file=fixture["file"]):
                self.assertEqual(hashlib.sha256((FIXTURES/fixture["file"]).read_bytes()).hexdigest(), fixture["sha256"])

    def fixture(self, name):
        return strict_json((FIXTURES / name).read_bytes())

    def package(self, name="trivy"):
        doc = self.fixture("trivy-0.58.2-image.json" if name == "trivy" else "grype-0.85.0-image.json")
        digest = doc["Metadata"]["ImageID"] if name == "trivy" else doc["source"]["target"]["manifestDigest"]
        selected = {"kind":"image", "image_digest":digest, "image_digest_kind":"config" if name == "trivy" else "manifest"}
        policy = {"detector":{"name":name,"version":"0.58.2" if name == "trivy" else "0.85.0",
                              "report_schema":"trivy-json-v2" if name == "trivy" else "grype-json-v0.85"},
                  "input":selected, "observed_at_utc":"2021-08-25T12:20:30Z", "allowed_rule_ids":[],
                  "database":{"sha256":"a"*64,"built_at_utc":"2021-08-24T00:00:00Z","max_age_seconds":86400}}
        context = {"input_identity":selected,"source":{},"image_digest":digest,"artifact":{}}
        return doc, policy, context

    def staging(self, name="nuclei"):
        doc = self.fixture("nuclei-3.3.8-positive.json" if name == "nuclei" else "zap-reports-0.35.0.json")
        selected = {"kind":"staging", "origin":"http://127.0.0.1:18463" if name == "nuclei" else "http://example.com",
                    "routes":["/fixture"] if name == "nuclei" else ["/example_3"],"deployment_sha256":"d"*64,
                    "scan_started_at_utc":"2026-10-30T18:53:44Z","scan_finished_at_utc":"2026-10-30T18:53:45Z"}
        policy = {"detector":{"name":name,"version":"3.3.8" if name == "nuclei" else "reports-0.35.0",
                              "report_schema":"nuclei-json-export-v3.3.8" if name == "nuclei" else "traditional-json"},
                  "input":selected,"observed_at_utc":selected["scan_finished_at_utc"],
                  "configuration":{"sha256":hashlib.sha256((FIXTURES/"nuclei-fixture.yaml").read_bytes()).hexdigest()},
                  "allowed_rule_ids":["aegis-fixture-marker"] if name == "nuclei" else ["1"]}
        context = {"input_identity":selected,"source":{},"origin":selected["origin"],"routes":selected["routes"]}
        return doc, policy, context

    def normalized_package(self, doc, policy, context):
        parsed = parse_package_report(doc, policy, context)
        policy["allowed_rule_ids"] = sorted({r["rule_id"] for r in parsed["observations"]})
        return normalize(parsed, policy, context)

    def test_actual_vendor_exports_and_duplicate_identity(self):
        for name in ("trivy", "grype"):
            with self.subTest(name=name):
                doc, policy, context = self.package(name)
                result = self.normalized_package(doc, policy, context)
                self.assertTrue(result["observations"])
                self.assertTrue(all(r["ecosystem"].startswith("os/") for r in result["observations"]))
                self.assertNotIn("severity", json.dumps(result))
                if name == "trivy":
                    doc["Results"][0]["Vulnerabilities"] *= 2
                else:
                    doc["matches"] *= 2
                repeated = self.normalized_package(doc, policy, context)
                self.assertEqual(result["observations"], repeated["observations"])
                self.assertGreater(repeated["duplicates_removed"], 0)

    def test_immutable_image_identity_and_artifact_class_must_agree(self):
        for name in ("trivy", "grype"):
            doc, policy, context = self.package(name)
            context["input_identity"]["image_digest"] = "sha256:" + "f"*64
            with self.assertRaises(ExecutionDenied):
                parse_package_report(doc, policy, context)
        doc, policy, context = self.package()
        context["input_identity"]["image_digest_kind"] = "manifest"
        with self.assertRaises(ExecutionDenied):
            parse_package_report(doc, policy, context)

    def test_database_version_schema_and_time_disagreement_denied(self):
        for mutate in (lambda d,p,c:p.update(database=None), lambda d,p,c:p["detector"].update(version="99.0.0"),
                       lambda d,p,c:d.update(SchemaVersion=99), lambda d,p,c:p.update(observed_at_utc="2026-01-01T00:00:00Z")):
            doc, policy, context = self.package()
            mutate(doc, policy, context)
            with self.assertRaises(ExecutionDenied):
                parse_package_report(doc, policy, context)
        doc, policy, context = self.package("grype")
        doc["descriptor"]["db"] = {"checksum":"sha256:" + "f"*64}
        with self.assertRaises(ExecutionDenied):
            parse_package_report(doc, policy, context)

    def test_unresolved_packages_and_derived_zero_match_controls(self):
        for name in ("trivy", "grype"):
            doc, policy, context = self.package(name)
            if name == "trivy":
                for result in doc["Results"]:
                    for entry in result["Vulnerabilities"]:
                        entry["InstalledVersion"] = None
            else:
                for match in doc["matches"]:
                    match["artifact"]["type"] = "unknown"
            parsed = parse_package_report(doc, policy, context)
            self.assertFalse(parsed["observations"])
            self.assertGreater(parsed["coverage"]["unresolved_records"], 0)
            if name == "trivy":
                doc["Results"] = []
            else:
                doc["matches"] = []
            self.assertFalse(parse_package_report(doc, policy, context)["observations"])

    def test_sbom_presence_is_bound_and_never_asserts_image_contents(self):
        doc, policy, context = self.package("grype")
        selected = {"kind":"sbom", "artifact_sha256":"f"*64}
        context["input_identity"] = policy["input"] = selected
        context["artifact"] = {"bomFormat":"CycloneDX","specVersion":"1.6", "components":[
            {"name":m["artifact"]["name"],"version":m["artifact"]["version"],
             "purl":"pkg:"+m["artifact"]["type"]+"/fixture/"+m["artifact"]["name"]+"@"+m["artifact"]["version"]} for m in doc["matches"]]}
        parsed = parse_package_report(doc, policy, context)
        self.assertEqual(len(parsed["observations"]), 2)
        self.assertIn("generator", " ".join(parsed["coverage"]["limitations"]))
        context["artifact"]["components"][0]["purl"] = "pkg:npm/package-1@1.1.1"
        with self.assertRaises(ExecutionDenied):
            parse_package_report(doc, policy, context)

    def test_source_paths_are_independently_selected(self):
        doc, policy, context = self.package()
        doc["ArtifactType"] = "filesystem"
        context["input_identity"] = policy["input"] = {"kind":"source"}
        context["source"] = {"package-lock.json":{}}
        with self.assertRaises(ExecutionDenied):
            parse_package_report(doc, policy, context)

    def test_actual_nuclei_capture_and_zap_export_deduplicate(self):
        for name in ("nuclei", "zap"):
            doc, policy, context = self.staging(name)
            with patch("subprocess.Popen", side_effect=AssertionError("no execution")), patch("socket.create_connection", side_effect=AssertionError("no network")):
                result = normalize(parse_staging_report(doc, policy, context), policy, context)
            self.assertEqual(len(result["observations"]), 1)
            if name == "zap":
                self.assertEqual(result["duplicates_removed"], 1)
        doc, policy, context = self.staging()
        self.assertFalse(parse_staging_report(self.fixture("nuclei-3.3.8-control.json"),policy,context)["observations"])

    def test_staging_scope_route_scan_time_and_configuration_cannot_be_forged(self):
        for mutate in (lambda d,p,c:d[0].update({"matched-at":"http://outside.invalid/fixture"}),
                       lambda d,p,c:d[0].update({"matched-at":"http://127.0.0.1:18463/private"}),
                       lambda d,p,c:d[0].update({"timestamp":"2000-01-01T00:00:00Z"}),
                       lambda d,p,c:p["configuration"].update(sha256="f"*64),
                       lambda d,p,c:d[0].update({"type":"dns"}),
                       lambda d,p,c:p["detector"].update(version="99.0.0")):
            doc, policy, context = self.staging()
            mutate(doc, policy, context)
            with self.assertRaises(ExecutionDenied):
                parse_staging_report(doc, policy, context)
        doc, policy, context = self.staging("zap")
        doc["site"][0]["@host"] = "outside.invalid"
        with self.assertRaises(ExecutionDenied):
            parse_staging_report(doc, policy, context)

    def test_sensitive_query_request_response_and_prose_never_survive(self):
        canary = "PRIVATE_CANARY_SECRET_123456"
        doc, policy, context = self.staging()
        doc[0]["matched-at"] += "?token=" + canary
        doc[0].update({"request":"Authorization: Bearer " + canary,"response":"Set-Cookie: " + canary,
                       "extracted-results":[canary], "curl-command":canary,"info":{"name":canary}})
        result = normalize(parse_staging_report(doc,policy,context),policy,context)
        self.assertNotIn(canary,json.dumps(result))
        self.assertEqual(result["observations"][0]["route"],"/fixture")
        doc, policy, context = self.package()
        for result in doc["Results"]:
            for entry in result["Vulnerabilities"]:
                entry.update(Description=canary,Title=canary,References=[canary])
        self.assertNotIn(canary, json.dumps(self.normalized_package(doc,policy,context)))

    def test_malformed_oversized_and_unsafe_identifiers_fail(self):
        for raw in (b'[]'*300000, b'{"a":1,"a":2}', b'[{"x":NaN}]'):
            with self.assertRaises(ExecutionDenied):
                strict_json(raw)
        doc, policy, context = self.package("grype")
        doc["matches"][0]["artifact"]["name"] = "<script>alert(1)</script>"
        with self.assertRaises(ExecutionDenied):
            parse_package_report(doc,policy,context)


class ExtendedScannerAdmissionTests(unittest.TestCase):
    def setUp(self):
        from test_scanner_admission import ScannerAdmissionTests
        self.admission = ScannerAdmissionTests("test_readonly_import_canonical_report_and_sensitive_output_absence")
        self.addCleanup(self.admission.doCleanups)
        self.admission.setUp()
        self.base = self.admission.fx.fx

    def prepare_image(self):
        fixture = self.admission
        helper = ExtendedScannerAdapterTests()
        doc, policy, _ = helper.package("grype")
        fixture.raw_report = doc
        fixture.admission["detector"] = policy["detector"]
        digest = policy["input"]["image_digest"]
        descriptor = self.base.p / "approved-image.json"
        descriptor.write_bytes(canonical({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","size":100,"digest":digest}))
        descriptor.chmod(0o600)
        fixture.admission["input"] = {"kind":"image","artifact_path":str(descriptor),
            "artifact_sha256":hashlib.sha256(descriptor.read_bytes()).hexdigest(),"format":"oci-descriptor-v1",
            "image_digest":digest,"image_digest_kind":"manifest"}
        fixture.admission["allowed_rule_ids"] = ["CVE-1999-0001","CVE-1999-0002"]
        fixture.admission["database"] = {"sha256":"a"*64,
            "built_at_utc":(datetime.now(timezone.utc)-timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),"max_age_seconds":3600}
        fixture.save_admission()

    def test_image_admission_canonical_evidence_and_database_staleness(self):
        self.prepare_image()
        fixture = self.admission
        with patch("subprocess.Popen", side_effect=AssertionError("no execution")), patch("socket.create_connection", side_effect=AssertionError("no network")):
            result = fixture.admit()
        report = fixture.sup.generate(result["run_id"], "scanner-import.json")
        document = json.loads(Path(report["report"]).read_bytes())
        self.assertEqual(len(document["findings"]), 2)
        self.assertTrue(all(f["verdict"] == "needs_validation" for f in document["findings"]))
        fixture.admission["database"]["built_at_utc"] = "2000-01-01T00:00:00Z"
        fixture.save_admission()
        with self.assertRaises(ExecutionDenied):
            fixture.admit()

    def test_staging_admission_uses_signed_origin_interval_and_deployment_identity(self):
        fixture = self.admission
        helper = ExtendedScannerAdapterTests()
        doc, policy, _ = helper.staging()
        origin = "https://staging.test.example"
        self.base.manifest["targets"]["origins"] = [origin]
        self.base.trust["allowed_origins"] = [origin]
        self.base.manifest["methods"]["allowed"] = ["controlled_http_testing"]
        self.base.trust["approved_methods"] = ["controlled_http_testing"]
        self.base.manifest["limits"].update(max_total_requests=1, max_requests_per_minute_per_origin=1,
            max_concurrent_requests=1, max_total_response_bytes=self.base.manifest["limits"]["max_response_body_bytes"])
        self.base.save()
        stamp = (datetime.now(timezone.utc)-timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Derived integration control changes the retained fixture's local origin/time to this fresh signed scope.
        doc[0].update({"matched-at":origin+"/fixture","url":origin+"/fixture","timestamp":stamp})
        fixture.raw_report = doc
        fixture.admission["detector"] = policy["detector"]
        fixture.admission["input"] = {"kind":"staging","origin":origin,"routes":["/fixture"],
            "deployment_sha256":"d"*64,"scan_started_at_utc":stamp,"scan_finished_at_utc":stamp}
        fixture.admission["observed_at_utc"] = stamp
        fixture.admission["allowed_rule_ids"] = ["aegis-fixture-marker"]
        fixture.config_path.write_bytes((FIXTURES/"nuclei-fixture.yaml").read_bytes())
        fixture.admission["configuration"]["sha256"] = hashlib.sha256(fixture.config_path.read_bytes()).hexdigest()
        fixture.save_admission()
        result = fixture.admit()
        report = fixture.sup.generate(result["run_id"], "scanner-import.json")
        document = json.loads(Path(report["report"]).read_bytes())
        self.assertEqual(document["findings"][0]["affected_asset"], origin+"/fixture")
        fixture.admission["input"]["origin"] = "https://outside.invalid"
        fixture.save_admission()
        with self.assertRaises((ExecutionDenied, HttpPolicyDenied)):
            fixture.admit()


if __name__ == "__main__":
    unittest.main()
