from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_preflight import PreflightError, validate

BASE = Path(__file__).resolve().parents[1]


class AegisPreflightTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.p = Path(self.td.name)
        self.repo = self.p / "authorized" / "repo"
        self.repo.mkdir(parents=True)
        self.report_root = self.p / "reports"
        self.alert_root = self.p / "alerts"
        self.report_root.mkdir()
        self.alert_root.mkdir()

        self.manifest = yaml.safe_load((BASE / "security-scope.example.yaml").read_text())
        self.trust = json.loads((BASE / "trust-policy.example.json").read_text())
        now = datetime.now(timezone.utc)
        ts = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.manifest["engagement"]["valid_from_utc"] = ts(now - timedelta(minutes=5))
        self.manifest["engagement"]["valid_until_utc"] = ts(now + timedelta(hours=1))
        self.manifest["targets"]["repositories"] = [str(self.repo)]
        self.manifest["targets"]["origins"] = ["https://staging.test.example"]
        for a in self.manifest["accounts"]:
            a["allowed_origins"] = ["https://staging.test.example"]
        self.manifest["reporting"]["output_dir"] = str(self.report_root / self.manifest["engagement"]["id"])
        self.manifest["reporting"]["critical_alert"]["path"] = str(self.alert_root / (self.manifest["engagement"]["id"] + ".ndjson"))

        self.key = Ed25519PrivateKey.generate()
        self.pub = self.p / "pinned.pub.pem"
        self.pub.write_bytes(self.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self.trust["configured"] = True
        self.trust["operator"]["public_key_pem_path"] = str(self.pub)
        self.trust["approved_engagement_ids"] = [self.manifest["engagement"]["id"]]
        self.trust["allowed_repository_roots"] = [str(self.repo.parent)]
        self.trust["allowed_origins"] = ["https://staging.test.example"]
        self.trust["approved_methods"] = list(self.manifest["methods"]["allowed"])
        self.trust["allowed_report_roots"] = [str(self.report_root)]
        self.trust["allowed_alert_roots"] = [str(self.alert_root)]
        self.manifest_path = self.p / "scope.yaml"
        self.sig_path = self.p / "scope.yaml.sig"
        self.trust_path = self.p / "operator-trust.json"
        self.save()

    def save(self, raw=None, sign=True):
        contents = raw if raw is not None else yaml.safe_dump(self.manifest, sort_keys=False).encode("utf-8")
        self.manifest_path.write_bytes(contents)
        if sign:
            self.sig_path.write_bytes(self.key.sign(contents))
        self.trust_path.write_text(json.dumps(self.trust))

    def check(self):
        return validate(self.manifest_path, self.sig_path, self.trust_path)

    def test_valid_signed_scope(self):
        verified = self.check()
        self.assertEqual(verified["status"], "PREFLIGHT_VERIFIED_NOT_RUNTIME_ENFORCEMENT")
        self.assertEqual(verified["authorized_origins"], ["https://staging.test.example"])

    def test_tampered_manifest_rejected(self):
        self.save()
        self.manifest_path.write_bytes(self.manifest_path.read_bytes() + b"\n# modified by attacker\n")
        with self.assertRaisesRegex(PreflightError, "signature"):
            self.check()

    def test_expired_scope_rejected_even_with_valid_signature(self):
        past = datetime.now(timezone.utc) - timedelta(days=2)
        self.manifest["engagement"]["valid_from_utc"] = past.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.manifest["engagement"]["valid_until_utc"] = (past + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.save()
        with self.assertRaisesRegex(PreflightError, "not currently authorized"):
            self.check()

    def test_unapproved_origin_rejected_even_with_valid_signature(self):
        self.manifest["targets"]["origins"].append("https://unapproved.example.org")
        self.save()
        with self.assertRaisesRegex(PreflightError, "origins exceed"):
            self.check()

    def test_credential_bound_to_outside_origin_rejected(self):
        self.manifest["accounts"][0]["allowed_origins"] = ["https://prod.test.example"]
        self.save()
        with self.assertRaisesRegex(PreflightError, "outside approved assets"):
            self.check()

    def test_revoked_engagement_rejected(self):
        self.trust["revoked_engagement_ids"] = [self.manifest["engagement"]["id"]]
        self.save()
        with self.assertRaisesRegex(PreflightError, "revoked"):
            self.check()

    def test_disabled_operator_policy_rejected(self):
        self.trust["configured"] = False
        self.save()
        with self.assertRaisesRegex(PreflightError, "not explicitly configured"):
            self.check()

    def test_overlong_window_rejected(self):
        self.manifest["engagement"]["valid_until_utc"] = (datetime.now(timezone.utc) + timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.save()
        with self.assertRaisesRegex(PreflightError, "window exceeds"):
            self.check()

    def test_untrusted_method_rejected(self):
        self.manifest["methods"]["allowed"].append("runtime_instrumentation")
        self.save()
        with self.assertRaisesRegex(PreflightError, "method exceeds"):
            self.check()

    def test_high_impact_approval_cannot_be_removed(self):
        self.manifest["methods"]["requires_approval"].remove("service_disruption")
        self.save()
        with self.assertRaisesRegex(PreflightError, "approval gates"):
            self.check()

    def test_doubled_yaml_key_rejected(self):
        raw = b"schema_version: 1\n" + yaml.safe_dump(self.manifest, sort_keys=False).encode()
        self.save(raw=raw)
        with self.assertRaisesRegex(PreflightError, "duplicate YAML key"):
            self.check()

    def test_missing_fields_rejected(self):
        del self.manifest["reporting"]["critical_alert"]
        self.save()
        with self.assertRaisesRegex(PreflightError, "manifest schema invalid"):
            self.check()

    def test_excluded_origin_cannot_be_target(self):
        self.manifest["targets"]["excluded_origins"] = ["https://staging.test.example"]
        self.save()
        with self.assertRaisesRegex(PreflightError, "also explicitly excluded"):
            self.check()

    def test_output_cannot_land_in_repo(self):
        # Even a mistakenly trusted reporting root must not permit repo-contained artifacts.
        self.trust["allowed_report_roots"] = [str(self.repo)]
        (self.repo / "artifacts").mkdir()
        self.manifest["reporting"]["output_dir"] = str(self.repo / "artifacts" / self.manifest["engagement"]["id"])
        self.save()
        with self.assertRaisesRegex(PreflightError, "inside assessed repositories"):
            self.check()

    def test_unsigned_scope_rejected(self):
        self.sig_path.unlink()
        with self.assertRaisesRegex(PreflightError, "signature/trust"):
            self.check()

    def test_budget_above_trusted_ceiling_rejected(self):
        self.manifest["limits"]["max_total_requests"] = 6000
        self.save()
        with self.assertRaisesRegex(PreflightError, "budget max_total_requests"):
            self.check()

    def test_network_empty_means_no_networks(self):
        self.assertEqual(self.check()["authorized_networks"], [])
        self.manifest["targets"]["networks"] = ["192.0.2.0/24"]
        self.save()
        with self.assertRaisesRegex(PreflightError, "CIDR exceeds"):
            self.check()


if __name__ == "__main__":
    unittest.main()
