from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import contextlib
import io
from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption
import unittest

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_preflight import PreflightError, SIGNING_CONTEXT, validate, validate_for_signing
from aegis_admin import main as admin_main

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
        self.trust["revocation"]["last_checked_utc"] = ts(now)
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
            self.sig_path.write_bytes(self.key.sign(SIGNING_CONTEXT + contents))
        self.trust_path.write_text(json.dumps(self.trust))

    def check(self):
        return validate(self.manifest_path, self.sig_path, self.trust_path)

    def test_operator_policy_symlink_is_rejected(self):
        moved = self.p / 'real-trust.json'
        self.trust_path.rename(moved)
        self.trust_path.symlink_to(moved)
        with self.assertRaisesRegex(PreflightError, 'trusted policy unavailable'):
            self.check()

    def test_operator_policy_group_writable_is_rejected(self):
        self.trust_path.chmod(0o664)
        with self.assertRaisesRegex(PreflightError, 'group/other writable'):
            self.check()

    def test_operator_policy_oversized_is_rejected(self):
        from aegis_preflight import MAX_TRUST_BYTES
        self.trust_path.write_bytes(b'x' * (MAX_TRUST_BYTES + 1))
        with self.assertRaisesRegex(PreflightError, 'exceeds size limit'):
            self.check()

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


    def test_legacy_signature_without_domain_separation_rejected(self):
        # v1.0 used a signature over raw bytes; v1.1 intentionally rejects it.
        self.sig_path.write_bytes(self.key.sign(self.manifest_path.read_bytes()))
        with self.assertRaisesRegex(PreflightError, "signature"):
            self.check()

    def test_other_protocol_context_is_not_accepted(self):
        raw = self.manifest_path.read_bytes()
        self.sig_path.write_bytes(self.key.sign(b"Different-Protocol\x00" + raw))
        with self.assertRaisesRegex(PreflightError, "signature"):
            self.check()

    def test_pre_sign_validation_accepts_authorized_scope(self):
        raw, info = validate_for_signing(self.manifest_path, self.trust_path, self.key)
        self.assertEqual(raw, self.manifest_path.read_bytes())
        self.assertEqual(info["engagement_id"], self.manifest["engagement"]["id"])

    def test_pre_sign_validation_rejects_out_of_scope_target(self):
        self.manifest["targets"]["origins"].append("https://not-allowed.test")
        self.save()
        with self.assertRaisesRegex(PreflightError, "origins exceed"):
            validate_for_signing(self.manifest_path, self.trust_path, self.key)

    def test_pre_sign_validation_rejects_wrong_operator_key(self):
        with self.assertRaisesRegex(PreflightError, "private key does not match"):
            validate_for_signing(self.manifest_path, self.trust_path, Ed25519PrivateKey.generate())

    def test_oversize_manifest_rejected_even_when_signed(self):
        self.save(raw=self.manifest_path.read_bytes() + b"#" * (256 * 1024), sign=True)
        with self.assertRaisesRegex(PreflightError, "exceeds size limit"):
            self.check()

    def test_sign_command_blocks_invalid_scope_and_does_not_write_signature(self):
        self.manifest["targets"]["origins"].append("https://not-allowed.test")
        self.save()
        dest = self.p / "invalid.sig"
        private_path = self.p / "private.pem"
        private_path.write_bytes(self.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        args = ["aegis_admin.py", "sign", "--private", str(private_path),
                "--manifest", str(self.manifest_path), "--trust-policy", str(self.trust_path),
                "--signature", str(dest)]
        with patch("sys.argv", args), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                admin_main()
        self.assertEqual(error.exception.code, 2)
        self.assertFalse(dest.exists())

    def test_sign_command_end_to_end(self):
        dest = self.p / "new.sig"
        private_path = self.p / "private.pem"
        private_path.write_bytes(self.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        args = ["aegis_admin.py", "sign", "--private", str(private_path),
                "--manifest", str(self.manifest_path), "--trust-policy", str(self.trust_path),
                "--signature", str(dest)]
        with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
            admin_main()
        self.assertEqual(len(dest.read_bytes()), 64)
        self.assertEqual(validate(self.manifest_path, dest, self.trust_path)["status"],
                         "PREFLIGHT_VERIFIED_NOT_RUNTIME_ENFORCEMENT")


    def test_stale_revocation_snapshot_rejected(self):
        self.trust["revocation"]["last_checked_utc"] = (
            datetime.now(timezone.utc) - timedelta(hours=2)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.save()
        with self.assertRaisesRegex(PreflightError, "revocation snapshot stale"):
            self.check()

    def test_future_revocation_snapshot_rejected(self):
        self.trust["revocation"]["last_checked_utc"] = (
            datetime.now(timezone.utc) + timedelta(minutes=2)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.save()
        with self.assertRaisesRegex(PreflightError, "future-dated"):
            self.check()

    def test_missing_revocation_snapshot_rejected(self):
        del self.trust["revocation"]
        self.save()
        with self.assertRaisesRegex(PreflightError, "revocation snapshot is missing"):
            self.check()



if __name__ == "__main__":
    unittest.main()
