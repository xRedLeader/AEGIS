"""Operator-approved credential sessions: replay, scope, revocation, time and leaks."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_credentials import (
    AegisCredentialAuthority, APPROVAL_CONTEXT, _json_bytes,
)
from aegis_supervisor import ExecutionDenied, operator_stop
from test_preflight import AegisPreflightTests


class CredentialSessionTests(unittest.TestCase):
    def setUp(self):
        self.fx = AegisPreflightTests("test_valid_signed_scope")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.state = self.fx.p / "state"
        self.state.mkdir(mode=0o700)
        self.fx.trust["allowed_http_path_prefixes"] = {
            "https://staging.test.example": ["/secure", "/api"]}
        self.fx.trust["allowed_networks"] = ["127.0.0.0/8"]
        self.fx.manifest["targets"]["networks"] = ["127.0.0.1/32"]
        self.fx.save()
        self.operator_key = Ed25519PrivateKey.generate()
        self.pub = self.fx.p / "approval-public.pem"
        self.pub.write_bytes(self.operator_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self.secret = self.fx.p / "bearer-token.secret"
        self.secret.write_text("TEST-only-credential-xyz-123456")
        self.secret.chmod(0o600)
        self.approval = self.fx.p / "approval.json"
        self.signature = self.fx.p / "approval.sig"
        self.credential_policy = self.fx.p / "credential-policy.json"
        self.policy = {
            "version": 1, "configured": True, "operator": "operator-identity",
            "public_key_pem_path": str(self.pub),
            "allowed_engagement_ids": [self.fx.manifest["engagement"]["id"]],
            "credential_paths": {"vault://aegis/example/ordinary": str(self.secret)},
            "credential_profiles": {"vault://aegis/example/ordinary": {
                "classification": "synthetic",
                "allowed_origins": ["https://staging.test.example"],
                "issued_at_utc": (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at_utc": (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "fingerprint_sha256": hashlib.sha256(self.secret.read_bytes()).hexdigest(),
                "exposure_acknowledged": True}},
            "max_session_seconds": 60, "max_uses": 3}
        self.policy_write()
        self.approve()

    def broker(self):
        return AegisCredentialAuthority(
            self.fx.manifest_path, self.fx.sig_path, self.fx.trust_path,
            self.state, self.credential_policy)

    def policy_write(self):
        self.credential_policy.write_text(json.dumps(self.policy))
        self.credential_policy.chmod(0o600)

    def approve(self, overrides=None):
        info, _ = self.broker()._guard()
        now = datetime.now(timezone.utc)
        ts = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.payload = {
            "version": 1, "approval_id": uuid.uuid4().hex,
            "operator": "operator-identity", "engagement_id": info["engagement_id"],
            "manifest_sha256": info["manifest_sha256"], "role": "ordinary_user",
            "secret_ref": "vault://aegis/example/ordinary",
            "origin": "https://staging.test.example", "path_prefix": "/secure",
            "not_before": ts(now - timedelta(seconds=10)),
            "expires_at": ts(now + timedelta(minutes=2)),
            "session_seconds": 30, "max_uses": 2,
        }
        self.payload.update(overrides or {})
        raw = _json_bytes(self.payload)
        self.approval.write_bytes(raw)
        self.signature.write_bytes(self.operator_key.sign(APPROVAL_CONTEXT + raw))

    def create(self):
        return self.broker().create_session(self.approval, self.signature)

    def test_create_and_use_without_exposing_vault_reference(self):
        opened = self.create()
        self.assertEqual(opened["status"], "SESSION_CREATED")
        self.assertNotIn("vault://", json.dumps(opened))
        token = opened["handle"]
        first = self.broker().authorize_operation(token, "https://staging.test.example/secure/status")
        self.assertEqual(first["remaining_uses"], 1)
        second = self.broker().authorize_operation(token, "https://staging.test.example/secure/check", "HEAD")
        self.assertEqual(second["remaining_uses"], 0)
        with self.assertRaisesRegex(ExecutionDenied, "exhausted"):
            self.broker().authorize_operation(token, "https://staging.test.example/secure/other")
        self.assertNotIn(self.secret.read_text(), (self.state / "ledger.sqlite3").read_bytes().decode("utf-8", "ignore"))

    def test_approval_replay_after_restart(self):
        self.create()
        with self.assertRaisesRegex(ExecutionDenied, "replay"):
            self.create()

    def test_vault_in_worker_visible_runtime_is_denied(self):
        self.policy['credential_paths']['vault://aegis/example/ordinary'] = '/usr/share/aegis/token'
        self.policy_write()
        with self.assertRaisesRegex(ExecutionDenied, 'sandbox runtime'):
            self.create()

    def test_operator_revocation(self):
        token = self.create()["handle"]
        self.broker().revoke_session(token)
        with self.assertRaisesRegex(ExecutionDenied, "revoked"):
            self.broker().authorize_operation(token, "https://staging.test.example/secure/a")

    def test_scope_rebinding_rejected(self):
        token = self.create()["handle"]
        for url in ["https://staging.test.example/api/v1", "https://elsewhere.test.example/secure/x",
                    "http://staging.test.example/secure/x", "https://staging.test.example/securex"]:
            with self.subTest(url=url), self.assertRaises(ExecutionDenied):
                self.broker().authorize_operation(token, url)

    def test_operator_override_cannot_expand_signed_route(self):
        self.approve({"path_prefix": "/elsewhere"})
        with self.assertRaisesRegex(ExecutionDenied, "route"):
            self.create()

    def test_approval_expired(self):
        now = datetime.now(timezone.utc)
        ts = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
        self.approve({"not_before": ts(now - timedelta(minutes=3)),
                      "expires_at": ts(now - timedelta(minutes=2))})
        with self.assertRaisesRegex(ExecutionDenied, "time"):
            self.create()

    def test_wrong_approval_signer(self):
        self.signature.write_bytes(Ed25519PrivateKey.generate().sign(
            APPROVAL_CONTEXT + self.approval.read_bytes()))
        with self.assertRaisesRegex(ExecutionDenied, "signature"):
            self.create()

    def test_payload_tampering(self):
        self.approval.write_bytes(self.approval.read_bytes().replace(b"/secure", b"/api"))
        with self.assertRaisesRegex(ExecutionDenied, "signature"):
            self.create()

    def test_mismatched_manifest_sha(self):
        self.approve({"manifest_sha256": "0" * 64})
        with self.assertRaisesRegex(ExecutionDenied, "scope"):
            self.create()

    def test_approval_for_unlisted_credential(self):
        self.approve({"secret_ref": "vault://unlisted/secret"})
        with self.assertRaisesRegex(ExecutionDenied, "unique authorized account"):
            self.create()

    def test_secret_file_symlink_and_permissions(self):
        token = self.create()["handle"]
        self.secret.chmod(0o644)
        with self.assertRaisesRegex(ExecutionDenied, "credential material"):
            self.broker()._open_secret_fd(token, {"origin": "https://staging.test.example", "target": "/secure/x"})
        self.secret.chmod(0o600)
        other = self.fx.p / "other.secret"
        other.write_text("insecure")
        self.secret.unlink()
        self.secret.symlink_to(other)
        with self.assertRaises(ExecutionDenied):
            self.broker()._open_secret_fd(token, {"origin": "https://staging.test.example", "target": "/secure/x"})

    def test_global_emergency_stop(self):
        token = self.create()["handle"]
        operator_stop(self.state, self.fx.manifest["engagement"]["id"])
        with self.assertRaisesRegex(ExecutionDenied, "emergency stop"):
            self.broker().authorize_operation(token, "https://staging.test.example/secure/x")

    def test_engagement_revocation(self):
        token = self.create()["handle"]
        self.fx.trust["revoked_engagement_ids"].append(self.fx.manifest["engagement"]["id"])
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "revoked"):
            self.broker().authorize_operation(token, "https://staging.test.example/secure/x")

    def test_concurrent_approval_single_consumption(self):
        def call(_):
            try:
                return self.create()["status"]
            except ExecutionDenied:
                return "DENIED"
        with ThreadPoolExecutor(max_workers=6) as pool:
            statuses = list(pool.map(call, range(6)))
        self.assertEqual(statuses.count("SESSION_CREATED"), 1)
        self.assertEqual(statuses.count("DENIED"), 5)

    def test_concurrent_use_limit(self):
        token = self.create()["handle"]
        def call(_):
            try:
                self.broker().authorize_operation(token, "https://staging.test.example/secure/x")
                return True
            except ExecutionDenied:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            permitted = list(pool.map(call, range(8)))
        self.assertEqual(sum(permitted), 2)

if __name__ == "__main__":
    unittest.main()
