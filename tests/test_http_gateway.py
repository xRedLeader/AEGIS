"""AEGIS v1.4 real loopback HTTP/HTTPS gateway and adversarial gate tests."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import ipaddress
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import unittest

from aegis_http_policy import HttpPolicyDenied, inspect_url, pinned_address
from aegis_http_runtime import AegisHttpSupervisor
from aegis_supervisor import ExecutionDenied, operator_stop
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        return

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.server.seen.append((self.command, self.path, self.headers.get("Host"),
                                 self.headers.get("Authorization"), self.headers.get("Cookie")))
        if self.path.startswith("/slow"):
            time.sleep(2)
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/never-follow")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/huge"):
            body = b"Q" * 32768
        else:
            body = b"SECRET_RESPONSE_BODY_12345678"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "superprivate=secret")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass


class HTTPGatewayTests(unittest.TestCase):
    def setUp(self):
        from test_preflight import AegisPreflightTests
        self.fx = AegisPreflightTests("test_valid_signed_scope")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.state = self.fx.p / "state"
        self.state.mkdir(mode=0o700)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.seen = []
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.fx.manifest["targets"].update(repositories=[], origins=[self.origin],
                                           networks=["127.0.0.1/32"],
                                           excluded_origins=[], excluded_networks=[])
        self.fx.manifest["accounts"] = []
        self.fx.manifest["methods"]["allowed"] = ["controlled_http_testing"]
        self.fx.trust["allowed_origins"] = [self.origin]
        self.fx.trust["allowed_networks"] = ["127.0.0.1/32"]
        self.fx.trust["approved_methods"] = ["controlled_http_testing"]
        self.fx.trust["allowed_http_path_prefixes"] = {self.origin: ["/"]}
        self.fx.manifest["limits"]["max_total_requests"] = 12
        self.fx.manifest["limits"]["max_requests_per_minute_per_origin"] = 12
        self.fx.manifest["limits"]["max_concurrent_requests"] = 2
        self.fx.manifest["limits"]["max_response_body_bytes"] = 4096
        self.fx.manifest["limits"]["engagement_runtime_minutes"] = 3
        self.fx.manifest["limits"]["max_single_run_minutes"] = 2
        self.fx.manifest["limits"]["deterministic_hypothesis_minutes"] = 1
        self.fx.save()

    def supervisor(self):
        return AegisHttpSupervisor(self.fx.manifest_path, self.fx.sig_path,
                                   self.fx.trust_path, self.state)

    def _serve_https(self, wrong_name=False):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AEGIS demo CA")])
        now = datetime.now(timezone.utc)
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=2))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                    key_encipherment=False, data_encipherment=False, key_agreement=False,
                    key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
              .sign(ca_key, hashes.SHA256()))
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AEGIS local HTTPS")])
        san = ([x509.DNSName("wrong-host.example.invalid")] if wrong_name else
               [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
        leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
                .public_key(server_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(hours=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False, key_agreement=False,
                    key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.SubjectAlternativeName(san), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        ca_file = self.fx.p / "operator-ca.pem"
        cert_file = self.fx.p / "server-cert.pem"
        key_file = self.fx.p / "server-key.pem"
        ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        tls_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        tls_server.seen = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_file), str(key_file))
        tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
        t = threading.Thread(target=tls_server.serve_forever, daemon=True)
        t.start()
        self.addCleanup(tls_server.server_close)
        self.addCleanup(tls_server.shutdown)
        origin = f"https://127.0.0.1:{tls_server.server_port}"
        self.fx.manifest["targets"]["origins"] = [origin]
        self.fx.trust["allowed_origins"] = [origin]
        self.fx.trust["allowed_http_path_prefixes"] = {origin: ["/"]}
        self.fx.save()
        return origin, ca_file

    def test_https_untrusted_cert_fails_closed(self):
        origin, ca_file = self._serve_https()
        # Even external caller SSL_CERT_FILE cannot bypass strict system trust:
        # the helper runs with a scrubbed environment.
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(ca_file)}):
            with self.assertRaisesRegex(ExecutionDenied, "helper rejected"):
                self.supervisor().request(origin + "/tls", budget_seconds=7)

    def test_https_with_operator_pinned_ca_and_hostname_verification(self):
        origin, ca_file = self._serve_https()
        self.fx.trust["tls_custom_ca"] = {"path": str(ca_file),
                                          "sha256": hashlib.sha256(ca_file.read_bytes()).hexdigest()}
        self.fx.save()
        result = self.supervisor().request(origin + "/tls", budget_seconds=7)
        self.assertEqual(result["status"], "COMPLETED_HTTP_METADATA_ONLY")
        self.assertEqual(result["http_status"], 200)

    def test_https_hostname_mismatch_rejected_despite_trusted_ca(self):
        origin, ca_file = self._serve_https(wrong_name=True)
        self.fx.trust["tls_custom_ca"] = {"path": str(ca_file),
                                          "sha256": hashlib.sha256(ca_file.read_bytes()).hexdigest()}
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "helper rejected"):
            self.supervisor().request(origin + "/tls", budget_seconds=7)

    def test_changed_trusted_ca_fails_before_reservation(self):
        origin, ca_file = self._serve_https()
        self.fx.trust["tls_custom_ca"] = {"path": str(ca_file), "sha256": "0" * 64}
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "fingerprint"):
            self.supervisor().request(origin + "/tls", budget_seconds=7)
        self.assertFalse((self.state / "ledger.sqlite3").exists())

    def test_supervisor_cli_http_and_persistent_usage(self):
        root = Path(__file__).resolve().parents[1]
        env = dict(os.environ, AEGIS_TRUST_POLICY=str(self.fx.trust_path),
                   AEGIS_STATE_ROOT=str(self.state))
        command = [sys.executable, str(root / "aegis_supervisor.py"),
                   "--manifest", str(self.fx.manifest_path),
                   "--signature", str(self.fx.sig_path)]
        result = subprocess.run(command + ["http", "--url", self.origin + "/status", "--seconds", "7"],
                                env=env, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "COMPLETED_HTTP_METADATA_ONLY")
        usage = subprocess.run(command + ["http-usage"], env=env, text=True,
                               capture_output=True, timeout=10)
        self.assertEqual(usage.returncode, 0, usage.stderr)
        self.assertEqual(json.loads(usage.stdout)["reserved_requests"], 1)

    def test_real_request_pinned_origin_and_no_sensitive_output(self):
        token = "SENSITIVE_QUERY_SHOULD_NOT_BE_RECORDED"
        output = self.supervisor().request(self.origin + "/ok?auth=" + token, budget_seconds=7)
        self.assertEqual(output["status"], "COMPLETED_HTTP_METADATA_ONLY")
        self.assertEqual(output["http_status"], 200)
        self.assertEqual(output["body_bytes"], len(b"SECRET_RESPONSE_BODY_12345678"))
        report = Path(output["report"]).read_text()
        self.assertNotIn(token, report)
        self.assertNotIn("SECRET_RESPONSE_BODY", report)
        self.assertNotIn("superprivate", report)
        self.assertEqual(self.server.seen[0][2], "127.0.0.1:" + str(self.server.server_port))
        self.assertEqual(self.server.seen[0][3:], (None, None))
        self.assertEqual(self.supervisor().http_usage(self.fx.manifest["engagement"]["id"])["reserved_requests"], 1)
        self.assertTrue(self.supervisor().verify_audit_chain())

    def test_head_no_body(self):
        result = self.supervisor().request(self.origin + "/head", "HEAD", 7)
        self.assertEqual(result["body_bytes"], 0)

    def test_redirect_is_never_followed(self):
        result = self.supervisor().request(self.origin + "/redirect", budget_seconds=7)
        self.assertEqual(result["http_status"], 302)
        self.assertTrue(result["redirect_not_followed"])
        evidence = json.loads(Path(result["report"]).read_text())
        self.assertNotIn("location", evidence["result"]["headers"])
        self.assertEqual(len(self.server.seen), 1)

    def test_response_limit_aborts_without_artifact(self):
        with self.assertRaisesRegex(ExecutionDenied, "helper rejected"):
            self.supervisor().request(self.origin + "/huge", budget_seconds=7)
        self.assertEqual(len(self.server.seen), 1)
        self.assertFalse(list(self.fx.report_root.rglob("http-result.json")))
        self.assertTrue(self.supervisor().verify_audit_chain())

    def test_route_policy_denies_unlisted_path_before_reservation(self):
        self.fx.trust["allowed_http_path_prefixes"] = {self.origin: ["/read-only"]}
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "HTTP route not authorized"):
            self.supervisor().request(self.origin + "/admin/delete")
        self.assertFalse((self.state / "ledger.sqlite3").exists())

    def test_encoded_path_ambiguity_denied_before_request(self):
        for suffix in ("/safe/%2e%2e/admin", "/safe/../admin", "/safe//admin", "/safe;a/admin"):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(ExecutionDenied, "ambiguous HTTP route"):
                    self.supervisor().request(self.origin + suffix)
        self.assertFalse((self.state / "ledger.sqlite3").exists())

    def test_cumulative_reserved_response_byte_budget(self):
        self.fx.manifest["limits"]["max_total_response_bytes"] = 4096
        self.fx.save()
        self.supervisor().request(self.origin + "/first", budget_seconds=7)
        with self.assertRaisesRegex(ExecutionDenied, "cumulative HTTP response-body budget"):
            self.supervisor().request(self.origin + "/second", budget_seconds=7)
        self.assertEqual(self.supervisor().http_usage(self.fx.manifest["engagement"]["id"])["reserved_body_bytes"], 4096)

    def test_unapproved_port_does_not_touch_ledger(self):
        with self.assertRaisesRegex(ExecutionDenied, "origin not present"):
            self.supervisor().request("http://127.0.0.1:9/secret")
        self.assertFalse((self.state / "ledger.sqlite3").exists())

    def test_networks_empty_denies_even_approved_origin(self):
        self.fx.manifest["targets"]["networks"] = []
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "explicit signed"):
            self.supervisor().request(self.origin + "/ok")
        self.assertFalse((self.state / "ledger.sqlite3").exists())

    def test_wrong_dns_answer_denied_without_packet_to_target(self):
        s = self.supervisor()
        with patch.object(s, "_resolve", return_value=["8.8.8.8"]):
            with self.assertRaisesRegex(ExecutionDenied, "DNS answer outside"):
                s.request(self.origin + "/ok", budget_seconds=7)
        self.assertFalse(self.server.seen)

    def test_mixed_dns_answer_denies_instead_of_choosing_allowed(self):
        s = self.supervisor()
        with patch.object(s, "_resolve", return_value=["127.0.0.1", "10.0.0.9"]):
            with self.assertRaisesRegex(ExecutionDenied, "DNS answer outside"):
                s.request(self.origin + "/ok", budget_seconds=7)
        self.assertFalse(self.server.seen)

    def test_excluded_origin_blocks_before_reservation(self):
        self.fx.manifest["targets"]["excluded_origins"] = [self.origin]
        self.fx.save()
        # Preflight itself denies contradictory active/excluded target scope.
        with self.assertRaisesRegex(ExecutionDenied, "explicitly excluded"):
            self.supervisor().request(self.origin + "/ok")

    def test_rate_budget_persists_across_instances(self):
        self.fx.manifest["limits"]["max_requests_per_minute_per_origin"] = 1
        self.fx.save()
        self.supervisor().request(self.origin + "/first", budget_seconds=7)
        with self.assertRaisesRegex(ExecutionDenied, "requests-per-minute"):
            self.supervisor().request(self.origin + "/second", budget_seconds=7)
        self.assertEqual(len(self.server.seen), 1)

    def test_cumulative_total_budget(self):
        self.fx.manifest["limits"]["max_total_requests"] = 1
        self.fx.save()
        self.supervisor().request(self.origin + "/first", budget_seconds=7)
        with self.assertRaisesRegex(ExecutionDenied, "cumulative HTTP request"):
            self.supervisor().request(self.origin + "/second", budget_seconds=7)

    def test_concurrency_gate_during_live_request(self):
        self.fx.manifest["limits"]["max_concurrent_requests"] = 1
        self.fx.save()
        outcome = []
        def first():
            try:
                outcome.append(self.supervisor().request(self.origin + "/slow", budget_seconds=7))
            except Exception as exc:
                outcome.append(exc)
        t = threading.Thread(target=first)
        t.start()
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                db = self.state / "ledger.sqlite3"
                if db.exists():
                    with sqlite3.connect(db) as con:
                        row = con.execute("SELECT name FROM sqlite_master WHERE name='http_requests'").fetchone()
                        if row and con.execute("SELECT COUNT(*) FROM http_requests").fetchone()[0]:
                            break
                time.sleep(0.03)
            else:
                self.fail("first request not reserved")
            with self.assertRaisesRegex(ExecutionDenied, "HTTP concurrency"):
                self.supervisor().request(self.origin + "/other", budget_seconds=7)
        finally:
            t.join(timeout=10)
        self.assertFalse(t.is_alive())
        self.assertIsInstance(outcome[0], dict)

    def test_emergency_stop_interrupts_blocking_response(self):
        def trigger():
            time.sleep(0.4)
            operator_stop(self.state, self.fx.manifest["engagement"]["id"])
        t = threading.Thread(target=trigger)
        t.start()
        try:
            with self.assertRaisesRegex(ExecutionDenied, "emergency stop"):
                self.supervisor().request(self.origin + "/slow", budget_seconds=7)
        finally:
            t.join(timeout=5)
        self.assertFalse(list(self.fx.report_root.rglob("http-result.json")))

    def test_operator_route_revocation_interrupts_response(self):
        def trigger():
            time.sleep(0.5)
            self.fx.trust["allowed_http_path_prefixes"] = {self.origin: ["/other"]}
            tmp = self.fx.trust_path.with_name("operator-trust.new.json")
            tmp.write_text(json.dumps(self.fx.trust))
            os.replace(tmp, self.fx.trust_path)
        t = threading.Thread(target=trigger)
        t.start()
        try:
            with self.assertRaisesRegex(ExecutionDenied, "HTTP route not authorized"):
                self.supervisor().request(self.origin + "/slow", budget_seconds=7)
        finally:
            t.join(timeout=5)
        self.assertFalse(list(self.fx.report_root.rglob("http-result.json")))

    def test_revocation_interrupts_blocking_response(self):
        def trigger():
            time.sleep(0.5)
            self.fx.trust["revoked_engagement_ids"] = [self.fx.manifest["engagement"]["id"]]
            temporary = self.fx.trust_path.with_name("operator-trust.new.json")
            temporary.write_text(json.dumps(self.fx.trust))
            os.replace(temporary, self.fx.trust_path)
        t = threading.Thread(target=trigger)
        t.start()
        try:
            with self.assertRaisesRegex(ExecutionDenied, "revoked"):
                self.supervisor().request(self.origin + "/slow", budget_seconds=7)
        finally:
            t.join(timeout=5)
        self.assertFalse(list(self.fx.report_root.rglob("http-result.json")))

    def test_unapproved_method_denied_before_reservation(self):
        self.fx.manifest["methods"]["allowed"] = ["source_review"]
        self.fx.trust["approved_methods"] = ["source_review"]
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "not authorized"):
            self.supervisor().request(self.origin + "/ok")

    def test_scope_change_after_first_request_denied(self):
        self.supervisor().request(self.origin + "/ok", budget_seconds=7)
        self.fx.manifest["limits"]["max_requests_per_minute_per_origin"] = 11
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "scope changed"):
            self.supervisor().request(self.origin + "/ok", budget_seconds=7)

    def test_no_proxy_use_even_if_environment_is_set(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:9", "ALL_PROXY": "http://127.0.0.1:9"}):
            result = self.supervisor().request(self.origin + "/ok", budget_seconds=7)
        self.assertEqual(result["http_status"], 200)

    def test_metadata_linklocal_and_multicast_denied_even_if_signed(self):
        for address, cidr in (("169.254.169.254", "169.254.169.254/32"),
                              ("224.0.0.1", "224.0.0.1/32"),
                              ("::", "::/128")):
            with self.subTest(address=address):
                with self.assertRaisesRegex(HttpPolicyDenied, "unsafe"):
                    pinned_address([address], [cidr], [], None)

    def test_url_injection_and_host_confusion_denied(self):
        origin = self.origin
        bad = [origin + "/x#fragment", origin + "/x\r\nHeader: bad", origin + "/x\\y",
               origin.replace("http://", "http://name:pass@"),
               origin.replace("127.0.0.1", "0177.0.0.1"),
               "https://[::1]:bad/path", "file:///etc/passwd"]
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises((HttpPolicyDenied, ValueError)):
                    inspect_url(value, [origin], [])


if __name__ == "__main__":
    unittest.main()
