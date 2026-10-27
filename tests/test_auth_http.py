"""Synthetic HTTPS credential use: fixed request, TLS and zero secret disclosure."""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import aegis_http_broker as transport
from aegis_http_gateway import TransportError
from aegis_approval_admin import sign_grant
from test_credentials import CredentialSessionTests
from aegis_supervisor import ExecutionDenied


class CapturingHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        self.server.auth_seen = self.headers.get('Authorization')
        self.server.target_seen = self.path
        payload = (self.server.auth_seen or '').encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *_): pass


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() != 0,
                     'NOT EXECUTED: requires non-root Linux namespaces and seccomp')
class AuthTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        p = Path(self.temp.name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'staging.test.example')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('staging.test.example')]), critical=False)
            .sign(key, hashes.SHA256()))
        self.key = p / 'tls.key'
        self.pem = p / 'tls.pem'
        self.key.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        self.pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.pem.chmod(0o600)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), CapturingHandler)
        self.server.auth_seen = None
        self.server.target_seen = None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.pem), str(self.key))
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.token = p / 'token'
        self.token.write_text('TEST-only-credential-xyz-123456')
        self.token.chmod(0o600)
        self.req = {'scheme':'https', 'hostname':'staging.test.example',
            'port':self.server.server_port, 'address':'127.0.0.1',
            'method':'GET', 'target':'/secure/status', 'timeout':3,
            'body_limit':2048,
            'ca_bundle':{'path':str(self.pem), 'sha256':__import__('hashlib').sha256(self.pem.read_bytes()).hexdigest()}}

    def sealed_token_fd(self):
        import fcntl
        fd = os.memfd_create('aegis-test-snapshot', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        token = self.token.read_bytes()
        os.write(fd, token)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd

    def fetch(self, req=None):
        # The broker consumes and closes a sealed token snapshot, never the vault.
        return transport.fetch(dict(self.req if req is None else req, mode='fetch'),
                               self.sealed_token_fd())

    def test_genuine_tls_request_and_no_secret_in_result(self):
        result = self.fetch()
        self.assertEqual(result['http_status'], 200)
        self.assertEqual(self.server.auth_seen, 'Bearer TEST-only-credential-xyz-123456')
        self.assertEqual(self.server.target_seen, '/secure/status')
        self.assertNotIn('credential', json.dumps(result).lower())
        self.assertEqual(set(result), {'status', 'http_status', 'body_bytes', 'redirect_not_followed'})

    def test_fresh_broker_confines_helper_with_inherited_fd(self):
        fd = self.sealed_token_fd()
        try:
            process = subprocess.run([sys.executable, '-I', '-S', str(Path(__file__).parents[1] / 'aegis_http_broker.py'),
                str(os.getpid()), '--credential-fd', str(fd)],
                input=json.dumps(dict(self.req, mode='fetch')), text=True, capture_output=True,
                timeout=8, pass_fds=(fd,))
        finally: os.close(fd)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)['status'], 'AUTH_METADATA_ONLY')
        self.assertNotIn('credential', process.stdout.lower())

    def test_hostname_mismatch_fails_tls(self):
        req = dict(self.req, hostname='wrong.test.example')
        with self.assertRaises(TransportError): self.fetch(req)
        self.assertIsNone(self.server.auth_seen)

    def test_untrusted_ca_fails_closed(self):
        req = dict(self.req); del req['ca_bundle']
        with self.assertRaises(TransportError): self.fetch(req)
        self.assertIsNone(self.server.auth_seen)

    def test_newline_in_secret_rejected(self):
        self.token.write_text('TEST-only-token\nInjected-Header:value')
        with self.assertRaises(TransportError): self.fetch()

    def test_plaintext_and_invalid_route_rejected(self):
        for req in [dict(self.req, scheme='http'),
                    dict(self.req, target='/secure/hi\r\nX:1')]:
            with self.assertRaises(TransportError): self.fetch(req)


class OperatorSignerTests(CredentialSessionTests):
    def test_operator_signs_and_broker_consumes(self):
        from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption
        keypath = self.fx.p / 'operator-private.pem'
        keypath.write_bytes(self.operator_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        keypath.chmod(0o600)
        signed = self.fx.p / 'new-approval.json'
        # Approval files live in a private operator-owned directory.
        result = sign_grant(self.broker(), keypath, signed, 'ordinary_user',
                            'https://staging.test.example', '/secure', 30, 1)
        self.assertEqual(result['status'], 'APPROVAL_SIGNED')
        opened = self.broker().create_session(signed, Path(str(signed)+'.sig'))
        self.assertEqual(opened['max_uses'], 1)

    def test_operator_signing_wrong_key_fails(self):
        from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption
        keypath = self.fx.p / 'unapproved.pem'
        keypath.write_bytes(rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        keypath.chmod(0o600)
        with self.assertRaises(ExecutionDenied):
            sign_grant(self.broker(), keypath, self.fx.p / 'failed-approval',
                      'ordinary_user', 'https://staging.test.example', '/secure')

if __name__ == '__main__': unittest.main()

class AuthenticatedSupervisorIntegration(unittest.TestCase):
    """Synthetic end-to-end broker request; no external target or credential used."""
    def setUp(self):
        import hashlib
        self.credential_fx = CredentialSessionTests('test_create_and_use_without_exposing_vault_reference')
        self.credential_fx.setUp()
        self.addCleanup(self.credential_fx.doCleanups)
        self.transport_fx = AuthTransportTests('test_genuine_tls_request_and_no_secret_in_result')
        self.transport_fx.setUp()
        self.addCleanup(self.transport_fx.doCleanups)
        self.port = self.transport_fx.server.server_port
        self.origin = f'https://staging.test.example:{self.port}'
        fx = self.credential_fx.fx
        fx.manifest['targets']['origins'] = [self.origin]
        for acc in fx.manifest['accounts']:
            acc['allowed_origins'] = [self.origin]
        fx.trust['allowed_origins'] = [self.origin]
        fx.trust['allowed_http_path_prefixes'] = {self.origin: ['/secure']}
        fx.trust['tls_custom_ca'] = {
            'path': str(self.transport_fx.pem),
            'sha256': hashlib.sha256(self.transport_fx.pem.read_bytes()).hexdigest()}
        fx.save()
        self.credential_fx.policy['credential_profiles']['vault://aegis/example/ordinary']['allowed_origins'] = [self.origin]
        self.credential_fx.policy_write()
        self.credential_fx.approve({'origin': self.origin})
        self.secret_value = self.transport_fx.token.read_text()
        self.credential_fx.secret.write_text(self.secret_value)
        self.credential_fx.policy['credential_profiles']['vault://aegis/example/ordinary']['fingerprint_sha256'] = __import__('hashlib').sha256(self.credential_fx.secret.read_bytes()).hexdigest()
        self.credential_fx.policy_write()
        self.token = self.credential_fx.create()['handle']
        self.broker = self.credential_fx.broker()
        # All resolution still goes through signed CIDR checks; synthetic DNS
        # maps an authorized hostname to an explicit signed loopback IP.
        self.broker._resolve = lambda hostname, port, timeout, route_plan=None: ['127.0.0.1']

    @unittest.skipIf(os.geteuid() == 0, 'requires non-root test user')
    def test_authenticated_operation_and_redacted_evidence(self):
        result = self.broker.authenticated_request(self.token, self.origin + '/secure/status', 'GET', 10)
        self.assertEqual(result['status'], 'AUTHENTICATED_METADATA_COMPLETED')
        self.assertEqual(result['http_status'], 200)
        self.assertEqual(self.transport_fx.server.auth_seen, 'Bearer ' + self.secret_value)
        self.assertNotIn(self.secret_value, json.dumps(result))
        artifact = Path(result['report']).read_text()
        self.assertNotIn(self.secret_value, artifact)
        self.assertNotIn('vault://', artifact)
        self.assertNotIn('Authorization', artifact)
        self.assertEqual(self.broker.http_usage(self.credential_fx.fx.manifest['engagement']['id'])['reserved_requests'], 1)

    @unittest.skipIf(os.geteuid() == 0, 'requires non-root test user')
    def test_revocation_before_request(self):
        self.broker.revoke_session(self.token)
        with self.assertRaisesRegex(ExecutionDenied, 'revoked'):
            self.broker.authenticated_request(self.token, self.origin + '/secure/status', 'GET', 10)
