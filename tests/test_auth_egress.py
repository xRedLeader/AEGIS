"""Real kernel and lifecycle attacks against the credential-bearing profile."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

import aegis_http_broker as transport
from aegis_http_gateway import TransportError
from aegis_supervisor import ExecutionDenied, operator_stop
import test_auth_http as fixtures

HERE = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() != 0,
                     'NOT EXECUTED: requires non-root Linux namespaces and seccomp')
class AuthenticatedEgressTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuthenticatedSupervisorIntegration()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.root = self.fx.credential_fx.fx.p
        self.seen, self.closed = threading.Event(), threading.Event()

    def sandbox_launcher(self, payload=None, setup=''):
        launcher = self.root / 'injected-sandbox.py'
        text = f'import sys\nsys.path.insert(0, {str(HERE)!r})\nimport aegis_sandbox as s\n'
        if payload is not None:
            worker = self.root / 'hostile-worker.py'
            worker.write_text(payload)
            text += f's.AUTH_HTTP_HOST = s.Path({str(worker)!r})\n'
        launcher.write_text(text + setup + '\nraise SystemExit(s.main())\n')
        return launcher

    @contextmanager
    def direct_sandbox(self, payload=None, setup='', remove_net=False):
        launcher = self.sandbox_launcher(payload, setup)
        original = transport.sandbox_command
        def command(*args):
            cmd = original(*args)
            self.assertIn('auth-http', cmd)
            cmd[cmd.index(str(HERE / 'aegis_sandbox.py'))] = str(launcher)
            return [v for v in cmd if v != '--net'] if remove_net else cmd
        with patch.object(transport, 'sandbox_command', side_effect=command):
            yield

    def hostile_payload(self, attack):
        return (
            'import json, os, sys, time\nsys.path.insert(0, "/app")\n'
            'from aegis_http_gateway import PinnedConnection\n'
            'req = json.load(sys.stdin)\n'
            'conn = PinnedConnection(req["hostname"], req["port"], req["address"], '
            '"https", 2, int(sys.argv[2]))\nconn.ca_pem = req["ca_pem"]\n'
            'conn.request("GET", "/secure/hang", headers={"Authorization": "Bearer " + req["bearer_token"]})\n'
            + attack + '\n')

    def broker_launcher(self, payload):
        sandbox = self.sandbox_launcher(payload)
        launcher = self.root / 'injected-broker.py'
        launcher.write_text(
            f'import sys\nsys.path.insert(0, {str(HERE)!r})\n'
            'import aegis_http_broker as b\noriginal = b.sandbox_command\n'
            'def command(*args):\n cmd = original(*args)\n'
            f' cmd[cmd.index({str(HERE / "aegis_sandbox.py")!r})] = {str(sandbox)!r}\n'
            ' return cmd\nb.sandbox_command = command\nraise SystemExit(b.main())\n')
        return launcher

    @contextmanager
    def hostile_broker(self, payload):
        launcher = self.broker_launcher(payload)
        original = subprocess.Popen
        def spawn(cmd, *args, **kwargs):
            cmd = list(cmd)
            cmd[cmd.index(str(HERE / 'aegis_http_broker.py'))] = str(launcher)
            return original(cmd, *args, **kwargs)
        with patch.object(subprocess, 'Popen', side_effect=spawn):
            yield

    @contextmanager
    def held_endpoint(self):
        def hold(handler):
            handler.server.auth_seen = handler.headers.get('Authorization')
            self.seen.set()
            try:
                handler.rfile.read(1)
            finally:
                self.closed.set()
        with patch.object(fixtures.CapturingHandler, 'do_GET', hold):
            yield

    def request(self, seconds=5):
        return self.fx.broker.authenticated_request(
            self.fx.token, self.fx.origin + '/secure/status', budget_seconds=seconds)

    def assert_no_secret_artifacts(self):
        for path in self.fx.credential_fx.state.rglob('*'):
            if path.is_file():
                self.assertNotIn(self.fx.secret_value.encode(), path.read_bytes(), str(path))

    def test_credential_profile_blocks_direct_network_and_vault_escape(self):
        # Reuse the v1.4.1 raw-syscall attack suite inside the actual auth profile.
        probe = (HERE / 'aegis_egress_probe.py').read_text()
        probe = probe.replace('sock = socket.socket(fileno=fd)',
            'sys.path.insert(0, "/app")\n    from aegis_http_gateway import PinnedConnection\n'
            '    conn = PinnedConnection(req["hostname"], req["port"], req["address"], "https", 2, fd)\n'
            '    conn.ca_pem = req["ca_pem"]\n    conn.connect()\n    sock = conn.sock')
        probe = probe.replace("checks = {'authorized_tcp_exchange': authorized}",
            "checks = {'authorized_tcp_exchange': authorized, "
            f"'token_received': req['bearer_token'] == {self.fx.secret_value!r}, "
            f"'vault_unreachable': not Path({str(self.fx.credential_fx.secret)!r}).exists()}}")
        # Test kernel connect denial directly, beyond SSLSocket's Python checks.
        probe = probe.replace("if req.get('mode') == 'hang':",
                              "sock = socket.socket(fileno=sock.detach())\n    if req.get('mode') == 'hang':")
        with self.direct_sandbox(probe):
            result = self.fx.transport_fx.fetch()
        self.assertTrue(all(result['checks'].values()), result)
        self.assertGreaterEqual(len(result['checks']), 25)
        print('AUTH KERNEL EGRESS EVIDENCE: ' + json.dumps(result['checks'], sort_keys=True))

    def test_auth_setup_failures_never_send_credentials(self):
        for step in ('_mount', '_drop_capabilities', '_install_default_deny_seccomp'):
            with self.subTest(step=step):
                setup = ('def fail(*a, **k):\n raise s.SandboxFailure("injected failure")\n'
                         f's.{step} = fail\n')
                with self.direct_sandbox(setup=setup), self.assertRaises(TransportError):
                    self.fx.transport_fx.fetch()
                self.assertIsNone(self.fx.transport_fx.server.auth_seen)
        with self.direct_sandbox(remove_net=True), self.assertRaises(TransportError):
            self.fx.transport_fx.fetch()
        self.assertIsNone(self.fx.transport_fx.server.auth_seen)

    def test_wrong_preconnected_peer_is_rejected_before_tls(self):
        req = dict(self.fx.transport_fx.req, mode='fetch', bearer_token=self.fx.secret_value)
        req['ca_pem'] = transport.tls_roots(req.pop('ca_bundle'))
        req['port'] = 1 if req['port'] != 1 else 2
        with socket.create_connection(self.fx.transport_fx.server.server_address) as sock:
            with self.assertRaises(TransportError):
                transport.confined_exchange(sock, req, 3, 'auth-http')
        self.assertIsNone(self.fx.transport_fx.server.auth_seen)

    def test_live_controls_kill_uncooperative_credential_worker(self):
        for control in ('revoke', 'expire', 'stop', 'route', 'ca'):
            with self.subTest(control=control):
                if control != 'revoke':
                    # Each control needs a fresh signed engagement and ledger.
                    self.fx.doCleanups()
                    self.setUp()
                def change():
                    if control == 'revoke':
                        self.fx.broker.revoke_session(self.fx.token)
                    elif control == 'expire':
                        with self.fx.broker._database() as con:
                            con.execute('UPDATE credential_sessions SET expires_epoch=0')
                            con.commit()
                    elif control == 'stop':
                        operator_stop(self.fx.credential_fx.state,
                                      self.fx.credential_fx.fx.manifest['engagement']['id'])
                    elif control == 'route':
                        fx = self.fx.credential_fx.fx
                        fx.trust['allowed_http_path_prefixes'] = {}
                        fx.save()
                    else:
                        self.fx.transport_fx.pem.write_text('invalid rotated CA')
                with self.held_endpoint(), self.hostile_broker(self.hostile_payload('while True: time.sleep(.1)')):
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(self.request, 10)
                        self.assertTrue(self.seen.wait(4), 'hostile worker never reached TLS endpoint')
                        start = time.monotonic()
                        change()
                        with self.assertRaises(ExecutionDenied):
                            future.result(timeout=3)
                        self.assertTrue(self.closed.wait(2), 'credential stream survived cancellation')
                        self.assertLess(time.monotonic() - start, 3)
                self.assert_no_secret_artifacts()

    def test_deadline_kills_uncooperative_worker(self):
        with self.held_endpoint(), self.hostile_broker(self.hostile_payload('while True: time.sleep(.1)')):
            start = time.monotonic()
            with self.assertRaises(ExecutionDenied):
                self.request(2)
            self.assertTrue(self.seen.is_set())
            self.assertTrue(self.closed.wait(2))
            self.assertLess(time.monotonic() - start, 4)

    def test_stdout_and_stderr_floods_are_bounded_and_redacted(self):
        for fd in (1, 2):
            with self.subTest(fd=fd):
                self.seen.clear()
                self.closed.clear()
                attack = f'while True: os.write({fd}, req["bearer_token"].encode() * 400)'
                with self.held_endpoint(), self.hostile_broker(self.hostile_payload(attack)):
                    with self.assertRaises(ExecutionDenied) as raised:
                        self.request()
                    self.assertNotIn(self.fx.secret_value, str(raised.exception))
                    self.assertTrue(self.seen.is_set())
                    self.assertTrue(self.closed.wait(2))
                self.assert_no_secret_artifacts()

    def test_parent_death_closes_credential_stream(self):
        launcher = self.broker_launcher(self.hostile_payload('while True: time.sleep(.1)'))
        fx = self.fx.credential_fx
        program = self.root / 'supervisor.py'
        program.write_text(
            f'import sys\nsys.path.insert(0, {str(HERE)!r})\n'
            'import subprocess\nfrom aegis_credentials import AegisCredentialAuthority\n'
            'original = subprocess.Popen\ndef spawn(cmd, *a, **k):\n cmd = list(cmd)\n'
            f' cmd[cmd.index({str(HERE / "aegis_http_broker.py")!r})] = {str(launcher)!r}\n'
            ' return original(cmd, *a, **k)\nsubprocess.Popen = spawn\n'
            f'b = AegisCredentialAuthority({str(fx.fx.manifest_path)!r}, {str(fx.fx.sig_path)!r}, '
            f'{str(fx.fx.trust_path)!r}, {str(fx.state)!r}, {str(fx.credential_policy)!r})\n'
            'b._resolve = lambda *a, **k: ["127.0.0.1"]\n'
            f'b.authenticated_request({self.fx.token!r}, {self.fx.origin + "/secure/status"!r}, budget_seconds=10)\n')
        with self.held_endpoint():
            parent = subprocess.Popen([sys.executable, str(program)], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, start_new_session=True)
            try:
                self.assertTrue(self.seen.wait(4), 'child never reached credentialed TLS exchange')
                parent.kill()  # Kill ONLY the supervisor, not its broker process group.
                parent.communicate(timeout=3)
                self.assertTrue(self.closed.wait(3), 'credential stream survived supervisor death')
            finally:
                if parent.poll() is None:
                    os.killpg(parent.pid, signal.SIGKILL)
                parent.communicate(timeout=3)

    def test_forged_secret_output_and_invalid_metadata_are_rejected(self):
        for field in ('secret', 'body_bytes'):
            with self.subTest(field=field):
                self.closed.clear()
                result = {'status': 'AUTH_METADATA_ONLY', 'http_status': 200,
                          'body_bytes': 0, 'redirect_not_followed': False}
                value = 'req["bearer_token"]' if field == 'secret' else '999999999999999999999'
                attack = f'result = {result!r}\nresult[{field!r}] = {value}\nprint(json.dumps(result))'
                with self.held_endpoint(), self.hostile_broker(self.hostile_payload(attack)):
                    with self.assertRaisesRegex(ExecutionDenied, 'invalid authenticated transport result'):
                        self.request()
                    self.assertTrue(self.closed.wait(2))
                self.assert_no_secret_artifacts()
