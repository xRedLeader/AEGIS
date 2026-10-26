"""Real kernel acceptance tests, distinct from policy unit tests."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import aegis_http_broker as broker
from aegis_http_gateway import TransportError

HERE = Path(__file__).resolve().parents[1]


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.seen.set()
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'OK')

    def finish(self):
        try:
            super().finish()
        finally:
            self.server.closed.set()


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() != 0,
                     'NOT EXECUTED: requires non-root Linux namespaces and seccomp')
class KernelEgressTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.seen = threading.Event()
        self.server.closed = threading.Event()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def request(self):
        return {'mode': 'fetch', 'scheme': 'http', 'hostname': '127.0.0.1',
                'port': self.server.server_port, 'address': '127.0.0.1',
                'method': 'GET', 'target': '/allowed', 'body_limit': 4096, 'timeout': 5}

    def probe(self, mode='probe', timeout=5):
        with socket.create_connection(self.server.server_address, timeout=2) as sock:
            return broker.confined_exchange(sock, {'mode': mode}, timeout, 'http-probe')

    def test_direct_socket_bypasses_are_denied_by_real_kernel(self):
        result = self.probe()
        self.assertEqual(result['status'], 'PROBED')
        self.assertGreaterEqual(len(result['checks']), 20)
        self.assertTrue(all(result['checks'].values()), result)
        print('KERNEL EGRESS EVIDENCE: ' + json.dumps(result['checks'], sort_keys=True))

    def test_authorized_tcp_and_gateway_still_work(self):
        result = broker.fetch(self.request())
        self.assertEqual(result['http_status'], 200)
        self.assertEqual(result['body_bytes'], 2)

    def test_pinned_address_does_not_reresolve_hostname(self):
        request = self.request()
        request['hostname'] = 'unresolvable-after-pinning.example.invalid'
        self.assertEqual(broker.fetch(request)['http_status'], 200)

    def test_authorized_ipv6(self):
        class IPv6Server(ThreadingHTTPServer):
            address_family = socket.AF_INET6
        server = IPv6Server(('::1', 0), Handler)
        server.seen, server.closed = threading.Event(), threading.Event()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        request = self.request()
        request.update(hostname='::1', address='::1', port=server.server_port)
        self.assertEqual(broker.fetch(request)['http_status'], 200)

    def test_unix_socket_cannot_be_granted_as_tcp(self):
        left, right = socket.socketpair()
        with left, right, self.assertRaises(TransportError):
            broker.confined_exchange(left, self.request(), 2)
        self.assertFalse(self.server.seen.is_set())

    def test_unconnected_socket_fails_closed(self):
        with socket.socket() as sock, self.assertRaises(TransportError):
            broker.confined_exchange(sock, self.request(), 2)
        self.assertFalse(self.server.seen.is_set())

    def test_missing_namespace_executable_fails_closed(self):
        with patch.object(broker, 'sandbox_command', return_value=['/aegis-missing-unshare']):
            with self.assertRaises(OSError):
                self.probe()
        self.assertFalse(self.server.seen.is_set())

    def test_unchanged_network_namespace_fails_closed(self):
        original = broker.sandbox_command
        def without_net(*args):
            return [arg for arg in original(*args) if arg != '--net']
        with patch.object(broker, 'sandbox_command', side_effect=without_net):
            with self.assertRaises(TransportError):
                self.probe()
        self.assertFalse(self.server.seen.is_set())

    def test_each_mount_failure_and_restart_fail_closed(self):
        original = broker.sandbox_command
        with tempfile.TemporaryDirectory() as tmp:
            launcher = Path(tmp) / 'fault.py'
            for fail_step in range(1, 7):
                with self.subTest(mount_step=fail_step):
                    launcher.write_text(
                        f'import sys\nsys.path.insert(0, {str(HERE)!r})\n'
                        'import aegis_sandbox as s\noriginal = s._mount\ncount = 0\n'
                        'def fail(*a, **k):\n global count\n count += 1\n'
                        f' if count == {fail_step}: raise s.SandboxFailure("injected mount failure")\n'
                        ' return original(*a, **k)\ns._mount = fail\nraise SystemExit(s.main())\n')
                    def faulty(*args):
                        cmd = original(*args)
                        cmd[cmd.index(str(HERE / 'aegis_sandbox.py'))] = str(launcher)
                        return cmd
                    self.server.seen.clear()
                    with patch.object(broker, 'sandbox_command', side_effect=faulty):
                        with self.assertRaises(TransportError):
                            self.probe()
                    self.assertFalse(self.server.seen.is_set())
                    self.assertTrue(all(self.probe()['checks'].values()))

    def test_capability_and_seccomp_setup_failures(self):
        original = broker.sandbox_command
        with tempfile.TemporaryDirectory() as tmp:
            launcher = Path(tmp) / 'fault.py'
            for function in ('_drop_capabilities', '_install_default_deny_seccomp'):
                with self.subTest(function=function):
                    launcher.write_text(
                        f'import sys\nsys.path.insert(0, {str(HERE)!r})\n'
                        'import aegis_sandbox as s\ndef fail(*a, **k):\n'
                        ' raise s.SandboxFailure("injected security setup failure")\n'
                        f's.{function} = fail\nraise SystemExit(s.main())\n')
                    def faulty(*args):
                        cmd = original(*args)
                        cmd[cmd.index(str(HERE / 'aegis_sandbox.py'))] = str(launcher)
                        return cmd
                    with patch.object(broker, 'sandbox_command', side_effect=faulty):
                        with self.assertRaises(TransportError):
                            self.probe()
                    self.assertFalse(self.server.seen.is_set())

    def test_interrupted_setup_leaves_no_network_path_on_restart(self):
        original = broker.sandbox_command
        with tempfile.TemporaryDirectory() as tmp:
            launcher = Path(tmp) / 'interrupted.py'
            reached = Path(tmp) / 'mounted'
            launcher.write_text(
                f'import sys, time\nsys.path.insert(0, {str(HERE)!r})\n'
                'import aegis_sandbox as s\noriginal = s._mount\ncount = 0\n'
                'def stall(*a, **k):\n global count\n count += 1\n original(*a, **k)\n'
                f' if count == 2:\n  open({str(reached)!r}, "w").close()\n  time.sleep(30)\n'
                's._mount = stall\nraise SystemExit(s.main())\n')
            def interrupted(*args):
                cmd = original(*args)
                cmd[cmd.index(str(HERE / 'aegis_sandbox.py'))] = str(launcher)
                return cmd
            with patch.object(broker, 'sandbox_command', side_effect=interrupted):
                with self.assertRaisesRegex(TransportError, 'deadline'):
                    self.probe(timeout=0.4)
            self.assertTrue(reached.exists(), 'test did not reach the partial-mount stage')
            self.assertFalse(self.server.seen.is_set())
            self.assertTrue(all(self.probe()['checks'].values()))

    def test_guardian_deadline_kills_uncooperative_worker(self):
        began = time.monotonic()
        with self.assertRaisesRegex(TransportError, 'deadline'):
            self.probe('hang', 0.4)
        self.assertTrue(self.server.seen.is_set(), 'test did not reach the uncooperative worker')
        self.assertLess(time.monotonic() - began, 2)
        self.assertTrue(self.server.closed.wait(2))

    def test_excessive_worker_output_is_bounded(self):
        with self.assertRaisesRegex(TransportError, 'output limit'):
            self.probe('flood')
        self.assertTrue(self.server.closed.wait(2))

    def test_concurrent_workers_do_not_inherit_each_others_sockets(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.probe(), range(2)))
        self.assertTrue(all(all(r['checks'].values()) for r in results))

    def test_supervisor_crash_closes_connection_without_watchdog_help(self):
        # Kill only the parent, not its process group: this exercises the
        # kernel parent-death chain, not ordinary supervisor cleanup.
        request = self.request()
        request['target'] = '/allowed'
        script = (
            'import os, subprocess, sys, time, json\n'
            f'p = subprocess.Popen([sys.executable, "-I", "-S", {str(HERE / "aegis_http_broker.py")!r}, str(os.getpid())], '
            'stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n'
            f'p.stdin.write(json.dumps({request!r}).encode()); p.stdin.close()\n'
            'print(p.pid, flush=True)\ntime.sleep(30)\n')
        # A slow, incomplete response keeps both the worker and TCP stream live.
        def stall(handler):
            handler.server.seen.set()
            handler.rfile.read(1)
        with patch.object(Handler, 'do_GET', stall):
            parent = subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                self.assertTrue(parent.stdout.readline().strip().isdigit())
                self.assertTrue(self.server.seen.wait(3))
                parent.kill()
                parent.communicate(timeout=3)
                self.assertTrue(self.server.closed.wait(3), 'orphaned TCP capability survived parent death')
            finally:
                try:
                    os.killpg(parent.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                parent.communicate(timeout=3)


class BrokerInputTests(unittest.TestCase):
    def test_invalid_budget_and_target_do_not_connect(self):
        with patch.object(socket.socket, 'connect') as connect:
            for address, port, timeout in [('not-an-ip', 80, 1), ('127.0.0.1', 0, 1),
                                          ('127.0.0.1', 80, 0), ('127.0.0.1', 80, float('nan'))]:
                with self.subTest(address=address, port=port, timeout=timeout):
                    with self.assertRaises((ValueError, TransportError)):
                        broker.fetch({'address': address, 'port': port, 'timeout': timeout})
            connect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
