"""Actual kernel enforcement tests; not mocks of policy decisions."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aegis_sandbox_check import run_check
from aegis_supervisor import AegisSupervisor, ExecutionDenied

HERE = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() != 0,
                     'requires non-root Linux with user/mount/network/PID namespaces')
class LinuxIsolationIntegrationTests(unittest.TestCase):
    def test_kernel_enforces_sandbox_prohibitions(self):
        checks = run_check()
        self.assertEqual(checks['status'], 'KERNEL_ISOLATION_VERIFIED_IN_THIS_ENVIRONMENT')
        self.assertGreaterEqual(len(checks['checks']), 13)
        self.assertTrue(checks['checks']['unlisted_getppid_denied'])
        self.assertTrue(checks['checks']['other_ioctl_denied'])
        self.assertTrue(all(checks['checks'].values()))

    def test_direct_launcher_outside_namespaces_fails_closed(self):
        with tempfile.TemporaryDirectory() as base:
            p = Path(base)
            (p / 'repo').mkdir()
            (p / 'jail').mkdir(mode=0o700)
            fd = os.open(p / 'repo', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                cmd = [sys.executable, '-I', '-S', str(HERE / 'aegis_sandbox.py'),
                       '--repo-fd', str(fd), '--jail', str(p / 'jail'),
                       '--mode', 'probe', '--host-uid', str(os.geteuid()),
                       '--parent-namespaces', ','.join('0' for _ in range(4))]
                res = subprocess.run(cmd, pass_fds=(fd,), capture_output=True, text=True)
                self.assertEqual(res.returncode, 76)
                self.assertIn('SANDBOX_DENIED', res.stderr)
                self.assertEqual(list((p / 'jail').iterdir()), [])
            finally:
                os.close(fd)

    def test_operator_diagnostic_fails_as_root_or_else_reports_enforced(self):
        res = subprocess.run([sys.executable, str(HERE / 'aegis_sandbox_check.py')],
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(json.loads(res.stdout)['all_passed'])


class EnforcedWorkerIntegrationTests(unittest.TestCase):
    """New integration cases using v1.2's signed-scope fixture setup."""
    def setUp(self):
        # Reuse the production-shape signed manifest and operator trust fixture.
        from test_runtime import AegisRuntimeTests
        self.fixture = AegisRuntimeTests('test_real_readonly_review_and_canonical_artifact')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fx = self.fixture.fx
        self.state = self.fixture.state

    def supervisor(self):
        return self.fixture.supervisor()

    def test_fresh_exec_worker_produces_nonempty_json_on_stdio(self):
        """Catch CPython startup syscalls denied after seccomp, before execv.

        This must exercise a fresh /usr/bin/python3 process in the real kernel
        namespace, not a mock or an already-initialized interpreter.
        """
        from aegis_supervisor import open_directory_nofollow
        sup = self.supervisor()
        jail = Path(tempfile.mkdtemp(prefix='sandbox-fresh-exec-', dir=self.state))
        try:
            with open_directory_nofollow(self.fx.repo) as repo_fd:
                res = subprocess.run(
                    sup._worker_command(repo_fd, jail),
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, cwd='/',
                    env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                    pass_fds=(repo_fd,), timeout=15,
                )
            self.assertEqual(res.returncode, 0, res.stderr.decode(errors='replace'))
            self.assertTrue(res.stdout.strip(),
                            'fresh worker returned rc=0 but empty stdout; check CPython dup syscalls')
            result = json.loads(res.stdout)
            self.assertEqual(result['status'], 'STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES')
        finally:
            jail.rmdir()

    def test_real_worker_result_states_os_isolation(self):
        result = self.supervisor().scan(self.fx.repo, 5)
        self.assertEqual(result['isolation'], 'LINUX_ROOTLESS_NAMESPACES_READONLY_ROOT_SECCOMP_DEFAULT_DENY')
        self.assertEqual(result['unverified_leads'], 1)

    def test_no_fallback_if_sandbox_command_fails(self):
        sup = self.supervisor()
        with patch.object(sup, '_worker_command', return_value=['/usr/bin/false']):
            with self.assertRaisesRegex(ExecutionDenied, 'isolated worker failed'):
                sup.scan(self.fx.repo, 5)
        self.assertTrue(sup.verify_audit_chain())
        info, _ = sup._guard()
        self.assertEqual(sup.usage(info['engagement_id'])['reserved_seconds'], 5)
        self.assertEqual(list(self.fx.report_root.rglob('source-review.json')), [])
        self.assertFalse(list(self.state.glob('sandbox-*')))

    def test_worker_command_exactly_requires_namespace_flags(self):
        cmd = self.supervisor()._worker_command(4, Path('/tmp/unused'))
        self.assertEqual(cmd[0], '/usr/bin/unshare')
        for flag in ('--user', '--map-root-user', '--mount', '--net', '--pid',
                     '--fork', '--kill-child'):
            self.assertIn(flag, cmd)
        self.assertIn('--repo-fd', cmd)
        self.assertIn('--parent-namespaces', cmd)
        self.assertNotIn('sh', cmd)
        self.assertNotIn('bash', cmd)


if __name__ == '__main__':
    unittest.main()
