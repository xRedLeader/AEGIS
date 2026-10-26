#!/usr/bin/env python3
"""Offline OS-enforcement probe. An OPERATOR-only diagnostic, not an agent tool.

Launches the fixed harmless diagnostic in the same rootless namespace layout as
AEGIS's scan worker. Requires Linux + unprivileged namespace/mount support and
libseccomp; never accesses an external target or sends network traffic.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def run_check() -> dict:
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise RuntimeError('Linux non-root identity required')
    with tempfile.TemporaryDirectory(prefix='aegis-v13-check-') as tmp:
        base = Path(tmp)
        repo = base / 'authorized-repo'
        jail = base / 'empty-jail'
        repo.mkdir(mode=0o700)
        jail.mkdir(mode=0o700)
        (repo / 'probe.txt').write_text('sandbox-fixture')
        fd = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            baseline = ','.join(str(os.stat('/proc/self/ns/' + name).st_ino)
                                for name in ('user', 'mnt', 'net', 'pid'))
            command = [
                '/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--net',
                '--pid', '--fork', '--kill-child', '--propagation', 'private', '--',
                '/usr/bin/python3', '-I', '-S', str(HERE / 'aegis_sandbox.py'),
                '--repo-fd', str(fd), '--jail', str(jail), '--mode', 'probe',
                '--host-uid', str(os.geteuid()), '--parent-namespaces', baseline,
            ]
            result = subprocess.run(command, pass_fds=(fd,), cwd='/',
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    timeout=12, env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE':'1'})
        finally:
            os.close(fd)
        if result.returncode != 0:
            raise RuntimeError('kernel sandbox probe failed; no unconfined fallback: '
                               + result.stderr.decode(errors='replace')[:300])
        report = json.loads(result.stdout)
        if not report.get('all_passed') or not report.get('checks') or not all(report['checks'].values()):
            raise RuntimeError('sandbox did not enforce all required kernel restrictions')
        if (repo / 'created.txt').exists() or (base / 'escape.txt').exists():
            raise RuntimeError('sandbox altered an external file')
        if any(jail.iterdir()):
            raise RuntimeError('namespace mounts leaked into host')
        report['status'] = 'KERNEL_ISOLATION_VERIFIED_IN_THIS_ENVIRONMENT'
        return report


if __name__ == '__main__':
    try:
        print(json.dumps(run_check(), indent=2))
    except (RuntimeError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
        print('DENIED: '+str(exc), file=sys.stderr)
        raise SystemExit(2)
