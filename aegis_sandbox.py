#!/usr/bin/env python3
"""AEGIS v1.3: *trusted* Linux namespace launcher for the fixed static worker.

Not an agent-facing general command runner. The supervisor launches this through
unshare(1) under a non-root service identity, inside new user+mount+net+PID
namespaces. Source is bind-mounted read-only at /repo; OS runtime and one fixed
trusted worker script are also read-only; no other host paths are exposed.
The launcher drops capabilities, installs syscall filters, then execs the worker.

This is a Linux-only backend. It deliberately fails if any containment step
cannot be completed; there is no unsandboxed fallback. The operator must still
prevent the model from invoking an unrestricted shell outside the supervisor.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import os
from pathlib import Path
import stat
import sys

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
PR_SET_NO_NEW_PRIVS = 38
PR_CAPBSET_DROP = 24
PR_SET_SECUREBITS = 28
SECBIT_NOROOT = 1
SECBIT_NOROOT_LOCKED = 2
SECBIT_NO_SETUID_FIXUP = 4
SECBIT_NO_SETUID_FIXUP_LOCKED = 8
CAP_LAST_LIMIT = 64
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO_EPERM = 0x00050000 | errno.EPERM

# These are the only library/script sources the confined worker can see.
SYSTEM_PYTHON = Path('/usr/bin/python3')
SYSTEM_ROOT = Path('/usr')
WORKER_HOST = Path(__file__).resolve().with_name('aegis_worker.py')
PROBE_HOST = Path(__file__).resolve().with_name('aegis_isolation_probe.py')

class SandboxFailure(RuntimeError):
    pass


def _libc():
    lib = ctypes.CDLL(None, use_errno=True)
    lib.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_ulong, ctypes.c_char_p]
    lib.mount.restype = ctypes.c_int
    lib.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
    lib.prctl.restype = ctypes.c_int
    return lib


def _mount(source: str | None, target: Path, fstype: str | None, flags: int = 0,
           data: str | None = None):
    lib = _libc()
    fmt = lambda s: None if s is None else os.fsencode(str(s))
    if lib.mount(fmt(source), fmt(target), fmt(fstype), flags, fmt(data)) != 0:
        code = ctypes.get_errno()
        raise SandboxFailure(f'namespace mount operation failed: {os.strerror(code)}')


def _bind_readonly(source: Path, target: Path, is_file: bool = False):
    if is_file:
        target.touch(exist_ok=False)
    else:
        target.mkdir(mode=0o755)
    _mount(str(source), target, None, MS_BIND)
    # Remount the bind itself RO; do NOT recursively import nested host mounts.
    _mount(None, target, None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)


def _drop_capabilities(lib):
    # Ensure root-in-userns cannot regain privilege across exec.
    bits = (SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
            SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED)
    if lib.prctl(PR_SET_SECUREBITS, bits, 0, 0, 0) != 0:
        raise SandboxFailure('cannot lock root capability semantics')
    for cap in range(CAP_LAST_LIMIT):
        if lib.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0:
            e = ctypes.get_errno()
            if e != errno.EINVAL:  # capability index higher than kernel's last
                raise SandboxFailure('cannot drop bounding capability')

    class CapHeader(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]

    class CapData(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32),
                    ('permitted', ctypes.c_uint32),
                    ('inheritable', ctypes.c_uint32)]

    capset = lib.capset
    capset.argtypes = [ctypes.POINTER(CapHeader), ctypes.POINTER(CapData)]
    capset.restype = ctypes.c_int
    hdr = CapHeader(0x20080522, 0)
    data = (CapData * 2)()
    if capset(ctypes.byref(hdr), data) != 0:
        raise SandboxFailure('cannot clear effective/permitted capabilities')


def _deny_sensitive_syscalls(sec):
    """Install kernel-level seccomp filter, denying network and escape syscalls.

    Needed libseccomp is a hard requirement, not optional; fail closed if absent.
    """
    sec.seccomp_init.argtypes = [ctypes.c_uint32]
    sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    sec.seccomp_syscall_resolve_name.restype = ctypes.c_int
    sec.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    sec.seccomp_rule_add.restype = ctypes.c_int
    sec.seccomp_load.argtypes = [ctypes.c_void_p]
    sec.seccomp_load.restype = ctypes.c_int
    sec.seccomp_release.argtypes = [ctypes.c_void_p]
    sec.seccomp_release.restype = None
    ctx = sec.seccomp_init(SCMP_ACT_ALLOW)
    if not ctx:
        raise SandboxFailure('cannot initialize syscall filter')
    try:
        forbidden = (
            'socket', 'socketpair', 'connect', 'bind', 'listen', 'accept',
            'accept4', 'sendto', 'sendmsg', 'sendmmsg', 'recvfrom', 'recvmsg',
            'recvmmsg', 'getsockopt', 'setsockopt', 'shutdown',
            'mount', 'umount2', 'pivot_root', 'unshare', 'setns', 'chroot',
            'ptrace', 'bpf', 'userfaultfd', 'keyctl', 'open_by_handle_at',
            'fsopen', 'fsconfig', 'fsmount', 'move_mount', 'open_tree',
            'mount_setattr', 'clone3', 'clone', 'fork', 'vfork',
            'io_uring_setup', 'io_uring_enter', 'io_uring_register',
            'perf_event_open', 'process_vm_readv', 'process_vm_writev',
            'pidfd_getfd',
        )
        for name in forbidden:
            number = sec.seccomp_syscall_resolve_name(name.encode())
            if number < 0:
                continue  # absent from this architecture; not a viable syscall
            if sec.seccomp_rule_add(ctx, SCMP_ACT_ERRNO_EPERM, number, 0) != 0:
                raise SandboxFailure(f'cannot deny syscall {name}')
        if sec.seccomp_load(ctx) != 0:
            raise SandboxFailure('cannot load syscall filter')
    finally:
        sec.seccomp_release(ctx)


def _setup(args):
    # Positive check that the operator-launched subprocess changed ALL four
    # namespaces, not just the user namespace. Deny if procfs denies evidence.
    baseline = args.parent_namespaces.split(',')
    if len(baseline) != 4 or not all(v.isdigit() for v in baseline):
        raise SandboxFailure('operator namespace baseline missing')
    for ns, host_inode in zip(('user', 'mnt', 'net', 'pid'), baseline):
        if os.stat('/proc/self/ns/' + ns).st_ino == int(host_inode):
            raise SandboxFailure('required namespace unchanged: ' + ns)
    if os.geteuid() != 0 or args.host_uid <= 0:
        raise SandboxFailure('expected root in an unprivileged user namespace')
    mappings = Path('/proc/self/uid_map').read_text().splitlines()
    fields = [line.split() for line in mappings]
    if len(fields) != 1 or fields[0][:2] != ['0', str(args.host_uid)] or fields[0][2] != '1':
        raise SandboxFailure('unexpected user namespace mapping')
    jail = Path(args.jail)
    repo_fd = args.repo_fd
    if repo_fd < 3 or not stat.S_ISDIR(os.fstat(repo_fd).st_mode):
        raise SandboxFailure('authorized repository descriptor invalid')
    repo = f'/proc/self/fd/{repo_fd}'
    for p in (jail, WORKER_HOST):
        if not p.is_absolute() or p.is_symlink():
            raise SandboxFailure('namespace input path invalid')
    if not jail.is_dir() or jail.stat().st_mode & 0o077:
        raise SandboxFailure('jail must be a private directory')
    try:
        sec = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    except OSError as exc:
        raise SandboxFailure('libseccomp unavailable') from exc
    # Mount propagation MUST be private before any subtree mounts.
    _mount(None, Path('/'), None, MS_REC | MS_PRIVATE)
    _mount('tmpfs', jail, 'tmpfs', MS_NOSUID | MS_NODEV | MS_NOEXEC, 'size=8m,mode=0700')
    (jail / 'usr').mkdir(mode=0o755)
    _mount(str(SYSTEM_ROOT), jail / 'usr', None, MS_BIND)
    _mount(None, jail / 'usr', None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)
    (jail / 'lib').symlink_to('usr/lib')
    (jail / 'lib64').symlink_to('usr/lib64')
    # /usr may be root-owned but remains readable under the mapped user.
    (jail / 'repo').mkdir(mode=0o755)
    # Bind the path resolved from a pinned directory fd, then verify the mount
    # refers to the very same inode before running any assessment worker.
    source = os.readlink(repo)
    if not source.startswith('/') or source.endswith(' (deleted)'):
        raise SandboxFailure('repository descriptor has lost its authorized path')
    _mount(source, jail / 'repo', None, MS_BIND)
    expected, actual = os.fstat(repo_fd), os.stat(jail / 'repo')
    if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
        raise SandboxFailure('repository changed during namespace binding')
    _mount(None, jail / 'repo', None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC)
    (jail / 'app').mkdir(mode=0o755)
    _bind_readonly(WORKER_HOST if args.mode == 'scan' else PROBE_HOST,
                   jail / 'app' / 'worker.py', is_file=True)
    os.chroot(jail)
    os.chdir('/')
    # Freeze writable root. All source, runtime, and app mounts are RO.
    os.chmod('/', 0o555)
    lib = _libc()
    if lib.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SandboxFailure('cannot set no_new_privs')
    _drop_capabilities(lib)
    _deny_sensitive_syscalls(sec)
    if args.mode == 'scan':
        argv = [str(SYSTEM_PYTHON), '-I', '-S', '-B', '/app/worker.py',
                '--repo', '/repo', '--max-files', '1000',
                '--max-bytes', str(4 * 1024 * 1024)]
    else:
        argv = [str(SYSTEM_PYTHON), '-I', '-S', '-B', '/app/worker.py']
    # These are constant args; target code is NEVER executed.
    os.execv(str(SYSTEM_PYTHON), argv)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-fd', type=int, required=True)
    ap.add_argument('--jail', required=True)
    ap.add_argument('--mode', choices=('scan', 'probe'), default='scan')
    ap.add_argument('--host-uid', type=int, required=True)
    ap.add_argument('--parent-namespaces', required=True)
    args = ap.parse_args(argv)
    try:
        _setup(args)
    except (SandboxFailure, OSError) as exc:
        print('SANDBOX_DENIED: ' + str(exc), file=sys.stderr)
        return 76
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
