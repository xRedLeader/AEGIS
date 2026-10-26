#!/usr/bin/env python3
"""AEGIS v1.4.1: trusted Linux namespace launcher for fixed assessment workers.

Not an agent-facing general command runner. The supervisor launches this through
unshare(1) under a non-root service identity, inside new user+mount+net+PID
namespaces. Scans receive /repo read-only; HTTP receives one connected TCP fd.
OS runtime and fixed worker code are read-only; no other host paths are exposed.
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
import socket
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
SCMP_ACT_ERRNO_EPERM = 0x00050000 | errno.EPERM

# These are the only library/script sources the confined worker can see.
SYSTEM_PYTHON = Path('/usr/bin/python3')
SYSTEM_ROOT = Path('/usr')
WORKER_HOST = Path(__file__).resolve().with_name('aegis_worker.py')
PROBE_HOST = Path(__file__).resolve().with_name('aegis_isolation_probe.py')
HTTP_HOST = Path(__file__).resolve().with_name('aegis_http_gateway.py')
HTTP_PROBE_HOST = Path(__file__).resolve().with_name('aegis_egress_probe.py')

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
        raise SandboxFailure(f'namespace mount operation failed ({target.name}, flags={flags}): {os.strerror(code)}')


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


# The trusted, fixed worker profile is a *positive* set. Unknown syscalls,
# including syscalls added by future kernels, get EPERM by default. The set is
# intentionally not appropriate for shell commands, exploit tools, or arbitrary
# third-party processes; those require separately reviewed sandbox profiles.
# Some syscalls (including execve and prctl) are required by this launch design
# or the operator-only kernel diagnostic. This is not an all-purpose sandbox.
WORKER_SYSCALL_ALLOWLIST = (
    # Basic Unix file and directory reads. RO mounts prevent mutation.
    'read', 'write', 'readv', 'writev', 'pread64', 'close', 'lseek',
    'fstat', 'newfstatat', 'stat', 'lstat', 'statx', 'getdents64',
    'open', 'openat', 'readlink', 'readlinkat', 'access',
    # CPython 3.10 duplicates the standard FDs during fresh interpreter startup.
    # Later builds may omit these calls; allow them for the supported range.
    'dup', 'dup2', 'dup3',
    'faccessat', 'faccessat2', 'fcntl', 'getcwd',
    # Python ELF loader, allocator and threads' runtime bookkeeping.
    'mmap', 'mprotect', 'munmap', 'mremap', 'madvise', 'brk',
    'arch_prctl', 'set_tid_address', 'set_robust_list', 'rseq', 'futex',
    'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn', 'sigaltstack',
    'rt_sigpending', 'rt_sigsuspend',
    # Monotonic timing, entropy, metadata and harmless scheduling.
    'clock_gettime', 'clock_getres', 'gettimeofday', 'time',
    'nanosleep', 'clock_nanosleep', 'getrandom', 'uname',
    'getpid', 'gettid', 'getuid', 'geteuid', 'getgid', 'getegid',
    'getresuid', 'getresgid', 'getrlimit', 'prlimit64', 'getrusage',
    'sysinfo', 'sched_yield',
    # The launcher's one fixed exec; diagnostic only observes prctl/capget.
    'execve', 'prctl', 'capget',
    # Clean process termination and restart.
    'exit', 'exit_group', 'restart_syscall',
)


def _install_default_deny_seccomp(sec, network_fd=None):
    """Load a libseccomp allowlist (all other syscalls return EPERM).

    The final known executable is invoked by os.execv *after* this filter is
    installed. No rule here can be relaxed by an unprivileged descendant.
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
    ctx = sec.seccomp_init(SCMP_ACT_ERRNO_EPERM)
    if not ctx:
        raise SandboxFailure('cannot initialize default-deny syscall filter')
    try:
        for name in WORKER_SYSCALL_ALLOWLIST:
            number = sec.seccomp_syscall_resolve_name(name.encode('ascii'))
            if number < 0:
                # On this ABI an unavailable syscall cannot be invoked. An
                # available but missing syscall gets EPERM and fails closed.
                continue
            if sec.seccomp_rule_add(ctx, 0x7FFF0000, number, 0) != 0:
                raise SandboxFailure(f'cannot allow required syscall {name}')
        # Python 3.13 opens the script with a file-descriptor ioctl.
        # Allow only FIOCLEX (mark close-on-exec), not arbitrary ioctl codes.
        class ArgCmp(ctypes.Structure):
            _fields_ = [('arg', ctypes.c_uint32), ('op', ctypes.c_uint32),
                        ('datum_a', ctypes.c_uint64), ('datum_b', ctypes.c_uint64)]
        sec.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                               ctypes.c_int, ctypes.c_uint,
                                               ctypes.POINTER(ArgCmp)]
        sec.seccomp_rule_add_array.restype = ctypes.c_int
        ioctl_num = sec.seccomp_syscall_resolve_name(b'ioctl')
        if ioctl_num < 0:
            raise SandboxFailure('ioctl syscall missing on runtime architecture')
        eq = ArgCmp(1, 4, 0x5451, 0)  # SCMP_CMP_EQ, Linux FIOCLEX
        if sec.seccomp_rule_add_array(ctx, 0x7FFF0000, ioctl_num, 1, ctypes.byref(eq)) != 0:
            raise SandboxFailure('cannot add restricted ioctl FIOCLEX rule')
        if network_fd is not None:
            nonblocking = (ArgCmp * 2)(ArgCmp(0, 4, network_fd, 0),
                                       ArgCmp(1, 4, 0x5421, 0))  # FIONBIO
            if sec.seccomp_rule_add_array(ctx, 0x7FFF0000, ioctl_num, 2, nonblocking) != 0:
                raise SandboxFailure('cannot enable socket nonblocking mode')
            # Only the broker's connected TCP capability supports socket I/O.
            # socket/connect/bind/listen/accept/setsockopt/netlink stay denied.
            for name in ('sendto', 'recvfrom', 'getsockname', 'getpeername',
                         'getsockopt', 'shutdown'):
                number = sec.seccomp_syscall_resolve_name(name.encode('ascii'))
                fd_eq = ArgCmp(0, 4, network_fd, 0)
                if number < 0 or sec.seccomp_rule_add_array(
                        ctx, 0x7FFF0000, number, 1, ctypes.byref(fd_eq)) != 0:
                    raise SandboxFailure('cannot restrict socket I/O: ' + name)
            for name in ('poll', 'ppoll', 'select', 'pselect6'):
                number = sec.seccomp_syscall_resolve_name(name.encode('ascii'))
                if number >= 0 and sec.seccomp_rule_add(ctx, 0x7FFF0000, number, 0) != 0:
                    raise SandboxFailure('cannot enable bounded socket polling')
        if sec.seccomp_load(ctx) != 0:
            raise SandboxFailure('cannot load default-deny syscall filter')
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
    network = args.mode in ('http', 'http-probe')
    repo_fd = args.repo_fd
    if network:
        if args.socket_fd is None or args.socket_fd < 3:
            raise SandboxFailure('connected TCP descriptor required')
        sock = socket.socket(fileno=args.socket_fd)
        try:
            if (sock.family not in (socket.AF_INET, socket.AF_INET6) or
                    sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM or
                    sock.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL) != socket.IPPROTO_TCP):
                raise SandboxFailure('only connected IPv4/IPv6 TCP is permitted')
            sock.getpeername()
        finally:
            sock.detach()
    elif repo_fd is None or repo_fd < 3 or not stat.S_ISDIR(os.fstat(repo_fd).st_mode):
        raise SandboxFailure('authorized repository descriptor invalid')
    worker_source = {'scan': WORKER_HOST, 'probe': PROBE_HOST,
                     'http': HTTP_HOST, 'http-probe': HTTP_PROBE_HOST}[args.mode]
    for p in (jail, worker_source):
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
    if not network:
        (jail / 'repo').mkdir(mode=0o755)
        source = os.readlink(f'/proc/self/fd/{repo_fd}')
        if not source.startswith('/') or source.endswith(' (deleted)'):
            raise SandboxFailure('repository descriptor has lost its authorized path')
        _mount(source, jail / 'repo', None, MS_BIND)
        expected, actual = os.fstat(repo_fd), os.stat(jail / 'repo')
        if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
            raise SandboxFailure('repository changed during namespace binding')
        _mount(None, jail / 'repo', None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC)
    (jail / 'app').mkdir(mode=0o755)
    _bind_readonly(worker_source, jail / 'app' / 'worker.py', is_file=True)
    # A directory fd from before chroot would provide an escape via openat.
    keep = {0, 1, 2} | ({args.socket_fd} if network else set())
    for fd in (int(name) for name in os.listdir('/proc/self/fd')):
        if fd not in keep:
            try:
                os.close(fd)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
    if network and not all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in (0, 1, 2)):
        raise SandboxFailure('HTTP standard streams must be pipes, not sockets')
    os.chroot(jail)
    os.chdir('/')
    # Freeze writable root. All source, runtime, and app mounts are RO.
    os.chmod('/', 0o555)
    lib = _libc()
    if lib.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise SandboxFailure('cannot set no_new_privs')
    _drop_capabilities(lib)
    _install_default_deny_seccomp(sec, args.socket_fd if network else None)
    if args.mode == 'scan':
        argv = [str(SYSTEM_PYTHON), '-I', '-S', '-B', '/app/worker.py',
                '--repo', '/repo', '--max-files', '1000',
                '--max-bytes', str(4 * 1024 * 1024)]
    else:
        argv = [str(SYSTEM_PYTHON), '-I', '-S', '-B', '/app/worker.py']
        if network:
            argv += ['--socket-fd', str(args.socket_fd)]
    # These are constant args; target code is NEVER executed.
    os.execv(str(SYSTEM_PYTHON), argv)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-fd', type=int)
    ap.add_argument('--socket-fd', type=int)
    ap.add_argument('--jail', required=True)
    ap.add_argument('--mode', choices=('scan', 'probe', 'http', 'http-probe'), default='scan')
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
