#!/usr/bin/env python3
"""Fixed operator-only adversarial payload; never selected by the supervisor."""
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import sys
import time


def denied(operation):
    try:
        result = operation()
        if hasattr(result, 'close'):
            result.close()
    except OSError as exc:
        return exc.errno == errno.EPERM
    return False


def syscall_denied(name, *args):
    sec = ctypes.CDLL('libseccomp.so.2')
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    number = sec.seccomp_syscall_resolve_name(name.encode())
    if number < 0:
        raise RuntimeError('required probe syscall unavailable: ' + name)
    lib = ctypes.CDLL(None, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    return lib.syscall(number, *args) == -1 and ctypes.get_errno() == errno.EPERM


def main():
    req = json.load(sys.stdin)
    fd = int(sys.argv[2])
    sock = socket.socket(fileno=fd)
    sock.settimeout(2)
    sock.sendall(b'GET /probe HTTP/1.0\r\nHost: localhost\r\n\r\n')
    authorized = sock.recv(256).startswith(b'HTTP/')
    if req.get('mode') == 'hang':
        while True:
            time.sleep(0.1)
    if req.get('mode') == 'flood':
        while True:
            os.write(1, b'X' * 8192)
    checks = {'authorized_tcp_exchange': authorized}
    for label, family, kind in (
            ('ipv4', socket.AF_INET, socket.SOCK_STREAM),
            ('ipv6', socket.AF_INET6, socket.SOCK_STREAM),
            ('udp', socket.AF_INET, socket.SOCK_DGRAM),
            ('unix', socket.AF_UNIX, socket.SOCK_STREAM),
            ('netlink_firewall', socket.AF_NETLINK, socket.SOCK_RAW),
            ('raw', socket.AF_INET, socket.SOCK_RAW)):
        checks[label + '_socket_denied'] = denied(lambda: socket.socket(family, kind))
    checks['unauthorized_ip_denied'] = denied(lambda: sock.connect(('127.0.0.2', 9)))
    checks['unauthorized_port_denied'] = denied(lambda: sock.connect(('127.0.0.1', 9)))
    checks['direct_libc_connect_denied'] = syscall_denied('connect', fd, 0, 0)
    checks['disconnect_af_unspec_denied'] = syscall_denied('connect', fd, ctypes.c_char_p(b'\0' * 16), 16)
    checks['socketpair_denied'] = syscall_denied('socketpair', socket.AF_UNIX, socket.SOCK_STREAM, 0, 0)
    checks['namespace_escape_denied'] = syscall_denied('setns', -1, 0)
    checks['namespace_create_denied'] = syscall_denied('unshare', 0x40000000)
    checks['mount_denied'] = syscall_denied('mount', 0, 0, 0, 0, 0)
    checks['ptrace_denied'] = syscall_denied('ptrace', 0, 0, 0, 0)
    checks['fork_denied'] = syscall_denied('clone', 17, 0, 0, 0, 0)
    checks['socket_option_denied'] = denied(lambda: sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1))
    checks['host_files_hidden'] = not Path('/etc/passwd').exists() and not Path('/proc').exists()
    checks['no_new_privs'] = ctypes.CDLL(None).prctl(39, 0, 0, 0, 0) == 1
    checks['seccomp'] = ctypes.CDLL(None).prctl(21, 0, 0, 0, 0) == 2
    header = (ctypes.c_uint32 * 2)(0x20080522, 0)
    caps = (ctypes.c_uint32 * 6)()
    checks['capabilities_cleared'] = (
        ctypes.CDLL(None).capget(ctypes.byref(header), ctypes.byref(caps)) == 0 and not any(caps))
    extra = []
    for candidate in range(3, 64):
        if candidate != fd:
            try:
                os.fstat(candidate)
                extra.append(candidate)
            except OSError:
                pass
    checks['no_extra_inherited_fds'] = not extra
    print(json.dumps({'status': 'PROBED', 'checks': checks}))
    return 0 if all(checks.values()) else 5


if __name__ == '__main__':
    raise SystemExit(main())
