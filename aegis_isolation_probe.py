#!/usr/bin/env python3
"""Operator-only sandbox diagnostic; never invoked by the AEGIS supervisor."""
import ctypes
import errno
import json
import os
from pathlib import Path
import socket


def blocked(operation):
    try:
        operation()
    except (OSError, PermissionError) as exc:
        return exc.errno in (errno.EPERM, errno.EACCES, errno.EROFS, errno.ENOENT)
    return False


def capabilities_cleared():
    libc = ctypes.CDLL(None, use_errno=True)
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                    ('inheritable', ctypes.c_uint32)]
    header = Header(0x20080522, 0)
    data = (Data * 2)()
    rc = libc.capget(ctypes.byref(header), data)
    return rc == 0 and all(
        data[i].effective == data[i].permitted == data[i].inheritable == 0
        for i in (0, 1))


def fork_denied():
    try:
        pid = os.fork()
    except OSError as exc:
        return exc.errno in (errno.EPERM, errno.EACCES)
    if pid == 0:
        os._exit(77)
    os.waitpid(pid, 0)
    return False


def main():
    with open('/repo/probe.txt') as f:
        value = f.read().strip()
    checks = {
        'repo_readable': value == 'sandbox-fixture',
        'repo_write_denied': blocked(lambda: Path('/repo/created.txt').write_text('BYPASS')),
        'root_write_denied': blocked(lambda: Path('/escape.txt').write_text('BYPASS')),
        'host_etc_hidden': not Path('/etc/passwd').exists(),
        'proc_hidden': not Path('/proc/self/environ').exists(),
        'socket_syscall_denied': blocked(lambda: socket.socket()),
        'no_new_privs_set': ctypes.CDLL(None).prctl(39, 0, 0, 0, 0) == 1,
        'seccomp_active': ctypes.CDLL(None).prctl(21, 0, 0, 0, 0) == 2,
        'capabilities_cleared': capabilities_cleared(),
        'fork_denied': fork_denied(),
        'app_write_denied': blocked(lambda: Path('/app/worker.py').write_text('BYPASS')),
    }
    print(json.dumps({'checks': checks, 'all_passed': all(checks.values())}))
    return 0 if all(checks.values()) else 5

if __name__ == '__main__':
    raise SystemExit(main())
