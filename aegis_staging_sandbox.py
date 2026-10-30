#!/usr/bin/env python3
"""Distinct loopback-only native scanner boundary and trusted framed-pipe relay."""
import argparse
import base64
import ctypes
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import resource
import select
import signal
import socket
import stat
import struct
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aegis_sandbox as kernel
from aegis_http_broker import parent_death_guard
from aegis_staging_protocol import PROFILE, MAX_BODY, MAX_HEADER, read_frame, write_frame

PROXY_PORT = 18464


def launch(binary_fd, config_fd, targets_fd, broker_read_fd, broker_write_fd, jail, seconds):
    baseline = ",".join(str(os.stat("/proc/self/ns/" + name).st_ino) for name in ("user", "mnt", "net", "pid"))
    return ["/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--net", "--pid", "--fork", "--kill-child",
            "--propagation", "private", "--", "/usr/bin/python3", "-I", "-S", str(Path(__file__).resolve()),
            "--binary-fd", str(binary_fd), "--config-fd", str(config_fd), "--targets-fd", str(targets_fd),
            "--broker-read-fd", str(broker_read_fd), "--broker-write-fd", str(broker_write_fd),
            "--jail", str(jail), "--seconds", str(seconds), "--host-uid", str(os.geteuid()), "--parent-namespaces", baseline]


def _seccomp(sec, *, relay=False):
    """Go threads and TCP only. Namespace routing, not flags, confines networking."""
    sec.seccomp_init.argtypes = [ctypes.c_uint32]; sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]; sec.seccomp_syscall_resolve_name.restype = ctypes.c_int
    sec.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    sec.seccomp_load.argtypes = [ctypes.c_void_p]; sec.seccomp_release.argtypes = [ctypes.c_void_p]
    class Compare(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint32), ("op", ctypes.c_uint32), ("a", ctypes.c_uint64), ("b", ctypes.c_uint64)]
    sec.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(Compare)]
    ctx = sec.seccomp_init(kernel.SCMP_ACT_ERRNO_EPERM)
    if not ctx:
        raise kernel.SandboxFailure("staging filter initialization failed")
    def allow(name, checks=()):
        number = sec.seccomp_syscall_resolve_name(name.encode())
        if number < 0:
            return
        if checks:
            values = (Compare * len(checks))(*(Compare(*c) for c in checks))
            code = sec.seccomp_rule_add_array(ctx, 0x7fff0000, number, len(checks), values)
        else:
            code = sec.seccomp_rule_add(ctx, 0x7fff0000, number, 0)
        if code != 0:
            raise kernel.SandboxFailure("staging syscall rule failed")
    try:
        extra = ("poll", "ppoll", "select", "pselect6", "epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait",
                 "epoll_pwait", "epoll_pwait2", "eventfd", "eventfd2", "pipe", "pipe2", "ftruncate", "fsync", "fdatasync",
                 "sched_getaffinity", "getcpu", "tgkill", "tkill", "setitimer", "getitimer", "umask", "mkdir", "mkdirat",
                 "unlink", "unlinkat", "rename", "renameat", "renameat2", "flock", "connect", "getsockname", "getpeername",
                 "setsockopt", "getsockopt", "shutdown", "sendto", "recvfrom", "sendmsg", "recvmsg")
        for name in (*kernel.WORKER_SYSCALL_ALLOWLIST, *extra):
            if name != "mmap" and (not relay or name != "execve"):
                allow(name)
        allow("mmap", ((3, 7, 0x10f, 2),))
        if relay:
            for name in ("accept", "accept4", "wait4", "kill"):
                allow(name)
        else:
            allow("clone", ((0, 7, 0x7e030080, 0x00010000),))
        for operation in (0x5451, 0x5421):
            allow("ioctl", ((1, 4, operation, 0),))
        # SOCK_STREAM with optional CLOEXEC/NONBLOCK flags; no UDP/raw/Unix sockets.
        for family in (socket.AF_INET, socket.AF_INET6):
            allow("socket", ((0, 4, family, 0), (1, 7, 0xF, socket.SOCK_STREAM)))
        if sec.seccomp_load(ctx) != 0:
            raise kernel.SandboxFailure("staging filter load failed")
    finally:
        sec.seccomp_release(ctx)


def parse_proxy_request(raw):
    """Strict one-request framing; caller closes the connection after one reply."""
    if not isinstance(raw, bytes) or not raw.endswith(b"\r\n\r\n") or len(raw) > MAX_HEADER:
        raise ValueError("invalid relay framing")
    lines = raw[:-4].decode("ascii").split("\r\n")
    if len(lines) > 33 or len(lines[0].split(" ")) != 3:
        raise ValueError("invalid relay request line")
    method, url, version = lines[0].split(" ")
    if method not in ("GET", "HEAD") or version not in ("HTTP/1.0", "HTTP/1.1"):
        raise ValueError("relay method or protocol denied")
    parts = urlsplit(url)
    if (parts.scheme != "http" or not parts.netloc or parts.username or parts.password or
            parts.query or parts.fragment or len(url) > 4096 or any(ord(c) <= 32 for c in url)):
        raise ValueError("relay URL denied")
    headers = {}
    for line in lines[1:]:
        if ":" not in line or line.startswith((" ", "\t")):
            raise ValueError("ambiguous relay header")
        name, value = line.split(":", 1)
        if not name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for c in name):
            raise ValueError("invalid relay header name")
        name, value = name.lower(), value.strip(" ")
        if name in headers or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("duplicate or invalid relay header")
        headers[name] = value
    if (headers.get("host") != parts.netloc or any(h in headers for h in ("authorization", "proxy-authorization", "cookie", "transfer-encoding")) or
            headers.get("content-length", "0") != "0" or headers.get("expect") is not None):
        raise ValueError("relay credentials or body denied")
    return {"method": method, "url": url}


def _request(connection):
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        chunk = connection.recv(min(4096, MAX_HEADER + 1 - len(raw)))
        if not chunk:
            if not raw:
                return None  # Nuclei tests proxy reachability with an empty connection.
            raise ValueError("incomplete relay request")
        raw.extend(chunk)
        if len(raw) > MAX_HEADER:
            raise ValueError("relay headers exceed bound")
    end = raw.index(b"\r\n\r\n") + 4
    if end != len(raw) or (select.select([connection], [], [], 0)[0] and connection.recv(1, socket.MSG_PEEK)):
        raise ValueError("pipelined or trailing relay data denied")
    return parse_proxy_request(bytes(raw))


def _reply(connection, result):
    if set(result) != {"kind", "status", "content_type", "body_b64", "body_bytes"} or result["kind"] != "response":
        raise ValueError("invalid trusted relay response")
    if type(result["status"]) is not int or not 100 <= result["status"] <= 599 or 300 <= result["status"] < 400:
        raise ValueError("invalid trusted response status")
    body = base64.b64decode(result["body_b64"], validate=True)
    if type(result["body_bytes"]) is not int or len(body) > MAX_BODY or len(body) != result["body_bytes"]:
        raise ValueError("invalid relay response body")
    content_type = result["content_type"]
    if not isinstance(content_type, str) or len(content_type) > 128 or not content_type.isascii() or any(ord(c) < 32 for c in content_type):
        raise ValueError("invalid relay response type")
    head = (f"HTTP/1.1 {result['status']} AEGIS\r\nContent-Length: {len(body)}\r\n"
            f"Content-Type: {content_type}\r\nConnection: close\r\n\r\n").encode("ascii")
    connection.sendall(head + body)


def _setup(args):
    if not 1 <= args.seconds <= 120 or args.host_uid <= 0 or os.geteuid() != 0:
        raise kernel.SandboxFailure("staging launch scope invalid")
    baseline = args.parent_namespaces.split(",")
    if len(baseline) != 4 or not all(x.isdigit() for x in baseline):
        raise kernel.SandboxFailure("namespace baseline missing")
    for name, old in zip(("user", "mnt", "net", "pid"), baseline):
        if os.stat("/proc/self/ns/" + name).st_ino == int(old):
            raise kernel.SandboxFailure("staging namespace unchanged")
    if Path("/proc/self/uid_map").read_text().split() != ["0", str(args.host_uid), "1"]:
        raise kernel.SandboxFailure("staging UID map invalid")
    fds = (args.binary_fd, args.config_fd, args.targets_fd, args.broker_read_fd, args.broker_write_fd)
    if len(set(fds)) != 5 or any(fd < 3 for fd in fds):
        raise kernel.SandboxFailure("staging capabilities invalid")
    if any(not stat.S_ISREG(os.fstat(fd).st_mode) for fd in fds[:3]) or any(not stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in fds[3:]):
        raise kernel.SandboxFailure("staging capabilities must be regular files and pipes")
    jail = Path(args.jail)
    if not jail.is_absolute() or jail.is_symlink() or not jail.is_dir() or jail.stat().st_mode & 0o077:
        raise kernel.SandboxFailure("staging private jail invalid")
    sec = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        flags = fcntl.ioctl(control.fileno(), 0x8913, struct.pack("16sh", b"lo", 0))
        old = struct.unpack_from("h", flags, 16)[0]
        fcntl.ioctl(control.fileno(), 0x8914, struct.pack("16sh", b"lo", old | 1))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", PROXY_PORT)); listener.listen(1); listener.settimeout(0.1)
    kernel._mount(None, Path("/"), None, kernel.MS_REC | kernel.MS_PRIVATE)
    kernel._mount("tmpfs", jail, "tmpfs", kernel.MS_NOSUID | kernel.MS_NODEV, "size=128m,mode=0700")
    # Anonymous memfds cannot be bind-mounted on supported WSL kernels. Copy only
    # verified sealed material into the private memory root, then freeze it.
    for fd, name, maximum, mode in ((args.binary_fd,"scanner",120*1024**2,0o500),
                                    (args.config_fd,"rules.yaml",16384,0o400),(args.targets_fd,"targets",8192,0o400)):
        needed = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & needed != needed or os.fstat(fd).st_size > maximum:
            raise kernel.SandboxFailure("unsealed or oversized staging material")
        os.lseek(fd, 0, os.SEEK_SET)
        with open(jail/name, "wb") as destination:
            while chunk := os.read(fd, 65536):
                destination.write(chunk)
        (jail/name).chmod(mode)
    (jail/"tmp").mkdir(mode=0o700)
    kernel._mount("tmpfs", jail/"tmp", "tmpfs", kernel.MS_NOSUID | kernel.MS_NODEV | kernel.MS_NOEXEC, "size=8m,mode=0700")
    jail.chmod(0o555)
    kernel._mount(None, jail, None, kernel.MS_REMOUNT | kernel.MS_RDONLY | kernel.MS_NOSUID | kernel.MS_NODEV)
    keep = {0, 1, 2, args.broker_read_fd, args.broker_write_fd, listener.fileno()}
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd not in keep:
            try:
                os.close(fd)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
    os.chroot(jail); os.chdir("/")
    for limit, value in ((resource.RLIMIT_AS, 8*1024**3), (resource.RLIMIT_DATA,512*1024**2),
                         (resource.RLIMIT_STACK,8*1024**2), (resource.RLIMIT_FSIZE, 524288),
                         (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 96), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(limit, (value, value))
    resource.setrlimit(resource.RLIMIT_CPU, (args.seconds, args.seconds+1))
    lib = kernel._libc()
    if lib.prctl(kernel.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise kernel.SandboxFailure("staging privilege lock failed")
    kernel._drop_capabilities(lib)
    entered_read, entered_write = os.pipe()
    relay_pid = os.getpid()
    child = os.fork()
    if child == 0:
        try:
            listener.close(); os.close(args.broker_read_fd); os.close(args.broker_write_fd); os.close(entered_read)
            parent_death_guard(relay_pid)
            _seccomp(sec)
            os.write(entered_write, b"entered"); os.close(entered_write)
            argv = ["/scanner", "-duc", "-ni", "-silent", "-no-color", "-t", "/rules.yaml", "-l", "/targets",
                    "-proxy", f"http://127.0.0.1:{PROXY_PORT}", "-json-export", "/tmp/report.json", "-timeout", "2",
                    "-retries", "0", "-concurrency", "1", "-rate-limit", "2", "-disable-redirects"]
            os.execve("/scanner", argv, {"PATH":"/nonexistent", "HOME":"/tmp", "TMPDIR":"/tmp", "GOMAXPROCS":"2", "GOMEMLIMIT":"256MiB"})
        except BaseException:
            os._exit(77)
    os.close(entered_write)
    _seccomp(sec, relay=True)
    deadline = time.monotonic() + args.seconds
    accepted_connections = 0
    try:
        if not select.select([entered_read], [], [], min(2, args.seconds))[0] or os.read(entered_read, 8) != b"entered":
            raise kernel.SandboxFailure("scanner confinement handshake failed")
        os.close(entered_read)
        write_frame(args.broker_write_fd, {"kind":"ready", "profile":PROFILE, "network":"private-loopback-only", "scanner_broker_fds":False})
        while time.monotonic() < deadline:
            pid, status = os.waitpid(child, os.WNOHANG)
            if pid:
                if os.waitstatus_to_exitcode(status) == 0:
                    report_fd = os.open("/tmp/report.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    try:
                        st = os.fstat(report_fd)
                        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not 0 < st.st_size <= 524288:
                            raise ValueError("scanner export is not bounded regular data")
                        remaining = st.st_size
                        while remaining:
                            chunk = os.read(report_fd, min(32768, remaining))
                            if not chunk:
                                raise ValueError("scanner export truncated")
                            remaining -= len(chunk)
                            write_frame(args.broker_write_fd, {"kind":"report_chunk", "data":base64.b64encode(chunk).decode("ascii")})
                    finally:
                        os.close(report_fd)
                write_frame(args.broker_write_fd, {"kind":"finished", "exit_code":os.waitstatus_to_exitcode(status)})
                return 0 if os.waitstatus_to_exitcode(status) == 0 else 77
            if select.select([args.broker_read_fd], [], [], 0)[0]:
                raise EOFError("parent pipe unexpectedly readable or closed")
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                accepted_connections += 1
                if accepted_connections > 128:
                    raise ValueError("relay connection limit exceeded")
                connection.settimeout(min(2, max(0.1, deadline-time.monotonic())))
                request = _request(connection)
                if request is None:
                    continue
                write_frame(args.broker_write_fd, {"kind":"request", **request})
                _reply(connection, read_frame(args.broker_read_fd))
        raise TimeoutError("staging lifetime exceeded")
    finally:
        listener.close()
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(child, 0)
        except ChildProcessError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jail", required=True); parser.add_argument("--parent-namespaces", required=True)
    for name in ("binary-fd", "config-fd", "targets-fd", "broker-read-fd", "broker-write-fd", "host-uid", "seconds"):
        parser.add_argument("--"+name, type=int, required=True)
    try:
        return _setup(parser.parse_args(argv))
    except Exception:
        sys.stderr.write("STAGING_BOUNDARY_DENIED\n")
        return 76


if __name__ == "__main__":
    raise SystemExit(main())
