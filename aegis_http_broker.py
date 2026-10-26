#!/usr/bin/env python3
"""Trusted connection broker and watchdog, never an agent-facing tool."""
from __future__ import annotations
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from aegis_http_gateway import MAX_INPUT, MAX_OUTPUT, TransportError, resolve


def parent_death_guard(expected_parent):
    lib = ctypes.CDLL(None, use_errno=True)
    if lib.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != expected_parent:
        raise TransportError("supervisor lifetime cannot be enforced")


def tls_roots(custom):
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    if custom is not None:
        if not isinstance(custom, dict) or set(custom) != {"path", "sha256"}:
            raise TransportError("invalid operator CA policy")
        fd = os.open(custom["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_size > 512 * 1024 or
                    st.st_mode & 0o022 or st.st_uid not in (0, os.geteuid())):
                raise TransportError("operator CA file is not protected")
            data = os.read(fd, 512 * 1024 + 1)
        finally:
            os.close(fd)
        if len(data) > 512 * 1024 or hashlib.sha256(data).hexdigest() != custom["sha256"]:
            raise TransportError("operator CA fingerprint changed")
        context.load_verify_locations(cadata=data.decode("ascii"))
    pem = "".join(ssl.DER_cert_to_PEM_cert(cert)
                  for cert in context.get_ca_certs(binary_form=True))
    if not pem or len(pem) > 1024 * 1024:
        raise TransportError("invalid TLS trust snapshot")
    return pem


def sandbox_command(fd, jail, mode="http"):
    if mode not in ("http", "http-probe"):
        raise TransportError("unknown fixed network worker")
    namespaces = ",".join(str(os.stat("/proc/self/ns/" + ns).st_ino)
                          for ns in ("user", "mnt", "net", "pid"))
    return ["/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--net",
            "--pid", "--fork", "--kill-child", "--propagation", "private", "--",
            "/usr/bin/python3", "-I", "-S", str(HERE / "aegis_sandbox.py"),
            "--socket-fd", str(fd), "--jail", str(jail), "--mode", mode,
            "--host-uid", str(os.geteuid()), "--parent-namespaces", namespaces]


def confined_exchange(sock, request, timeout, mode="http"):
    """Bounded pipes and a wall-clock watchdog outside the assessment worker."""
    body = json.dumps(request, separators=(",", ":")).encode()
    if len(body) > MAX_INPUT or not 0 < timeout <= 30:
        raise TransportError("invalid confined request budget")
    with tempfile.TemporaryDirectory(prefix="aegis-http-") as jail:
        parent = os.getpid()
        worker = subprocess.Popen(
            sandbox_command(sock.fileno(), jail, mode), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/",
            pass_fds=(sock.fileno(),),
            preexec_fn=lambda: parent_death_guard(parent),
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"})
        try:
            # Capped nonblocking pipes prevent parser output exhausting the
            # supervisor or blocking its revocation/watchdog loop.
            with selectors.DefaultSelector() as poll:
                pending = memoryview(body)
                output, errors = bytearray(), bytearray()
                for stream, event, label in ((worker.stdin, selectors.EVENT_WRITE, "in"),
                                             (worker.stdout, selectors.EVENT_READ, "out"),
                                             (worker.stderr, selectors.EVENT_READ, "err")):
                    os.set_blocking(stream.fileno(), False)
                    poll.register(stream, event, label)
                deadline = time.monotonic() + timeout
                while poll.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TransportError("confined worker deadline expired")
                    for key, _ in poll.select(min(remaining, 0.1)):
                        if key.data == "in":
                            pending = pending[os.write(key.fd, pending[:65536]):]
                            if not pending:
                                poll.unregister(key.fileobj)
                                key.fileobj.close()
                        else:
                            data = os.read(key.fd, 8192)
                            if not data:
                                poll.unregister(key.fileobj)
                                key.fileobj.close()
                            target = output if key.data == "out" else errors
                            target.extend(data)
                            if len(target) > MAX_OUTPUT:
                                raise TransportError("confined worker output limit exceeded")
                if worker.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                    raise TransportError("kernel confinement or transport failed: " +
                                         errors.decode(errors="replace")[:512])
                result = json.loads(output)
                if not isinstance(result, dict):
                    raise TransportError("invalid confined result")
                return result
        finally:
            # Killing unshare kills namespace init; the kernel then closes all
            # worker descriptors and kills every process in that PID namespace.
            if worker.poll() is None:
                worker.kill()
            worker.wait()
            for stream in (worker.stdin, worker.stdout, worker.stderr):
                stream.close()


def fetch(request):
    request = dict(request)
    address = ipaddress.ip_address(request["address"])
    port, timeout = request["port"], request["timeout"]
    if (type(port) is not int or not 1 <= port <= 65535 or
            type(timeout) not in (int, float) or not 0 < timeout <= 30):
        raise TransportError("invalid broker destination or deadline")
    began = time.monotonic()
    custom = request.pop("ca_bundle", None)
    if request["scheme"] == "https":
        request["ca_pem"] = tls_roots(custom)
    elif request["scheme"] != "http" or custom is not None:
        raise TransportError("invalid broker TLS request")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP) as sock:
        sock.settimeout(timeout)
        sock.connect((str(address), port))
        remaining = timeout - (time.monotonic() - began)
        if remaining <= 0:
            raise TransportError("connection budget exhausted")
        return confined_exchange(sock, request, remaining)


def main():
    try:
        if sys.platform != "linux" or os.geteuid() == 0 or len(sys.argv) != 2:
            raise TransportError("non-root Linux supervisor required")
        parent_death_guard(int(sys.argv[1]))
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise TransportError("broker input too large")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise TransportError("invalid broker request")
        if request.get("mode") == "resolve":
            result = resolve(request)
        elif request.get("mode") == "fetch":
            result = fetch(request)
        else:
            raise TransportError("unknown broker operation")
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        return 0
    except (TransportError, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError) as exc:
        sys.stderr.write("BROKER_DENIED: " + type(exc).__name__ + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
