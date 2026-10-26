#!/usr/bin/env python3
"""Trusted v1.5 credentialed metadata fetch. NOT an assessment worker.

Only operator-side AEGIS control plane may spawn this helper, with one
prevalidated secret fd and a prevalidated numeric destination. No agent-visible
credentials, arbitrary headers, redirects, bodies or authentication responses.
This trusted process has host networking; it is not a seccomp-confined worker.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import ssl
import stat
import sys

class TransportError(Exception):
    pass

MAX_INPUT = 16384
MAX_BODY = 1048576


def exchange(req: dict, credential_fd: int) -> dict:
    mandatory = {"scheme", "hostname", "port", "address", "method", "target", "timeout", "body_limit"}
    if not isinstance(req, dict) or set(req) != mandatory | ({"ca_bundle"} if "ca_bundle" in req else set()):
        raise TransportError("invalid trusted credential request shape")
    if (req["scheme"] != "https" or req["method"] not in ("GET", "HEAD") or
            type(req["port"]) is not int or not 1 <= req["port"] <= 65535 or
            type(req["timeout"]) not in (int, float) or not 0 < req["timeout"] <= 30 or
            type(req["body_limit"]) is not int or not 0 < req["body_limit"] <= MAX_BODY or
            not isinstance(req["hostname"], str) or not req["hostname"].isascii() or
            not req["hostname"] or any(c in req["hostname"] for c in "/\\\r\n@%") or
            not isinstance(req["target"], str) or not req["target"].startswith("/") or
            len(req["target"]) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in req["target"])):
        raise TransportError("invalid trusted credential request")
    try:
        address = ipaddress.ip_address(req["address"])
    except ValueError as exc:
        raise TransportError("destination must be numeric") from exc
    import re
    token_re = re.compile(r"^[A-Za-z0-9._~+/-]{8,2048}$")
    secret = os.read(credential_fd, 4097)
    if len(secret) > 4096 or not token_re.fullmatch(secret.decode("ascii", errors="replace")):
        raise TransportError("invalid protected credential")
    token = secret.decode("ascii")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    conn = http.client.HTTPConnection(req["hostname"], req["port"], timeout=req["timeout"])
    sock = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        sock.settimeout(req["timeout"])
        sock.connect((str(address), req["port"]))  # already policy-pinned numeric destination
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        ca = req.get("ca_bundle")
        if ca is not None:
            if not isinstance(ca, dict) or set(ca) != {"path", "sha256"}:
                raise TransportError("invalid operator CA")
            import hashlib
            fd = os.open(ca["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_size > 512 * 1024 or st.st_mode & 0o022 or st.st_uid not in (0, os.geteuid()):
                    raise TransportError("operator CA file is not protected")
                content = os.read(fd, 512 * 1024 + 1)
            finally:
                os.close(fd)
            if hashlib.sha256(content).hexdigest() != ca["sha256"]:
                raise TransportError("operator CA fingerprint changed")
            context.load_verify_locations(cadata=content.decode("ascii"))
        conn.sock = context.wrap_socket(sock, server_hostname=req["hostname"])
        sock = conn.sock
        conn.request(req["method"], req["target"], headers={
            "Authorization": "Bearer " + token,
            "User-Agent": "AEGIS-Authorized-Metadata/1.5",
            "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close"})
        response = conn.getresponse()
        total = 0
        while True:
            chunk = response.read(min(65536, req["body_limit"] + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > req["body_limit"]:
                raise TransportError("body limit exceeded")
        # No bodies, hashes, echoed headers, raw request paths or credentials returned.
        return {"status": "AUTH_METADATA_ONLY", "http_status": int(response.status),
                "body_bytes": total, "redirect_not_followed": 300 <= response.status <= 399}
    finally:
        conn.close()
        sock.close()


def main():
    try:
        if len(sys.argv) != 2:
            raise TransportError("fixed inherited credential FD required")
        fd = int(sys.argv[1])
        if fd <= 2:
            raise TransportError("standard fd cannot hold credential")
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_uid not in (0, os.geteuid()):
            raise TransportError("credential fd not protected")
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise TransportError("credential request too large")
        result = exchange(json.loads(raw), fd)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (TransportError, OSError, ValueError, KeyError, TypeError, ssl.SSLError,
            http.client.HTTPException, json.JSONDecodeError, TimeoutError):
        sys.stderr.write("AUTH_REQUEST_DENIED\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
