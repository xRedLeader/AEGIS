#!/usr/bin/env python3
"""AEGIS v1.4 fixed, uncredentialed HTTP/HTTPS request transport.

Trusted-supervisor helper ONLY. Receives validated destination/route over stdin;
connects to exactly one numeric IP with no second DNS lookup, never follows
redirects, uses system-trusted TLS verification, discards response bodies.

This program is NOT a standalone authorization boundary and MUST NOT be exposed
as a tool to agents or untrusted callers.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import stat
import socket
import ssl
import sys

MAX_INPUT = 16384
MAX_OUTPUT = 8192
MAX_READ = 64 * 1024
SAFE_HEADERS = {"content-type", "content-length", "cache-control", "x-content-type-options", "strict-transport-security"}


class TransportError(Exception):
    pass


class PinnedConnection(http.client.HTTPConnection):
    """Use numeric address only; preserve signed hostname for Host and TLS SNI."""

    def __init__(self, host: str, port: int, address: str, scheme: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self.pinned_address = address
        self.scheme = scheme
        self.ca_bundle = None

    def connect(self):
        address = ipaddress.ip_address(self.pinned_address)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            # Literal address => no DNS re-resolution, proxy or CONNECT tunnel.
            sock.connect((str(address), self.port))
            if self.scheme == "https":
                context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
                if self.ca_bundle is not None:
                    custom = self.ca_bundle
                    if set(custom) != {"path", "sha256"}:
                        raise TransportError("invalid operator CA specification")
                    fd = os.open(custom["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    try:
                        st = os.fstat(fd)
                        if (not stat.S_ISREG(st.st_mode) or st.st_size > 512 * 1024 or
                            st.st_mode & 0o022 or st.st_uid not in (0, os.geteuid())):
                            raise TransportError("operator CA bundle is not protected")
                        cert_bytes = os.read(fd, 512 * 1024 + 1)
                    finally:
                        os.close(fd)
                    if (len(cert_bytes) > 512 * 1024 or
                        hashlib.sha256(cert_bytes).hexdigest() != custom["sha256"]):
                        raise TransportError("operator CA bundle fingerprint changed")
                    context.load_verify_locations(cadata=cert_bytes.decode("ascii"))
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                sock = context.wrap_socket(sock, server_hostname=self.host)
            self.sock = sock
        except BaseException:
            sock.close()
            raise


def execute(req: dict) -> dict:
    allowed = {"scheme", "hostname", "port", "address", "method", "target", "body_limit", "timeout"}
    if not allowed <= set(req) or set(req) - allowed - {"ca_bundle"}:
        raise TransportError("unexpected transport configuration")
    scheme, host, address = req["scheme"], req["hostname"], req["address"]
    port, method, target = req["port"], req["method"], req["target"]
    limit, timeout = req["body_limit"], req["timeout"]
    if (scheme not in ("http", "https") or not isinstance(host, str) or
        not host or not host.isascii() or any(c in host for c in "\r\n/\\@%") or
        method not in ("GET", "HEAD") or type(port) is not int or not (1 <= port <= 65535) or
        type(limit) is not int or not (1 <= limit <= 1024 * 1024) or
        type(timeout) not in (int, float) or not (0 < timeout <= 60) or
        not isinstance(target, str) or len(target) > 4096 or not target.startswith("/") or
        any(ord(c) < 33 or ord(c) > 126 for c in target)):
        raise TransportError("invalid transport parameters")
    try:
        ipaddress.ip_address(address)
    except ValueError as exc:
        raise TransportError("destination must be a numeric address") from exc

    conn = PinnedConnection(host, port, address, scheme, timeout)
    conn.ca_bundle = req.get("ca_bundle")
    if conn.ca_bundle is not None and (scheme != "https" or not isinstance(conn.ca_bundle, dict)):
        raise TransportError("operator CA bundle allowed only for HTTPS")
    try:
        # No caller-provided headers, cookies, credentials, proxy settings or bodies.
        conn.request(method, target, headers={
            "User-Agent": "AEGIS-Authorized-Testing/1.4",
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        response = conn.getresponse()
        digester = hashlib.sha256()
        total = 0
        while True:
            chunk = response.read(min(MAX_READ, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise TransportError("response body exceeded signed byte limit")
            digester.update(chunk)
        headers = {}
        for name, value in response.getheaders():
            lower = name.lower()
            if lower in SAFE_HEADERS and lower not in headers:
                headers[lower] = value[:256].replace("\n", " ").replace("\r", " ")
        result = {
            "status": "SUCCESS", "http_status": response.status,
            "body_bytes": total, "body_sha256": digester.hexdigest(),
            "redirect_not_followed": 300 <= response.status <= 399,
            "headers": headers,
        }
        if len(json.dumps(result, separators=(",", ":")).encode()) > MAX_OUTPUT:
            raise TransportError("response metadata exceeds output limit")
        return result
    finally:
        conn.close()


def resolve(req: dict) -> dict:
    if set(req) != {"mode", "hostname", "port"} or req["mode"] != "resolve":
        raise TransportError("invalid resolution request")
    hostname, port = req["hostname"], req["port"]
    if (not isinstance(hostname, str) or not hostname or not hostname.isascii() or
        any(c in hostname for c in "\r\n/\\@%") or type(port) is not int or not (1 <= port <= 65535)):
        raise TransportError("invalid resolution host")
    records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not records or len(records) > 32:
        raise TransportError("invalid resolution cardinality")
    addresses = set()
    for family, kind, proto, canonname, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM:
            raise TransportError("unexpected resolver address family")
        address = ipaddress.ip_address(sockaddr[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        addresses.add(str(address))
    if len(addresses) > 16:
        raise TransportError("too many distinct DNS answers")
    return {"status": "RESOLVED", "addresses": sorted(addresses)}


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise TransportError("transport input exceeds limit")
        req = json.loads(raw)
        if not isinstance(req, dict):
            raise TransportError("invalid request object")
        if req.get("mode") == "resolve":
            result = resolve(req)
        elif req.get("mode") == "fetch":
            req = dict(req)
            del req["mode"]
            result = execute(req)
        else:
            raise TransportError("unknown gateway mode")
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (TransportError, OSError, ssl.SSLError, http.client.HTTPException, ValueError, KeyError, TypeError,
            json.JSONDecodeError, TimeoutError) as exc:
        # No attacker-controlled URL, response body, sensitive headers or tracebacks.
        sys.stderr.write("GATEWAY_DENIED: " + type(exc).__name__ + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
