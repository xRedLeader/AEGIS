#!/usr/bin/env python3
"""AEGIS v1.4 fixed, uncredentialed HTTP/HTTPS request transport.

Confined worker ONLY. Receives one broker-connected TCP descriptor and validated
configuration; verifies its peer without reconnecting, never follows redirects,
verifies TLS using the broker's public CA snapshot and discards response bodies.

This program is NOT a standalone authorization boundary and MUST NOT be exposed
as a tool to agents or untrusted callers.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import sys

MAX_INPUT = 1024 * 1024 + 16384
MAX_OUTPUT = 8192
MAX_READ = 64 * 1024
SAFE_HEADERS = {"content-type", "content-length", "cache-control", "x-content-type-options", "strict-transport-security"}


class TransportError(Exception):
    pass


class PinnedConnection(http.client.HTTPConnection):
    """Use numeric address only; preserve signed hostname for Host and TLS SNI."""

    def __init__(self, host: str, port: int, address: str, scheme: str, timeout: float,
                 connected_fd: int):
        super().__init__(host, port, timeout=timeout)
        self.pinned_address = address
        self.scheme = scheme
        self.connected_fd = connected_fd
        self.ca_pem = None

    def connect(self):
        address = ipaddress.ip_address(self.pinned_address)
        sock = socket.socket(fileno=self.connected_fd)
        try:
            peer = sock.getpeername()
            if ipaddress.ip_address(peer[0]) != address or peer[1] != self.port:
                raise TransportError("broker socket does not match pinned destination")
            sock.settimeout(self.timeout)
            if self.scheme == "https":
                context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH,
                                                     cadata=self.ca_pem)
                context.check_hostname = True
                context.verify_mode = ssl.CERT_REQUIRED
                sock = context.wrap_socket(sock, server_hostname=self.host)
            self.sock = sock
        except BaseException:
            sock.close()
            raise


def execute(req: dict, connected_fd: int) -> dict:
    allowed = {"scheme", "hostname", "port", "address", "method", "target", "body_limit", "timeout"}
    if not allowed <= set(req) or set(req) - allowed - {"ca_pem"}:
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

    conn = PinnedConnection(host, port, address, scheme, timeout, connected_fd)
    conn.ca_pem = req.get("ca_pem")
    if scheme == "https" and (not isinstance(conn.ca_pem, str) or
                              not conn.ca_pem or len(conn.ca_pem) > 1024 * 1024):
        raise TransportError("broker TLS trust snapshot required")
    if scheme == "http" and conn.ca_pem is not None:
        raise TransportError("operator CA is only valid for HTTPS")
    try:
        # No caller-provided headers, cookies, credentials, proxy settings or bodies.
        conn.request(method, target, headers={
            "User-Agent": "AEGIS-Authorized-Testing/1.4.1",
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
        if (req.get("mode") == "fetch" and len(sys.argv) == 3 and
                sys.argv[1] == "--socket-fd" and int(sys.argv[2]) >= 3):
            req = dict(req)
            del req["mode"]
            result = execute(req, int(sys.argv[2]))
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
