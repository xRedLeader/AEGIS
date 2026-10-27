#!/usr/bin/env python3
"""Confined v1.5 HTTPS transport with one preconnected TCP capability.

Only the operator broker supplies the bearer token over bounded stdin after
validating its protected vault descriptor. No vault path or descriptor reaches
this process. Never expose this private protocol as an agent tool.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
from pathlib import Path
import re
import ssl
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aegis_http_gateway import MAX_INPUT, PinnedConnection, TransportError

MAX_BODY = 1048576


def exchange(req: dict, connected_fd: int) -> dict:
    mandatory = {"mode", "scheme", "hostname", "port", "address", "method",
                 "target", "timeout", "body_limit", "ca_pem", "bearer_token"}
    if not isinstance(req, dict) or set(req) != mandatory:
        raise TransportError("invalid confined credential request shape")
    if (req["mode"] != "fetch" or req["scheme"] != "https" or req["method"] not in ("GET", "HEAD") or
            type(req["port"]) is not int or not 1 <= req["port"] <= 65535 or
            type(req["timeout"]) not in (int, float) or not 0 < req["timeout"] <= 30 or
            type(req["body_limit"]) is not int or not 0 < req["body_limit"] <= MAX_BODY or
            not isinstance(req["hostname"], str) or not req["hostname"].isascii() or
            not req["hostname"] or any(c in req["hostname"] for c in "/\\\r\n@%") or
            not isinstance(req["target"], str) or not req["target"].startswith("/") or
            len(req["target"]) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in req["target"]) or
            not isinstance(req["ca_pem"], str) or not 0 < len(req["ca_pem"]) <= 1048576 or
            not isinstance(req["bearer_token"], str) or
            not re.fullmatch(r"[A-Za-z0-9._~+/-]{8,2048}", req["bearer_token"])):
        raise TransportError("invalid confined credential request")
    ipaddress.ip_address(req["address"])
    conn = PinnedConnection(req["hostname"], req["port"], req["address"],
                            "https", req["timeout"], connected_fd)
    conn.ca_pem = req["ca_pem"]
    try:
        conn.request(req["method"], req["target"], headers={
            "Authorization": "Bearer " + req["bearer_token"],
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
        return {"status": "AUTH_METADATA_ONLY", "http_status": int(response.status),
                "body_bytes": total, "redirect_not_followed": 300 <= response.status <= 399}
    finally:
        conn.close()


def main():
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--socket-fd" or int(sys.argv[2]) < 3:
            raise TransportError("fixed inherited TCP descriptor required")
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise TransportError("credential request too large")
        result = exchange(json.loads(raw), int(sys.argv[2]))
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (TransportError, OSError, ValueError, KeyError, TypeError,
            http.client.HTTPException, ssl.SSLError):
        sys.stderr.write("AUTH_REQUEST_DENIED\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
