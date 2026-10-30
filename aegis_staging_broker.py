#!/usr/bin/env python3
"""Fixed trusted numeric-address HTTP fetch helper; never executes scanner input."""
import base64
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aegis_http_broker import parent_death_guard
from aegis_staging_protocol import MAX_BODY


def fetch(request):
    if (not isinstance(request, dict) or set(request) != {"address", "port", "hostname", "method", "target", "timeout", "body_limit"} or
            request["method"] not in ("GET", "HEAD") or type(request["port"]) is not int or not 1 <= request["port"] <= 65535 or
            type(request["timeout"]) not in (int, float) or not 0 < request["timeout"] <= 5 or
            type(request["body_limit"]) is not int or not 1 <= request["body_limit"] <= MAX_BODY):
        raise ValueError("invalid fixed HTTP request")
    address = str(ipaddress.ip_address(request["address"]))
    if address != request["address"] or not isinstance(request["hostname"], str) or not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", request["hostname"]):
        raise ValueError("invalid canonical destination")
    target = request["target"]
    if (not isinstance(target, str) or len(target) > 256 or not target.startswith("/") or not target.isascii() or
            any(ord(c) <= 32 for c in target) or any(c in target for c in "?#%\\;") or "//" in target or
            any(p in (".", "..") for p in target.split("/"))):
        raise ValueError("invalid exact route")
    http.client._MAXLINE = 4096
    http.client._MAXHEADERS = 32
    host = "[" + request["hostname"] + "]" if ":" in request["hostname"] else request["hostname"]
    if request["port"] != 80:
        host += ":" + str(request["port"])
    connection = http.client.HTTPConnection(address, request["port"], timeout=request["timeout"])
    try:
        connection.putrequest(request["method"], target, skip_host=True, skip_accept_encoding=True)
        for name, value in (("Host", host), ("User-Agent", "AEGIS-restricted-staging/1"),
                            ("Accept", "*/*"), ("Accept-Encoding", "identity"), ("Connection", "close")):
            connection.putheader(name, value)
        connection.endheaders()
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ValueError("redirects are forbidden")
        lengths = [value for name,value in response.getheaders() if name.lower() == "content-length"]
        if response.getheader("Transfer-Encoding") is not None or len(lengths) > 1:
            raise ValueError("transfer-encoded or ambiguous responses are unsupported")
        if lengths and (not re.fullmatch(r"[0-9]+", lengths[0]) or
                        request["method"] != "HEAD" and int(lengths[0]) > request["body_limit"]):
            raise ValueError("response length exceeds signed limit")
        if response.getheader("Content-Encoding", "identity").lower() not in ("", "identity"):
            raise ValueError("encoded responses are unsupported")
        body = response.read(request["body_limit"] + 1)
        if len(body) > request["body_limit"]:
            raise ValueError("response exceeds signed limit")
        content_type = response.getheader("Content-Type", "application/octet-stream")
        if not re.fullmatch(r"[A-Za-z0-9._+/;= -]{1,128}", content_type):
            content_type = "application/octet-stream"
        return {"status": response.status, "content_type": content_type,
                "body_b64": base64.b64encode(body).decode("ascii"), "body_bytes": len(body)}
    finally:
        connection.close()


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError("parent identity required")
        parent_death_guard(int(sys.argv[1]))
        raw = sys.stdin.buffer.read(16385)
        if not 0 < len(raw) <= 16384:
            raise ValueError("request exceeds bound")
        result = fetch(json.loads(raw))
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        sys.stderr.write("STAGING_FETCH_DENIED\n")
        return 74


if __name__ == "__main__":
    raise SystemExit(main())
