#!/usr/bin/env python3
"""Offline operator-only signed client for the Unix command service."""
from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_credentials import _protected_bytes
from aegis_operator_service import issue_command, MAX_ENVELOPE, MAX_RESPONSE
from aegis_supervisor import ExecutionDenied, deny


def send(socket_path, signed_envelope):
    if len(signed_envelope) > MAX_ENVELOPE:
        deny("operator envelope too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(socket_path))
        sock.sendall(signed_envelope)
        sock.shutdown(socket.SHUT_WR)
        chunks = bytearray()
        while len(chunks) <= MAX_RESPONSE:
            data = sock.recv(MAX_RESPONSE + 1 - len(chunks))
            if not data:
                break
            chunks.extend(data)
    if len(chunks) > MAX_RESPONSE or not chunks:
        deny("missing or oversized operator reply")
    result = json.loads(chunks)
    if not isinstance(result, dict) or set(result) not in ({"ok", "result"}, {"ok", "status"}):
        deny("invalid operator reply")
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description="Send operator-signed AEGIS command")
    for name in ("socket", "operator-key", "principal", "engagement-id", "operation", "args-json"):
        p.add_argument("--" + name, required=True)
    a = p.parse_args(argv)
    try:
        key = load_pem_private_key(_protected_bytes(Path(a.operator_key), 8192, private=True), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            deny("operator API signing key must be Ed25519")
        request = issue_command(key, a.principal, a.engagement_id,
            a.operation, json.loads(a.args_json))
        result = send(Path(a.socket), request)
        print(json.dumps(result, sort_keys=True))
        return 0 if result.get("ok") is True else 2
    except (ExecutionDenied, OSError, TypeError, ValueError, KeyError):
        print("OPERATOR_CLIENT_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
