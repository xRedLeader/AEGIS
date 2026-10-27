#!/usr/bin/env python3
"""Operator-only offline snapshot signer. Never fetches or trusts arbitrary URLs."""
from __future__ import annotations
import argparse
from pathlib import Path
import os
import sys

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_intelligence import protected_bytes, validate_snapshot, _json_no_dupes, CONTEXT, MAX_BUNDLE, IntelligenceDenied


def sign_file(bundle: Path, operator_private_key: Path, signature_path: Path):
    raw = protected_bytes(bundle, MAX_BUNDLE)
    validate_snapshot(_json_no_dupes(raw))
    key = load_pem_private_key(protected_bytes(operator_private_key, 8192, private=True), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise IntelligenceDenied("operator key is not Ed25519")
    if not signature_path.is_absolute():
        raise IntelligenceDenied("operator output must have an absolute path")
    fd = os.open(signature_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        signature = key.sign(CONTEXT + raw)
        os.write(fd, signature)
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    ap = argparse.ArgumentParser(description="Sign an operator-reviewed OSV snapshot (no network)")
    ap.add_argument("--bundle", type=Path, required=True)
    ap.add_argument("--operator-key", type=Path, required=True)
    ap.add_argument("--signature", type=Path, required=True)
    args = ap.parse_args()
    try:
        sign_file(args.bundle, args.operator_key, args.signature)
        print("OSV_SNAPSHOT_SIGNED")
    except (IntelligenceDenied, OSError, ValueError):
        print("OSV_SNAPSHOT_DENIED", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
