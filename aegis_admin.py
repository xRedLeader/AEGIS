#!/usr/bin/env python3
"""Operator-side Ed25519 key creation and offline signature utility.

NEVER place the generated private key in an agent/repository/test environment.
The signed manifest remains subject to an independent approved-target registry.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key
from aegis_preflight import PreflightError, SIGNING_CONTEXT, validate_for_signing


def write_new(path: Path, content: bytes, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    cmds = parser.add_subparsers(dest="command", required=True)
    kg = cmds.add_parser("keygen")
    kg.add_argument("--private", type=Path, required=True)
    kg.add_argument("--public", type=Path, required=True)
    sign = cmds.add_parser("sign")
    sign.add_argument("--private", type=Path, required=True)
    sign.add_argument("--manifest", type=Path, required=True)
    sign.add_argument("--signature", type=Path, required=True)
    sign.add_argument("--trust-policy", type=Path, required=True,
                      help="operator-protected policy; checked before signing")
    args = parser.parse_args()
    if args.command == "keygen":
        if args.private.exists() or args.public.exists():
            parser.error("refusing to overwrite existing key files")
        key = Ed25519PrivateKey.generate()
        private_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        public_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        write_new(args.private, private_pem, 0o600)
        write_new(args.public, public_pem, 0o644)
        print("Generated operator key pair. KEEP THE PRIVATE KEY OUTSIDE THE AGENT ENVIRONMENT.")
    else:
        key = load_pem_private_key(args.private.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            parser.error("private key must be Ed25519")
        try:
            raw, approved = validate_for_signing(args.manifest, args.trust_policy, key)
        except PreflightError as exc:
            parser.error(f"refusing to sign: {exc}")
        signature = key.sign(SIGNING_CONTEXT + raw)
        write_new(args.signature, signature, 0o644)
        print(f"Signed authorized manifest {approved['engagement_id']}: {args.signature}")


if __name__ == "__main__":
    main()
