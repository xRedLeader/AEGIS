#!/usr/bin/env python3
"""Offline operator-side signer for single-use, short-lived AEGIS v1.5 grants.

Run only with an operator identity. It does not issue credentials or start an
assessment; it produces a separately signed authorization for the service.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import secrets
import sys

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_credentials import AegisCredentialAuthority, APPROVAL_CONTEXT, _json_bytes, _protected_bytes
from aegis_supervisor import ExecutionDenied, deny, open_directory_nofollow


def _create_private_file(path, contents):
    path = Path(path)
    with open_directory_nofollow(path.parent) as directory:
        meta = os.fstat(directory)
        if meta.st_uid not in (0, os.geteuid()) or meta.st_mode & 0o077:
            deny("approval output parent must be a private operator-controlled directory")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            view = memoryview(contents)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("incomplete operator approval write")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)


def sign_grant(authority, private_key_file: Path, approval_file: Path,
               role: str, origin: str, path_prefix: str,
               session_seconds: int = 60, max_uses: int = 1,
               valid_for_seconds: int = 120):
    info, manifest = authority._guard()
    policy, pinned = authority._authority(info)
    if not 1 <= valid_for_seconds <= 600:
        deny("approval freshness must be within ten minutes")
    private_bytes = _protected_bytes(Path(private_key_file), 8192, private=True)
    key = load_pem_private_key(private_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey) or key.public_key() != pinned:
        deny("operator signing key does not match protected authority key")
    now = datetime.now(timezone.utc)
    stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
    accounts = [a for a in manifest["accounts"] if
                a["role"] == role and origin in a["allowed_origins"]]
    if len(accounts) != 1:
        deny("operator must identify exactly one signed test account")
    obj = {
        "version": 1, "approval_id": secrets.token_hex(16), "operator": policy["operator"],
        "engagement_id": info["engagement_id"], "manifest_sha256": info["manifest_sha256"],
        "role": role, "secret_ref": accounts[0]["secret_ref"], "origin": origin,
        "path_prefix": path_prefix, "not_before": stamp(now - timedelta(seconds=5)),
        "expires_at": stamp(now + timedelta(seconds=valid_for_seconds)),
        "session_seconds": session_seconds, "max_uses": max_uses,
    }
    authority.validate_grant(obj, info, manifest, policy)
    raw = _json_bytes(obj)
    target = Path(approval_file)
    _create_private_file(target, raw)
    try:
        _create_private_file(target.with_name(target.name + ".sig"),
                             key.sign(APPROVAL_CONTEXT + raw))
    except BaseException:
        # An unsigned approval is harmless but best effort avoids partial files.
        target.unlink(missing_ok=True)
        raise
    return {"status": "APPROVAL_SIGNED", "approval_id": obj["approval_id"],
            "approval_path": str(target), "signature_path": str(target) + ".sig"}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Sign a single-use AEGIS credential grant")
    for name in ("manifest", "signature", "trust", "state-root", "credential-policy",
                 "operator-key", "output", "role", "origin", "path-prefix"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--session-seconds", type=int, default=60)
    parser.add_argument("--max-uses", type=int, default=1)
    parser.add_argument("--valid-for-seconds", type=int, default=120)
    a = parser.parse_args(argv)
    try:
        auth = AegisCredentialAuthority(a.manifest, a.signature, a.trust,
                                        a.state_root, a.credential_policy)
        result = sign_grant(auth, Path(a.operator_key), Path(a.output), a.role,
                            a.origin, a.path_prefix, a.session_seconds,
                            a.max_uses, a.valid_for_seconds)
        print(f"{result['status']}: {result['approval_id']}")
        return 0
    except (ExecutionDenied, OSError, ValueError, TypeError):
        print("APPROVAL_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
