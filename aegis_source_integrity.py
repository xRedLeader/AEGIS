#!/usr/bin/env python3
"""Verify all tracked source bytes against SHA256SUMS.txt, without execution.

The manifest is a local consistency check, not an independent signature or
artifact provenance guarantee; pin the final Git commit through trusted CI.
"""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_ENTRIES = 512
MAX_FILE = 4 * 1024 * 1024


class SourceIntegrityError(ValueError):
    pass


def verify(root: Path, tracked_files: set[str]) -> dict:
    root = Path(root)
    manifest = root / "SHA256SUMS.txt"
    raw = manifest.read_bytes()
    if not 0 < len(raw) <= 65536 or b"\r" in raw:
        raise SourceIntegrityError("manifest absent, oversized, or not LF normalized")
    try:
        entries = raw.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise SourceIntegrityError("manifest is not ASCII") from exc
    if len(entries) > MAX_ENTRIES:
        raise SourceIntegrityError("too many tracked files")
    expected = {}
    for line in entries:
        if "  " not in line:
            raise SourceIntegrityError("bad checksum entry")
        digest,name = line.split("  ", 1)
        rel = PurePosixPath(name)
        if (not HASH.fullmatch(digest) or not name or name.startswith("/") or
                name != str(rel) or any(x in (".", "..") for x in rel.parts) or
                name in expected or name == "SHA256SUMS.txt"):
            raise SourceIntegrityError("invalid tracked path or checksum")
        expected[name] = digest
    if set(expected) != tracked_files - {"SHA256SUMS.txt"}:
        raise SourceIntegrityError("manifest missing or adding tracked files")
    for name, digest in expected.items():
        path = root
        for part in PurePosixPath(name).parts:
            path = path / part
            if path.is_symlink():
                raise SourceIntegrityError("tracked path is symlink")
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise SourceIntegrityError("tracked file missing or exceeds limit")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SourceIntegrityError("tracked file digest mismatch")
    return {"status": "TRACKED_SOURCE_DIGESTS_MATCH", "verified_files": len(expected)}


def main() -> int:
    root = Path(__file__).resolve().parent
    try:
        raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"], timeout=10)
        tracked = set(raw.decode("utf-8").rstrip("\0").split("\0"))
        print(__import__("json").dumps(verify(root, tracked), sort_keys=True))
        return 0
    except (SourceIntegrityError, OSError, ValueError, subprocess.SubprocessError):
        print("SOURCE_INTEGRITY_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
