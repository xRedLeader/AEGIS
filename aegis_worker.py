#!/usr/bin/env python3
"""Trusted, deliberately narrow read-only source reviewer (stdlib only).

No target code is imported or executed, no sockets are created, and no shell is
invoked. Linux/POSIX O_NOFOLLOW directory-relative opens prevent traversal of
symbolic links. This is NOT an OS sandbox for arbitrary adversarial code.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys

SKIP_DIRS = {".git", ".hg", "node_modules", "vendor", ".venv", "venv", "dist", "build", "__pycache__"}
SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".cs", ".c", ".cpp", ".h", ".hpp", ".yaml", ".yml", ".json"}
# Static review leads, NOT validated vulnerabilities. No source snippets output.
RULES = (
    ("PY-SHELL-TRUE", "shell execution enabled", re.compile(r"\bshell\s*=\s*True\b"), ".py"),
    ("PY-PICKLE-LOAD", "pickle deserialization requires trust review", re.compile(r"\bpickle\.loads?\s*\("), ".py"),
    ("PY-EVAL", "dynamic evaluation requires trust review", re.compile(r"(?<![\w.])eval\s*\("), ".py"),
    ("PY-TLS-NOVERIFY", "TLS certificate validation disabled", re.compile(r"\bverify\s*=\s*False\b"), ".py"),
    ("JS-TLS-NOVERIFY", "TLS certificate validation disabled", re.compile(r"\brejectUnauthorized\s*:\s*false\b"), ".js,.jsx,.ts,.tsx"),
    ("JS-EVAL", "dynamic evaluation requires trust review", re.compile(r"(?<![\w.])eval\s*\("), ".js,.jsx,.ts,.tsx"),
)
O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
O_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def review(root: str, max_files: int, max_bytes: int) -> dict:
    if not os.path.isabs(root) or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("absolute repository and POSIX nofollow support required")
    fd = os.open(root, O_DIR)
    frames = [(fd, "")]
    processed = 0
    bytes_read = 0
    symlinks = 0
    skipped = 0
    truncated = False
    candidates = []
    try:
        while frames:
            dfd, prefix = frames.pop()
            try:
                with os.scandir(dfd) as entries:
                    listing = sorted(entries, key=lambda e: e.name)  # bounded by RLIMIT_AS
                for ent in listing:
                    if processed >= max_files or bytes_read >= max_bytes:
                        truncated = True
                        break
                    if ent.is_symlink():
                        symlinks += 1
                        continue
                    relative = prefix + ent.name
                    try:
                        st = ent.stat(follow_symlinks=False)
                    except OSError:
                        skipped += 1
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        if ent.name in SKIP_DIRS:
                            skipped += 1
                            continue
                        try:
                            child = os.open(ent.name, O_DIR, dir_fd=dfd)
                            frames.append((child, relative + "/"))
                        except OSError:
                            skipped += 1
                        continue
                    if not stat.S_ISREG(st.st_mode) or not any(relative.endswith(s) for s in SUFFIXES):
                        skipped += 1
                        continue
                    processed += 1
                    try:
                        ffd = os.open(ent.name, O_FILE, dir_fd=dfd)
                        try:
                            if not stat.S_ISREG(os.fstat(ffd).st_mode):
                                skipped += 1
                                continue
                            take = min(max_bytes - bytes_read, 128 * 1024)
                            raw = os.read(ffd, take)
                        finally:
                            os.close(ffd)
                    except OSError:
                        skipped += 1
                        continue
                    bytes_read += len(raw)
                    content = raw.decode("utf-8", errors="replace")
                    ext = "." + relative.rsplit(".", 1)[-1].lower()
                    for lineno, line in enumerate(content.splitlines(), 1):
                        if len(candidates) >= 64:
                            truncated = True
                            break
                        for rule_id, label, pattern, applies in RULES:
                            if ext in applies.split(",") and pattern.search(line):
                                candidates.append({"id": rule_id, "description": label,
                                                   "file": relative, "line": lineno,
                                                   "status": "unverified_static_lead"})
                    if len(candidates) >= 64:
                        break
                if truncated or len(candidates) >= 64:
                    truncated = True
                    break
            finally:
                os.close(dfd)
        return {"status": "STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES",
                "summary": {"files_examined": processed, "bytes_read": bytes_read,
                            "symlinks_skipped": symlinks, "other_entries_skipped": skipped,
                            "truncated": truncated}, "candidates": candidates,
                "limitations": ["Heuristic static signatures are leads only; no runtime exploitation was performed.",
                                "Source files are sampled up to 128 KiB each; scan may be truncated."]}
    finally:
        # On truncation, release queued directory descriptors too.
        for queued_fd, _ in frames:
            os.close(queued_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--max-files", type=int, default=1000)
    parser.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    args = parser.parse_args()
    if not 1 <= args.max_files <= 10000 or not 1 <= args.max_bytes <= 16 * 1024 * 1024:
        print("DENIED: scan limits invalid", file=sys.stderr)
        return 2
    try:
        print(json.dumps(review(args.repo, args.max_files, args.max_bytes), separators=(",", ":")))
    except (ValueError, OSError) as exc:
        print("DENIED: source scan failed: " + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
