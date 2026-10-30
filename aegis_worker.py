#!/usr/bin/env python3
"""Trusted, deliberately narrow read-only source reviewer (stdlib only).

No target code is imported or executed, no sockets are created, and no shell is
invoked. Linux/POSIX O_NOFOLLOW directory-relative opens prevent traversal of
symbolic links. This is NOT an OS sandbox for arbitrary adversarial code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys

SKIP_DIRS = {".git", ".hg", "node_modules", "vendor", ".venv", "venv", "dist", "build", "__pycache__"}
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
MAX_OUTPUT = 32768
MAX_FILE_BYTES = 128 * 1024
MAX_CANDIDATES = 64
ENGINE = {"name": "aegis-regex", "version": "2", "ruleset_sha256": hashlib.sha256(
    json.dumps([[rid, label, pattern.pattern, pattern.flags, applies.split(",")]
                for rid, label, pattern, applies in RULES], separators=(",", ":")).encode()).hexdigest()}
RULE_CATALOG = [{"id": rid, "extensions": applies.split(","), "family": label}
                for rid, label, _, applies in RULES]


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink


def review(root: str, max_files: int, max_bytes: int) -> dict:
    if not os.path.isabs(root) or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("absolute repository and POSIX nofollow support required")
    if type(max_files) is not int or not 1 <= max_files <= 10000 or type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024:
        raise ValueError("scan limits invalid")
    fd = os.open(root, O_DIR)
    frames = [(fd, "")]
    summary = {"files_examined": 0, "bytes_read": 0, "symlinks_skipped": 0,
               "other_entries_skipped": 0, "truncated": False}
    coverage = {"schema_version": 1, "assessment_status": "no_leads_in_assessed_files",
                "engine": dict(ENGINE), "rules": RULE_CATALOG, "files": [],
                "counts": {name: 0 for name in ("assessed", "unsupported", "excluded", "unreadable", "partial")},
                "limits": {"files": max_files, "bytes": max_bytes, "per_file_bytes": MAX_FILE_BYTES,
                           "candidates": MAX_CANDIDATES, "evidence_bytes": MAX_OUTPUT},
                "limits_hit": [], "unrecorded_entries": 0, "remaining_entries_unknown": False,
                "source_identity": {"kind": "recorded_observation_manifest", "sha256": "0" * 64,
                                    "complete_repository": False}}
    result = {"status": "STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES", "summary": summary,
              "coverage": coverage, "candidates": [],
              "limitations": ["Regex matches are unverified leads, not reachable vulnerabilities or runtime proof.",
                              "Only the listed rule families assess Python/JavaScript/TypeScript; other languages are unsupported.",
                              "Source identity covers recorded observations, not a complete repository or an atomic Git revision."]}

    def limit(name):
        if name not in coverage["limits_hit"]:
            coverage["limits_hit"].append(name)
        summary["truncated"] = True

    def record(path, state, reason, *, details=None, candidates=()):
        entry = {"path": path[:180], "path_sha256": hashlib.sha256(os.fsencode(path)).hexdigest(),
                 "path_truncated": len(path) > 180, "status": state, "reason": reason}
        if details:
            entry.update(details)
        coverage["files"].append(entry)
        result["candidates"].extend(candidates)
        # Reserve room for final counters, limit reasons and the outcome label.
        if len(_encoded(result)) > MAX_OUTPUT - 1024:
            coverage["files"].pop()
            if candidates:
                del result["candidates"][-len(candidates):]
            coverage["unrecorded_entries"] += 1
            limit("evidence_bytes")
            return False
        coverage["counts"][state] += 1
        return True

    stopped = False
    try:
        while frames:
            dfd, prefix = frames.pop()
            try:
                try:
                    with os.scandir(dfd) as entries:
                        listing = sorted(entries, key=lambda e: e.name)  # bounded by RLIMIT_AS
                except OSError:
                    summary["other_entries_skipped"] += 1
                    stopped = not record(prefix.rstrip("/") or ".", "unreadable", "directory_unreadable")
                    if stopped:
                        break
                    continue
                for ent in listing:
                    relative = prefix + ent.name
                    try:
                        st = ent.stat(follow_symlinks=False)
                    except OSError:
                        summary["other_entries_skipped"] += 1
                        if not record(relative, "unreadable", "stat_failed"):
                            stopped = True
                            break
                        continue
                    if stat.S_ISLNK(st.st_mode):
                        summary["symlinks_skipped"] += 1
                        if not record(relative, "excluded", "symlink"):
                            stopped = True
                            break
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        if ent.name in SKIP_DIRS:
                            summary["other_entries_skipped"] += 1
                            if not record(relative, "excluded", "configured_directory_exclusion"):
                                stopped = True
                                break
                            continue
                        try:
                            child = os.open(ent.name, O_DIR, dir_fd=dfd)
                            frames.append((child, relative + "/"))
                        except OSError:
                            summary["other_entries_skipped"] += 1
                            if not record(relative, "unreadable", "directory_open_failed"):
                                stopped = True
                                break
                        continue
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                        summary["other_entries_skipped"] += 1
                        if not record(relative, "excluded", "not_single_link_regular_file"):
                            stopped = True
                            break
                        continue
                    ext = os.path.splitext(relative)[1].lower()
                    applicable = [(rid, label, pattern) for rid, label, pattern, applies in RULES if ext in applies.split(",")]
                    if not applicable:
                        summary["other_entries_skipped"] += 1
                        if not record(relative, "unsupported", "no_applicable_rules",
                                      details={"extension": ext[:16], "size_bytes": st.st_size, "rule_ids": []}):
                            stopped = True
                            break
                        continue
                    if (len(relative) > 180 or not re.fullmatch(r"[@.A-Za-z0-9_][@A-Za-z0-9._/-]*", relative)):
                        summary["other_entries_skipped"] += 1
                        if not record(relative, "excluded", "path_not_representable_in_canonical_report"):
                            stopped = True
                            break
                        continue
                    if summary["files_examined"] >= max_files or summary["bytes_read"] >= max_bytes:
                        limit("files" if summary["files_examined"] >= max_files else "bytes")
                        coverage["unrecorded_entries"] += 1
                        stopped = True
                        break
                    summary["files_examined"] += 1
                    try:
                        ffd = os.open(ent.name, O_FILE, dir_fd=dfd)
                        try:
                            before = os.fstat(ffd)
                            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or _identity(st) != _identity(before):
                                raise OSError("source replaced before read")
                            take = min(max_bytes - summary["bytes_read"], MAX_FILE_BYTES)
                            raw = bytearray()
                            while len(raw) < min(take, before.st_size):
                                chunk = os.read(ffd, min(65536, take - len(raw)))
                                if not chunk:
                                    break
                                raw.extend(chunk)
                                summary["bytes_read"] += len(chunk)
                            after = os.fstat(ffd)
                            current = os.stat(ent.name, dir_fd=dfd, follow_symlinks=False)
                            if (_identity(before) != _identity(after) or _identity(after) != _identity(current)
                                    or len(raw) != min(take, before.st_size)):
                                raise OSError("source changed during read")
                        finally:
                            os.close(ffd)
                    except OSError:
                        summary["other_entries_skipped"] += 1
                        if not record(relative, "unreadable", "unreadable_or_unstable_source"):
                            stopped = True
                            break
                        continue
                    details = {"size_bytes": before.st_size, "read_bytes": len(raw),
                               "content_sha256": hashlib.sha256(raw).hexdigest(),
                               "hash_scope": "full_file" if len(raw) == before.st_size else "prefix",
                               "rule_ids": [rid for rid, _, _ in applicable]}
                    try:
                        content = raw.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        if len(raw) < before.st_size and exc.reason == "unexpected end of data" and exc.end == len(raw):
                            content = raw[:exc.start].decode("utf-8")
                        else:
                            if not record(relative, "unreadable", "invalid_utf8", details=details):
                                stopped = True
                                break
                            continue
                    state, reason = "assessed", "all_applicable_regex_rules_evaluated"
                    if len(raw) < before.st_size:
                        state, reason = "partial", "source_byte_limit"
                        limit("per_file_bytes" if take == MAX_FILE_BYTES else "bytes")
                    candidates = []
                    for lineno, line in enumerate(content.splitlines(), 1):
                        for rule_id, label, pattern in applicable:
                            if len(result["candidates"]) + len(candidates) >= MAX_CANDIDATES:
                                state, reason = "partial", "candidate_limit"
                                limit("candidates")
                                stopped = True
                                break
                            if pattern.search(line):
                                candidates.append({"id": rule_id, "description": label,
                                                   "file": relative, "line": lineno,
                                                   "status": "unverified_static_lead"})
                        if stopped:
                            break
                    if not record(relative, state, reason, details=details, candidates=candidates):
                        stopped = True
                    if stopped:
                        break
                if stopped:
                    break
            finally:
                os.close(dfd)
        coverage["remaining_entries_unknown"] = stopped
        counts = coverage["counts"]
        if coverage["limits_hit"] or counts["unreadable"] or counts["partial"] or counts["excluded"]:
            coverage["assessment_status"] = "incomplete"
        elif not counts["assessed"]:
            coverage["assessment_status"] = "unsupported_analysis" if counts["unsupported"] else "no_supported_source_files"
        elif counts["unsupported"]:
            coverage["assessment_status"] = "incomplete"
        elif result["candidates"]:
            coverage["assessment_status"] = "unverified_leads"
        coverage["source_identity"]["sha256"] = hashlib.sha256(_encoded(coverage["files"])).hexdigest()
        if len(_encoded(result)) > MAX_OUTPUT:
            raise ValueError("source evidence exceeds reserved output budget")
        return result
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
