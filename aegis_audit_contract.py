"""Bounded source-audit contracts adapted from Cloudflare's MIT-licensed skill.

See third_party/cloudflare-security-audit for the pinned originals. Research
messages are data, never commands, deployment authority, or staging proofs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import unicodedata
from urllib.parse import quote

from aegis_reporting import canonical
from aegis_supervisor import ExecutionDenied, deny, open_directory_nofollow

MAX_BUNDLE = 262144
MAX_UNITS = 32
MAX_FILES = 128
MAX_FILE = 1048576
MAX_SOURCE = 8388608
MAX_FINDINGS = 8
GUIDES = frozenset({"ATTACK-CLASSES.md", "AI-AND-LLM.md", "CLIENT-SIDE.md",
    "CLOUD-AND-DEPLOYMENT.md", "DATA-ISOLATION-AND-LIFECYCLE.md",
    "DESKTOP-MOBILE-AND-LOCAL-IPC.md", "MEMORY-SAFETY-AND-BINARY.md",
    "PROTOCOLS-RPC-AND-MESSAGING.md", "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md",
    "SUPPLY-CHAIN-AND-RELEASE.md", "WEB-PROTOCOL-AND-AUTH.md"})
DIMENSIONS = ("surface", "boundary", "subsystem", "attack_class")
AGENT = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
DEVICE = re.compile(r"(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)", re.I)
IGNORABLE = re.compile("[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u3164\ufe00-\ufe0f\uffa0\ufff0-\ufff8\U000e0000-\U000e0fff]")


def require(ok, message):
    if not ok:
        deny(message)


def fields(value, expected):
    require(isinstance(value, dict) and set(value) == set(expected), "unexpected research fields")


def text(value, maximum=400):
    require(isinstance(value, str) and 0 < len(value) <= maximum and value.strip() == value,
            "invalid bounded research text")
    require(all(unicodedata.category(c) not in {"Cc", "Cf", "Cs", "Zl", "Zp"} for c in value)
            and not IGNORABLE.search(value) and any(not c.isspace() for c in value), "invisible research text")
    return value


def agent_id(value):
    require(isinstance(value, str) and AGENT.fullmatch(value) and not DEVICE.match(value),
            "invalid canonical agent identity")
    return value


def relative_path(value):
    text(value, 240)
    require(not value.startswith(("/", "~")) and ":" not in value and "\\" not in value,
            "research path must be repository relative")
    require(all(p not in ("", ".", "..") and not p.endswith((" ", ".")) and not DEVICE.match(p)
                for p in value.split("/")), "unsafe research path component")
    return value


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def decode(raw, maximum=MAX_BUNDLE):
    require(isinstance(raw, bytes) and 0 < len(raw) <= maximum, "research input exceeds byte limit")
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            require(key not in obj, "duplicate research JSON field")
            obj[key] = value
        return obj
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=lambda _: deny("nonfinite research number"))
        def bounded(node, depth=0):
            require(depth <= 32, "research JSON nesting exceeds limit")
            if isinstance(node, dict):
                require(len(node) <= 128, "too many research object fields")
                for k, v in node.items():
                    text(k, 256)
                    bounded(v, depth + 1)
            elif isinstance(node, list):
                require(len(node) <= 256, "research array exceeds limit")
                for v in node:
                    bounded(v, depth + 1)
            elif isinstance(node, str):
                require(len(node) <= 8192 and not any(unicodedata.category(c) == "Cs" for c in node),
                        "invalid research string")
        bounded(value)
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise ExecutionDenied("malformed bounded research JSON") from exc


def canonical_coverage_id(refs):
    require(isinstance(refs, dict), "coverage references must be an object")
    keys = (*DIMENSIONS, "lifecycle") if "lifecycle" in refs else DIMENSIONS
    fields(refs, keys)
    for value in refs.values():
        text(value, 1024)
        require(unicodedata.normalize("NFC", value) == value, "noncanonical coverage reference")
    return "::".join(quote(refs[k], safe="-._~", encoding="utf-8") for k in keys)


def seed_unit(seed, scope):
    fields(seed, {"canonical_refs", "starting_paths", "guides", "exclusion"})
    identity = canonical_coverage_id(seed["canonical_refs"])
    paths = seed["starting_paths"]
    require(isinstance(paths, list) and 1 <= len(paths) <= 8 and len(set(paths)) == len(paths),
            "invalid coverage starting paths")
    require(all(relative_path(p) in scope for p in paths), "coverage escaped approved source files")
    require(isinstance(seed["guides"], list) and 1 <= len(seed["guides"]) <= len(GUIDES)
            and len(set(seed["guides"])) == len(seed["guides"])
            and set(seed["guides"]) <= GUIDES, "unapproved hunting guide")
    if seed["exclusion"] is not None:
        text(seed["exclusion"])
    refs = seed["canonical_refs"]
    return {"coverage_id": identity, "canonical_refs": refs, **refs,
            "starting_paths": sorted(paths), "ordinary_attack_class_block": refs["attack_class"],
            "selected_companion_blocks": sorted(seed["guides"]), "excluded_blocks": [],
            "prior_status": "none", "attempts": [], "wave": 1,
            "status": "out_of_scope" if seed["exclusion"] else "planned", "agent_id": None,
            "reviewed_paths": [], "local_checks": [], "result_fingerprints": [],
            "unresolved": [seed["exclusion"]] if seed["exclusion"] else []}


def validate_ledger(units):
    """The state, owner, history and canonical-ID invariants of the upstream ledger."""
    require(isinstance(units, list) and len(units) <= MAX_UNITS, "coverage ledger exceeds bound")
    identities = []
    semantics = set()
    for unit in units:
        require(isinstance(unit, dict), "invalid coverage unit")
        fields(unit, {"coverage_id", "canonical_refs", *DIMENSIONS, "starting_paths",
                      "ordinary_attack_class_block", "selected_companion_blocks", "excluded_blocks",
                      "prior_status", "attempts", "wave", "status", "agent_id", "reviewed_paths",
                      "local_checks", "result_fingerprints", "unresolved"} |
                     ({"lifecycle"} if "lifecycle" in unit else set()))
        require(unit["prior_status"] in {"new", "none", "prior_confirmed_same_source", "prior_confirmed_changed_source",
                "prior_needs_validation", "prior_deferred", "prior_blocked", "prior_out_of_scope",
                "prior_covered_same_source", "prior_covered_changed_source", "prior_rejected_claim_changed"},
                "invalid prior coverage status")
        require(isinstance(unit["starting_paths"], list) and 1 <= len(unit["starting_paths"]) <= 8,
                "missing bounded starting paths")
        for path in unit["starting_paths"]:
            relative_path(path)
        require(len(set(unit["starting_paths"])) == len(unit["starting_paths"]), "duplicate starting paths")
        text(unit["ordinary_attack_class_block"], 1024)
        require(isinstance(unit["selected_companion_blocks"], list) and len(unit["selected_companion_blocks"]) <= 32
                and isinstance(unit["excluded_blocks"], list) and len(unit["excluded_blocks"]) <= 32,
                "unbounded coverage guide selection")
        for block in unit["selected_companion_blocks"]:
            text(block)
        excluded = []
        for block in unit["excluded_blocks"]:
            fields(block, {"block", "reason"}); text(block["block"]); text(block["reason"])
            excluded.append(block["block"])
        require(len(set(excluded)) == len(excluded) and
                len(set(unit["selected_companion_blocks"])) == len(unit["selected_companion_blocks"]) and
                not set(excluded) & set(unit["selected_companion_blocks"]), "conflicting coverage guide selection")
        require(isinstance(unit["attempts"], list) and len(unit["attempts"]) <= 32, "unbounded coverage history")
        identity = canonical_coverage_id(unit["canonical_refs"])
        require(unit["coverage_id"] == identity, "coverage identity mismatch")
        semantic = tuple(unit[k] for k in unit["canonical_refs"])
        require(all(unit[k] == v for k, v in unit["canonical_refs"].items()) and semantic not in semantics,
                "ambiguous coverage semantics")
        semantics.add(semantic)
        identities.append(identity)
        require(type(unit["wave"]) is int and unit["wave"] >= 1, "invalid coverage wave")
        prior_owners, prior_artifacts = set(), set()
        previous_wave = 0
        for record in [*unit["attempts"], unit]:
            state = record["status"]
            require(isinstance(state, str) and state in {"planned", "in_progress", "covered", "candidate", "blocked",
                              "deferred", "out_of_scope", "not_applicable"}, "invalid coverage state")
            if record is not unit:
                fields(record, {"wave", "status", "agent_id", "reviewed_paths", "local_checks",
                                "result_fingerprints", "unresolved", "reassignment_reason"})
                require(state in {"covered", "candidate", "blocked"} and
                        previous_wave < record["wave"] < unit["wave"], "invalid coverage attempt history")
                text(record["reassignment_reason"])
                previous_wave = record["wave"]
            owner = record["agent_id"]
            assigned = state in {"in_progress", "covered", "candidate", "blocked"}
            require((owner is not None) == assigned, "coverage ownership/state mismatch")
            if owner is not None:
                agent_id(owner)
                require(owner not in prior_owners, "coverage reassignment reused its owner")
            for key in ("reviewed_paths", "local_checks", "result_fingerprints", "unresolved"):
                require(isinstance(record[key], list) and len(record[key]) <= 32, "unbounded coverage evidence")
            paths, checks, findings, unresolved = (record[k] for k in
                ("reviewed_paths", "local_checks", "result_fingerprints", "unresolved"))
            for p in paths:
                relative_path(p)
            for value in unresolved:
                text(value)
            for value in findings:
                text(value, 1024)
            require(len(set(paths)) == len(paths) and len(set(findings)) == len(findings), "duplicate coverage evidence")
            if state in {"planned", "in_progress", "deferred", "out_of_scope", "not_applicable"}:
                require(not paths and not checks and not findings, "unperformed coverage claims evidence")
            else:
                require(paths and checks, "coverage conclusion lacks owned evidence")
            require(bool(findings) == (state == "candidate"), "coverage/finding linkage mismatch")
            if state in {"planned", "in_progress", "covered"}:
                require(not unresolved, "coverage state contradicts unresolved work")
            if state in {"blocked", "deferred", "out_of_scope", "not_applicable"}:
                require(unresolved, "coverage gap needs a reason")
            owned_paths = set()
            artifacts = set()
            for check in checks:
                fields(check, {"agent_id", "reviewed_paths", "invariant", "method", "result", "artifact"})
                agent_id(check["agent_id"])
                require(check["agent_id"] not in prior_owners, "reassignment reused previous evidence owner")
                require(check["reviewed_paths"] and isinstance(check["reviewed_paths"], list), "check lacks paths")
                require(len(check["reviewed_paths"]) <= 32 and len(set(check["reviewed_paths"])) == len(check["reviewed_paths"]),
                        "unbounded or duplicate check paths")
                owned_paths.update(relative_path(p) for p in check["reviewed_paths"])
                text(check["invariant"]); text(check["result"])
                require(check["method"] in {"source", "local"}, "invalid coverage evidence method")
                if check["method"] == "source":
                    require(check["artifact"] is None, "source-only check has an artifact")
                else:
                    artifact = relative_path(check["artifact"])
                    require(artifact.startswith("agents/" + check["agent_id"] + "/artifacts/")
                            and artifact not in prior_artifacts, "artifact escaped its producing agent")
                    artifacts.add(artifact)
            require(set(paths) == owned_paths, "coverage paths lack an evidence owner")
            if record is not unit:
                prior_owners.add(owner)
                prior_artifacts.update(artifacts)
    require(identities == sorted(set(identities)), "coverage ledger must have unique sorted IDs")


def read_relative(root_fd, name, maximum=MAX_FILE):
    """Read one stable regular file through retained no-follow directory descriptors."""
    relative_path(name)
    parent = os.dup(root_fd)
    try:
        parts = name.split("/")
        for component in parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                    0 <= before.st_size <= maximum, "source/evidence file is not bounded regular material")
            data = bytearray()
            while len(data) <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(fd)
            require(len(data) == before.st_size and
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    "source/evidence changed during read")
            return bytes(data)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def source_snapshot(repository, paths, guard=lambda: None):
    require(isinstance(paths, list) and 1 <= len(paths) <= MAX_FILES and paths == sorted(set(paths)),
            "source scope must be a sorted unique bounded file list")
    snapshot, total = {}, 0
    with open_directory_nofollow(Path(repository)) as root:
        for name in paths:
            guard()
            raw = read_relative(root, name)
            total += len(raw)
            require(total <= MAX_SOURCE, "source snapshot exceeds byte budget")
            try:
                lines = raw.decode("utf-8").splitlines()
            except UnicodeError as exc:
                raise ExecutionDenied("source references require UTF-8 text") from exc
            snapshot[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "lines": lines}
    return snapshot


def source_references(refs, snapshot):
    require(isinstance(refs, list) and 1 <= len(refs) <= 8, "source evidence is missing or unbounded")
    require(len({digest(r) for r in refs}) == len(refs), "duplicate source evidence")
    for ref in refs:
        fields(ref, {"path", "start_line", "end_line", "sha256", "excerpt_sha256"})
        name = relative_path(ref["path"])
        require(name in snapshot and ref["sha256"] == snapshot[name]["sha256"], "source evidence is stale or out of scope")
        start, end = ref["start_line"], ref["end_line"]
        require(type(start) is int and type(end) is int and 1 <= start <= end <= len(snapshot[name]["lines"])
                and end - start < 80, "source line range is invalid")
        excerpt = "\n".join(snapshot[name]["lines"][start-1:end]).encode("utf-8")
        require(ref["excerpt_sha256"] == hashlib.sha256(excerpt).hexdigest(), "source excerpt does not match current bytes")
    return sorted({r["path"] for r in refs})
