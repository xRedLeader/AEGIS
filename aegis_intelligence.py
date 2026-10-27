#!/usr/bin/env python3
"""Operator-attested OSV snapshot correlation; no network or code execution.

The signature attests who admitted a bounded advisory snapshot; it cannot prove
that a remote database is complete, current, or authentic by itself. Only
explicit OSV affected-version enumeration is matched. Ecosystem/Git/SemVer
range-only data is unresolved, never converted into a false negative.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONTEXT = b"AEGIS-osv-intelligence-snapshot-v1\x00"
MAX_BUNDLE = 1024 * 1024
MAX_INVENTORY = 32768
MAX_RECORDS = 250
MAX_CANDIDATES = 150
ADVISORY_ID = re.compile(r"[A-Z0-9][A-Z0-9._-]{2,79}\Z")
PACKAGE_NAME = re.compile(r"(?:@[a-z0-9_.-]{1,80}/)?[a-z0-9_.-]{1,128}\Z")


class IntelligenceDenied(ValueError):
    pass


def fail(reason):
    raise IntelligenceDenied(reason)


def protected_bytes(file: Path, maximum: int, *, private=False) -> bytes:
    """Reject final-component links and unsafe owners/permissions and sizes."""
    file = Path(file)
    if not file.is_absolute():
        fail("protected intelligence file path must be absolute")
    try:
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_size > maximum or st.st_size < 0 or
                    st.st_uid not in (0, os.geteuid()) or
                    st.st_mode & (0o077 if private else 0o022)):
                fail("untrusted intelligence file owner, permissions or size")
            raw = os.read(fd, maximum + 1)
            if len(raw) > maximum:
                fail("intelligence input exceeds byte limit")
            return raw
        finally:
            os.close(fd)
    except OSError as exc:
        raise IntelligenceDenied("intelligence material unavailable") from exc


def timestamp(utc: str) -> datetime:
    if not isinstance(utc, str) or not utc.endswith("Z"):
        fail("freshness timestamp must be UTC")
    try:
        dt = datetime.fromisoformat(utc.replace("Z", "+00:00"))
    except (ValueError, OverflowError) as exc:
        raise IntelligenceDenied("invalid snapshot timestamp") from exc
    if dt.utcoffset().total_seconds() != 0:
        fail("timestamp must be UTC")
    return dt


def _json_no_dupes(raw: bytes):
    def unique(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                fail("duplicate JSON key in intelligence snapshot")
            obj[k] = v
        return obj
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: fail("invalid JSON numeric constant"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise IntelligenceDenied("invalid JSON intelligence snapshot") from exc


def validate_snapshot(bundle: dict, *, now: datetime | None = None, max_age_hours=72) -> dict:
    if (not isinstance(bundle, dict) or
            set(bundle) != {"format", "source", "source_url", "retrieved_at_utc", "records"} or
            bundle["format"] != "AEGIS-OSV-v1" or bundle["source"] != "OSV" or
            bundle["source_url"] != "https://api.osv.dev" or
            not isinstance(bundle["records"], list) or len(bundle["records"]) > MAX_RECORDS or
            type(max_age_hours) is not int or not 1 <= max_age_hours <= 168):
        fail("invalid source-attested intelligence bundle format")
    age = ((now or datetime.now(timezone.utc)) - timestamp(bundle["retrieved_at_utc"])).total_seconds()
    if not 0 <= age <= max_age_hours * 3600:
        fail("intelligence snapshot stale or future-dated")
    if len(bundle["records"]) == 0:
        fail("empty OSV snapshot cannot support negative assessment")
    ids = set()
    for rec in bundle["records"]:
        if not isinstance(rec, dict) or not isinstance(rec.get("id"), str) or not ADVISORY_ID.fullmatch(rec["id"]):
            fail("unusable OSV advisory ID")
        if rec["id"] in ids:
            fail("duplicate advisory ID")
        ids.add(rec["id"])
        if not isinstance(rec.get("affected", []), list) or len(rec.get("affected", [])) > 128:
            fail("unbounded advisory affected records")
    return bundle


def load_signed_snapshot(bundle_path: Path, signature_path: Path, public_key_path: Path, *, now=None) -> tuple[dict, str]:
    raw = protected_bytes(bundle_path, MAX_BUNDLE)
    signature = protected_bytes(signature_path, 64, private=True)
    key_raw = protected_bytes(public_key_path, 8192)
    if len(signature) != 64:
        fail("signed intelligence digest absent")
    try:
        key = load_pem_public_key(key_raw)
        if not isinstance(key, Ed25519PublicKey):
            fail("intelligence signer must use Ed25519")
        key.verify(signature, CONTEXT + raw)
    except (InvalidSignature, ValueError) as exc:
        raise IntelligenceDenied("invalid intelligence snapshot signature or pinned key") from exc
    return validate_snapshot(_json_no_dupes(raw), now=now), hashlib.sha256(raw).hexdigest()


def canonical(ecosystem: str, name: str) -> str | None:
    if ecosystem == "PyPI" and isinstance(name, str) and len(name) <= 128:
        n = re.sub(r"[-_.]+", "-", name).lower()
        return n if PACKAGE_NAME.fullmatch(n) else None
    if ecosystem == "npm" and isinstance(name, str) and name == name.lower():
        return name if PACKAGE_NAME.fullmatch(name) else None
    return None


def correlate(inventory: dict, bundle: dict, *, digest: str = "") -> dict:
    """Only exact enumerated OSV versions create dependency leads."""
    if (not isinstance(inventory, dict) or inventory.get("status") != "OFFLINE_DEPENDENCY_INVENTORY_NOT_VULNERABILITY_VERIFICATION" or
            not isinstance(inventory.get("packages"), list) or len(inventory["packages"]) > 150):
        fail("dependency inventory is untrusted or malformed")
    if not isinstance(bundle, dict) or bundle.get("format") != "AEGIS-OSV-v1":
        fail("OSV snapshot must be validated before correlation")
    leads, unresolved, withdrawals = [], 0, 0
    for dependency in inventory["packages"]:
        if (not isinstance(dependency, dict) or set(dependency) != {"ecosystem", "name", "version", "source", "classification"} or
                not isinstance(dependency["version"], str) or len(dependency["version"]) > 80 or
                canonical(dependency["ecosystem"], dependency["name"]) is None):
            fail("malformed dependency coordinate")
        for advisory in bundle["records"]:
            if advisory.get("withdrawn"):
                withdrawals += 1
                continue
            for affected in advisory.get("affected", []):
                if not isinstance(affected, dict):
                    fail("invalid advisory affected entry")
                pkg = affected.get("package")
                if not isinstance(pkg, dict) or not isinstance(pkg.get("ecosystem"), str):
                    fail("invalid advisory package field")
                e = pkg["ecosystem"]
                n = canonical(e, pkg.get("name"))
                if e != dependency["ecosystem"] or n != dependency["name"]:
                    continue
                versions = affected.get("versions", [])
                ranges = affected.get("ranges", [])
                if not isinstance(versions, list) or len(versions) > 10000 or not isinstance(ranges, list):
                    fail("invalid advisory version evidence")
                if dependency["version"] in versions:
                    if len(leads) >= MAX_CANDIDATES:
                        fail("candidate count cap exceeded; do not imply complete coverage")
                    leads.append({"advisory_id": advisory["id"], "ecosystem": e, "package": n,
                                  "version": dependency["version"], "source": dependency["source"],
                                  "classification": "OSV_ENUMERATED_VERSION_LEAD_NOT_CONFIRMED_EXPLOITABLE"})
                elif ranges:
                    unresolved += 1
    return {"status": "SIGNED_OSV_ADVISORY_LEADS_NOT_EXPLOIT_VERIFICATION",
            "source": "OSV", "retrieved_at_utc": bundle["retrieved_at_utc"],
            "bundle_sha256": digest, "leads": leads,
            "summary": {"dependency_entries": len(inventory["packages"]), "exact_version_leads": len(leads),
                        "range_only_associations_unresolved": unresolved, "withdrawn_entries_skipped": withdrawals},
            "limitations": ["Absence from this bounded snapshot does not mean no vulnerability exists.",
                            "Only enumerated OSV versions are correlated; ranges require ecosystem-aware verification.",
                            "The signer attests admission/freshness, not completeness of OSV data or exploitability."]}
