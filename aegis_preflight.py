#!/usr/bin/env python3
"""Fail-closed scope-manifest preflight, NOT a runtime sandbox or authorization grant.

The privileged execution supervisor MUST pin AEGIS_TRUST_POLICY to an operator-
controlled, read-only file outside agent/target-writable locations. It MUST invoke
this preflight and independently enforce the granted restrictions at runtime.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator
import yaml


BASE = Path(__file__).resolve().parent
# Domain separation prevents an AEGIS signature being accepted in a different
# Ed25519 protocol that happens to use the same operator key.
SIGNING_CONTEXT = b"AEGIS-scope-v1\x00"
MAX_MANIFEST_BYTES = 256 * 1024

REQUIRED_APPROVALS = {
    "production_state_changes", "high_impact_exploitation", "destructive_tests",
    "service_disruption", "real_data_access", "credential_use_outside_test",
    "persistent_changes",
}


class PreflightError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def construct_unique_mapping(loader, node):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        require(isinstance(key, (str, int)), "YAML mapping key has unsupported type")
        require(key not in result, f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping)


def parse_utc(text: str) -> datetime:
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise PreflightError(f"invalid UTC timestamp: {text!r}") from exc


def normal_origin(value: str) -> str:
    require(isinstance(value, str), "origin must be a string")
    p = urlsplit(value)
    require(p.scheme in {"http", "https"} and p.hostname is not None, f"invalid HTTP origin: {value}")
    require(not p.username and not p.password and not p.path and not p.query and not p.fragment, f"origin must contain no credentials, path, query, or fragment: {value}")
    require("*" not in value and "@" not in value, "wildcards and userinfo are not allowed")
    require(p.hostname == p.hostname.lower(), "hostname must be normalized")
    try:
        port = p.port
    except ValueError as exc:
        raise PreflightError(f"invalid origin port: {value}") from exc
    require(port is None or 0 < port < 65536, "invalid port")
    require(value == value.lower(), f"origin must be lowercase and exact: {value}")
    require(value == f"{p.scheme}://{p.netloc}", f"origin must be an exact normalized origin: {value}")
    return value


def network(value: str):
    try:
        return ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise PreflightError(f"invalid CIDR network: {value}") from exc


def canon(path: str) -> Path:
    require(isinstance(path, str) and Path(path).is_absolute(), f"path must be absolute: {path}")
    return Path(path).resolve(strict=False)


def under(candidate: Path, root: Path, strict_child: bool = False) -> bool:
    return (candidate != root or not strict_child) and (candidate == root or root in candidate.parents)


def _load_trust(trust_path: Path):
    """Load operator-pinned policy; the protected path must be passed by supervisor."""
    require(trust_path.is_absolute(), "trusted policy location must be absolute")
    try:
        trust = json.loads(trust_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PreflightError(f"trusted policy unavailable or invalid: {exc}") from exc
    require(isinstance(trust, dict) and trust.get("schema_version") == 1
            and trust.get("configured") is True,
            "trusted policy not explicitly configured")
    try:
        signer = trust["operator"]
        key_path = canon(signer["public_key_pem_path"])
        key = load_pem_public_key(key_path.read_bytes())
        require(isinstance(key, Ed25519PublicKey), "trusted signing key must be Ed25519")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise PreflightError(f"trusted signing identity invalid: {exc}") from exc
    return trust, signer, key, key_path


def _read_manifest(manifest_path: Path) -> bytes:
    try:
        # Refuse oversized inputs before reading or parsing untrusted YAML.
        require(manifest_path.stat().st_size <= MAX_MANIFEST_BYTES,
                "manifest exceeds size limit")
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise PreflightError(f"manifest unavailable: {exc}") from exc
    require(len(raw) <= MAX_MANIFEST_BYTES, "manifest exceeds size limit")
    return raw


def _validate_contents(raw: bytes, trust: dict, signer: dict,
                       key_path: Path, trust_path: Path,
                       now: datetime | None = None) -> dict:
    """Apply identical content and target-policy checks for signing and preflight."""
    try:
        manifest = yaml.load(raw.decode("utf-8"), Loader=UniqueKeyLoader)
    except (UnicodeError, yaml.YAMLError) as exc:
        raise PreflightError(f"manifest cannot be parsed safely: {exc}") from exc
    require(isinstance(manifest, dict), "manifest must be a mapping")
    schema = json.loads((BASE / "security-scope.schema.json").read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(manifest), key=lambda x: list(map(str, x.path)))
    if errors:
        first = errors[0]
        raise PreflightError("manifest schema invalid at " + ".".join(map(str, first.path)) + ": " + first.message)

    eng = manifest["engagement"]
    eid = eng["id"]
    require(eng["signer_id"] == signer["signer_id"] and eng["authorized_by"] == signer["principal"],
            "declared authorization identity does not match pinned signer identity")
    require(eid in trust.get("approved_engagement_ids", []), "engagement ID not approved by trusted policy")
    require(eid not in trust.get("revoked_engagement_ids", []), "engagement has been revoked")

    start, end = parse_utc(eng["valid_from_utc"]), parse_utc(eng["valid_until_utc"])
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    # The operator-maintained revocation snapshot must be recent. This assumes
    # the trusted policy updater verifies the source and protects its timestamp.
    rev = trust.get("revocation")
    require(isinstance(rev, dict), "trusted revocation snapshot is missing")
    max_staleness = rev.get("max_staleness_seconds")
    require(type(max_staleness) is int and 1 <= max_staleness <= 3600,
            "invalid trusted revocation freshness ceiling")
    last_checked = parse_utc(rev.get("last_checked_utc", ""))
    age = (current - last_checked).total_seconds()
    require(0 <= age <= max_staleness, "trusted revocation snapshot stale or future-dated")
    require(start < end, "authorization window not increasing")
    require(start <= current < end, "engagement not currently authorized")
    max_hours = trust.get("max_authorization_hours")
    require(type(max_hours) in (int, float) and 0 < max_hours <= 24 * 365, "invalid trusted authorization-window ceiling")
    require((end - start).total_seconds() <= max_hours * 3600, "authorization window exceeds trusted maximum")

    targets = manifest["targets"]
    origins = {normal_origin(o) for o in targets["origins"]}
    excluded_origins = {normal_origin(o) for o in targets["excluded_origins"]}
    trusted_origins = {normal_origin(o) for o in trust.get("allowed_origins", [])}
    require(origins <= trusted_origins, "manifest origins exceed independently approved allowlist")
    require(not origins.intersection(excluded_origins), "a target origin is also explicitly excluded")

    networks = [network(n) for n in targets["networks"]]
    excluded_networks = [network(n) for n in targets["excluded_networks"]]
    trusted_networks = [network(n) for n in trust.get("allowed_networks", [])]
    for n in networks:
        require(any(n.subnet_of(parent) for parent in trusted_networks), f"CIDR exceeds approved allowlist: {n}")
        require(not any(n.overlaps(ex) for ex in excluded_networks), f"CIDR overlaps a manifest exclusion: {n}")

    repo_roots = [canon(x) for x in trust.get("allowed_repository_roots", [])]
    repositories = [canon(x) for x in targets["repositories"]]
    for p in repositories:
        require(p.is_dir(), f"repository directory does not exist: {p}")
        require(any(under(p, root) for root in repo_roots), f"repository outside trusted roots: {p}")
    for p in (trust_path.resolve(), key_path):
        require(not any(under(p, repo) for repo in repositories), "trust material must not be inside target repo")

    for a in manifest["accounts"]:
        allowed = {normal_origin(o) for o in a["allowed_origins"]}
        require(allowed <= origins and not allowed.intersection(excluded_origins),
                f"test account {a['role']!r} includes a host outside approved assets")

    allowed_methods = set(manifest["methods"]["allowed"])
    require(allowed_methods <= set(trust.get("approved_methods", [])), "manifest method exceeds trusted permission")
    require(REQUIRED_APPROVALS <= set(manifest["methods"]["requires_approval"]),
            "baseline high-impact approval gates must not be removed")

    ceilings = trust.get("limits_ceiling", {})
    for name, value in manifest["limits"].items():
        ceiling = ceilings.get(name)
        require(type(ceiling) is int and ceiling > 0 and value <= ceiling,
                f"budget {name} exceeds or lacks a trusted ceiling")
    lim = manifest["limits"]
    require(lim["max_single_run_minutes"] <= lim["engagement_runtime_minutes"],
            "single run exceeds cumulative engagement time")
    require(lim["deterministic_hypothesis_minutes"] <= lim["max_single_run_minutes"],
            "single deterministic hypothesis exceeds permitted run time")
    if origins or networks:
        require(lim["max_total_requests"] > 0 and lim["max_requests_per_minute_per_origin"] > 0 and lim["max_concurrent_requests"] > 0,
                "network testing requires explicit nonzero network limits")

    out = canon(manifest["reporting"]["output_dir"])
    alert = canon(manifest["reporting"]["critical_alert"]["path"])
    report_roots = [canon(x) for x in trust.get("allowed_report_roots", [])]
    alert_roots = [canon(x) for x in trust.get("allowed_alert_roots", [])]
    require(out.name == eid and any(under(out, root, strict_child=True) for root in report_roots),
            "output directory must be an engagement-specific child of trusted reporting root")
    require(alert.name == eid + ".ndjson" and any(under(alert, root, strict_child=True) for root in alert_roots),
            "critical alert path must be inside approved alert root")
    require(not any(under(out, repo) or under(alert, repo) for repo in repositories),
            "reports and alert sinks cannot be written inside assessed repositories")
    require(out.parent.is_dir() and os.access(out.parent, os.W_OK),
            "reporting parent directory is unavailable or unwritable")
    require(alert.parent.is_dir() and os.access(alert.parent, os.W_OK),
            "critical alert sink directory is unavailable or unwritable")

    return {
        "status": "PREFLIGHT_VERIFIED_NOT_RUNTIME_ENFORCEMENT",
        "engagement_id": eid,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "authorized_until_utc": eng["valid_until_utc"],
        "revocation_snapshot_checked_at_utc": rev["last_checked_utc"],
        "revocation_max_staleness_seconds": max_staleness,
        "authorized_origins": sorted(origins),
        "authorized_repositories": [str(p) for p in repositories],
        "authorized_networks": [str(n) for n in networks],
        "approved_methods": sorted(allowed_methods),
        "report_directory": str(out),
    }


def validate(manifest_path: Path, signature_path: Path, trust_path: Path,
             now: datetime | None = None) -> dict:
    """Verify signature BEFORE parsing YAML; trust path must be supervisor-pinned."""
    trust, signer, key, key_path = _load_trust(trust_path)
    raw = _read_manifest(manifest_path)
    try:
        sig = signature_path.read_bytes()
        require(len(sig) == 64, "detached Ed25519 signature must be exactly 64 bytes")
        key.verify(sig, SIGNING_CONTEXT + raw)
    except InvalidSignature as exc:
        raise PreflightError("detached manifest signature failed verification") from exc
    except OSError as exc:
        raise PreflightError(f"signature/trust verification failed: {exc}") from exc
    return _validate_contents(raw, trust, signer, key_path, trust_path, now)


def validate_for_signing(manifest_path: Path, trust_path: Path,
                         signing_key, now: datetime | None = None) -> tuple[bytes, dict]:
    """Operator-side lint/policy check prior to signing, not an authorization grant."""
    trust, signer, pinned_public, key_path = _load_trust(trust_path)
    require(isinstance(signing_key, Ed25519PrivateKey), "private key must be Ed25519")
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key_bytes = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pinned_bytes = pinned_public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    require(key_bytes == pinned_bytes, "private key does not match pinned signing identity")
    raw = _read_manifest(manifest_path)
    result = _validate_contents(raw, trust, signer, key_path, trust_path, now)
    return raw, result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="absolute path to signed scope manifest")
    parser.add_argument("--signature", required=True, type=Path, help="path to raw 64-byte detached .sig")
    args = parser.parse_args(argv)
    trust_text = os.environ.get("AEGIS_TRUST_POLICY")
    if not trust_text:
        print("DENIED: AEGIS_TRUST_POLICY must be pinned by the trusted supervisor", file=sys.stderr)
        return 2
    try:
        result = validate(args.manifest, args.signature, Path(trust_text))
    except (PreflightError, FileNotFoundError, PermissionError) as exc:
        print(f"DENIED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
