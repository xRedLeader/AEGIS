"""Read-only, exact-candidate release evidence reconciliation; never grants approval."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from aegis_audit import AUDIT_CONTEXT, _validate_payload, verify_rows
from aegis_audit_contract import canonical, digest, fields, read_relative, relative_path, require, text
from aegis_scanner_contract import MAX_INPUT, observed_time, sha256, strict_json
from aegis_supervisor import ExecutionDenied, open_directory_nofollow, private_directory

SIGNOFF_CONTEXT = b"AEGIS-RELEASE-SIGNOFF-v1\x00"
MACHINE_GATES = frozenset({"ci_ubuntu_22_04", "ci_ubuntu_24_04", "ci_agent_delegation",
    "ci_native_scanners_22_04", "ci_native_scanners_24_04",
    "ci_packaged_services_22_04", "ci_packaged_services_24_04",
    "ci_notification_receiver", "ci_source_integrity", "installed_host", "staging_proof",
    "recovery_drills", "delivery_drills"})
ROLES = frozenset({"independent_reviewer", "signing_key_custodian", "off_host_custodian", "release_owner"})
UNITTEST_GATES = frozenset({"ci_ubuntu_22_04", "ci_ubuntu_24_04",
                            "ci_native_scanners_22_04", "ci_native_scanners_24_04"})


def commit(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{40}", value), "full candidate commit required")
    return value


def reference(root, ref):
    fields(ref, {"path", "sha256"})
    sha256(ref["sha256"])
    raw = read_relative(root, relative_path(ref["path"]), MAX_INPUT)
    require(hashlib.sha256(raw).hexdigest() == ref["sha256"], "evidence reference digest differs")
    return raw


def git_source(root, candidate):
    """Compare regular tracked bytes directly to Git objects; never run filters/hooks."""
    from aegis_git_evidence import read_commit
    inventory = {}
    with open_directory_nofollow(Path(root)) as fd:
        for name, body in read_commit(root, candidate).items():
            require(read_relative(fd, name, 4*1024*1024) == body, "installed source differs from exact candidate")
            inventory[name] = hashlib.sha256(body).hexdigest()
    require("SHA256SUMS.txt" in inventory, "source checksum manifest missing")
    from aegis_source_integrity import verify
    verify(root, set(inventory))
    return inventory


def signed(public, signature, domain, payload):
    key = load_pem_public_key(public)
    require(isinstance(key, Ed25519PublicKey) and len(signature) == 64, "invalid release verification material")
    key.verify(signature, domain+canonical(payload))


def validate_record(record, candidate, maximum_age, now):
    fields(record, {"schema_version", "candidate_sha", "kind", "observed_at_utc", "result", "details", "artifacts"})
    require(type(record["schema_version"]) is int and record["schema_version"] == 1 and
            record["candidate_sha"] == candidate and record["kind"] in MACHINE_GATES and record["result"] == "PASS",
            "machine observation is mixed, unsupported or unsuccessful")
    observed_time(record["observed_at_utc"], maximum_age, now)
    details = record["details"]
    require(isinstance(details, dict), "machine observation details missing")
    if record["kind"].startswith("ci_"):
        require(re.fullmatch(r"https://github\.com/[^/]+/[^/]+/actions/runs/[0-9]+/job/[0-9]+", details.get("job_url", "")),
                "exact CI job reference required")
        require(details.get("head_sha") == candidate and details.get("conclusion") == "success", "CI candidate/result differs")
        if record["kind"] in UNITTEST_GATES:
            require(type(details.get("tests")) is int and details["tests"] > 0 and
                    type(details.get("skipped")) is int and details["skipped"] == 0, "test count or no-skip evidence missing")
    elif record["kind"] == "installed_host":
        for name in ("host_identity_sha256", "configuration_sha256", "dependency_inventory_sha256"):
            sha256(details.get(name))
        require(details.get("installed_commit") == candidate and details.get("kernel_acceptance") == "PASS" and
                details.get("packaged_services") == "PASS", "installed host acceptance is incomplete")
    else:
        sha256(details.get("engagement_scope_sha256"))
        required = {"staging_proof": {"proof_admission", "forged_proof_rejected", "remediation_retest"},
            "recovery_drills": {"crash", "expired_lease", "stop", "revocation", "no_silent_rerun", "audited_abandonment"},
            "delivery_drills": {"successful_ack", "failed_delivery", "receiver_restart"}}[record["kind"]]
        require(all(details.get(k) == "PASS" for k in required), "required drill/proof observation missing")
    require(isinstance(record["artifacts"], list) and 1 <= len(record["artifacts"]) <= 32,
            "machine observations need bounded original artifact references")


def collect(bundle_root, source_root, candidate, trust_path, *, now=None):
    """All diagnostics are fixed labels: source, logs, host details and actor names stay private."""
    now = now or datetime.now(timezone.utc)
    commit(candidate)
    checks, observations, accepted_roles = [], {}, []
    def check(name, operation):
        try:
            value = operation()
            checks.append({"check": name, "result": "PASS"})
            return value
        except Exception:
            checks.append({"check": name, "result": "MISSING_INVALID_OR_STALE"})
            return None
    inventory = check("exact_candidate_source", lambda: git_source(source_root, candidate))
    with open_directory_nofollow(Path(bundle_root)) as root:
        private_directory(root)
        bundle = strict_json(read_relative(root, "bundle.json", MAX_INPUT))
        fields(bundle, {"schema_version", "candidate_sha", "created_at_utc", "max_age_seconds",
                        "source_manifest_sha256", "observations", "checkpoint", "signoffs"})
        require(type(bundle["schema_version"]) is int and bundle["schema_version"] == 1 and
                bundle["candidate_sha"] == candidate, "release bundle candidate/schema differs")
        observed_time(bundle["created_at_utc"], bundle["max_age_seconds"], now)
        check("source_manifest_binding", lambda: require(inventory is not None and
              inventory["SHA256SUMS.txt"] == sha256(bundle["source_manifest_sha256"]), "source manifest differs"))
        require(isinstance(bundle["observations"], list) and len(bundle["observations"]) <= len(MACHINE_GATES), "unbounded machine observations")
        for ref in bundle["observations"]:
            def observation():
                record = strict_json(reference(root, ref))
                validate_record(record, candidate, bundle["max_age_seconds"], now)
                require(record["kind"] not in observations, "duplicate machine observation")
                artifacts = [reference(root, artifact) for artifact in record["artifacts"]]
                if record["kind"] in UNITTEST_GATES:
                    logs = b"\n".join(artifacts).decode("utf-8", "replace")
                    # Strip GitHub's presentation prefix only after hashing the retained bytes.
                    logs = re.sub(r"(?m)^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
                                  r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z ", "", logs)
                    counts = re.findall(r"(?m)^Ran ([0-9]+) tests? in [^\r\n]+", logs)
                    endings = re.findall(r"(?m)^OK(?: \(([^\r\n]*)\))?\s*$", logs)
                    require(counts and int(counts[-1]) == record["details"]["tests"] and endings and
                            endings[-1] in {"", "skipped=0"} and not re.search(r"(?m)^FAILED(?: |$)", logs),
                            "retained regression output differs from supplied test counts/result")
                observations[record["kind"]] = ref["sha256"]
            check("supplied_machine_record_"+str(len(checks)), observation)
        for gate in sorted(MACHINE_GATES - observations.keys()):
            checks.append({"check": gate, "result": "MISSING_INVALID_OR_STALE"})
        with open_directory_nofollow(Path(trust_path).parent) as trust_root:
            private_directory(trust_root)
            trust = strict_json(read_relative(trust_root, Path(trust_path).name, 32768))
            fields(trust, {"schema_version", "role_keys", "checkpoint_key"})
            require(type(trust["schema_version"]) is int and trust["schema_version"] == 1 and
                    isinstance(trust["role_keys"], dict) and set(trust["role_keys"]) <= ROLES,
                    "invalid independently selected release trust")
            def checkpoint():
                fields(bundle["checkpoint"], {"record", "ledger"})
                anchor = strict_json(reference(root, bundle["checkpoint"]["record"]))
                fields(anchor, {"payload", "signature_hex"})
                payload = _validate_payload(anchor["payload"])
                observed_time(payload["created_utc"], bundle["max_age_seconds"], now)
                signed(reference(trust_root, trust["checkpoint_key"]), bytes.fromhex(anchor["signature_hex"]), AUDIT_CONTEXT, payload)
                ledger = strict_json(reference(root, bundle["checkpoint"]["ledger"]))
                fields(ledger, {"ledger_id", "rows"})
                count, head, _ = verify_rows(ledger["rows"])
                require(ledger["ledger_id"] == payload["ledger_id"] and count == payload["sequence"] and
                        head == payload["head_sha256"], "checkpoint does not anchor complete supplied ledger snapshot")
            check("signed_checkpoint_and_ledger", checkpoint)
            require(isinstance(bundle["signoffs"], list) and len(bundle["signoffs"]) <= len(ROLES), "unbounded signoff references")
            for ref in bundle["signoffs"]:
                def signoff():
                    envelope = strict_json(reference(root, ref)); fields(envelope, {"payload", "signature_hex"})
                    payload = envelope["payload"]
                    fields(payload, {"schema_version", "candidate_sha", "role", "accountable_identity", "observed_at_utc", "decision", "evidence_sha256"})
                    role = payload["role"]
                    require(type(payload["schema_version"]) is int and payload["schema_version"] == 1 and
                            payload["candidate_sha"] == candidate and role in ROLES and
                            role not in accepted_roles and payload["decision"] == "accepted", "signoff is not an accepted exact-candidate decision")
                    text(payload["accountable_identity"], 128)
                    observed_time(payload["observed_at_utc"], bundle["max_age_seconds"], now)
                    expected = digest({"observations": observations, "checkpoint": bundle["checkpoint"],
                                       "source_manifest_sha256": bundle["source_manifest_sha256"],
                                       "created_at_utc": bundle["created_at_utc"], "max_age_seconds": bundle["max_age_seconds"]})
                    require(payload["evidence_sha256"] == expected, "signoff refers to different evidence")
                    signed(reference(trust_root, trust["role_keys"][role]), bytes.fromhex(envelope["signature_hex"]), SIGNOFF_CONTEXT, payload)
                    accepted_roles.append(role)
                check("supplied_signoff_"+str(len(checks)), signoff)
    machine_complete = not any(c["result"] != "PASS" for c in checks if not c["check"].startswith("supplied_signoff_"))
    return {"schema_version": 1, "candidate_sha": candidate, "status": "NOT_PRODUCTION_APPROVED",
            "machine_evidence_complete": machine_complete, "checks": checks,
            "signed_roles": sorted(accepted_roles), "pending_roles": sorted(ROLES-set(accepted_roles)),
            "note": "Artifact integrity and signature checks do not establish truthful CI results, reviewer independence, actual staging impact or off-host custody. Accountable release review remains required."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "source", "trust"):
        parser.add_argument("--"+name, required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    args = parser.parse_args(argv)
    try:
        result = collect(args.bundle, args.source, args.candidate, args.trust)
        print(canonical(result).decode())
        return 0 if result["machine_evidence_complete"] else 1
    except Exception:
        print('{"status":"NOT_PRODUCTION_APPROVED","error":"release evidence inputs missing, invalid or stale"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
