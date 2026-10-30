"""Shared, inert scanner evidence contract. Vendor prose is never retained."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re

from aegis_audit_contract import canonical, digest, fields, relative_path, require, text
from aegis_security_tool_adapters import import_scanner_report
from aegis_supervisor import ExecutionDenied

MAX_INPUT = 524288
MAX_OBSERVATIONS = 64
ATTESTATION_CONTEXT = b"AEGIS-SCANNER-ATTESTATION-v1\x00"
HEX = re.compile(r"[a-f0-9]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+\-]{0,179}\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+~:\-]{0,79}\Z")
BASE_OBSERVATION = {"kind", "rule_id", "path", "start_line", "end_line", "package", "version", "ecosystem", "origin", "route", "revision"}


def strict_json(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_INPUT, "scanner input exceeds byte bound")
    def unique(pairs):
        require(len(pairs) <= 2000, "scanner object exceeds field bound")
        result = {}
        for key, value in pairs:
            require(len(key) <= 1024 and not any(0xD800 <= ord(c) <= 0xDFFF for c in key), "scanner JSON field is invalid or oversized")
            require(key not in result, "duplicate scanner JSON field")
            result[key] = value
        return result
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                            parse_constant=lambda _: require(False, "nonfinite scanner JSON number"))
        nodes = 0
        def bounded(value, depth=0):
            nonlocal nodes
            nodes += 1
            require(depth <= 32 and nodes <= 50000, "scanner JSON exceeds structural bound")
            if isinstance(value, (dict, list)):
                require(len(value) <= 2000, "scanner collection exceeds bound")
                for child in value.values() if isinstance(value, dict) else value:
                    bounded(child, depth + 1)
            elif isinstance(value, str):
                require(len(value) <= 65536 and not any(0xD800 <= ord(c) <= 0xDFFF for c in value),
                        "scanner string is invalid or oversized")
        bounded(result)
        return result
    except (ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ExecutionDenied("malformed scanner JSON") from exc


def sha256(value):
    require(isinstance(value, str) and HEX.fullmatch(value), "invalid evidence digest")
    return value


def identifier(value):
    require(isinstance(value, str) and IDENTIFIER.fullmatch(value), "unsafe scanner identifier")
    return value


def observed_time(value, maximum_age, now=None):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value), "scanner timestamp must be UTC seconds")
    require(type(maximum_age) is int and 1 <= maximum_age <= 31 * 86400, "invalid scanner freshness window")
    try:
        stamp = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ExecutionDenied("invalid scanner timestamp") from exc
    require(0 <= ((now or datetime.now(timezone.utc)) - stamp).total_seconds() <= maximum_age,
            "scanner evidence is stale or future-dated")


def validate_policy(policy):
    fields(policy, {"schema_version", "configured", "engagement_id", "detector", "configuration",
                    "report_sha256", "observed_at_utc", "max_age_seconds", "input", "allowed_rule_ids",
                    "provenance", "database"})
    require(type(policy["schema_version"]) is int and policy["schema_version"] == 1 and
            policy["configured"] is True, "scanner admission is not configured")
    text(policy["engagement_id"], 128)
    require(isinstance(policy["input"], dict), "scanner input selection is invalid")
    fields(policy["detector"], {"name", "version", "report_schema"})
    for value in policy["detector"].values():
        identifier(value)
    fields(policy["configuration"], {"path", "sha256"})
    sha256(policy["configuration"]["sha256"]); sha256(policy["report_sha256"])
    observed_time(policy["observed_at_utc"], policy["max_age_seconds"])
    require(isinstance(policy["allowed_rule_ids"], list) and len(policy["allowed_rule_ids"]) <= 256,
            "bounded operator-selected rules required")
    for value in policy["allowed_rule_ids"]:
        identifier(value)
    require(len(set(policy["allowed_rule_ids"])) == len(policy["allowed_rule_ids"]), "duplicate selected rule")
    if policy["database"] is not None:
        fields(policy["database"], {"sha256", "built_at_utc", "max_age_seconds"})
        sha256(policy["database"]["sha256"])
        observed_time(policy["database"]["built_at_utc"], policy["database"]["max_age_seconds"])
    provenance = policy["provenance"]
    fields(provenance, {"mode", "producer", "attestation_path", "signature_path", "public_key_path", "execution_run_id"})
    require(provenance["mode"] in {"operator_attested_external", "verified_ci", "aegis_governed"}, "unknown scanner provenance mode")
    identifier(provenance["producer"])
    if provenance["mode"] == "operator_attested_external":
        require(all(provenance[k] is None for k in ("attestation_path", "signature_path", "public_key_path", "execution_run_id")),
                "operator-attested import cannot claim execution or CI verification")
    elif provenance["mode"] == "verified_ci":
        require(provenance["execution_run_id"] is None and all(isinstance(provenance[k], str) for k in
                ("attestation_path", "signature_path", "public_key_path")), "CI import requires independently pinned signed provenance")
    else:
        require(isinstance(provenance["execution_run_id"], str) and all(provenance[k] is None for k in
                ("attestation_path", "signature_path", "public_key_path")), "governed import requires an internal execution receipt")


def attestation(policy, input_identity):
    return {"schema_version": 1, "engagement_id": policy["engagement_id"], "detector": policy["detector"],
            "configuration_sha256": policy["configuration"]["sha256"], "input_sha256": digest(input_identity),
            "report_sha256": policy["report_sha256"], "observed_at_utc": policy["observed_at_utc"],
            "database": policy["database"], "producer": policy["provenance"]["producer"]}


def observation(kind, rule_id, **values):
    return {"kind": kind, "rule_id": rule_id, **{k: values.get(k) for k in BASE_OBSERVATION - {"kind", "rule_id"}}}


def parse_report(raw, policy, context):
    """Only compiled-in adapters; additions must return the same bounded records."""
    doc = strict_json(raw)
    detector = policy["detector"]
    name = detector["name"]
    if name in {"semgrep", "codeql", "gitleaks"}:
        from aegis_source_scanners import parse_semgrep, parse_codeql, parse_gitleaks
        return {"semgrep": parse_semgrep, "codeql": parse_codeql, "gitleaks": parse_gitleaks}[name](doc, policy, context)
    if name in {"trivy", "grype"}:
        from aegis_extended_scanner_adapters import parse_package_report
        return parse_package_report(doc, policy, context)
    if name in {"zap", "nuclei"}:
        from aegis_extended_scanner_adapters import parse_staging_report
        return parse_staging_report(doc, policy, context)
    if name in {"pip-audit", "npm-audit"}:
        require((name, detector["version"], detector["report_schema"]) in {
            ("pip-audit", "2.9.0", "pip-audit-json"), ("npm-audit", "10.9.2", "npm-audit-v2")},
            "unsupported scanner release/schema")
        parsed = import_scanner_report(detector["report_schema"], raw)
        return {"observations": [observation("package", f["advisory_id"], package=f["package"],
                    ecosystem=f["ecosystem"], version=f["version"]) for f in parsed["leads"]],
                "coverage": {"assessed_records": len(parsed["leads"]),
                             "unresolved_records": parsed["summary"]["unresolved_entries"],
                             "limitations": ["External package output does not prove installed inventory or reachability."]}}
    require(False, "scanner release/schema has no admitted adapter")


def normalize(parsed, policy, context):
    fields(parsed, {"observations", "coverage"})
    records = parsed["observations"]
    require(isinstance(records, list) and len(records) <= MAX_OBSERVATIONS, "scanner observation bound exceeded")
    fields(parsed["coverage"], {"assessed_records", "unresolved_records", "limitations"})
    for key in ("assessed_records", "unresolved_records"):
        require(type(parsed["coverage"][key]) is int and 0 <= parsed["coverage"][key] <= 100000,
                "invalid scanner coverage count")
    require(isinstance(parsed["coverage"]["limitations"], list) and len(parsed["coverage"]["limitations"]) <= 8,
            "unbounded scanner limitations")
    for note in parsed["coverage"]["limitations"]:
        text(note)
    unique = {}
    for record in records:
        fields(record, BASE_OBSERVATION)
        require(record["kind"] in {"source", "secret", "package", "staging"}, "unknown scanner observation")
        require(identifier(record["rule_id"]) in policy["allowed_rule_ids"], "scanner rule was not independently selected")
        if record["kind"] in {"source", "secret"}:
            path = relative_path(record["path"])
            source = context["source"]
            if policy["input"]["kind"] == "history":
                require(record["revision"] in context.get("approved_revisions", []), "historical observation lacks selected revision")
                source = context["history_sources"][record["revision"]]
            else:
                require(record["revision"] is None, "current-source observation cannot assert history")
            require(path in source, "scanner location escaped selected source")
            start, end = record["start_line"], record["end_line"]
            require(type(start) is int and type(end) is int and 1 <= start <= end <= len(source[path]["lines"]),
                    "scanner source line is invalid")
            require(all(record[k] is None for k in ("package", "version", "ecosystem", "origin", "route")),
                    "source observation contains unrelated authority")
            require(record["revision"] is None or record["revision"] in context.get("approved_revisions", []),
                    "history revision is not approved")
        elif record["kind"] == "package":
            identifier(record["package"]); identifier(record["ecosystem"])
            require(record["version"] is None or isinstance(record["version"], str) and VERSION.fullmatch(record["version"]),
                    "invalid package version")
            require(all(record[k] is None for k in ("path", "start_line", "end_line", "origin", "route", "revision")),
                    "package observation contains unrelated authority")
        else:
            require(record["origin"] == context.get("origin") and record["route"] in context.get("routes", []),
                    "staging observation escaped approved origin or route")
            require(all(record[k] is None for k in ("path", "start_line", "end_line", "package", "version", "ecosystem", "revision")),
                    "staging observation contains unrelated authority")
        fingerprint = digest(record)
        unique[fingerprint] = {"fingerprint": fingerprint, **record}
    return {"observations": [unique[k] for k in sorted(unique)], "coverage": parsed["coverage"],
            "duplicates_removed": len(records) - len(unique)}


def report_projection(raw, eid, run_id, ended):
    evidence = strict_json(raw)
    require(evidence["status"] == "UNVERIFIED_SCANNER_IMPORT" and evidence["engagement_id"] == eid,
            "incompatible scanner evidence")
    sha = hashlib.sha256(raw).hexdigest()
    path = "runs/" + run_id + "/scanner-import.json"
    findings = []
    for index, item in enumerate(evidence["observations"]):
        asset = (item["path"] or (item["origin"] + item["route"] if item["kind"] == "staging" else
                 item["ecosystem"] + "/" + item["package"] + "@" + (item["version"] or "unresolved")))
        findings.append({"id": "A18-" + digest([eid, evidence["input_sha256"], item["fingerprint"]])[:20],
            "verdict": "needs_validation", "title": "Unverified " + evidence["detector"]["name"] + " rule " + item["rule_id"],
            "affected_asset": asset, "evidence_sha256": sha, "evidence_ref": path + "#item=" + str(index),
            "description": "An admitted scanner observation; scanner prose and sensitive raw output were not retained.",
            "blocker": "Scanner output does not establish deployed reachability, attacker impact or independent corroboration.",
            "validation_plan": "Review the source/artifact and obtain independently signed staging proof before confirmation."})
    coverage = evidence["coverage"]
    execution_note = ("Pinned scanner execution is recorded separately; this admission does not execute a tool or establish deployed impact."
                      if evidence["provenance"]["mode"] == "aegis_governed" else
                      "Import-only; no scanner, target request, build or package manager executed by this admission.")
    return {"schema_version": 2, "engagement_id": eid, "source_run_id": run_id, "generated_at_utc": ended,
        "assessment_status": "limited_source_evidence_only",
        "source_evidence": {"relative_path": path, "sha256": sha, "kind": "scanner_import"}, "findings": findings,
        "coverage": {"tested": ["Detector: " + evidence["detector"]["name"] + " " + evidence["detector"]["version"],
            "Provenance: " + evidence["provenance"]["mode"], "Input digest: " + evidence["input_sha256"],
            "Configuration digest: " + evidence["configuration_sha256"]],
            "untested": ["Unresolved records: " + str(coverage["unresolved_records"]),
                         "Deployment impact and remediation remain unverified."],
            "limitations": [execution_note,
                            "No findings is not a security clearance. Repeated observations are not independent corroboration.",
                            *coverage["limitations"]][:10]}}
