"""Pinned offline source/secret report parsers; vendor text is inert and discarded."""
from __future__ import annotations

from aegis_audit_contract import relative_path, require
from aegis_scanner_contract import MAX_OBSERVATIONS, identifier, observation

PINS = {"semgrep": ("1.125.0", "semgrep-json-v1"),
        "codeql": ("2.23.8", "sarif-2.1.0"), "gitleaks": ("8.24.3", "gitleaks-json-v8")}
SAST_LIMITATION = "Only shipped C#/JavaScript/TypeScript fixture rules are regression-proven; Java, Go, infrastructure and other rules are unvalidated."


def pinned(policy, name):
    detector = policy["detector"]
    require(detector == {"name": name, "version": PINS[name][0], "report_schema": PINS[name][1]},
            "unsupported source scanner release/schema")


def collection(value, maximum=MAX_OBSERVATIONS):
    require(isinstance(value, list) and len(value) <= maximum, "invalid or oversized scanner record collection")
    return value


def source_location(path, start, end, context, revision=None, start_column=None, end_column=None,
                    *, utf16=False, inclusive=False):
    path = relative_path(path)
    require(not any(c in path for c in ("%", "?", "#")), "encoded or ambiguous scanner source path")
    sources = context.get("history_sources", {}).get(revision, {}) if revision else context["source"]
    require(path in sources, "scanner source location is outside the approved snapshot")
    lines = sources[path]["lines"]
    require(type(start) is int and type(end) is int and 1 <= start <= end <= len(lines) and end-start < 80,
            "scanner source range is unsafe or oversized")
    def width(line):
        return len(line.encode("utf-16-le"))//2 if utf16 else len(line.encode("utf-8"))
    if start_column is not None:
        require(type(start_column) is int and 1 <= start_column <= width(lines[start-1])+1, "invalid scanner start column")
    if end_column is not None:
        require(type(end_column) is int and 1 <= end_column <= width(lines[end-1])+(0 if inclusive else 1),
                "invalid scanner end column")
    if start == end and start_column is not None and end_column is not None:
        require(start_column <= end_column, "reversed scanner source columns")
    return path


def parse_semgrep(doc, policy, context):
    pinned(policy, "semgrep")
    require(policy["input"]["kind"] == "source" and isinstance(doc, dict) and doc.get("version") == "1.125.0",
            "Semgrep requires its pinned current-source JSON export")
    results = collection(doc.get("results"))
    errors = collection(doc.get("errors"), 256)
    paths = doc.get("paths")
    require(isinstance(paths, dict), "Semgrep scanned-path manifest is missing")
    scanned = collection(paths.get("scanned"), 128)
    require(all(isinstance(p, str) and relative_path(p) in context["source"] for p in scanned) and
            len(scanned) == len(set(scanned)), "Semgrep scanned paths differ from selected source")
    skipped = collection(paths.get("skipped", []), 256)
    skipped_rules = collection(doc.get("skipped_rules", []), 256)
    records = []
    for result in results:
        require(isinstance(result, dict) and isinstance(result.get("start"), dict) and isinstance(result.get("end"), dict),
                "invalid Semgrep location record")
        start, end = result["start"], result["end"]
        require(type(start.get("col")) is int and type(end.get("col")) is int, "Semgrep column fields are missing or invalid")
        path = source_location(result.get("path"), start.get("line"), end.get("line"), context,
                               start_column=start.get("col"), end_column=end.get("col"))
        require(path in scanned, "Semgrep finding was not in its scanned-file manifest")
        records.append(observation("source", identifier(result.get("check_id")), path=path,
                                   start_line=start["line"], end_line=end["line"]))
    unresolved = len(errors)+len(skipped)+len(skipped_rules)+len(set(context["source"])-set(scanned))
    return {"observations": records, "coverage": {"assessed_records": len(scanned), "unresolved_records": unresolved,
        "limitations": ["Captured coverage is limited to selected rules; no taint or language-completeness claim.",
                        "Scanner messages, source snippets, fixes and commands are discarded.", SAST_LIMITATION]}}


def sarif_location(location, run):
    require(isinstance(location, dict), "invalid SARIF artifact location")
    artifacts = collection(run.get("artifacts", []), 2000)
    if "index" in location:
        index = location["index"]
        require(type(index) is int and 0 <= index < len(artifacts) and isinstance(artifacts[index], dict), "unsafe SARIF artifact index")
        indexed = artifacts[index].get("location")
        require(isinstance(indexed, dict), "SARIF indexed artifact lacks a location")
        for key in ("uri", "uriBaseId"):
            require(key not in location or location[key] == indexed.get(key), "SARIF artifact index/location mismatch")
        location = {**indexed, **location}
    require(location.get("uriBaseId") in (None, "%SRCROOT%"), "external SARIF URI base is unsupported")
    return location.get("uri")


def parse_codeql(doc, policy, context):
    pinned(policy, "codeql")
    require(policy["input"]["kind"] == "source" and isinstance(doc, dict) and doc.get("version") == "2.1.0",
            "CodeQL requires its pinned current-source SARIF export")
    runs = collection(doc.get("runs"), 8)
    require(runs, "CodeQL SARIF lacks a run")
    records, unresolved = [], 0
    for run in runs:
        require(isinstance(run, dict) and isinstance(run.get("tool"), dict), "invalid CodeQL SARIF run")
        driver = run["tool"].get("driver")
        require(isinstance(driver, dict) and driver.get("name") == "CodeQL" and driver.get("semanticVersion") == "2.23.8",
                "CodeQL producer identity/version mismatch")
        require(run.get("columnKind", "utf16CodeUnits") == "utf16CodeUnits", "unsupported SARIF column convention")
        rules = collection(driver.get("rules"), 256)
        require(all(isinstance(rule, dict) for rule in rules), "invalid SARIF rule registry")
        rule_ids = [identifier(rule.get("id")) for rule in rules]
        require(len(rule_ids) == len(set(rule_ids)), "duplicate SARIF rule identity")
        invocations = collection(run.get("invocations"), 8)
        require(invocations, "CodeQL execution status is absent")
        for invocation in invocations:
            require(isinstance(invocation, dict) and type(invocation.get("executionSuccessful")) is bool,
                    "invalid CodeQL execution status")
            unresolved += int(not invocation["executionSuccessful"])
            for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
                notices = collection(invocation.get(key, []), 256)
                require(all(isinstance(n, dict) for n in notices), "invalid CodeQL diagnostic records")
                unresolved += sum(n.get("level") in ("warning", "error") for n in notices)
        for result in collection(run.get("results")):
            require(isinstance(result, dict), "invalid SARIF finding record")
            rule = identifier(result.get("ruleId"))
            require(rule in rule_ids, "SARIF finding rule is absent from its registry")
            if "ruleIndex" in result:
                index = result["ruleIndex"]
                require(type(index) is int and 0 <= index < len(rule_ids) and rule_ids[index] == rule, "SARIF rule index mismatch")
            if "rule" in result:
                descriptor = result["rule"]
                require(isinstance(descriptor, dict) and descriptor.get("id") == rule and
                        descriptor.get("index") == rule_ids.index(rule), "SARIF rule descriptor mismatch")
            locations = collection(result.get("locations"), 1)
            require(len(locations) == 1 and isinstance(locations[0], dict), "SARIF requires one exact primary source location")
            physical = locations[0].get("physicalLocation")
            require(isinstance(physical, dict) and isinstance(physical.get("region"), dict), "SARIF source region is missing")
            region = physical["region"]
            start, end = region.get("startLine"), region.get("endLine", region.get("startLine"))
            path = source_location(sarif_location(physical.get("artifactLocation"), run), start, end, context,
                start_column=region.get("startColumn"), end_column=region.get("endColumn"), utf16=True)
            records.append(observation("source", rule, path=path, start_line=start, end_line=end))
            require(len(records) <= MAX_OBSERVATIONS, "CodeQL observation bound exceeded")
    return {"observations": records, "coverage": {"assessed_records": len(records), "unresolved_records": unresolved,
        "limitations": ["SARIF findings do not establish complete extraction, language or query coverage.",
                        "Code actions, messages, related traces, snippets and partial fingerprints are discarded.", SAST_LIMITATION]}}


def parse_gitleaks(doc, policy, context):
    pinned(policy, "gitleaks")
    kind = policy["input"]["kind"]
    require(kind in ("source", "history"), "Gitleaks requires explicit current-source or bounded history scope")
    records = []
    for result in collection(doc):
        require(isinstance(result, dict) and result.get("SymlinkFile", "") == "", "invalid or symlinked Gitleaks source")
        commit = result.get("Commit")
        require(isinstance(commit, str), "Gitleaks scan scope is missing")
        if kind == "history":
            require(commit in context.get("approved_revisions", []) and commit in context.get("history_sources", {}),
                    "Gitleaks history revision was not independently selected")
            revision = commit
        else:
            require(commit == "", "Git-history result cannot enter a current-source import")
            revision = None
        path = source_location(result.get("File"), result.get("StartLine"), result.get("EndLine"), context, revision,
            result.get("StartColumn"), result.get("EndColumn"), inclusive=True)
        rule = identifier(result.get("RuleID"))
        secret, match = result.get("Secret"), result.get("Match")
        require(isinstance(secret, str) and secret and isinstance(match, str) and match, "Gitleaks secret evidence fields are malformed")
        if secret != "REDACTED":
            source = context["history_sources"][revision] if revision else context["source"]
            excerpt = "\n".join(source[path]["lines"][result["StartLine"]-1:result["EndLine"]])
            require(secret.replace("\r\n", "\n") in excerpt, "Gitleaks detected value is absent from selected source range")
            require(secret not in path and secret not in rule and (not revision or secret not in revision),
                    "Gitleaks identity fields contain detected sensitive material")
        records.append(observation("secret", rule, path=path, start_line=result["StartLine"], end_line=result["EndLine"], revision=revision))
    return {"observations": records, "coverage": {"assessed_records": len(records), "unresolved_records": 0,
        "limitations": ["Suspected-secret leads only; credentials were not used, tested, revoked or rotated.",
                        "Secret, Match, descriptions, author metadata and vendor fingerprints are not retained.",
                        "Gitleaks JSON lists matches only; an empty report does not attest complete scan coverage."]}}
