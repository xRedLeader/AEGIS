#!/usr/bin/env python3
"""Non-executing, fixed-schema imports for externally run security scanners.

This module never launches a scanner or trusts its commands, descriptions,
paths, links, or remediation scripts. Imported findings are unverified leads.
"""
from __future__ import annotations
import json
import re
from aegis_intelligence import IntelligenceDenied, canonical, ADVISORY_ID, _json_no_dupes

MAX_REPORT = 512 * 1024
MAX_LEADS = 150


def import_scanner_report(kind: str, raw: bytes) -> dict:
    if kind not in ("pip-audit-json", "npm-audit-v2") or not isinstance(raw, bytes) or len(raw) > MAX_REPORT:
        raise IntelligenceDenied("unknown or oversized scanner report")
    doc = _json_no_dupes(raw)
    if not isinstance(doc, dict):
        raise IntelligenceDenied("scanner report must be an object")
    leads, skipped = [], 0
    if kind == "pip-audit-json":
        entries = doc.get("dependencies")
        if not isinstance(entries, list) or len(entries) > 2000:
            raise IntelligenceDenied("invalid pip-audit dependency list")
        for dep in entries:
            if not isinstance(dep, dict):
                skipped += 1; continue
            name = canonical("PyPI", dep.get("name"))
            version = dep.get("version")
            vulns = dep.get("vulns", [])
            if not name or not isinstance(version, str) or len(version) > 80 or not isinstance(vulns, list) or len(vulns) > 100:
                skipped += 1;continue
            for finding in vulns:
                if not isinstance(finding, dict) or not isinstance(finding.get("id"), str) or not ADVISORY_ID.fullmatch(finding["id"]):
                    skipped += 1; continue
                if len(leads) >= MAX_LEADS:
                    raise IntelligenceDenied("scanner lead cap exceeded")
                leads.append({"advisory_id": finding["id"], "ecosystem": "PyPI", "package": name,
                              "version": version, "classification": "UNVERIFIED_EXTERNAL_SCANNER_LEAD"})
    else:
        vulnerabilities = doc.get("vulnerabilities")
        if not isinstance(vulnerabilities, dict) or len(vulnerabilities) > 2000:
            raise IntelligenceDenied("invalid npm audit vulnerabilities mapping")
        for name_raw, finding in sorted(vulnerabilities.items()):
            name = canonical("npm", name_raw)
            if not name or not isinstance(finding, dict):
                skipped += 1;continue
            via = finding.get("via", [])
            if not isinstance(via, list) or len(via) > 100:
                skipped += 1;continue
            # npm audit v2 does not provide an installed version per advisory;
            # 'range' text cannot justify an exact affected-version claim.
            for item in via:
                if not isinstance(item, dict):
                    skipped += 1;continue
                vid = item.get("name")
                if not isinstance(vid, str) or not ADVISORY_ID.fullmatch(vid):
                    skipped += 1;continue
                if len(leads) >= MAX_LEADS:
                    raise IntelligenceDenied("scanner lead cap exceeded")
                leads.append({"advisory_id": vid, "ecosystem": "npm", "package": name,
                              "version": None, "classification": "UNVERIFIED_EXTERNAL_SCANNER_ASSOCIATION_VERSION_UNKNOWN"})
    return {"status": "UNVERIFIED_EXTERNAL_SCANNER_LEADS", "adapter": kind,
            "leads": leads, "summary": {"leads": len(leads), "unresolved_entries": skipped},
            "limitations": ["Scanner output is untrusted, and results are not confirmed vulnerabilities.",
                            "No scanner, package manager, or remediation command was executed."]}
