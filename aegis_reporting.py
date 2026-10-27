#!/usr/bin/env python3
"""v1.8: operator-only, evidence-bound report producer and durable notice enqueue.

Never accept free-form model findings as verified impact. Only the fixed, already
completed source/fuzz/OSV evidence families can be projected into *unverified*
leads. Keep the original v1 schema for old reports; v2 is an explicit migration.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import uuid

from jsonschema import Draft202012Validator
from aegis_audit import AuditError, verify_rows
from aegis_supervisor import (AegisSupervisor, ExecutionDenied, deny,
                              open_directory_nofollow, private_directory, O_DIR)

HERE = Path(__file__).resolve().parent
MAX_EVIDENCE = 32768
MAX_REPORT = 65536
ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SAFE_ID = re.compile(r"[@.A-Za-z0-9_][@A-Za-z0-9._/-]{0,180}\Z")
FAMILIES = {"bounded-fuzz.json": "bounded_fuzz", "source-review.json": "source_review",
            "advisory-candidates.json": "osv_advisory"}
RULE_IDS = {"PY-SHELL-TRUE", "PY-PICKLE-LOAD", "PY-EVAL", "PY-TLS-NOVERIFY",
            "JS-TLS-NOVERIFY", "JS-EVAL"}


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def safe(value, max_length=180) -> str:
    if (not isinstance(value, str) or len(value) > max_length or
            not SAFE_ID.fullmatch(value) or "//" in value or
            any(p in (".", "..") for p in value.split("/"))):
        deny("evidence has an unsafe identifier")
    return value


def limited_int(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        deny("evidence has an invalid bounded count")
    return value


def projection(raw: bytes, filename: str, eid: str, run_id: str, ended: str):
    """Allowlist source evidence; never accept asserted severities or impact."""
    if filename not in FAMILIES or not 0 < len(raw) <= MAX_EVIDENCE:
        deny("unsupported bounded evidence")
    try:
        obj = json.loads(raw, parse_constant=lambda _: deny("invalid JSON constant"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ExecutionDenied("malformed assessment evidence") from exc
    if not isinstance(obj, dict):
        deny("assessment evidence must be an object")
    source_digest = hashlib.sha256(raw).hexdigest()
    source_path = "runs/" + run_id + "/" + filename
    kind = FAMILIES[filename]
    items = []
    def lead(title, asset, index, blocker, plan):
        # The identity is bound to the exact run *and* evidence bytes, not a model description.
        token = hashlib.sha256(canonical([eid, run_id, source_digest, index])).hexdigest()[:20]
        items.append({"id": "A18-" + token, "verdict": "needs_validation", "title": title,
                      "affected_asset": asset, "evidence_sha256": source_digest,
                      "evidence_ref": source_path + "#item=" + str(index),
                      "description": "Automatically extracted security lead; no deployed impact established.",
                      "blocker": blocker, "validation_plan": plan})
    if kind == "source_review":
        if obj.get("status") != "STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES":
            deny("incompatible source-review evidence")
        candidates = obj.get("candidates")
        if not isinstance(candidates, list) or len(candidates) > 64:
            deny("unbounded source-review candidates")
        for i, c in enumerate(candidates):
            if (not isinstance(c, dict) or c.get("id") not in RULE_IDS or
                    c.get("status") != "unverified_static_lead"):
                deny("invalid source-review candidate")
            asset = safe(c.get("file"), 180)
            line = limited_int(c.get("line"), 10000000)
            if line == 0: deny("zero line index")
            lead("Static security pattern " + c["id"], asset + ":" + str(line), i,
                 "A textual match alone does not establish a reachable security boundary failure.",
                 "Trace input to sink and reproduce safely in an authorized isolated fixture.")
        tested = "Bounded static rule review of explicitly authorized repository."
        limits = "A heuristic match is not runtime exploit evidence; scanned files may be truncated."
    elif kind == "bounded_fuzz":
        if (obj.get("status") != "BOUNDED_OFFLINE_AUTHORIZATION_REPRODUCTION_ONLY" or
                obj.get("mode") != "fuzz" or not isinstance(obj.get("candidates"), list) or
                len(obj["candidates"]) > 5):
            deny("incompatible local reproduction evidence")
        contract = safe(obj.get("contract"), 100)
        for i,c in enumerate(obj["candidates"]):
            if (not isinstance(c, dict) or
                    c.get("classification") not in ("local_oracle_mismatch_needs_validation",
                         "local_contract_mismatch_needs_validation", "local_nondeterministic_case_needs_validation")):
                deny("unexpected local reproduction candidate")
            index = limited_int(c.get("case_index"), 64)
            lead("Synthetic contract mismatch " + contract, "contract/" + contract + "/case/" + str(index), i,
                 "Synthetic result does not prove the deployed call path or production authorization policy.",
                 "Independently replay the case, inspect the real boundary and verify effective controls.")
        tested = "Operator-approved isolated synthetic security-contract testing."
        limits = "Local mismatches or instability do not establish deployed exploitability."
    else:
        if (obj.get("status") != "SIGNED_OSV_ADVISORY_LEADS_NOT_EXPLOIT_VERIFICATION" or
                not isinstance(obj.get("leads"), list) or len(obj["leads"]) > 150):
            deny("incompatible OSV evidence")
        safe(obj.get("bundle_sha256"))
        for i,c in enumerate(obj["leads"]):
            if (not isinstance(c, dict) or
                    c.get("classification") != "OSV_ENUMERATED_VERSION_LEAD_NOT_CONFIRMED_EXPLOITABLE"):
                deny("invalid OSV lead")
            advisory = safe(c.get("advisory_id"),80)
            ecosystem = safe(c.get("ecosystem"),40)
            name = safe(c.get("package"),140)
            version = safe(c.get("version"),80)
            lead("Potential dependency advisory " + advisory, ecosystem + "/" + name + "@" + version, i,
                 "An affected declared version does not prove installation, reachability or exploitability.",
                 "Verify installed version, affected conditions, fixed versions and reachable application paths.")
        tested = "Operator-attested bounded OSV enumerated-version correlation."
        limits = "Missing/range-only advisories, incomplete feeds and runtime dependencies are not cleared."
    report = {"schema_version": 2, "engagement_id": eid, "source_run_id": run_id,
        "generated_at_utc": ended, "assessment_status": "limited_source_evidence_only",
        "source_evidence": {"relative_path": source_path, "sha256": source_digest, "kind": kind},
        "findings": items, "coverage": {
            "tested": [tested],
            "untested": ["Deployment reachability and attacker impact are not established by this source artifact."],
            "limitations": [limits]}}
    schema = json.loads((HERE / "findings-v2.schema.json").read_text())
    errors = list(Draft202012Validator(schema).iter_errors(report))
    if errors: deny("canonical report failed v2 schema")
    return report


def markdown(report):
    """All prose derived from schema-checked canonical data; no raw source text."""
    findings = report["findings"]
    eid = report["engagement_id"]
    run = report["source_run_id"]
    lines = ["# AEGIS bounded security assessment", "", "Engagement: `" + eid + "`",
             "Source run: `" + run + "`", "", "**Assessment is limited, not a clean bill of security.**", "",
             "## Findings", "", "| Verdict | Finding | Asset |", "|---|---|---|"]
    for item in findings:
        lines.append("| Needs validation | " + item["title"] + " | `" + item["affected_asset"] + "` |")
    if not findings: lines.append("| — | No leads in this bounded source artifact | — |")
    lines += ["", "## Coverage and limitations", ""]
    for key in ("tested", "untested", "limitations"):
        lines.append("### " + key.capitalize())
        lines.extend("- " + x for x in report["coverage"][key]);lines.append("")
    needs = ["# Leads requiring validation", ""]
    for item in findings:
        needs.extend(["## " + item["id"] + ": " + item["title"], "",
                      "- Asset: `" + item["affected_asset"] + "`",
                      "- Evidence: `" + item["evidence_ref"] + "`",
                      "- Blocker: " + item["blocker"],
                      "- Next step: " + item["validation_plan"], ""])
    if not findings: needs.append("No leads were produced by this particular source artifact; other coverage remains untested.")
    detail = "# Confirmed security findings\n\nNo independently confirmed findings are present in this automated projection.\n"
    return {"REPORT.md": "\n".join(lines) + "\n", "NEEDS-VALIDATION.md": "\n".join(needs) + "\n",
            "FINDINGS-DETAIL.md": detail}


class ReportingSupervisor(AegisSupervisor):
    @staticmethod
    def _tables(con):
        con.execute("""CREATE TABLE IF NOT EXISTS assessment_reports (
            source_run_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
            source_sha256 TEXT NOT NULL, report_sha256 TEXT NOT NULL,
            report_path TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS notification_outbox (
            notice_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
            source_run_id TEXT NOT NULL, report_sha256 TEXT NOT NULL,
            lead_count INTEGER NOT NULL, status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0, lease_until REAL NOT NULL DEFAULT 0,
            last_failure TEXT, acknowledged_utc TEXT)""")

    def _read_source(self, info, run_id, filename):
        with open_directory_nofollow(Path(info["report_directory"]) / "runs" / run_id) as directory:
            private_directory(directory)
            fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            try:
                st = os.fstat(fd)
                if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or
                        st.st_mode & 0o077 or st.st_nlink != 1 or not 0 < st.st_size <= MAX_EVIDENCE):
                    deny("evidence must be private, bounded and unlinkable")
                raw = os.read(fd, MAX_EVIDENCE + 1)
                if len(raw) != st.st_size: deny("evidence source changed during read")
                after = os.fstat(fd)
                if (st.st_ino, st.st_dev, st.st_size) != (after.st_ino, after.st_dev, after.st_size):
                    deny("unstable evidence source")
                return raw
            finally:
                os.close(fd)

    @staticmethod
    def _write_report_dir(root, source_id, contents):
        """Exclusive directory promotion; no write-through or symlink overwrite."""
        os.mkdir("assessments", 0o700, dir_fd=root) if not _exists_dir(root, "assessments") else None
        folder = os.open("assessments", O_DIR, dir_fd=root)
        try:
            private_directory(folder)
            stage = ".stage-" + uuid.uuid4().hex
            os.mkdir(stage, 0o700, dir_fd=folder)
            temp = os.open(stage, O_DIR, dir_fd=folder)
            try:
                for filename, raw in contents.items():
                    f = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=temp)
                    try:
                        view = memoryview(raw)
                        while view:
                            n = os.write(f, view)
                            if n < 1: deny("short report artifact write")
                            view = view[n:]
                        os.fsync(f)
                    finally: os.close(f)
                os.fsync(temp)
            finally:os.close(temp)
            # Linux RENAME_NOREPLACE is required: ordinary rename may replace an
            # empty existing directory. No silent overwrite of retained reports.
            lib = ctypes.CDLL(None, use_errno=True)
            rename = getattr(lib, "renameat2", None)
            if rename is None:
                deny("atomic no-replace report promotion unsupported")
            rename.argtypes = [ctypes.c_int, ctypes.c_char_p,
                               ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            rename.restype = ctypes.c_int
            if rename(folder, stage.encode(), folder, source_id.encode(), 1) != 0:
                number = ctypes.get_errno()
                if number == errno.EEXIST:
                    deny("assessment report already exists")
                raise OSError(number, "atomic report promotion failed")
            os.fsync(folder)
        finally:
            # Never leave a failed staging directory behind for a future run
            # to mistake for a completed or operator-approved report.
            try:
                leftover=os.open(stage, O_DIR, dir_fd=folder)
                try:
                    for filename in contents:
                        try:os.unlink(filename,dir_fd=leftover)
                        except FileNotFoundError:pass
                finally:os.close(leftover)
                os.rmdir(stage,dir_fd=folder)
            except FileNotFoundError:pass  # successfully renamed
            finally:os.close(folder)

    @staticmethod
    def _match_existing(root, source_id, contents):
        """Idempotence requires byte-identical artifacts, no hard/symlinks."""
        folder=os.open("assessments", O_DIR, dir_fd=root)
        try:
            fd=os.open(source_id, O_DIR, dir_fd=folder)
            try:
                private_directory(fd)
                for filename, original in contents.items():
                    item=os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        st=os.fstat(item)
                        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or
                                st.st_mode & 0o077 or st.st_nlink != 1 or st.st_size != len(original)):
                            deny("retained report permissions or size changed")
                        if os.read(item,len(original)+1)!=original:
                            deny("retained report changed since generation")
                    finally:os.close(item)
            finally:os.close(fd)
        finally:os.close(folder)

    def generate(self, run_id: str, filename: str) -> dict:
        if not isinstance(run_id, str) or not ID.fullmatch(run_id) or filename not in FAMILIES:
            deny("invalid assessment run or evidence type")
        info, _ = self._guard()
        eid = info["engagement_id"]
        with self._database() as con:
            record = con.execute("SELECT status,ended_utc FROM runs WHERE run_id=? AND engagement_id=?",
                                 (run_id, eid)).fetchone()
            if not record or record[0] != "completed" or not record[1]:
                deny("cannot report incomplete or foreign run")
            try: verify_rows(con.execute("SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq").fetchall())
            except AuditError as exc: raise ExecutionDenied("report audit verification failed") from exc
        raw = self._read_source(info, run_id, filename)
        canonical_report = projection(raw, filename, eid, run_id, record[1])
        result = canonical(canonical_report)
        digest = hashlib.sha256(result).hexdigest()
        rendered = markdown(canonical_report)
        package = {"findings.json": result, **{k:v.encode("utf-8") for k,v in rendered.items()}}
        package["integrity.json"] = canonical({"report_sha256": digest, "artifacts":
             {k:hashlib.sha256(v).hexdigest() for k,v in package.items()}})
        if sum(map(len, package.values())) > MAX_REPORT:deny("bounded report output exceeded")
        self._guard()  # revocation/stop before persisting any new artifact
        dest = Path(info["report_directory"]) / "assessments" / run_id
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            previous = con.execute("SELECT source_sha256,report_sha256 FROM assessment_reports WHERE source_run_id=? AND engagement_id=?",(run_id,eid)).fetchone()
            if previous:
                if previous != (canonical_report["source_evidence"]["sha256"], digest):
                    deny("existing report identity mismatch")
                with open_directory_nofollow(Path(info["report_directory"])) as root:
                    private_directory(root)
                    self._match_existing(root,run_id,package)
                return {"status":"ASSESSMENT_ALREADY_QUEUED", "report":str(dest / "findings.json"),
                        "sha256":digest,"lead_count":len(canonical_report["findings"])}
            with open_directory_nofollow(Path(info["report_directory"]),create=True) as root:
                private_directory(root)
                folder=Path(info["report_directory"]) / "assessments" / run_id
                if folder.exists() or folder.is_symlink():
                    self._match_existing(root,run_id,package)
                else:
                    self._write_report_dir(root,run_id,package)
            notice_id = hashlib.sha256(canonical([eid,run_id,digest])).hexdigest()
            con.execute("INSERT INTO assessment_reports VALUES(?,?,?,?,?)",
                        (run_id,eid,canonical_report["source_evidence"]["sha256"],digest,str(dest)))
            con.execute("INSERT INTO notification_outbox(notice_id,engagement_id,source_run_id,report_sha256,lead_count,status) VALUES(?,?,?,?,?,'pending')",
                        (notice_id,eid,run_id,digest,len(canonical_report["findings"])))
            self._event(con,{"type":"assessment_report_generated","engagement_id":eid,
                             "source_run_id":run_id,"report_sha256":digest,"lead_count":len(canonical_report["findings"]),
                             "notice_id":notice_id})
            con.commit()
        return {"status":"ASSESSMENT_QUEUED", "report":str(dest / "findings.json"),
                "sha256":digest,"lead_count":len(canonical_report["findings"]),"notice_id":notice_id}


def _exists_dir(fd, name):
    try: os.stat(name,dir_fd=fd,follow_symlinks=False);return True
    except FileNotFoundError:return False


def main(argv=None):
    ap=argparse.ArgumentParser(description="Operator-only v1.8 verified-report producer")
    for n in ("manifest","signature","trust","state-root","run-id","evidence"):
        ap.add_argument("--"+n,required=True)
    a=ap.parse_args(argv)
    try:
        sup=ReportingSupervisor(a.manifest,a.signature,a.trust,a.state_root)
        print(json.dumps(sup.generate(a.run_id,a.evidence),sort_keys=True))
        return 0
    except (OSError,ExecutionDenied,ValueError,TypeError) as exc:
        print("REPORT_DENIED",file=sys.stderr)
        return 2


if __name__=="__main__":raise SystemExit(main())
