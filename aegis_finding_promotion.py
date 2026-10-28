#!/usr/bin/env python3
"""Operator-only, dual-signed, evidence-bound finding review and immutable promotion.

An Ed25519 verifier and a DIFFERENT operator sign the exact same canonical
review. A privately retained verification fixture is cryptographically pinned.
This is attestational acceptance, not automated proof that a deployed exploit
occurred. Neither agent output nor unsigned descriptions may promote findings.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from aegis_credentials import _protected_bytes
from aegis_audit import verify_rows, AuditError
from aegis_reporting import (ReportingSupervisor, canonical, report_package, verified_package,
    _publish_package, ID, O_DIR, private_directory, open_directory_nofollow)
from aegis_supervisor import ExecutionDenied, deny

VERIFY_CONTEXT = b"AEGIS-independent-finding-review-v1\x00"
APPROVE_CONTEXT = b"AEGIS-operator-finding-acceptance-v1\x00"
HEX = re.compile(r"[a-f0-9]{64}\Z")
FINDING = re.compile(r"A18-[a-f0-9]{20}\Z")
VERIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,63}\Z")
KEYS = frozenset({"version", "engagement_id", "source_run_id", "prior_report_sha256",
                  "source_evidence_sha256", "finding_id", "verdict", "verifier_id",
                  "operator_id", "reviewed_at_utc", "verification_evidence_sha256", "severity",
                  "demonstrated_impact", "remediation", "rejection_reason"})
ALLOWED_VERDICTS = frozenset({"confirmed", "rejected"})


def _review_text(value, length=400):
    # Prevent report-structure or Markdown injection in admitted human text.
    if (not isinstance(value, str) or not 5 <= len(value) <= length or
            any(ord(c) < 32 or ord(c) > 126 or c in "|<>`\\" for c in value)):
        deny("review contains unsafe or empty factual statement")
    return value


def _now(value):
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 40:
        deny("review timestamp must be UTC")
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.utcoffset().total_seconds() != 0:
            deny("review timestamp offset must be UTC")
        return date
    except (ValueError, TypeError, OverflowError) as exc:
        raise ExecutionDenied("invalid review UTC timestamp") from exc


def _read_bundle(directory: Path, review_name: str):
    # All files are service-protected and must be under an independently
    # provisioned review directory, never the assessed repository or report root.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,96}\.json", review_name):
        deny("review identifier invalid")
    with open_directory_nofollow(directory) as fd:
        st = os.fstat(fd)
        if st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o077:
            deny("review directory must be private")
    def read(name, size=8192):
        return _protected_bytes(directory / name, size, private=True)
    return read(review_name), read(review_name + ".verifier.sig", 256), read(review_name + ".operator.sig", 256), read(review_name + ".proof", 8192)


def _admit_review(policy_path, info, state):
    policy_path = Path(policy_path)
    if not policy_path.is_absolute():deny("review policy must be absolute")
    data = _protected_bytes(policy_path, 8192, private=True)
    try:policy = json.loads(data)
    except (UnicodeError, ValueError) as exc:raise ExecutionDenied("invalid review policy") from exc
    keys = {"schema_version", "configured", "review_dir", "verifier_public_key_path",
            "operator_public_key_path", "max_age_seconds", "allowed_engagement_ids"}
    if (not isinstance(policy, dict) or set(policy) != keys or
            policy["schema_version"] != 1 or policy["configured"] is not True or
            type(policy["max_age_seconds"]) is not int or not 30 <= policy["max_age_seconds"] <= 86400 or
            not isinstance(policy["allowed_engagement_ids"], list) or
            info["engagement_id"] not in policy["allowed_engagement_ids"]):
        deny("review policy not explicitly configured for engagement")
    protected = [state, Path(info["report_directory"]),
                 *[Path(p) for p in info["authorized_repositories"]]]
    if any(policy_path == forbidden or forbidden in policy_path.parents for forbidden in protected):
        deny("review policy cannot live under mutable assessment artifacts")
    for field in ("review_dir", "verifier_public_key_path", "operator_public_key_path"):
        value = policy[field]
        if not isinstance(value, str) or not value.startswith("/") or any(p in (".", "..") for p in value.split("/")):
            deny("review policy paths must be protected absolute paths")
        path = Path(value)
        if any(path == prohibited or prohibited in path.parents for prohibited in protected):
            deny("verification material overlaps mutable target/report/state")
    for field in ("review_dir", "verifier_public_key_path", "operator_public_key_path"):
        if policy_path == Path(policy[field]) or Path(policy[field]) in policy_path.parents:
            deny("review policy hierarchy unexpectedly overlaps verification material")
    return policy


def _get_key(path):
    try:key = load_pem_public_key(_protected_bytes(Path(path), 8192, private=True))
    except (ValueError, TypeError) as exc:raise ExecutionDenied("invalid verifier/operator key") from exc
    if not isinstance(key, Ed25519PublicKey):deny("review signer must be Ed25519")
    return key


class FindingPromotionSupervisor(ReportingSupervisor):
    def promote(self, run_id, review_policy_file, review_name):
        if not isinstance(run_id, str) or not ID.fullmatch(run_id):deny("invalid promoted run")
        info, _ = self._guard()
        eid = info["engagement_id"]
        policy = _admit_review(review_policy_file, info, self.state_root)
        raw, signed_verifier, signed_operator, proof = _read_bundle(Path(policy["review_dir"]), review_name)
        if len(raw) > 8192 or not 0 < len(proof) <= 8192:
            deny("bounded review/proof sizes invalid")
        try:
            review = json.loads(raw)
            if not isinstance(review, dict) or canonical(review) != raw or set(review) != KEYS:
                deny("review payload must have canonical fixed fields")
        except (ValueError, UnicodeError, TypeError) as exc:
            raise ExecutionDenied("invalid canonical review") from exc
        if (review["version"] != 1 or review["engagement_id"] != eid or
                review["source_run_id"] != run_id or review["verdict"] not in ALLOWED_VERDICTS or
                not isinstance(review["finding_id"], str) or not FINDING.fullmatch(review["finding_id"]) or
                not isinstance(review["prior_report_sha256"], str) or not HEX.fullmatch(review["prior_report_sha256"]) or
                not isinstance(review["source_evidence_sha256"], str) or not HEX.fullmatch(review["source_evidence_sha256"]) or
                not isinstance(review["verification_evidence_sha256"], str) or
                not HEX.fullmatch(review["verification_evidence_sha256"]) or
                hashlib.sha256(proof).hexdigest() != review["verification_evidence_sha256"] or
                not isinstance(review["verifier_id"], str) or not VERIFIER.fullmatch(review["verifier_id"]) or
                not isinstance(review["operator_id"], str) or not VERIFIER.fullmatch(review["operator_id"]) or
                review["verifier_id"] == review["operator_id"]):
            deny("signed review identity, previous state, or independent proof invalid")
        _review_text(review["demonstrated_impact"])
        _review_text(review["remediation"])
        _review_text(review["rejection_reason"])
        if review["verdict"] == "confirmed":
            if review["severity"] not in ("critical", "high", "medium", "low", "informational") or review["rejection_reason"] != "not_applicable":
                deny("confirmed review must be precise")
        elif review["severity"] != "none" or review["demonstrated_impact"] != "not_applicable" or review["remediation"] != "not_applicable":
            deny("rejected review must contain no severity or impact")
        stamp = _now(review["reviewed_at_utc"])
        age = (datetime.now(timezone.utc) - stamp).total_seconds()
        if not -30 <= age <= policy["max_age_seconds"]:
            deny("signed review expired or issued in the future")
        verifier = _get_key(policy["verifier_public_key_path"])
        operator = _get_key(policy["operator_public_key_path"])
        if verifier.public_bytes(Encoding.Raw, PublicFormat.Raw) == operator.public_bytes(Encoding.Raw, PublicFormat.Raw):
            deny("independent verifier and operator must use distinct signing keys")
        try:
            verifier.verify(signed_verifier, VERIFY_CONTEXT + raw)
            operator.verify(signed_operator, APPROVE_CONTEXT + raw)
        except (InvalidSignature, ValueError) as exc:
            raise ExecutionDenied("independent review signature invalid") from exc
        # A reviewed proof must be a fixed, independently retained fixture or
        # operator-observed staging validation, not untrusted model prose alone.
        try:
            evidence = json.loads(proof)
            if canonical(evidence) != proof:
                deny("review proof must be canonical JSON without ambiguous fields")
        except (ValueError, TypeError) as exc:
            raise ExecutionDenied("reviewed proof is invalid") from exc
        expected_proof = {"version", "kind", "source_reference", "starting_access",
                          "observed_behavior", "affected_principal", "conditions"}
        if (not isinstance(evidence, dict) or set(evidence) != expected_proof or
                evidence["version"] != 1 or
                evidence["kind"] not in ("operator_verified_staging", "isolated_local_fixture")):
            deny("verification fixture has unsupported format")
        for field in expected_proof - {"version", "kind"}:
            _review_text(evidence[field], 350)
        if review["verdict"] == "confirmed" and evidence["kind"] != "operator_verified_staging":
            deny("synthetic fixture alone cannot confirm deployed security impact")
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            try:verify_rows(con.execute("SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq").fetchall())
            except AuditError as exc:raise ExecutionDenied("report ledger integrity invalid") from exc
            source = con.execute("SELECT status FROM runs WHERE run_id=? AND engagement_id=?", (run_id, eid)).fetchone()
            root = con.execute("SELECT source_sha256,report_sha256 FROM assessment_reports WHERE source_run_id=? AND engagement_id=?",
                               (run_id,eid)).fetchone()
            if source != ("completed",) or not root:deny("only completed, reported runs admit independent reviews")
            # The current accepted revision is the one with an outbox created
            # most recently; use explicit current SHA rather than relying on clocks.
            self._tables(con)
            current = con.execute("SELECT latest_sha256 FROM assessment_reports WHERE source_run_id=? AND engagement_id=?",
                                  (run_id,eid)).fetchone()[0] or root[1]
            if current != review["prior_report_sha256"]:
                deny("review targets stale report revision")
            if current == root[1]:
                prior_folder = Path(info["report_directory"]) / "assessments" / run_id
            else:
                rec = con.execute("SELECT report_sha256 FROM assessment_report_revisions WHERE report_sha256=? AND engagement_id=? AND source_run_id=?",
                                  (current,eid,run_id)).fetchone()
                if not rec:deny("review parent revision is not admitted")
                prior_folder = Path(info["report_directory"]) / "assessments" / run_id / "revisions" / current
            document, previous_proofs = verified_package(prior_folder,current,include_proofs=True)
            if (document["engagement_id"] != eid or document["source_run_id"] != run_id or
                document["source_evidence"]["sha256"] != review["source_evidence_sha256"] or
                root[0] != review["source_evidence_sha256"]):
                deny("reviewed evidence does not match source run")
            relative = document["source_evidence"]["relative_path"]
            current_blob = self._read_source(info, run_id, Path(relative).name)
            if hashlib.sha256(current_blob).hexdigest() != root[0]:
                deny("original assessment evidence changed since report creation")
            matches = [x for x in document["findings"] if x["id"] == review["finding_id"]]
            if len(matches) != 1 or matches[0]["verdict"] != "needs_validation":
                deny("review must identify exactly one unresolved existing lead")
            new = dict(document)
            new["assessment_status"] = "independently_reviewed_limited_evidence"
            findings = [dict(x) for x in document["findings"]]
            item = next(x for x in findings if x["id"] == review["finding_id"])
            del item["blocker"]
            del item["validation_plan"]
            item.update({"verdict": review["verdict"], "verification_evidence_sha256": review["verification_evidence_sha256"],
                         "verifier_id": review["verifier_id"], "verified_at_utc": review["reviewed_at_utc"]})
            if review["verdict"] == "confirmed":
                item.update({"severity":review["severity"], "demonstrated_impact":review["demonstrated_impact"],
                             "remediation":review["remediation"]})
            else:
                item["rejection_reason"] = review["rejection_reason"]
            new["findings"] = findings
            added_proof = "proof-" + review["verification_evidence_sha256"] + ".json"
            proofs = {**previous_proofs, added_proof: proof}
            package = report_package(new, proofs)
            digest = hashlib.sha256(package["findings.json"]).hexdigest()
            self._guard()  # check live revocation before persistence
            revision_root = Path(info["report_directory"]) / "assessments" / run_id / "revisions"
            with open_directory_nofollow(revision_root, create=True) as folder:
                private_directory(folder)
                try:
                    _publish_package(folder, digest, package)
                except FileExistsError:
                    # Fail-closed crash recovery if the prior invocation
                    # published files but did not commit the protected ledger.
                    if verified_package(revision_root / digest, digest, include_proofs=True) != (new, proofs):
                        deny("incompatible existing review revision")
            notice_id = hashlib.sha256(canonical([eid, run_id, digest])).hexdigest()
            con.execute("""INSERT INTO assessment_report_revisions VALUES(?,?,?,?,?,?)""",
                        (digest, run_id, eid, current, review["verification_evidence_sha256"], str(revision_root/digest)))
            con.execute("UPDATE assessment_reports SET latest_sha256=? WHERE source_run_id=? AND engagement_id=?",
                        (digest,run_id,eid))
            con.execute("""INSERT INTO notification_outbox(notice_id,engagement_id,source_run_id,
                report_sha256,lead_count,status,report_revision) VALUES(?,?,?,?,?,'pending',?)""",
                (notice_id,eid,run_id,digest,len(findings),digest))
            self._event(con,{"type":"finding_review_accepted","engagement_id":eid,"source_run_id":run_id,
                             "finding_id":review["finding_id"],"verdict":review["verdict"],
                             "previous_sha256":current,"report_sha256":digest,
                             "proof_sha256":review["verification_evidence_sha256"],"notice_id":notice_id})
            con.commit()
        return {"status":"FINDING_REVIEW_PUBLISHED", "verdict":review["verdict"],
                "report":str(revision_root/digest/"findings.json"), "sha256":digest, "notice_id":notice_id}


def main():
    parser=argparse.ArgumentParser(description="Accept independently signed, operator-countersigned review")
    for field in ("manifest","signature","trust","state-root","run-id","review-policy","review-name"):
        parser.add_argument("--"+field,required=True)
    args=parser.parse_args()
    try:
        obj=FindingPromotionSupervisor(args.manifest,args.signature,args.trust,args.state_root)
        print(json.dumps(obj.promote(args.run_id,Path(args.review_policy),args.review_name),sort_keys=True))
        return 0
    except (ExecutionDenied, OSError, ValueError, TypeError, sqlite3.Error):
        print("REVIEW_PROMOTION_DENIED",file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
