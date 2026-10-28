#!/usr/bin/env python3
"""AEGIS v2.0 development: bounded operator-owned end-to-end assessment controller.

This controller has no generic tool dispatch, model-facing API, signing keys,
credential vault or independent target execution authority. The actual operations
run through their preexisting signed-scope supervisors and persistent budgets.
An interrupted side-effecting action is NEVER automatically retried.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import sys
import time
import uuid

from aegis_audit import verify_rows, AuditError
from aegis_reporting import ReportingSupervisor, canonical
from aegis_supervisor import (AegisSupervisor, ExecutionDenied, deny,
    open_directory_nofollow, private_directory)

MAX_POLICY = 16384
MAX_ACTIONS = 12
MAX_RESULT = 1536
PLAN_ID = re.compile(r"[0-9a-f-]{36}\Z")
STEP_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
RUN_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
MODULE = re.compile(r"[A-Za-z0-9_/-]{1,160}\.py\Z")
ACTION_FIELDS = {
    "source_review": {"seconds"},
    "dependency_intelligence": {"seconds", "snapshot", "signature"},
    "local_contract": {"seconds", "module", "seed", "cases", "trials", "fuzz_policy"},
    "http_metadata": {"seconds", "url", "method"},
    "report": {"source"},
    "admit_report": {"run_id", "report_sha256", "investigation_policy"},
    "remediation_retest": {"source", "retest_run_id", "finding_id", "investigation_policy"},
    "investigate": {"source", "investigation_policy"},
    "progress_investigation": {"source", "investigation_policy", "max_steps"},
    "notify": {"source", "notification_policy"},
}
SOURCES = {
    "report": {"source_review", "dependency_intelligence", "local_contract"},
    "investigate": {"report", "admit_report"},
    "remediation_retest": {"investigate"},
    "progress_investigation": {"investigate"},
    "notify": {"report", "admit_report"},
}
EVIDENCE_NAMES = {
    "source_review": "source-review.json",
    "dependency_intelligence": "advisory-candidates.json",
    "local_contract": "bounded-fuzz.json",
}


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate policy key")
        out[key] = value
    return out


def _path(value):
    if (not isinstance(value, str) or not value.startswith("/") or len(value) > 400 or
            "\x00" in value or any(p in ("", ".", "..") for p in value.split("/")[1:])):
        deny("operator path must be an absolute canonical path")
    return Path(value)


def _operator_path(value, info, state):
    value = _path(value)
    forbidden = [state, Path(info["report_directory"]), Path("/usr"),
                 *[Path(p) for p in info["authorized_repositories"]]]
    if any(value == other or other in value.parents for other in forbidden):
        deny("operator-controlled file may not come from worker runtime, state, reports or repository")
    return value


def _pinned_reference(path, info, state):
    """Pin independently protected, bounded operator inputs for this plan.

    Reading only these files never authorizes them: the existing source-specific
    supervisors independently recheck signatures, scope, and their policies.
    """
    name=_operator_path(path,info,state)
    with open_directory_nofollow(name.parent) as parent:
        st=os.fstat(parent)
        if st.st_uid not in (0,os.geteuid()) or st.st_mode & 0o022:
            deny("referenced operator file parent is not protected")
        fd=os.open(name.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
        try:
            before=os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or
                before.st_uid not in (0,os.geteuid()) or before.st_mode & 0o022 or
                not 0<before.st_size<=2*1024*1024):
                deny("referenced operator material has unsafe type, owner, permissions or size")
            body=os.read(fd,2*1024*1024+1)
            after=os.fstat(fd)
            if (len(body)!=before.st_size or
                (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size)):
                deny("referenced operator material changed during read")
            return hashlib.sha256(body).hexdigest()
        finally:os.close(fd)


def _policy(path, info, state):
    path = _operator_path(str(path), info, state)
    with open_directory_nofollow(path.parent) as fd:
        parent = os.fstat(fd)
        if (parent.st_uid not in (0, os.geteuid()) or parent.st_mode & 0o022):
            deny("assessment policy directory is not protected")
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                          os.O_CLOEXEC, dir_fd=fd)
        try:
            before = os.fstat(file_fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    before.st_uid not in (0, os.geteuid()) or before.st_mode & 0o077 or
                    not 0 < before.st_size <= MAX_POLICY):
                deny("assessment policy must be a private bounded regular file")
            raw = os.read(file_fd, MAX_POLICY + 1)
            after = os.fstat(file_fd)
            if (len(raw) != before.st_size or
                    (before.st_dev, before.st_ino, before.st_size) !=
                    (after.st_dev, after.st_ino, after.st_size)):
                deny("assessment policy changed during read")
        finally:
            os.close(file_fd)
    try:
        policy = json.loads(raw, object_pairs_hook=_object)
        if canonical(policy) != raw:
            deny("assessment policy must be canonical JSON")
    except (UnicodeError, ValueError, RecursionError, TypeError) as exc:
        raise ExecutionDenied("invalid canonical assessment policy") from exc
    if (not isinstance(policy, dict) or set(policy) !=
        {"schema_version", "configured", "engagement_ids", "repository", "lease_seconds", "steps"} or
        type(policy["schema_version"]) is not int or policy["schema_version"] != 1 or
        policy["configured"] is not True or
        not isinstance(policy["engagement_ids"], list) or len(policy["engagement_ids"]) > 16 or
        info["engagement_id"] not in policy["engagement_ids"] or
        any(not isinstance(x, str) or len(x) > 64 for x in policy["engagement_ids"]) or
        type(policy["lease_seconds"]) is not int or not 60 <= policy["lease_seconds"] <= 300 or
        not isinstance(policy["steps"], list) or not 1 <= len(policy["steps"]) <= MAX_ACTIONS):
        deny("assessment policy is not positively configured")
    repository = _path(policy["repository"])
    if str(repository.resolve()) not in info["authorized_repositories"]:
        deny("assessment repository not within signed scope")
    seen = {}
    for entry in policy["steps"]:
        if not isinstance(entry, dict) or entry.get("action") not in ACTION_FIELDS:
            deny("unsupported fixed assessment step")
        kind = entry["action"]
        required_method = {"source_review": "source_review",
                           "dependency_intelligence": "dependency_analysis",
                           "local_contract": "bounded_fuzzing",
                           "http_metadata": "controlled_http_testing"}.get(kind)
        if required_method is not None and required_method not in info["approved_methods"]:
            deny("assessment action is absent from signed/operator authorization")
        if set(entry) != {"id", "action", *ACTION_FIELDS[kind]} or not isinstance(entry["id"], str) or not STEP_ID.fullmatch(entry["id"]):
            deny("unexpected assessment step shape")
        if entry["id"] in seen:
            deny("duplicate assessment action identifier")
        if kind in SOURCES:
            source = entry["source"]
            if not isinstance(source, str) or source not in seen or seen[source] not in SOURCES[kind]:
                deny("assessment action depends on a missing or incompatible prior step")
        if "seconds" in entry and (type(entry["seconds"]) is not int or not 2 <= entry["seconds"] <= 30):
            deny("assessment runtime limit invalid")
        if kind == "dependency_intelligence":
            for name in ("snapshot", "signature"):
                _operator_path(entry[name], info, state)
        if kind == "local_contract":
            if (not isinstance(entry["module"], str) or not MODULE.fullmatch(entry["module"]) or
                any(part in (".", "..") for part in entry["module"].split("/")) or
                type(entry["seed"]) is not int or not 0 <= entry["seed"] <= 2**31 - 1 or
                type(entry["cases"]) is not int or not 8 <= entry["cases"] <= 64 or
                type(entry["trials"]) is not int or not 1 <= entry["trials"] <= 5 or
                entry["cases"] * entry["trials"] > 192):
                deny("invalid bounded local contract")
            _operator_path(entry["fuzz_policy"], info, state)
        if kind == "http_metadata":
            if (entry["method"] not in ("GET", "HEAD") or
                not isinstance(entry["url"], str) or not 1 <= len(entry["url"]) <= 2048):
                deny("invalid fixed HTTP metadata operation")
            # The HTTP supervisor performs the definitive signed origin/route
            # and pinned numeric IP checks BEFORE any connection.
        if kind in ("investigate", "progress_investigation", "notify", "admit_report", "remediation_retest"):
            _operator_path(entry["notification_policy"] if kind == "notify" else entry["investigation_policy"], info, state)
        if kind == "admit_report":
            if (not isinstance(entry["run_id"],str) or not RUN_ID.fullmatch(entry["run_id"]) or
                not isinstance(entry["report_sha256"],str) or not HEX.fullmatch(entry["report_sha256"])):
                deny("admitted report must pin exact completed source and version")
        if kind == "remediation_retest":
            if (not isinstance(entry["retest_run_id"],str) or not RUN_ID.fullmatch(entry["retest_run_id"]) or
                not isinstance(entry["finding_id"],str) or not re.fullmatch(r"A18-[0-9a-f]{20}",entry["finding_id"])):
                deny("remediation retest requires an exact source run and confirmed finding")
        if kind == "progress_investigation":
            if type(entry["max_steps"]) is not int or not 1 <= entry["max_steps"] <= 10:
                deny("invalid bounded investigation progression")
        seen[entry["id"]] = kind
    references=[]
    for entry in policy["steps"]:
        for key in ("snapshot", "signature", "fuzz_policy", "investigation_policy", "notification_policy"):
            if key in entry:
                references.append((entry["id"], key, entry[key],
                                   _pinned_reference(entry[key],info,state)))
    # A byte-level change to an operator tool policy or signed advisory must
    # invalidate the active plan, even if the main assessment policy is intact.
    pinned=canonical([hashlib.sha256(raw).hexdigest(),references])
    return policy, hashlib.sha256(pinned).hexdigest()


def _audit(con):
    try:
        verify_rows(con.execute("SELECT seq,event,previous_hash,digest FROM audit ORDER BY seq").fetchall())
    except AuditError as exc:
        raise ExecutionDenied("integrated assessment audit chain invalid") from exc


class IntegratedAssessment(AegisSupervisor):
    def __init__(self, manifest, signature, trust, state_root, assessment_policy):
        super().__init__(manifest, signature, trust, state_root)
        self.assessment_policy = Path(assessment_policy)

    @staticmethod
    def _tables(con):
        con.execute("""CREATE TABLE IF NOT EXISTS integrated_assessments (
            assessment_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
            manifest_sha TEXT NOT NULL, policy_sha TEXT NOT NULL,
            plan_sha TEXT NOT NULL, created_utc TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS integrated_steps (
            assessment_id TEXT NOT NULL, ordinal INTEGER NOT NULL, step_id TEXT NOT NULL,
            kind TEXT NOT NULL, status TEXT NOT NULL, lease_token TEXT,
            lease_until REAL NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
            result_json TEXT, result_sha TEXT,
            PRIMARY KEY(assessment_id,ordinal), UNIQUE(assessment_id,step_id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS integrated_abandonments (
            assessment_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL,
            reason_code TEXT NOT NULL, recorded_utc TEXT NOT NULL)""")

    def _admit(self):
        info, _ = self._guard()
        policy, digest = _policy(self.assessment_policy, info, self.state_root)
        return info, policy, digest

    @staticmethod
    def _plan_sha(info, policy, policy_sha):
        return hashlib.sha256(canonical([info["engagement_id"], info["manifest_sha256"], policy_sha,
                                          [(x["id"], x["action"], x.get("source")) for x in policy["steps"]]])).hexdigest()

    def create(self, request_id=None):
        info, policy, policy_sha = self._admit()
        if request_id is not None and (not isinstance(request_id, str) or not PLAN_ID.fullmatch(request_id)):
            deny("invalid operator request identifier")
        assessment_id = request_id or str(uuid.uuid4())
        digest = self._plan_sha(info, policy, policy_sha)
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            _audit(con)
            existing = con.execute("SELECT engagement_id,manifest_sha,policy_sha,plan_sha FROM integrated_assessments WHERE assessment_id=?",(assessment_id,)).fetchone()
            expected = (info["engagement_id"], info["manifest_sha256"], policy_sha, digest)
            if existing and existing != expected:
                deny("operator request identifier already bound to different assessment")
            if existing is None:
                con.execute("INSERT INTO integrated_assessments VALUES(?,?,?,?,?,?)",
                            (assessment_id, *expected, _timestamp()))
                for ordinal, entry in enumerate(policy["steps"]):
                    con.execute("INSERT INTO integrated_steps(assessment_id,ordinal,step_id,kind,status) VALUES(?,?,?,?,?)",
                                (assessment_id, ordinal, entry["id"], entry["action"], "pending"))
                self._event(con, {"type":"integrated_assessment_created", "engagement_id":info["engagement_id"],
                                  "assessment_id":assessment_id, "plan_sha256":digest, "steps":len(policy["steps"])})
            con.commit()
        return self.snapshot(assessment_id)

    @staticmethod
    def _valid_result(kind, record):
        shape={
            "source_review":{"action","run_id","evidence"},
            "dependency_intelligence":{"action","run_id","evidence","snapshot_sha256"},
            "local_contract":{"action","run_id","evidence"},
            "http_metadata":{"action","request_id","status"},
            "report":{"action","run_id","report_sha256"},
            "admit_report":{"action","run_id","report_sha256"},
            "remediation_retest":{"action","plan_id","run_id","finding_id","status"},
            "investigate":{"action","plan_id","run_id"},
            "progress_investigation":{"action","plan_id","executed","operator_review_required"},
            "notify":{"action","notice_id","status"},
        }
        if not isinstance(record,dict) or set(record)!=shape[kind] or record["action"]!=kind:
            deny("integrated outcome changed its fixed action schema")
        for key in ("run_id","plan_id","request_id"):
            if key in record and (not isinstance(record[key],str) or not RUN_ID.fullmatch(record[key])):
                deny("integrated outcome has invalid run or plan identity")
        for key in ("report_sha256","snapshot_sha256","notice_id"):
            if key in record and (not isinstance(record[key],str) or not HEX.fullmatch(record[key])):
                deny("integrated outcome has invalid digest identity")
        if kind=="remediation_retest" and (
                not isinstance(record["finding_id"],str) or
                not re.fullmatch(r"A18-[0-9a-f]{20}",record["finding_id"]) or
                record["status"] not in ("RETEST_LOCAL_LEAD_REPRODUCED_NEEDS_REVIEW",
                                           "RETEST_LOCAL_NOT_REPRODUCED_NEEDS_REVIEW",
                                           "RETEST_NO_LOCAL_LEADS_NOT_VERIFIED_FIXED")):
            deny("integrated retest must remain a bounded, unverified observation")
        if "evidence" in record and record["evidence"]!=EVIDENCE_NAMES[kind]:
            deny("integrated outcome changed evidence type")
        if kind=="http_metadata" and record["status"]!="SCOPED_HTTP_METADATA_ONLY":
            deny("unexpected HTTP outcome")
        if kind=="notify" and record["status"]!="LOCAL_DELIVERY_ACKNOWLEDGED":
            deny("unexpected notification outcome")
        if kind=="progress_investigation" and (type(record["executed"]) is not int or
              not 0 <= record["executed"] <= 10 or record["operator_review_required"] is not True):
            deny("untrusted investigation progress")

    def _rows(self, assessment_id, info, policy, policy_sha):
        if not isinstance(assessment_id,str) or not PLAN_ID.fullmatch(assessment_id):
            deny("invalid integrated assessment identifier")
        with self._database() as con:
            self._tables(con)
            _audit(con)
            plan = con.execute("SELECT engagement_id,manifest_sha,policy_sha,plan_sha FROM integrated_assessments WHERE assessment_id=?",(assessment_id,)).fetchone()
            if plan != (info["engagement_id"], info["manifest_sha256"], policy_sha,
                        self._plan_sha(info, policy, policy_sha)):
                deny("integrated assessment identity or operator policy changed")
            rows = con.execute("SELECT ordinal,step_id,kind,status,lease_token,lease_until,attempts,result_json,result_sha FROM integrated_steps WHERE assessment_id=? ORDER BY ordinal",(assessment_id,)).fetchall()
            # Each completed result is bound into the existing verified audit
            # hash chain, not merely to a mutable row-level digest in SQLite.
            completed_events=set()
            for (event_raw,) in con.execute("SELECT event FROM audit ORDER BY seq").fetchall():
                event=json.loads(event_raw)
                if event.get("type")=="integrated_action_completed" and event.get("assessment_id")==assessment_id:
                    completed_events.add((event.get("step_id"),event.get("result_sha256")))
        if len(rows) != len(policy["steps"]):
            deny("integrated assessment step count changed")
        outcomes=[]
        for i,(ordinal,sid,kind,status,token,until,attempts,raw,digest) in enumerate(rows):
            if ((ordinal,sid,kind) != (i,policy["steps"][i]["id"],policy["steps"][i]["action"]) or
                status not in ("pending", "leased", "completed", "attention") or
                type(attempts) is not int or attempts not in (0,1) or
                (status == "leased" and (not isinstance(token,str) or len(token)!=32)) or
                (status != "leased" and token is not None)):
                deny("integrated step ledger diverged from operator plan")
            if raw is not None:
                if (status != "completed" or not isinstance(raw,str) or len(raw)>MAX_RESULT or
                    not isinstance(digest,str) or not HEX.fullmatch(digest) or
                    hashlib.sha256(raw.encode("ascii")).hexdigest() != digest):
                    deny("integrated result integrity check failed")
                try: result=json.loads(raw,object_pairs_hook=_object)
                except (ValueError, UnicodeError, TypeError) as exc:
                    raise ExecutionDenied("integrated result corrupt") from exc
                self._valid_result(kind,result)
                if (sid,digest) not in completed_events:
                    deny("integrated outcome has no matching hash-chained completion record")
            else:
                if digest is not None or status == "completed":
                    deny("integrated completed result missing")
                result=None
            outcomes.append({"id":sid,"action":kind,"state":status,"attempts":attempts,
                             "result":result,"lease_until":until if status=="leased" else None})
        return outcomes

    def snapshot(self, assessment_id):
        info, policy, sha = self._admit()
        steps=self._rows(assessment_id, info, policy, sha)
        done = sum(x["state"]=="completed" for x in steps)
        blocked = next((x for x in steps if x["state"]=="attention"),None)
        with self._database() as con:
            self._tables(con)
            abandoned=con.execute("SELECT reason_code,recorded_utc FROM integrated_abandonments WHERE assessment_id=? AND engagement_id=?",
                                  (assessment_id,info["engagement_id"])).fetchone()
            if abandoned:
                _audit(con)
                events=[json.loads(row[0]) for row in con.execute("SELECT event FROM audit ORDER BY seq")]
                if not any(e.get("type")=="integrated_assessment_abandoned" and
                           e.get("assessment_id")==assessment_id and e.get("reason_code")==abandoned[0] and
                           e.get("recorded_utc")==abandoned[1] for e in events):
                    deny("abandoned assessment has no hash-chained operator event")
        status = ("ABANDONED_REQUIRES_OPERATOR_REVIEW" if abandoned else
                  "REQUIRES_OPERATOR_RECONCILIATION" if blocked else
                  "WORKFLOW_COMPLETED_PENDING_INDEPENDENT_VALIDATION" if done==len(steps) else
                  "IN_PROGRESS")
        return {"status":status,"assessment_id":assessment_id,"completed":done,
                "total":len(steps),"steps":steps,
                "warning":"Local evidence is not deployed exploitation or remediation confirmation."}

    def _claim(self, assessment_id, info, policy, sha):
        with self._database() as con:
            self._tables(con)
            if con.execute("SELECT 1 FROM integrated_abandonments WHERE assessment_id=?",(assessment_id,)).fetchone():
                deny("operator abandoned workflow; no automatic retry")
        steps = self._rows(assessment_id,info,policy,sha)
        index = next((i for i,x in enumerate(steps) if x["state"]!="completed"),None)
        if index is None: return None
        step=steps[index]
        if step["state"]=="attention":
            deny("interrupted or failed action requires operator reconciliation; never auto retry")
        if step["state"]=="leased":
            if step["lease_until"] < time.time():
                with self._database() as con:
                    con.execute("BEGIN IMMEDIATE")
                    row=con.execute("SELECT lease_token FROM integrated_steps WHERE assessment_id=? AND ordinal=? AND status='leased'",(assessment_id,index)).fetchone()
                    if row:
                        con.execute("UPDATE integrated_steps SET status='attention',lease_token=NULL,lease_until=0 WHERE assessment_id=? AND ordinal=?",(assessment_id,index))
                        self._event(con,{"type":"integrated_action_interrupted", "engagement_id":info["engagement_id"],
                                         "assessment_id":assessment_id, "step_id":step["id"]})
                    con.commit()
                deny("expired action lease requires reconciliation; never auto rerun")
            deny("integrated assessment action already in progress")
        token=secrets.token_hex(16)
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            _audit(con)
            row=con.execute("SELECT status,attempts FROM integrated_steps WHERE assessment_id=? AND ordinal=?",(assessment_id,index)).fetchone()
            if row != ("pending",0):
                deny("another worker already claimed this action")
            changed=con.execute("UPDATE integrated_steps SET status='leased',attempts=1,lease_token=?,lease_until=? WHERE assessment_id=? AND ordinal=? AND status='pending' AND attempts=0",(token,time.time()+policy["lease_seconds"],assessment_id,index)).rowcount
            if changed!=1: deny("integrated action reservation raced")
            self._event(con,{"type":"integrated_action_claimed","engagement_id":info["engagement_id"],
                             "assessment_id":assessment_id,"step_id":step["id"],"action":step["action"]})
            con.commit()
        return index,token

    def _operation(self, entry, completed, policy):
        """Only compiled-in named supervisors. Return bounded metadata, not target text."""
        kind=entry["action"]
        args=(self.manifest_path,self.signature_path,self.trust_path,self.state_root)
        repo=Path(policy["repository"])
        if kind=="source_review":
            result=AegisSupervisor(*args).scan(repo,budget_seconds=entry["seconds"])
            if result.get("status")!="COMPLETED_STATIC_REVIEW_ONLY": deny("source review did not complete")
            return {"action":kind,"run_id":result["run_id"],"evidence":"source-review.json"}
        if kind=="dependency_intelligence":
            from aegis_intelligence_runtime import AegisIntelligenceSupervisor
            result=AegisIntelligenceSupervisor(*args).assess_dependencies(repo,Path(entry["snapshot"]),Path(entry["signature"]),entry["seconds"])
            if result.get("status")!="COMPLETED_SIGNED_OSV_EXACT_VERSION_CORRELATION": deny("dependency intelligence not completed")
            return {"action":kind,"run_id":result["run_id"],"evidence":"advisory-candidates.json",
                    "snapshot_sha256":result["snapshot_sha256"]}
        if kind=="local_contract":
            from aegis_fuzz_runtime import AegisFuzzSupervisor
            result=AegisFuzzSupervisor(*args,Path(entry["fuzz_policy"])).execute(repo,entry["module"],seed=entry["seed"],max_cases=entry["cases"],trials=entry["trials"],seconds=entry["seconds"])
            if result.get("status")!="COMPLETED_BOUNDED_LOCAL_VALIDATION_ONLY": deny("local contract not completed")
            return {"action":kind,"run_id":result["run_id"],"evidence":"bounded-fuzz.json"}
        if kind=="http_metadata":
            from aegis_http_runtime import AegisHttpSupervisor
            result=AegisHttpSupervisor(*args).request(entry["url"],entry["method"],entry["seconds"])
            if not isinstance(result,dict) or not isinstance(result.get("request_id"),str):
                deny("fixed HTTP metadata operation did not complete")
            return {"action":kind,"request_id":result["request_id"],"status":"SCOPED_HTTP_METADATA_ONLY"}
        if kind=="admit_report":
            from aegis_investigation_evidence import EvidenceInvestigationSupervisor
            reviewer=EvidenceInvestigationSupervisor(*args,Path(entry["investigation_policy"]))
            current,_=self._guard()
            _,sha,_=reviewer._report(current,entry["run_id"])
            if sha!=entry["report_sha256"]:
                deny("admitted report differs from operator-pinned reviewed revision")
            return {"action":kind,"run_id":entry["run_id"],"report_sha256":sha}
        source=completed[entry["source"]]
        if kind=="remediation_retest":
            from aegis_investigation_evidence import EvidenceInvestigationSupervisor
            reviewer=EvidenceInvestigationSupervisor(*args,Path(entry["investigation_policy"]))
            reviewer.attach(source["plan_id"],entry["retest_run_id"],
                purpose="remediation_retest",finding_id=entry["finding_id"])
            outcome=reviewer.retest(source["plan_id"],entry["retest_run_id"])
            if outcome.get("status")!="RETEST_OBSERVATION_RECORDED":
                deny("remediation retest was not independently recorded")
            status=outcome.get("outcome",{}).get("status")
            if status not in ("RETEST_LOCAL_LEAD_REPRODUCED_NEEDS_REVIEW",
                             "RETEST_LOCAL_NOT_REPRODUCED_NEEDS_REVIEW",
                             "RETEST_NO_LOCAL_LEADS_NOT_VERIFIED_FIXED"):
                deny("unrecognized remediation retest outcome")
            return {"action":kind,"plan_id":source["plan_id"],
                "run_id":entry["retest_run_id"],"finding_id":entry["finding_id"],"status":status}
        if kind=="report":
            result=ReportingSupervisor(*args).generate(source["run_id"],source["evidence"])
            if result.get("status") not in ("ASSESSMENT_QUEUED","ASSESSMENT_ALREADY_QUEUED") or not HEX.fullmatch(result["sha256"]):
                deny("canonical report not admitted")
            return {"action":kind,"run_id":source["run_id"],"report_sha256":result["sha256"]}
        if kind=="investigate":
            from aegis_investigation_evidence import EvidenceInvestigationSupervisor
            result=EvidenceInvestigationSupervisor(*args,Path(entry["investigation_policy"])).create(source["run_id"])
            if result.get("status")!="INVESTIGATION_PLAN": deny("investigation not recorded")
            return {"action":kind,"plan_id":result["plan_id"],"run_id":source["run_id"]}
        if kind=="progress_investigation":
            from aegis_investigation_evidence import EvidenceInvestigationSupervisor
            result=EvidenceInvestigationSupervisor(*args,Path(entry["investigation_policy"])).run_allowed(source["plan_id"],entry["max_steps"])
            if result.get("status")!="INVESTIGATION_BOUNDED_PROGRESS": deny("investigation did not progress")
            return {"action":kind,"plan_id":source["plan_id"],"executed":result["executed"],
                    "operator_review_required":True}
        if kind=="notify":
            from aegis_notifications import NotificationSupervisor
            info,_=self._guard()
            with self._database() as con:
                row=con.execute("SELECT notice_id FROM notification_outbox WHERE engagement_id=? AND source_run_id=? AND report_sha256=?",(info["engagement_id"],source["run_id"],source["report_sha256"])).fetchone()
            if not row: deny("report not queued for notification")
            result=NotificationSupervisor(*args).deliver(row[0],Path(entry["notification_policy"]))
            if result.get("status") not in ("DELIVERY_ACKNOWLEDGED","DELIVERY_ALREADY_ACKNOWLEDGED"):
                deny("notification not acknowledged by protected receiver")
            return {"action":kind,"notice_id":row[0],"status":"LOCAL_DELIVERY_ACKNOWLEDGED"}
        deny("unrecognized integrated action")

    def advance(self, assessment_id):
        info, policy, sha = self._admit()
        claim = self._claim(assessment_id,info,policy,sha)
        if claim is None:
            return {"status":"WORKFLOW_COMPLETED_PENDING_INDEPENDENT_VALIDATION",
                    "assessment_id":assessment_id}
        index, token = claim
        entry = policy["steps"][index]
        try:
            existing=self._rows(assessment_id,info,policy,sha)
            done={x["id"]:x["result"] for x in existing if x["state"]=="completed"}
            result=self._operation(entry,done,policy)
            current,_,current_sha=self._admit()
            if current["engagement_id"]!=info["engagement_id"] or current_sha!=sha:
                deny("assessment authorization changed during operation")
            raw=canonical(result).decode("ascii")
            self._valid_result(entry["action"],result)
            if len(raw)>MAX_RESULT:deny("integrated result too large")
            digest=hashlib.sha256(raw.encode("ascii")).hexdigest()
        except BaseException as exc:
            with self._database() as con:
                con.execute("BEGIN IMMEDIATE")
                updated=con.execute("UPDATE integrated_steps SET status='attention',lease_token=NULL,lease_until=0 WHERE assessment_id=? AND ordinal=? AND status='leased' AND lease_token=?",(assessment_id,index,token)).rowcount
                if updated:
                    self._event(con,{"type":"integrated_action_needs_reconciliation","assessment_id":assessment_id,
                                    "step_id":entry["id"],"error_type":type(exc).__name__})
                con.commit()
            raise
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            _audit(con)
            updated=con.execute("UPDATE integrated_steps SET status='completed',lease_token=NULL,lease_until=0,result_json=?,result_sha=? WHERE assessment_id=? AND ordinal=? AND status='leased' AND lease_token=? AND lease_until>?",(raw,digest,assessment_id,index,token,time.time())).rowcount
            if updated != 1:deny("integrated action lease expired or was replaced; reconciliation required")
            self._event(con,{"type":"integrated_action_completed","engagement_id":info["engagement_id"],
                             "assessment_id":assessment_id,"step_id":entry["id"],"result_sha256":digest})
            con.commit()
        return {"status":"INTEGRATED_ACTION_COMPLETED","assessment_id":assessment_id,
                "step_id":entry["id"],"result":result}

    def abandon(self, assessment_id, reason_code):
        """Operator-only append-only terminal reconciliation of an abandoned run.

        Cannot erase completed actions, rewind budgets or roll back evidence;
        the operator must inspect uncertain side effects and create a *new*
        authorization-bound workflow when further execution is warranted.
        """
        if reason_code not in ("interrupted_unknown_outcome","operator_cancelled",
                               "deployment_recovery_required"):
            deny("invalid operator reconciliation reason")
        info,policy,sha=self._admit()
        steps=self._rows(assessment_id,info,policy,sha)
        if all(x["state"]=="completed" for x in steps):
            deny("completed workflow cannot be abandoned retroactively")
        if any(x["state"]=="leased" and x["lease_until"]>time.time() for x in steps):
            deny("cannot abandon workflow with a live worker lease")
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            _audit(con)
            prior=con.execute("SELECT reason_code FROM integrated_abandonments WHERE assessment_id=?",
                              (assessment_id,)).fetchone()
            if prior and prior!=(reason_code,):
                deny("operator reconciliation history is immutable")
            if prior is None:
                stamp=_timestamp()
                con.execute("INSERT INTO integrated_abandonments VALUES(?,?,?,?)",
                            (assessment_id,info["engagement_id"],reason_code,stamp))
                self._event(con,{"type":"integrated_assessment_abandoned",
                        "assessment_id":assessment_id,"engagement_id":info["engagement_id"],
                        "reason_code":reason_code,"recorded_utc":stamp})
            con.commit()
        return self.snapshot(assessment_id)

    def run(self, assessment_id, max_actions=12):
        if type(max_actions) is not int or not 1 <= max_actions <= MAX_ACTIONS:
            deny("invalid integrated progression limit")
        outcomes=[]
        for _ in range(max_actions):
            value=self.advance(assessment_id)
            outcomes.append(value)
            if value["status"]!="INTEGRATED_ACTION_COMPLETED":break
        snap=self.snapshot(assessment_id)
        return {"status":snap["status"],"assessment_id":assessment_id,
                "completed":snap["completed"],"total":snap["total"],"outcomes":outcomes,
                "warning":"Independent authorized validation remains required for deployed impact and remediation."}


def main(argv=None):
    ap=argparse.ArgumentParser(description="AEGIS v2.0 operator-owned typed assessment orchestration")
    for name in ("manifest","signature","trust","state-root","assessment-policy"):
        ap.add_argument("--"+name,required=True)
    ap.add_argument("action",choices=("create","snapshot","advance","run","abandon"))
    ap.add_argument("--assessment-id")
    ap.add_argument("--request-id")
    ap.add_argument("--max-actions",type=int,default=12)
    ap.add_argument("--reason-code")
    a=ap.parse_args(argv)
    try:
        engine=IntegratedAssessment(a.manifest,a.signature,a.trust,a.state_root,a.assessment_policy)
        if a.action=="create" and not a.assessment_id:
            result=engine.create(a.request_id)
        elif a.action=="snapshot" and a.assessment_id and not a.request_id:
            result=engine.snapshot(a.assessment_id)
        elif a.action=="advance" and a.assessment_id and not a.request_id:
            result=engine.advance(a.assessment_id)
        elif a.action=="run" and a.assessment_id and not a.request_id and not a.reason_code:
            result=engine.run(a.assessment_id,a.max_actions)
        elif a.action=="abandon" and a.assessment_id and not a.request_id and a.reason_code:
            result=engine.abandon(a.assessment_id,a.reason_code)
        else:
            deny("invalid operator-only assessment action")
        print(json.dumps(result,sort_keys=True,separators=(",", ":")))
        return 0
    except (ExecutionDenied,OSError,ValueError,TypeError):
        print("INTEGRATED_ASSESSMENT_DENIED",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
