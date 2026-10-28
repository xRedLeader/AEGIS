#!/usr/bin/env python3
"""v1.9: immutable multi-run evidence and operator-gated local remediation retest.

Only canonical, completed, same-engagement v1.8 reports enter a plan. An
operator must explicitly attach each additional run. The only executable retest
is the already-authorized v1.7 offline replay; no agent gains new capabilities.
No result here asserts a vulnerability was fixed, reachable or exploited.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import time
import secrets
from pathlib import Path

from aegis_investigation import InvestigationSupervisor, RUN_ID, FINDING_ID, HEX, _audit_ok
from aegis_reporting import canonical
from aegis_supervisor import ExecutionDenied, deny

MAX_ATTACHMENTS = 8
MAX_CROSS_RUN_LINKS = 24
MAX_RESULT_SIZE = 1500
PURPOSES = frozenset({"context", "remediation_retest"})


class EvidenceInvestigationSupervisor(InvestigationSupervisor):
    """Append-only source admissions and separately leased retest observations."""

    @staticmethod
    def _tables(con):
        InvestigationSupervisor._tables(con)
        con.execute("""CREATE TABLE IF NOT EXISTS investigation_evidence (
            plan_id TEXT NOT NULL, source_run_id TEXT NOT NULL,
            report_sha TEXT NOT NULL, source_sha TEXT NOT NULL,
            purpose TEXT NOT NULL, target_finding TEXT,
            observed_kind TEXT NOT NULL, added_utc TEXT NOT NULL,
            state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            lease_token TEXT, lease_until REAL NOT NULL DEFAULT 0,
            result_json TEXT, result_sha TEXT,
            PRIMARY KEY(plan_id,source_run_id))""")

    def _bound_plan(self, plan_id):
        info, policy, policy_sha = self._admit()
        plan_row = self._check_plan(plan_id, info, policy_sha)
        # Verifies both the immutable report AND the ledger's canonical step graph.
        base_snapshot = self.snapshot(plan_id)
        return info, policy, policy_sha, plan_row, base_snapshot

    def _retest_binding(self, info, policy, base_document, target_finding, source_run, new_document):
        if not isinstance(target_finding, str) or not FINDING_ID.fullmatch(target_finding):
            deny("remediation retest requires exact confirmed finding ID")
        original = next((x for x in base_document["findings"]
                         if x["id"] == target_finding), None)
        if original is None or original["verdict"] != "confirmed":
            deny("remediation retest requires independently reviewed confirmed finding")
        if (base_document["source_evidence"]["kind"] != "bounded_fuzz" or
                new_document["source_evidence"]["kind"] != "bounded_fuzz"):
            deny("local replay cannot validate unrelated source/review classes")
        if not policy["allow_local_replay"] or source_run not in policy["replay_targets"]:
            deny("retest source lacks exact independent operator replay capability")
        # Bind the asserted remediation to the *same synthetic contract*, not
        # merely to an operator-supplied string or the same asset's human label.
        parts = original["affected_asset"].split("/")
        if len(parts) != 4 or parts[0] != "contract" or parts[2] != "case" or not parts[3].isdigit():
            deny("retest target must be a bounded local contract finding")
        cap = policy["replay_targets"][source_run]
        previous_bytes = self._read_source(info, base_document["source_run_id"], "bounded-fuzz.json")
        evidence = self._read_source(info, source_run, "bounded-fuzz.json")
        try:
            earlier = json.loads(previous_bytes)
            observed = json.loads(evidence)
        except (ValueError, UnicodeError, TypeError) as exc:
            raise ExecutionDenied("retest source has malformed evidence") from exc
        # The earlier reviewed local failure MUST identify its exact fixed
        # callable; a second approved function implementing the same *kind* of
        # contract does not retest that vulnerability.
        prior_recipe = earlier.get("minimal_reproducer") if isinstance(earlier, dict) else None
        if (not isinstance(prior_recipe, dict) or
                prior_recipe.get("contract") != parts[1] or
                prior_recipe.get("module") != cap["module"] or
                not isinstance(prior_recipe.get("callable"), str) or
                not isinstance(observed, dict) or observed.get("contract") != parts[1] or
                observed.get("status") != "BOUNDED_OFFLINE_AUTHORIZATION_REPRODUCTION_ONLY" or
                observed.get("mode") != "fuzz"):
            deny("retest evidence does not match reviewed source module and contract")
        # Bind the new evidence to the protected operator policy which originally
        # selects the actual callable and SHA. A changed target or a different
        # function under the same contract cannot masquerade as a remediation.
        from aegis_fuzz_runtime import load_operator_policy
        fuzz = load_operator_policy(Path(cap["fuzz_policy"]),Path(cap["repository"]),self.state_root)
        current_target = fuzz["targets"].get(cap["module"])
        if (not isinstance(current_target,dict) or
                current_target["callable"] != prior_recipe["callable"] or
                current_target["contract"] != parts[1] or
                observed.get("source_sha256") != current_target["sha256"]):
            deny("retest evidence changed from exact operator-pinned callable or source")
        candidate_recipe = observed.get("minimal_reproducer")
        if candidate_recipe is not None and (
                not isinstance(candidate_recipe, dict) or
                candidate_recipe.get("module") != prior_recipe["module"] or
                candidate_recipe.get("callable") != prior_recipe["callable"]):
            deny("retest candidate is for a different source callable")
        return original

    def attach(self, plan_id, source_run, *, purpose="context", finding_id=None):
        """Operator admits one new completed report, pinned to exact revisions."""
        if purpose not in PURPOSES or not isinstance(source_run, str) or not RUN_ID.fullmatch(source_run):
            deny("invalid multi-run evidence admission")
        if purpose == "context" and finding_id is not None:
            deny("context evidence may not claim remediation mapping")
        info, policy, policy_sha, plan, _ = self._bound_plan(plan_id)
        if source_run == plan[1]:
            deny("cannot attach primary source twice")
        document, digest, source_sha = self._report(info, source_run)
        if purpose == "remediation_retest":
            base, _, _ = self._report(info, plan[1])
            self._retest_binding(info, policy, base, finding_id, source_run, document)
        self._check_plan(plan_id, info, policy_sha)
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con)
            _audit_ok(con)
            existing = con.execute("""SELECT report_sha,source_sha,purpose,target_finding,observed_kind
                FROM investigation_evidence WHERE plan_id=? AND source_run_id=?""",
                (plan_id, source_run)).fetchone()
            identity = (digest,source_sha,purpose,finding_id,document["source_evidence"]["kind"])
            if existing and existing != identity:
                deny("existing source evidence cannot be rebound or silently revised")
            if not existing:
                count = con.execute("SELECT count(*) FROM investigation_evidence WHERE plan_id=?",
                                    (plan_id,)).fetchone()[0]
                if count >= MAX_ATTACHMENTS:
                    deny("investigation evidence attachment limit reached")
                con.execute("""INSERT INTO investigation_evidence
                    (plan_id,source_run_id,report_sha,source_sha,purpose,target_finding,
                     observed_kind,added_utc,state)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (plan_id,source_run,digest,source_sha,purpose,finding_id,
                     document["source_evidence"]["kind"],datetime.now(timezone.utc).isoformat(),
                     "pending" if purpose == "remediation_retest" else "context_only"))
                self._event(con,{"type":"investigation_evidence_attached", "plan_id":plan_id,
                                 "engagement_id":info["engagement_id"], "source_run_id":source_run,
                                 "report_sha256":digest,"source_sha256":source_sha,
                                 "purpose":purpose,"target_finding":finding_id})
            con.commit()
        return self.evidence_snapshot(plan_id)

    def _admitted(self, plan_id, info):
        with self._database() as con:
            self._tables(con)
            _audit_ok(con)
            rows=con.execute("""SELECT source_run_id,report_sha,source_sha,purpose,target_finding,
                observed_kind,state,attempts,lease_token,lease_until,result_json,result_sha
                FROM investigation_evidence WHERE plan_id=? ORDER BY source_run_id""",(plan_id,)).fetchall()
        if len(rows)>MAX_ATTACHMENTS:
            deny("investigation evidence ledger exceeds maximum size")
        docs=[]
        for row in rows:
            run,sha,source_sha,purpose,fid,kind,state,attempts,token,until,result,rs = row
            if (not RUN_ID.fullmatch(run) or not HEX.fullmatch(sha) or
                    not HEX.fullmatch(source_sha) or purpose not in PURPOSES or
                    (fid is not None and not FINDING_ID.fullmatch(fid)) or
                    type(attempts) is not int or attempts<0 or attempts>3):
                deny("investigation evidence ledger has invalid identity")
            document,actual,source_actual=self._report(info,run)
            if (sha,source_sha,kind)!=(actual,source_actual,document["source_evidence"]["kind"]):
                deny("attached report was revised or source evidence changed")
            if purpose=="context" and (fid is not None or state!="context_only" or result is not None):
                deny("context-only evidence cannot contain retest result")
            if purpose=="remediation_retest":
                if state not in ("pending","leased","completed","failed"):
                    deny("invalid retest state")
                if state=="completed" and result is None:
                    deny("retained retest outcome missing")
                if state=="leased" and (not isinstance(token,str) or len(token)!=32):
                    deny("leased retest has no fence token")
            if result is not None:
                record = self._read_result(result,rs)
                if not isinstance(record.get("status"),str) or not record["status"].startswith("RETEST_"):
                    deny("invalid persisted retest outcome")
            else:
                record = None
            docs.append({"source_run_id":run,"report_sha256":sha,"source_sha256":source_sha,
                         "purpose":purpose,"target_finding_id":fid,"source_kind":kind,
                         "state":state,"attempts":attempts,"result":record,"document":document})
        return docs

    @staticmethod
    def _cross_run_links(primary, primary_run, attached):
        """Report exact shared assets only. Never construct causal attack chains."""
        records = [(primary_run,f) for f in primary["findings"]]
        for evidence in attached:
            records.extend((evidence["source_run_id"], f) for f in evidence["document"]["findings"])
        output=[]
        for i,(run_a,a) in enumerate(records):
            for run_b,b in records[i+1:]:
                if run_a == run_b or a["affected_asset"] != b["affected_asset"]:
                    continue
                output.append({"left_run":run_a,"left_finding_id":a["id"],
                               "right_run":run_b,"right_finding_id":b["id"],
                               "asset":a["affected_asset"],
                               "classification":"UNVERIFIED_CROSS_RUN_ASSET_OVERLAP",
                               "causal_transition_observed":False})
                if len(output)>=MAX_CROSS_RUN_LINKS:
                    return output
        return output

    def evidence_snapshot(self, plan_id):
        info, policy, policy_sha, plan, base_snapshot = self._bound_plan(plan_id)
        attached=self._admitted(plan_id,info)
        primary,_,_=self._report(info,plan[1])
        return {"status":"INVESTIGATION_EVIDENCE_SNAPSHOT","plan_id":plan_id,
                "primary_source_run_id":plan[1],"report_sha256":plan[4],
                "attachments":[{k:v for k,v in d.items() if k!="document"} for d in attached],
                "cross_run_hypotheses":self._cross_run_links(primary,plan[1],attached),
                "original_steps":base_snapshot["steps"],
                "warning":"Cross-run correlation is not proof of reachability, remediation or exploitation."}

    def _claim_retest(self, plan_id, run_id, policy):
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con);_audit_ok(con)
            row=con.execute("""SELECT state,attempts,lease_until FROM investigation_evidence
                WHERE plan_id=? AND source_run_id=? AND purpose='remediation_retest'""",
                (plan_id,run_id)).fetchone()
            if not row:deny("retest evidence not explicitly attached and authorized")
            state,attempts,until=row
            if state=="completed":return {"status":"RETEST_ALREADY_RECORDED"}
            if state=="failed":return {"status":"RETEST_ATTEMPTS_EXHAUSTED"}
            if state=="leased" and until>time.time():return {"status":"RETEST_BUSY"}
            if attempts>=policy["max_attempts"]:
                con.execute("""UPDATE investigation_evidence SET state='failed',lease_token=NULL,
                    lease_until=0 WHERE plan_id=? AND source_run_id=?""",(plan_id,run_id))
                self._event(con,{"type":"investigation_retest_exhausted", "plan_id":plan_id,
                                 "source_run_id":run_id})
                con.commit();return {"status":"RETEST_ATTEMPTS_EXHAUSTED"}
            token=secrets.token_hex(16)
            con.execute("""UPDATE investigation_evidence SET state='leased',attempts=attempts+1,
                lease_token=?,lease_until=? WHERE plan_id=? AND source_run_id=?""",
                (token,time.time()+policy["lease_seconds"],plan_id,run_id))
            self._event(con,{"type":"investigation_retest_claimed","plan_id":plan_id,
                             "source_run_id":run_id,"attempt":attempts+1})
            con.commit()
            return {"status":"RETEST_CLAIMED","token":token,"attempt":attempts+1}

    def _finish_retest(self, plan_id, run_id, token, result, *, success):
        raw=canonical(result)
        if (not isinstance(result,dict) or not str(result.get("status","")).startswith("RETEST_") or
                len(raw)>MAX_RESULT_SIZE):
            deny("invalid bounded retest result")
        digest=hashlib.sha256(raw).hexdigest()
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE")
            self._tables(con);_audit_ok(con)
            row=con.execute("""SELECT state,lease_token,lease_until FROM investigation_evidence
                WHERE plan_id=? AND source_run_id=?""",(plan_id,run_id)).fetchone()
            if not row or row[0]!="leased" or row[1]!=token or row[2]<=time.time():
                return {"status":"RETEST_LEASE_SUPERSEDED"}
            con.execute("""UPDATE investigation_evidence SET state=?,lease_token=NULL,lease_until=0,
                result_json=?,result_sha=? WHERE plan_id=? AND source_run_id=?""",
                ("completed" if success else "pending",raw.decode("ascii"),digest,plan_id,run_id))
            self._event(con,{"type":"investigation_retest_completed" if success else "investigation_retest_failed",
                             "plan_id":plan_id,"source_run_id":run_id,"result_sha256":digest,
                             "outcome":result["status"]})
            con.commit()
        return {"status":"RETEST_OBSERVATION_RECORDED" if success else "RETEST_RETRY_PENDING",
                "outcome":result,"result_sha256":digest}

    def retest(self, plan_id, retest_run):
        """Operator-selected local retest; never auto-upgrade reviewed findings."""
        info,policy,policy_sha,plan,_=self._bound_plan(plan_id)
        records=self._admitted(plan_id,info)
        entry=next((d for d in records if d["source_run_id"]==retest_run and
                    d["purpose"]=="remediation_retest"),None)
        if not entry:
            deny("retest source was not explicitly bound to a confirmed finding")
        original,_,_=self._report(info,plan[1])
        self._retest_binding(info,policy,original,entry["target_finding_id"],retest_run,entry["document"])
        claim=self._claim_retest(plan_id,retest_run,policy)
        if claim["status"]!="RETEST_CLAIMED":return claim
        outcome={"status":"RETEST_EXECUTION_DENIED_RETRYABLE","source_run_id":retest_run}
        success=False
        try:
            doc=entry["document"]
            if not doc["findings"]:
                # A completed new assessment with zero leads is useful evidence,
                # but does NOT warrant a claim of a fix or a live retest.
                outcome={"status":"RETEST_NO_LOCAL_LEADS_NOT_VERIFIED_FIXED",
                         "source_run_id":retest_run,"independent_replay":False}
            else:
                if not policy["allow_local_replay"] or retest_run not in policy["replay_targets"]:
                    deny("bounded retest replay authority revoked")
                from aegis_fuzz_runtime import AegisFuzzSupervisor
                cap=policy["replay_targets"][retest_run]
                runner=AegisFuzzSupervisor(self.manifest_path,self.signature_path,self.trust_path,
                                           self.state_root,Path(cap["fuzz_policy"]))
                fresh_result=runner.verify_evidence(Path(cap["repository"]),cap["module"],retest_run,seconds=8)
                status=fresh_result.get("status")
                if status not in ("LOCAL_REPRODUCED_NEEDS_DEPLOYMENT_VALIDATION",
                                  "LOCAL_NOT_INDEPENDENTLY_REPRODUCED"):
                    deny("unrecognized bounded retest replay outcome")
                outcome={"status":("RETEST_LOCAL_LEAD_REPRODUCED_NEEDS_REVIEW" if status.startswith("LOCAL_REPRODUCED")
                                    else "RETEST_LOCAL_NOT_REPRODUCED_NEEDS_REVIEW"),
                         "source_run_id":retest_run,"independent_replay":True,
                         "replay_run_id":fresh_result["replay_run_id"]}
            # Never finalize after scope revocation, policy change, or report revision.
            _,_,current_sha,current_plan,_=self._bound_plan(plan_id)
            if current_sha!=policy_sha or current_plan!=plan:
                deny("investigation changed after local retest")
            current=self._admitted(plan_id,info)
            if not any(x["source_run_id"]==retest_run and x["report_sha256"]==entry["report_sha256"]
                       for x in current):
                deny("retest evidence changed after execution")
            success=True
        except (ExecutionDenied,OSError,ValueError,TypeError):
            # Revocation and changed policy MUST NOT be disguised as retryable
            # success/failure. Leave the lease for recovery under a valid scope.
            _,_,current_sha,_,_=self._bound_plan(plan_id)
            if current_sha!=policy_sha:
                deny("retest authorization changed during failure handling")
        result=self._finish_retest(plan_id,retest_run,claim["token"],outcome,success=success)
        return result


def main(argv=None):
    ap=argparse.ArgumentParser(description="Operator-only v1.9 multi-run evidence and bounded remediation retest")
    for key in ("manifest","signature","trust","state-root","investigation-policy"):
        ap.add_argument("--"+key,required=True)
    ap.add_argument("action",choices=("attach","snapshot","retest"))
    ap.add_argument("--plan-id",required=True)
    ap.add_argument("--source-run")
    ap.add_argument("--purpose",choices=sorted(PURPOSES),default="context")
    ap.add_argument("--finding-id")
    a=ap.parse_args(argv)
    try:
        sup=EvidenceInvestigationSupervisor(a.manifest,a.signature,a.trust,a.state_root,a.investigation_policy)
        if a.action=="attach" and a.source_run:
            result=sup.attach(a.plan_id,a.source_run,purpose=a.purpose,finding_id=a.finding_id)
        elif a.action=="snapshot" and a.source_run is None and a.finding_id is None:
            result=sup.evidence_snapshot(a.plan_id)
        elif a.action=="retest" and a.source_run and a.finding_id is None:
            result=sup.retest(a.plan_id,a.source_run)
        else:
            deny("unsupported typed investigation extension request")
        print(json.dumps(result,sort_keys=True,separators=(",", ":")))
        return 0
    except (ExecutionDenied,OSError,ValueError,TypeError):
        print("INVESTIGATION_EXTENSION_DENIED",file=__import__('sys').stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
