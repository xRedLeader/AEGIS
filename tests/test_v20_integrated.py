"""v2.0: operator-only end-to-end orchestration; no new agent execution privilege."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor

from aegis_integrated_assessment import IntegratedAssessment, _policy
from aegis_reporting import canonical
from aegis_supervisor import ExecutionDenied, operator_stop
from test_v18_reporting import ReportFixture


class IntegratedFixture(ReportFixture):
    def setUp(self):
        super().setUp()
        self.policy_path = self.fx.fx.p / "integrated-policy.json"
        self.inv_path = self.fx.fx.p / "investigation-policy.json"
        self.inv_policy = {"schema_version": 1, "configured": True,
            "engagement_ids": [self.fx.fx.manifest["engagement"]["id"]],
            "max_steps": 12, "max_attempts": 2, "lease_seconds": 90,
            "allow_local_replay": False, "replay_targets": {}}
        self.inv_path.write_bytes(canonical(self.inv_policy))
        self.inv_path.chmod(0o600)
        self.policy = {"schema_version": 1, "configured": True,
            "engagement_ids": [self.fx.fx.manifest["engagement"]["id"]],
            "repository": str(self.fx.fx.repo), "lease_seconds": 90,
            "steps": [{"id":"scan", "action":"source_review", "seconds":5},
                      {"id":"render", "action":"report", "source":"scan"},
                      {"id":"investigate", "action":"investigate", "source":"render",
                       "investigation_policy":str(self.inv_path)},
                      {"id":"progress", "action":"progress_investigation",
                       "source":"investigate", "investigation_policy":str(self.inv_path),
                       "max_steps":2}]}
        self.save()

    def save(self):
        self.policy_path.write_bytes(canonical(self.policy))
        self.policy_path.chmod(0o600)

    def controller(self):
        return IntegratedAssessment(self.fx.fx.manifest_path, self.fx.fx.sig_path,
                                    self.fx.fx.trust_path, self.fx.state, self.policy_path)


class IntegratedAssessmentTests(IntegratedFixture):
    def test_plan_creates_only_fixed_actions_without_execution(self):
        selected = self.controller().create()
        self.assertEqual([x["action"] for x in selected["steps"]],
            ["source_review","report","investigate","progress_investigation"])
        self.assertEqual([x["state"] for x in selected["steps"]], ["pending"]*4)
        self.assertEqual(selected["status"],"IN_PROGRESS")
        with self.controller()._database() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM runs").fetchone()[0],0)
            self.assertEqual(con.execute("SELECT count(*) FROM integrated_steps").fetchone()[0],4)
        self.assertTrue(self.controller().verify_audit_chain())

    def test_real_isolated_source_to_report_investigation_and_operator_checkpoint(self):
        engine = self.controller()
        assessment = engine.create()["assessment_id"]
        result = engine.run(assessment, max_actions=5)
        self.assertEqual(result["completed"],4)
        self.assertEqual(result["status"],"WORKFLOW_COMPLETED_PENDING_INDEPENDENT_VALIDATION")
        recovered = self.controller().snapshot(assessment)
        self.assertTrue(all(s["state"] == "completed" for s in recovered["steps"]))
        source = recovered["steps"][0]["result"]
        review = recovered["steps"][1]["result"]
        self.assertEqual(source["evidence"],"source-review.json")
        self.assertEqual(review["run_id"],source["run_id"])
        self.assertEqual(len(review["report_sha256"]),64)
        self.assertEqual(recovered["steps"][3]["result"]["operator_review_required"],True)
        self.assertEqual(recovered["steps"][3]["result"]["executed"],1)
        with engine._database() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM assessment_reports").fetchone()[0],1)
            self.assertEqual(con.execute("SELECT count(*) FROM investigations").fetchone()[0],1)
            self.assertEqual(con.execute("SELECT count(*) FROM notification_outbox").fetchone()[0],1)
        self.assertTrue(engine.verify_audit_chain())
        self.assertEqual(self.controller().advance(assessment)["status"],
                         "WORKFLOW_COMPLETED_PENDING_INDEPENDENT_VALIDATION")

    def test_resumes_completed_actions_after_restart_without_duplicate_scans(self):
        assessment = self.controller().create()["assessment_id"]
        step = self.controller().advance(assessment)
        self.assertEqual(step["step_id"],"scan")
        before = self.controller().snapshot(assessment)["steps"][0]["result"]["run_id"]
        later = self.controller().run(assessment)
        self.assertEqual(later["completed"],4)
        with self.controller()._database() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM runs WHERE run_id=?",(before,)).fetchone()[0],1)
        self.assertEqual(self.controller().snapshot(assessment)["steps"][0]["attempts"],1)

    def test_real_signed_osv_and_offline_fuzz_feed_reports_and_investigation(self):
        # Every adapter uses the existing signed authorization and kernel sandbox;
        # the controller cannot run target code or obtain a network capability.
        from datetime import datetime, timezone
        from aegis_intelligence import CONTEXT
        self.fx.fx.manifest["methods"]["allowed"]=["source_review","dependency_analysis","bounded_fuzzing"]
        self.fx.fx.trust["approved_methods"]=["source_review","dependency_analysis","bounded_fuzzing"]
        self.fx.fx.manifest["limits"]["engagement_runtime_minutes"]=3
        self.fx.fx.save()
        (self.fx.fx.repo/"requirements.txt").write_text("requests==2.31.0\n")
        bundle=self.fx.fx.p/"osv.json"
        sig=self.fx.fx.p/"osv.sig"
        record={"format":"AEGIS-OSV-v1","source":"OSV",
            "source_url":"https://api.osv.dev",
            "retrieved_at_utc":datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "records":[{"id":"GHSA-TEST-LOCAL-1001","affected":[{
                "package":{"ecosystem":"PyPI","name":"requests"},
                "versions":["2.31.0"]}]}]}
        raw=canonical(record);bundle.write_bytes(raw);sig.write_bytes(self.fx.fx.key.sign(CONTEXT+raw));sig.chmod(0o600)
        (self.fx.fx.repo/"auth").mkdir()
        target=self.fx.fx.repo/"auth"/"tenant.py"
        target.write_text('def gate(actor, owner):\n    return str(actor).casefold() == str(owner).casefold()\n')
        fpolicy=self.fx.fx.p/"fuzz-policy.json"
        fpolicy.write_text(json.dumps({"schema_version":1,"configured":True,
           "authorized_repository":str(self.fx.fx.repo),"targets":{"auth/tenant.py":{
               "sha256":hashlib.sha256(target.read_bytes()).hexdigest(),
               "callable":"gate","contract":"strict_tenant_owner_v1","max_cases":24}}}))
        fpolicy.chmod(0o600)
        self.policy["steps"]=[
            {"id":"scan","action":"source_review","seconds":5},
            {"id":"scan_report","action":"report","source":"scan"},
            {"id":"deps","action":"dependency_intelligence","seconds":5,"snapshot":str(bundle),"signature":str(sig)},
            {"id":"deps_report","action":"report","source":"deps"},
            {"id":"fuzz","action":"local_contract","seconds":5,"module":"auth/tenant.py",
             "seed":42,"cases":24,"trials":3,"fuzz_policy":str(fpolicy)},
            {"id":"fuzz_report","action":"report","source":"fuzz"},
            {"id":"investigate","action":"investigate","source":"fuzz_report","investigation_policy":str(self.inv_path)},
        ]
        self.save()
        plan=self.controller().create()["assessment_id"]
        outcome=self.controller().run(plan)
        self.assertEqual(outcome["completed"],7)
        self.assertEqual(outcome["status"],"WORKFLOW_COMPLETED_PENDING_INDEPENDENT_VALIDATION")
        results=[x["result"] for x in self.controller().snapshot(plan)["steps"]]
        self.assertTrue(all(x["action"] in ("source_review","report","dependency_intelligence","local_contract","investigate") for x in results))
        self.assertEqual(results[2]["evidence"],"advisory-candidates.json")
        self.assertEqual(results[4]["evidence"],"bounded-fuzz.json")
        with self.controller()._database() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM assessment_reports").fetchone()[0],3)
            self.assertEqual(con.execute("SELECT count(*) FROM investigations").fetchone()[0],1)
            self.assertEqual(con.execute("SELECT count(*) FROM runs WHERE status='completed'").fetchone()[0],3)
        self.assertTrue(self.controller().verify_audit_chain())

    def test_real_local_receiver_acknowledgement_after_canonical_report(self):
        self.policy["steps"] = self.policy["steps"][:2] + [{"id":"notice","action":"notify",
            "source":"render", "notification_policy":str(self.policy_file)}]
        self.save()
        received,done=self.listener()
        plan=self.controller().create()["assessment_id"]
        out=self.controller().run(plan)
        self.assertEqual(out["completed"],3)
        self.assertTrue(done.wait(5))
        self.assertEqual(len(received),1)
        snap=self.controller().snapshot(plan)
        self.assertEqual(snap["steps"][-1]["result"]["status"],"LOCAL_DELIVERY_ACKNOWLEDGED")
        self.assertNotIn("Authorization",repr(received))
        self.assertTrue(self.controller().verify_audit_chain())

    def test_operator_request_id_is_idempotent_but_cannot_change_policy(self):
        key=str(uuid.uuid4())
        self.assertEqual(self.controller().create(key)["assessment_id"],key)
        self.assertEqual(self.controller().create(key)["assessment_id"],key)
        with self.controller()._database() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM integrated_assessments").fetchone()[0],1)
        self.policy["lease_seconds"]=100;self.save()
        with self.assertRaises(ExecutionDenied): self.controller().create(key)

    def test_reject_unapproved_missing_forward_duplicate_and_arbitrary_steps(self):
        invalid = [
            [{"id":"shell","action":"shell","command":"curl localhost"}],
            [{"id":"report","action":"report","source":"later"},
             {"id":"later","action":"source_review","seconds":5}],
            [{"id":"dup","action":"source_review","seconds":5},
             {"id":"dup","action":"source_review","seconds":5}],
            [{"id":"bad","action":"source_review","seconds":5,"extra":"y"}],
            [{"id":"bad","action":"source_review","seconds":600}],
            [{"id":"bad","action":"notify","source":"bad","notification_policy":str(self.policy_file)}],
        ]
        for steps in invalid:
            with self.subTest(steps=steps):
                self.policy["steps"]=steps;self.save()
                with self.assertRaises(ExecutionDenied): self.controller().create()
        with self.controller()._database() as con:
            self.assertIsNone(con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='integrated_assessments'").fetchone())

    def test_out_of_scope_repository_does_not_create_ledger_plan(self):
        other=self.fx.fx.p / "other"
        other.mkdir()
        self.policy["repository"]=str(other);self.save()
        with self.assertRaises(ExecutionDenied): self.controller().create()
        with self.controller()._database() as con:
            self.assertIsNone(con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='integrated_assessments'").fetchone())

    def test_policy_rejects_symlink_wide_permissions_repos_and_state_location(self):
        alias=self.fx.fx.p / "alias-policy.json"
        alias.symlink_to(self.policy_path)
        other=IntegratedAssessment(self.fx.fx.manifest_path,self.fx.fx.sig_path,
             self.fx.fx.trust_path,self.fx.state,alias)
        with self.assertRaises((ExecutionDenied,OSError)): other.create()
        self.policy_path.chmod(0o644)
        with self.assertRaises(ExecutionDenied): self.controller().create()
        self.policy_path.chmod(0o600)
        report_dir=Path(self.controller()._guard()[0]["report_directory"])
        replaced=self.controller()
        replaced.assessment_policy=report_dir/"policy.json"
        with self.assertRaises(ExecutionDenied): replaced.create()

    def test_policy_change_and_stop_prevent_continuation(self):
        plan=self.controller().create()["assessment_id"]
        self.policy["lease_seconds"]=120;self.save()
        with self.assertRaises(ExecutionDenied): self.controller().advance(plan)
        self.policy["lease_seconds"]=90;self.save()
        operator_stop(self.fx.state,self.fx.fx.manifest["engagement"]["id"])
        with self.assertRaises(ExecutionDenied): self.controller().advance(plan)

    def test_expired_inflight_step_fails_closed_and_never_double_runs(self):
        engine=self.controller();plan=engine.create()["assessment_id"]
        info,policy,sha=engine._admit()
        claim=engine._claim(plan,info,policy,sha)
        self.assertEqual(claim[0],0)
        with engine._database() as con:
            con.execute("UPDATE integrated_steps SET lease_until=? WHERE assessment_id=? AND ordinal=0",(time.time()-3,plan))
        with self.assertRaisesRegex(ExecutionDenied,"reconciliation"):
            engine.advance(plan)
        snap=engine.snapshot(plan)
        self.assertEqual(snap["status"],"REQUIRES_OPERATOR_RECONCILIATION")
        self.assertEqual(snap["steps"][0]["state"],"attention")
        with engine._database() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM runs").fetchone()[0],0)
        with self.assertRaises(ExecutionDenied):engine.run(plan)

    def test_parallel_claims_are_single_owner(self):
        engine=self.controller();plan=engine.create()["assessment_id"]
        info,policy,sha=engine._admit()
        with ThreadPoolExecutor(max_workers=3) as pool:
            outcomes=list(pool.map(lambda _ : _try_claim(self.controller(),plan),range(3)))
        self.assertEqual(sum(outcomes),1)
        with engine._database() as con:
            self.assertEqual(con.execute("SELECT attempts FROM integrated_steps WHERE ordinal=0").fetchone()[0],1)

    def test_corrupt_stored_result_denied_even_if_audit_chain_valid(self):
        plan=self.controller().create()["assessment_id"]
        self.controller().advance(plan)
        with self.controller()._database() as con:
            con.execute("UPDATE integrated_steps SET result_json='{}' WHERE assessment_id=? AND ordinal=0",(plan,))
        with self.assertRaises(ExecutionDenied):self.controller().snapshot(plan)

    def test_recomputed_sqlite_result_digest_cannot_erase_audit_provenance(self):
        engine=self.controller()
        plan=engine.create()["assessment_id"]
        engine.advance(plan)
        forged=canonical({"action":"source_review","run_id":str(uuid.uuid4()),
                          "evidence":"source-review.json"}).decode("ascii")
        with engine._database() as con:
            con.execute("UPDATE integrated_steps SET result_json=?,result_sha=? WHERE assessment_id=? AND ordinal=0",
                (forged,hashlib.sha256(forged.encode()).hexdigest(),plan))
        self.assertTrue(engine.verify_audit_chain())
        with self.assertRaisesRegex(ExecutionDenied,"hash-chained"):
            engine.snapshot(plan)

    def test_run_does_not_claim_unapproved_live_http_permission(self):
        self.policy["steps"]=[{"id":"network","action":"http_metadata","url":"https://example.test/",
             "method":"HEAD", "seconds":2}]
        self.save()
        with self.assertRaises(ExecutionDenied):self.controller().create()
        with self.controller()._database() as con:
            self.assertIsNone(con.execute("SELECT name FROM sqlite_master WHERE name='integrated_assessments'").fetchone())

    def test_report_and_credential_material_not_exposed_in_step_results(self):
        plan=self.controller().create()["assessment_id"]
        self.controller().run(plan)
        snapshot=self.controller().snapshot(plan)
        raw=json.dumps(snapshot)
        self.assertNotIn(str(self.fx.fx.p),raw)
        self.assertNotIn("subprocess.run",raw)
        self.assertNotIn("shell=True",raw)
        self.assertNotIn("Bearer ",raw)


def _table(connection, name):
    return connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone() is not None


def _try_claim(controller, plan):
    try:
        info,policy,sha=controller._admit()
        controller._claim(plan,info,policy,sha)
        return 1
    except ExecutionDenied:
        return 0
