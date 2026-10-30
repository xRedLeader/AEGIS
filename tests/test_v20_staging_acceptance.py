"""v2.0 complete, synthetic staging path through operator review and local remediation observation.

No production systems, network endpoints or real identities are involved. Human
review keys and synthetic source fixtures are deliberately disposable.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

from aegis_integrated_assessment import IntegratedAssessment
from aegis_reporting import canonical
from aegis_supervisor import ExecutionDenied
from test_v17_fuzz import SAFE_TARGET
import test_v19_evidence as v19_tests


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()!=0,
                     'NOT EXECUTED: real non-root namespace execution required')
class FullStagingAcceptance(unittest.TestCase):
    def setUp(self):
        self.fx=v19_tests.BoundedRemediationTests('test_real_bound_retest_replays_only_approved_sandbox')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.assessment_policy=self.fx.fx.p/'v2-assessment-policy.json'
        self.plan={"schema_version":1,"configured":True,
            "engagement_ids":[self.fx.fx.manifest['engagement']['id']],
            "repository":str(self.fx.fx.repo),"lease_seconds":90,"steps":[]}

    def controller(self):
        return IntegratedAssessment(self.fx.fx.manifest_path,self.fx.fx.sig_path,
            self.fx.fx.trust_path,self.fx.state,self.assessment_policy)

    def save(self):
        self.assessment_policy.write_bytes(canonical(self.plan))
        self.assessment_policy.chmod(0o600)

    def local_assessment(self):
        self.plan['steps']=[
            {"id":"test","action":"local_contract","seconds":5,"module":"auth/guard.py",
             "seed":42,"cases":24,"trials":3,"fuzz_policy":str(self.fx.policy_path)},
            {"id":"report","action":"report","source":"test"},
        ]
        self.save()
        engine=self.controller()
        plan=engine.create()['assessment_id']
        outcome=engine.run(plan)
        self.assertEqual(outcome['completed'],2)
        self.assertEqual(outcome['status'],'WORKFLOW_COMPLETED_PENDING_INDEPENDENT_VALIDATION')
        steps=engine.snapshot(plan)['steps']
        self.assertEqual(steps[1]['result']['run_id'],steps[0]['result']['run_id'])
        return steps[0]['result']['run_id'],steps[1]['result']['report_sha256']

    def test_dual_signed_impact_review_then_operator_bound_remediation_retest(self):
        initial_run,_=self.local_assessment()
        info,_=self.controller()._guard()
        report_path=Path(info['report_directory'])/'assessments'/initial_run/'findings.json'
        doc=json.loads(report_path.read_bytes())
        self.assertGreater(len(doc['findings']),0)
        self.assertTrue(all(x['verdict']=='needs_validation' for x in doc['findings']))

        # v1.8 is the ONLY path for independently verified staging promotion.
        finding=self.fx.promote({'report':str(report_path)},initial_run)
        with self.fx.reporter._database() as con:
            latest=con.execute('SELECT latest_sha256 FROM assessment_reports WHERE source_run_id=?',
                               (initial_run,)).fetchone()[0]
        self.assertEqual(len(latest),64)
        self.assertNotEqual(latest,hashlib.sha256(report_path.read_bytes()).hexdigest())

        # Operator substitutes a fixed synthetic local function and explicitly
        # re-pins its source hash for an independent, separately charged run.
        self.fx.target.write_text(SAFE_TARGET)
        self.fx.policy['targets']['auth/guard.py']['sha256']=hashlib.sha256(self.fx.target.read_bytes()).hexdigest()
        self.fx.save()
        fixed_run,_=self.local_assessment()
        self.assertNotEqual(initial_run,fixed_run)
        self.fx.enable(fixed_run)

        self.plan['steps']=[
            {"id":"reviewed","action":"admit_report","run_id":initial_run,
             "report_sha256":latest,"investigation_policy":str(self.fx.pfile)},
            {"id":"investigate","action":"investigate","source":"reviewed",
             "investigation_policy":str(self.fx.pfile)},
            {"id":"retest","action":"remediation_retest","source":"investigate",
             "retest_run_id":fixed_run,"finding_id":finding,
             "investigation_policy":str(self.fx.pfile)},
        ]
        self.save()
        engine=self.controller()
        final=engine.create()['assessment_id']
        result=engine.run(final)
        self.assertEqual(result['completed'],3)
        snap=engine.snapshot(final)
        self.assertEqual(snap['steps'][-1]['result']['status'],
                         'RETEST_NO_LOCAL_LEADS_NOT_VERIFIED_FIXED')
        self.assertEqual(snap['status'],'WORKFLOW_COMPLETED_PENDING_INDEPENDENT_VALIDATION')
        self.assertTrue(engine.verify_audit_chain())
        from aegis_investigation_evidence import EvidenceInvestigationSupervisor
        inv=EvidenceInvestigationSupervisor(self.fx.fx.manifest_path,self.fx.fx.sig_path,
            self.fx.fx.trust_path,self.fx.state,self.fx.pfile)
        inv_id=snap['steps'][1]['result']['plan_id']
        details=inv.evidence_snapshot(inv_id)
        self.assertEqual(details['attachments'][0]['purpose'],'remediation_retest')
        self.assertEqual(details['attachments'][0]['state'],'completed')
        # No outcome may assert a verified production fix or exploit.
        self.assertNotIn('REMEDIATED',json.dumps(details))
        self.assertNotIn('FIXED_VERIFIED',json.dumps(details))

    def test_rebinding_trusted_retest_policy_invalidates_incomplete_plan(self):
        initial_run,_=self.local_assessment()
        self.fx.enable(initial_run)
        self.plan['steps']=[
            {"id":"reviewed","action":"admit_report","run_id":initial_run,
             "report_sha256":"a"*64,"investigation_policy":str(self.fx.pfile)}]
        self.save()
        engine=self.controller()
        created=engine.create()['assessment_id']
        current=json.loads(self.fx.pfile.read_bytes())
        current['max_attempts']=3
        self.fx.pfile.write_bytes(canonical(current))
        with self.assertRaises(ExecutionDenied):engine.advance(created)
        with engine._database() as con:
            self.assertEqual(con.execute('SELECT count(*) FROM integrated_steps WHERE assessment_id=? AND attempts>0',(created,)).fetchone()[0],0)

    def test_unreviewed_or_wrong_revision_cannot_be_admitted(self):
        initial_run,base_sha=self.local_assessment()
        self.fx.enable(initial_run)
        self.plan['steps']=[
            {"id":"reviewed","action":"admit_report","run_id":initial_run,
             "report_sha256":"0"*64,"investigation_policy":str(self.fx.pfile)}]
        self.save()
        engine=self.controller()
        ident=engine.create()['assessment_id']
        with self.assertRaises(ExecutionDenied):engine.advance(ident)
        self.assertEqual(engine.snapshot(ident)['status'],'REQUIRES_OPERATOR_RECONCILIATION')

if __name__=='__main__':unittest.main()
