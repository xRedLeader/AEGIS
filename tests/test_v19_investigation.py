"""v1.9 policy-pinned planning, audit, lease recovery, and sandbox-only replay."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

from aegis_investigation import InvestigationSupervisor, _policy
from aegis_reporting import ReportingSupervisor, canonical
from aegis_supervisor import ExecutionDenied, operator_stop
from test_v18_reporting import ReportFixture
from test_v17_fuzz import BaseFuzzFixture


class PlannerTests(ReportFixture):
    def setUp(self):
        super().setUp()
        self.pfile=self.fx.fx.p / 'investigation-policy.json'
        self.policy={"schema_version":1,"configured":True,
            "engagement_ids":[self.fx.fx.manifest['engagement']['id']],
            "max_steps":12,"max_attempts":2,"lease_seconds":90,
            "allow_local_replay":False,"replay_targets":{}}
        self.save()

    def save(self):
        self.pfile.write_bytes(canonical(self.policy))
        self.pfile.chmod(0o600)

    def planner(self):
        return InvestigationSupervisor(self.fx.fx.manifest_path,
            self.fx.fx.sig_path,self.fx.fx.trust_path,self.fx.state,self.pfile)

    def test_plan_from_completed_report_and_no_agent_selected_action(self):
        report,source=self.report()
        plan=self.planner().create(source)
        self.assertEqual(plan['status'],'INVESTIGATION_PLAN')
        self.assertEqual([x['kind'] for x in plan['steps']],
            ['verify_report_integrity','await_independent_review'])
        self.assertEqual([x['state'] for x in plan['steps']], ['pending','awaiting_operator'])
        self.assertEqual(plan['source_run_id'],source)
        self.assertFalse(plan['attack_path_hypotheses'])
        self.assertEqual(self.planner().create(source)['plan_id'],plan['plan_id'])
        with self.planner()._database() as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM investigations').fetchone()[0],1)
        self.assertTrue(self.planner().verify_audit_chain())

    def test_safe_automatic_step_rechecks_full_immutable_package(self):
        report,source=self.report()
        plan=self.planner().create(source)
        outcome=self.planner().advance(plan['plan_id'])
        self.assertEqual(outcome['status'],'INVESTIGATION_ACTION_COMPLETED')
        self.assertEqual(outcome['result']['status'],'REPORT_PACKAGE_VERIFIED')
        after=self.planner().snapshot(plan['plan_id'])
        self.assertEqual(after['steps'][0]['state'],'completed')
        self.assertEqual(after['steps'][0]['result']['report_sha256'], report['sha256'])
        self.assertEqual(self.planner().advance(plan['plan_id'])['status'],
                         'INVESTIGATION_OPERATOR_ACTION_REQUIRED')

    def test_reject_source_not_reported_or_incomplete(self):
        source=self.completed()
        with self.assertRaises(ExecutionDenied):self.planner().create(source)
        with self.assertRaises(ExecutionDenied):self.planner().create('0'*36)

    def test_report_or_source_tamper_denied(self):
        report,source=self.report()
        plan=self.planner().create(source)
        Path(report['report']).parent.joinpath('REPORT.md').write_text('tampered')
        with self.assertRaises(ExecutionDenied):self.planner().advance(plan['plan_id'])
        self.assertFalse(self.planner().verify_audit_chain() is False)

    def test_modification_of_source_bytes_denies_snapshot(self):
        report,source=self.report()
        plan=self.planner().create(source)
        p=Path(report['report']).parents[2]/'runs'/source/'source-review.json'
        p.write_text('{}')
        with self.assertRaises(ExecutionDenied):self.planner().snapshot(plan['plan_id'])

    def test_scope_revocation_and_emergency_stop_fail_closed(self):
        report,source=self.report()
        plan=self.planner().create(source)
        operator_stop(self.fx.state,self.fx.fx.manifest['engagement']['id'])
        with self.assertRaises(ExecutionDenied):self.planner().advance(plan['plan_id'])

    def test_policy_edit_revocation_and_noncanonical_json_denied(self):
        report,source=self.report()
        plan=self.planner().create(source)
        self.policy['max_steps']=11;self.save()
        with self.assertRaises(ExecutionDenied):self.planner().snapshot(plan['plan_id'])
        self.pfile.write_text(json.dumps(self.policy,indent=2))
        with self.assertRaises(ExecutionDenied):self.planner().create(source)

    def test_untrusted_policy_symlink_permissions_and_path_overlap(self):
        report,source=self.report()
        self.pfile.chmod(0o644)
        with self.assertRaises(ExecutionDenied):self.planner().create(source)
        self.pfile.chmod(0o600)
        bad=self.fx.fx.p/'symlink.json';bad.symlink_to(self.pfile)
        sup=InvestigationSupervisor(self.fx.fx.manifest_path,
            self.fx.fx.sig_path,self.fx.fx.trust_path,self.fx.state,bad)
        with self.assertRaises(OSError):sup.create(source)
        inside=self.fx.state/'config.json';inside.write_bytes(canonical(self.policy));inside.chmod(0o600)
        sup=InvestigationSupervisor(self.fx.fx.manifest_path,
            self.fx.fx.sig_path,self.fx.fx.trust_path,self.fx.state,inside)
        with self.assertRaises(ExecutionDenied):sup.create(source)

    def test_max_steps_blocks_unbounded_planning(self):
        report,source=self.report()
        self.policy['max_steps']=1;self.save()
        with self.assertRaisesRegex(ExecutionDenied,'step ceiling'):
            self.planner().create(source)

    def test_zero_leads_is_not_clean_report(self):
        data=canonical({'status':'STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES','candidates':[]})
        report,source=self.report(data)
        plan=self.planner().create(source)
        self.assertEqual(len(plan['steps']),1)
        self.assertIn('unverified',plan['warning'].lower())

    def test_shared_asset_generates_only_unverified_correlation(self):
        data=canonical({'status':'STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES','candidates':[
            {'id':'PY-EVAL','status':'unverified_static_lead','file':'same.py','line':12},
            {'id':'PY-PICKLE-LOAD','status':'unverified_static_lead','file':'same.py','line':12}]})
        report,source=self.report(data)
        plan=self.planner().create(source)
        self.assertEqual(len(plan['attack_path_hypotheses']),1)
        edge=plan['attack_path_hypotheses'][0]
        self.assertEqual(edge['classification'],'UNVERIFIED_SHARED_ASSET_ONLY')
        self.assertIs(edge['observed_transition'],False)
        self.assertNotIn('verified_chain',plan)

    def test_new_report_revision_requires_an_explicit_new_plan(self):
        report,source=self.report()
        plan=self.planner().create(source)
        with self.planner()._database() as con:
            con.execute("UPDATE assessment_reports SET latest_sha256=? WHERE source_run_id=?",
                        ('f'*64,source))
        with self.assertRaises(ExecutionDenied):self.planner().snapshot(plan['plan_id'])
        with self.assertRaises(ExecutionDenied):self.planner().advance(plan['plan_id'])

    def test_worker_visible_policy_path_is_denied_before_open(self):
        report,source=self.report()
        sup=InvestigationSupervisor(self.fx.fx.manifest_path,self.fx.fx.sig_path,
             self.fx.fx.trust_path,self.fx.state,'/usr/aegis-insecure-config.json')
        with self.assertRaises(ExecutionDenied):sup.create(source)

    def test_exact_concurrent_create_is_idempotent(self):
        report,source=self.report()
        with ThreadPoolExecutor(max_workers=3) as pool:
            values=list(pool.map(lambda _: self.planner().create(source)['plan_id'],range(3)))
        self.assertEqual(len(set(values)),1)
        self.assertTrue(self.planner().verify_audit_chain())

    def test_bounded_autonomous_run_stops_at_operator_review_gate(self):
        report,source=self.report()
        plan=self.planner().create(source)
        result=self.planner().run_allowed(plan['plan_id'],max_steps=3)
        self.assertEqual(result['status'],'INVESTIGATION_BOUNDED_PROGRESS')
        self.assertEqual(result['executed'],1)
        self.assertEqual([s['status'] for s in result['outcomes']],
            ['INVESTIGATION_ACTION_COMPLETED','INVESTIGATION_OPERATOR_ACTION_REQUIRED'])
        with self.assertRaises(ExecutionDenied):self.planner().run_allowed(plan['plan_id'],0)
        with self.assertRaises(ExecutionDenied):self.planner().run_allowed(plan['plan_id'],True)
        self.assertTrue(self.planner().verify_audit_chain())

    def test_expired_claim_recovers_with_new_token_and_fencing(self):
        report,source=self.report()
        plan=self.planner().create(source)
        planner=self.planner();info,pol,sha=planner._admit()
        claim1=planner._claim(plan['plan_id'],info,pol)
        self.assertEqual(claim1['status'],'CLAIMED')
        self.assertEqual(planner._claim(plan['plan_id'],info,pol)['status'],'INVESTIGATION_BUSY')
        with planner._database() as con:
            con.execute('UPDATE investigation_steps SET lease_until=0 WHERE step_id=?',(claim1['step_id'],))
        claim2=self.planner()._claim(plan['plan_id'],info,pol)
        self.assertEqual(claim2['status'],'CLAIMED')
        self.assertNotEqual(claim1['token'],claim2['token'])
        self.assertEqual(planner._complete(plan['plan_id'],claim1['step_id'],claim1['token'],
            {'status':'REPORT_PACKAGE_VERIFIED'},success=True)['status'], 'INVESTIGATION_LEASE_SUPERSEDED')
        finish=planner._complete(plan['plan_id'],claim2['step_id'],claim2['token'],
            {'status':'REPORT_PACKAGE_VERIFIED'},success=True)
        self.assertEqual(finish['status'],'INVESTIGATION_ACTION_COMPLETED')
        self.assertEqual(self.planner().snapshot(plan['plan_id'])['steps'][0]['attempts'],2)
        self.assertTrue(self.planner().verify_audit_chain())

    def test_expired_claim_exhausted_attempts_fail_safe(self):
        report,source=self.report()
        plan=self.planner().create(source)
        p=self.planner();info,policy,_=p._admit()
        for _ in range(2):
            first=p._claim(plan['plan_id'],info,policy)
            self.assertEqual(first['status'],'CLAIMED')
            with p._database() as con:con.execute('UPDATE investigation_steps SET lease_until=0 WHERE step_id=?',(first['step_id'],))
        self.assertEqual(p._claim(plan['plan_id'],info,policy)['status'],'INVESTIGATION_ACTION_FAILED')
        self.assertEqual(p.snapshot(plan['plan_id'])['steps'][0]['state'],'failed')

    def test_corrupt_result_digest_rejected(self):
        report,source=self.report()
        plan=self.planner().create(source)
        self.planner().advance(plan['plan_id'])
        with self.planner()._database() as con:
            con.execute("UPDATE investigation_steps SET result_json='{}' WHERE plan_id=?",(plan['plan_id'],))
        with self.assertRaises(ExecutionDenied):self.planner().snapshot(plan['plan_id'])

    def test_policy_scope_and_replay_allowlist_negative(self):
        report,source=self.report()
        self.policy['allow_local_replay']=True
        self.policy['replay_targets']={source:{'repository':'/not/an/authorized/repository',
            'module':'src/a.py','fuzz_policy':str(self.fx.fx.p/'fuzz.json')}}
        self.save()
        with self.assertRaises(ExecutionDenied):self.planner().create(source)
        self.policy['replay_targets']={source:{'repository':str(self.fx.fx.repo),
            'module':'../escape.py','fuzz_policy':str(self.fx.fx.p/'fuzz.json')}}
        self.save()
        with self.assertRaises(ExecutionDenied):self.planner().create(source)


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()!=0,
    'NOT EXECUTED: needs non-root Linux namespaces and seccomp')
class LocalReplayIntegration(BaseFuzzFixture,unittest.TestCase):
    """Actual v1.7 execution remains behind its signed, kernel-constrained gate."""
    def setUp(self):
        super().setUp()
        self.investigation_file=self.fx.p/'investigation.json'

    def test_authorized_replay_uses_separate_budget_and_remains_unverified(self):
        run=self.run_fuzz()
        run_id=run['run_id']
        reporter=ReportingSupervisor(self.fx.manifest_path,self.fx.sig_path,self.fx.trust_path,self.state)
        record=reporter.generate(run_id,'bounded-fuzz.json')
        policy={'schema_version':1,'configured':True,
            'engagement_ids':[self.fx.manifest['engagement']['id']],
            'max_steps':8,'max_attempts':2,'lease_seconds':90,'allow_local_replay':True,
            'replay_targets':{run_id:{'repository':str(self.fx.repo),
                'module':'auth/guard.py','fuzz_policy':str(self.policy_path)}}}
        self.investigation_file.write_bytes(canonical(policy));self.investigation_file.chmod(0o600)
        inv=lambda:InvestigationSupervisor(self.fx.manifest_path,self.fx.sig_path,
                                    self.fx.trust_path,self.state,self.investigation_file)
        plan=inv().create(run_id)
        self.assertEqual([s['kind'] for s in plan['steps']][:2],
                         ['verify_report_integrity','replay_bounded_local'])
        self.assertEqual(inv().advance(plan['plan_id'])['status'],'INVESTIGATION_ACTION_COMPLETED')
        replay=inv().advance(plan['plan_id'])
        self.assertEqual(replay['status'],'INVESTIGATION_ACTION_COMPLETED')
        self.assertIn(replay['result']['status'],('LOCAL_REPRODUCED_NEEDS_DEPLOYMENT_VALIDATION',
                'LOCAL_NOT_INDEPENDENTLY_REPRODUCED'))
        self.assertNotIn('confirmed',str(replay).lower())
        plan2=inv().snapshot(plan['plan_id'])
        self.assertEqual(plan2['steps'][1]['result']['replay_run_id'],replay['result']['replay_run_id'])
        self.assertEqual(inv().advance(plan['plan_id'])['status'],'INVESTIGATION_OPERATOR_ACTION_REQUIRED')
        self.assertTrue(inv().verify_audit_chain())

if __name__=='__main__': unittest.main()
