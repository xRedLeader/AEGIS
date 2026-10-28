"""v1.9 append-only multi-run correlations, scope, and fenced remediation retest."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_investigation_evidence import EvidenceInvestigationSupervisor
from aegis_reporting import ReportingSupervisor, canonical
from aegis_supervisor import ExecutionDenied, operator_stop
from aegis_finding_promotion import FindingPromotionSupervisor, VERIFY_CONTEXT, APPROVE_CONTEXT
from test_v18_reporting import ReportFixture
from test_v17_fuzz import BaseFuzzFixture


class MultiRunTests(ReportFixture):
    def setUp(self):
        super().setUp()
        self.pfile=self.fx.fx.p/'investigation-policy.json'
        self.policy={"schema_version":1,"configured":True,
            "engagement_ids":[self.fx.fx.manifest['engagement']['id']],
            "max_steps":16,"max_attempts":2,"lease_seconds":90,
            "allow_local_replay":False,"replay_targets":{}}
        self.save_policy_v19()

    def save_policy_v19(self):
        self.pfile.write_bytes(canonical(self.policy));self.pfile.chmod(0o600)

    def engine(self):
        return EvidenceInvestigationSupervisor(self.fx.fx.manifest_path,
            self.fx.fx.sig_path,self.fx.fx.trust_path,self.fx.state,self.pfile)

    def test_correlation_is_source_bound_and_unverified(self):
        first,run1=self.report()
        second,run2=self.report()
        plan=self.engine().create(run1)
        result=self.engine().attach(plan['plan_id'],run2)
        self.assertEqual(result['status'],'INVESTIGATION_EVIDENCE_SNAPSHOT')
        self.assertEqual(len(result['attachments']),1)
        self.assertEqual(result['attachments'][0]['state'],'context_only')
        self.assertEqual(result['attachments'][0]['report_sha256'],second['sha256'])
        self.assertEqual(len(result['cross_run_hypotheses']),1)
        self.assertEqual(result['cross_run_hypotheses'][0]['classification'],
                         'UNVERIFIED_CROSS_RUN_ASSET_OVERLAP')
        self.assertIs(result['cross_run_hypotheses'][0]['causal_transition_observed'],False)
        self.assertEqual(self.engine().attach(plan['plan_id'],run2)['attachments'],result['attachments'])
        self.assertEqual(len(self.engine().evidence_snapshot(plan['plan_id'])['attachments']),1)
        self.assertTrue(self.engine().verify_audit_chain())

    def test_independent_reports_have_no_invented_cross_run_link(self):
        _,run1=self.report()
        different=canonical({"status":"STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES",
            "candidates":[{"id":"PY-EVAL","status":"unverified_static_lead","file":"different.py","line":9}]})
        _,run2=self.report(different)
        plan=self.engine().create(run1)
        attached=self.engine().attach(plan['plan_id'],run2)
        self.assertFalse(attached['cross_run_hypotheses'])

    def test_retest_requires_confirmed_finding_and_explicit_allowlist(self):
        _,run1=self.report();_,run2=self.report()
        plan=self.engine().create(run1)
        fid=plan['steps'][1]['finding_id']
        with self.assertRaises(ExecutionDenied):
            self.engine().attach(plan['plan_id'],run2,purpose='remediation_retest',finding_id=fid)
        with self.assertRaises(ExecutionDenied):
            self.engine().attach(plan['plan_id'],run2,purpose='context',finding_id=fid)
        with self.assertRaises(ExecutionDenied):
            self.engine().retest(plan['plan_id'],run2)

    def test_reject_same_source_missing_invalid_purpose_and_unreported_run(self):
        _,run=self.report()
        plan=self.engine().create(run)
        with self.assertRaises(ExecutionDenied):
            self.engine().attach(plan['plan_id'],run)
        with self.assertRaises(ExecutionDenied):
            self.engine().attach(plan['plan_id'],str(uuid.uuid4()))
        with self.assertRaises(ExecutionDenied):
            self.engine().attach(plan['plan_id'],'not-uuid')
        with self.assertRaises(ExecutionDenied):
            self.engine().attach(plan['plan_id'],str(uuid.uuid4()),purpose='arbitrary_tool')

    def test_source_or_report_tamper_stops_snapshot_and_retest(self):
        _,run1=self.report();second,run2=self.report()
        plan=self.engine().create(run1)
        self.engine().attach(plan['plan_id'],run2)
        # Existing signed report package is complete: altering a derived Markdown
        # file must stop the entire evidence-graph read.
        (Path(second['report']).parent/'REPORT.md').write_text('arbitrary changed report')
        with self.assertRaises(ExecutionDenied):
            self.engine().evidence_snapshot(plan['plan_id'])

    def test_concurrent_duplicate_attachment_is_one_audited_row(self):
        _,run1=self.report();_,run2=self.report()
        plan=self.engine().create(run1)
        with ThreadPoolExecutor(max_workers=3) as pool:
            out=list(pool.map(lambda _:self.engine().attach(plan['plan_id'],run2), range(3)))
        self.assertTrue(all(len(x['attachments'])==1 for x in out))
        with self.engine()._database() as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM investigation_evidence').fetchone()[0],1)
        self.assertTrue(self.engine().verify_audit_chain())

    def test_policy_or_stop_revocation_rejects_new_admission(self):
        _,run1=self.report();_,run2=self.report()
        plan=self.engine().create(run1)
        self.policy['max_attempts']=3;self.save_policy_v19()
        with self.assertRaises(ExecutionDenied):
            self.engine().attach(plan['plan_id'],run2)
        self.policy['max_attempts']=2;self.save_policy_v19()
        operator_stop(self.fx.state,self.fx.fx.manifest['engagement']['id'])
        with self.assertRaises(ExecutionDenied):
            self.engine().attach(plan['plan_id'],run2)

    def test_attachment_limit_is_fail_closed(self):
        _,run1=self.report();plan=self.engine().create(run1)
        for i in range(8):
            _,run=self.report()
            self.engine().attach(plan['plan_id'],run)
        _,additional=self.report()
        with self.assertRaisesRegex(ExecutionDenied,'limit'):
            self.engine().attach(plan['plan_id'],additional)
        self.assertEqual(len(self.engine().evidence_snapshot(plan['plan_id'])['attachments']),8)


@unittest.skipUnless(sys.platform=='linux' and os.geteuid()!=0,
                     'NOT EXECUTED: isolated non-root Linux sandbox required')
class BoundedRemediationTests(BaseFuzzFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.pfile=self.fx.p/'investigation-policy.json'
        self.reviewer=Ed25519PrivateKey.generate();self.operator=Ed25519PrivateKey.generate()
        self.reviews=self.fx.p/'review-documents';self.reviews.mkdir(mode=0o700)
        self.review_policy=self.fx.p/'review-policy.json'
        vpub=self.fx.p/'reviewer.pub';opub=self.fx.p/'operator.pub'
        for path,key in [(vpub,self.reviewer),(opub,self.operator)]:
            path.write_bytes(key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
            path.chmod(0o600)
        cfg={"schema_version":1,"configured":True,"review_dir":str(self.reviews),
             "verifier_public_key_path":str(vpub),"operator_public_key_path":str(opub),
             "max_age_seconds":3600,"allowed_engagement_ids":[self.fx.manifest['engagement']['id']]}
        self.review_policy.write_bytes(canonical(cfg));self.review_policy.chmod(0o600)
        self.reporter=ReportingSupervisor(self.fx.manifest_path,self.fx.sig_path,self.fx.trust_path,self.state)
        self.promotion=FindingPromotionSupervisor(self.fx.manifest_path,self.fx.sig_path,self.fx.trust_path,self.state)

    def engine(self):
        return EvidenceInvestigationSupervisor(self.fx.manifest_path,self.fx.sig_path,
                              self.fx.trust_path,self.state,self.pfile)

    def enable(self, retest_run):
        p={"schema_version":1,"configured":True,
            "engagement_ids":[self.fx.manifest['engagement']['id']],"max_steps":16,
            "max_attempts":2,"lease_seconds":90,"allow_local_replay":True,
            "replay_targets":{retest_run:{"repository":str(self.fx.repo),
                           "module":"auth/guard.py","fuzz_policy":str(self.policy_path)}}}
        self.pfile.write_bytes(canonical(p));self.pfile.chmod(0o600)

    def promote(self, report, source):
        doc=json.loads(Path(report['report']).read_bytes())
        fid=doc['findings'][0]['id']
        proof={"version":1,"kind":"operator_verified_staging",
            "source_reference":"staging/authorized-synthetic-test",
            "starting_access":"Dummy tenant actor",
            "observed_behavior":"Operator-attested local staging authorization failure",
            "affected_principal":"Independent synthetic tenant",
            "conditions":"Operator-controlled isolated staging fixture"}
        p=canonical(proof)
        raw=canonical({"version":1,"engagement_id":doc['engagement_id'],"source_run_id":source,
            "prior_report_sha256":hashlib.sha256(canonical(doc)).hexdigest(),
            "source_evidence_sha256":doc['source_evidence']['sha256'],"finding_id":fid,
            "verdict":"confirmed","verifier_id":"independentReviewer001","operator_id":"releaseOwner001",
            "reviewed_at_utc":datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "verification_evidence_sha256":hashlib.sha256(p).hexdigest(),
            "severity":"medium","demonstrated_impact":"Operator observed staging-only cross tenant authorization mismatch",
            "remediation":"Enforce exact type and owner equality","rejection_reason":"not_applicable"})
        for suffix,data in [('',raw),('.proof',p),('.verifier.sig',self.reviewer.sign(VERIFY_CONTEXT+raw)),
                            ('.operator.sig',self.operator.sign(APPROVE_CONTEXT+raw))]:
            f=self.reviews/('review-001.json'+suffix);f.write_bytes(data);f.chmod(0o600)
        approved=self.promotion.promote(source,self.review_policy,'review-001.json')
        self.assertEqual(approved['status'],'FINDING_REVIEW_PUBLISHED')
        return fid

    def prepare(self, *, retest_fixed=False):
        first=self.run_fuzz()
        initial=self.reporter.generate(first['run_id'],'bounded-fuzz.json')
        fid=self.promote(initial,first['run_id'])
        if retest_fixed:
            from test_v17_fuzz import SAFE_TARGET
            self.target.write_text(SAFE_TARGET)
            self.policy['targets']['auth/guard.py']['sha256']=hashlib.sha256(self.target.read_bytes()).hexdigest()
            self.save()
        retest=self.run_fuzz()
        second=self.reporter.generate(retest['run_id'],'bounded-fuzz.json')
        self.enable(retest['run_id'])
        plan=self.engine().create(first['run_id'])
        self.engine().attach(plan['plan_id'],retest['run_id'],purpose='remediation_retest',finding_id=fid)
        return plan['plan_id'], retest['run_id'],fid

    def test_real_bound_retest_replays_only_approved_sandbox(self):
        pid,source,fid=self.prepare()
        outcome=self.engine().retest(pid,source)
        self.assertEqual(outcome['status'],'RETEST_OBSERVATION_RECORDED')
        self.assertEqual(outcome['outcome']['status'],'RETEST_LOCAL_LEAD_REPRODUCED_NEEDS_REVIEW')
        self.assertEqual(self.engine().retest(pid,source)['status'],'RETEST_ALREADY_RECORDED')
        recorded=self.engine().evidence_snapshot(pid)['attachments'][0]
        self.assertEqual(recorded['target_finding_id'],fid)
        self.assertEqual(recorded['state'],'completed')
        self.assertTrue(self.engine().verify_audit_chain())

    def test_fixed_synthetic_input_never_declares_deployed_fix(self):
        pid,source,fid=self.prepare(retest_fixed=True)
        recorded=self.engine().retest(pid,source)
        self.assertEqual(recorded['status'],'RETEST_OBSERVATION_RECORDED')
        self.assertEqual(recorded['outcome']['status'],'RETEST_NO_LOCAL_LEADS_NOT_VERIFIED_FIXED')
        self.assertFalse(recorded['outcome']['independent_replay'])
        self.assertNotIn('FIXED',recorded['outcome']['status'].replace('NOT_VERIFIED_FIXED',''))
        self.assertTrue(self.engine().verify_audit_chain())

    def test_same_contract_different_source_module_cannot_claim_retest(self):
        original=self.run_fuzz()
        first=self.reporter.generate(original['run_id'],'bounded-fuzz.json')
        fid=self.promote(first,original['run_id'])
        next_run=self.run_fuzz()
        self.reporter.generate(next_run['run_id'],'bounded-fuzz.json')
        self.enable(next_run['run_id'])
        cap=self.engine()._admit()[1]['replay_targets'][next_run['run_id']]
        self.policy['targets']['auth/other.py']={**self.policy['targets']['auth/guard.py']}
        (self.fx.repo/'auth'/'other.py').write_bytes(self.target.read_bytes())
        self.save()
        current=json.loads(self.pfile.read_bytes())
        current['replay_targets'][next_run['run_id']]['module']='auth/other.py'
        self.pfile.write_bytes(canonical(current));self.pfile.chmod(0o600)
        plan=self.engine().create(original['run_id'])
        with self.assertRaisesRegex(ExecutionDenied,'module and contract'):
            self.engine().attach(plan['plan_id'],next_run['run_id'],
                                 purpose='remediation_retest',finding_id=fid)

    def test_expired_retest_claim_recovery_never_uses_stale_token(self):
        pid,source,fid=self.prepare()
        sup=self.engine()
        first=sup._claim_retest(pid,source,{'max_attempts':2,'lease_seconds':90})
        self.assertEqual(first['status'],'RETEST_CLAIMED')
        self.assertEqual(sup._claim_retest(pid,source,{'max_attempts':2,'lease_seconds':90})['status'],'RETEST_BUSY')
        with sup._database() as con:
            con.execute('UPDATE investigation_evidence SET lease_until=0 WHERE source_run_id=?',(source,))
        new=sup._claim_retest(pid,source,{'max_attempts':2,'lease_seconds':90})
        self.assertEqual(new['status'],'RETEST_CLAIMED')
        self.assertNotEqual(first['token'],new['token'])
        stale=sup._finish_retest(pid,source,first['token'],{'status':'RETEST_OLD_WORKER'},success=True)
        self.assertEqual(stale['status'],'RETEST_LEASE_SUPERSEDED')
        with sup._database() as con:
            con.execute('UPDATE investigation_evidence SET lease_until=0 WHERE source_run_id=?',(source,))
        self.assertEqual(sup._claim_retest(pid,source,{'max_attempts':2,'lease_seconds':90})['status'],
                         'RETEST_ATTEMPTS_EXHAUSTED')
        self.assertEqual(sup.evidence_snapshot(pid)['attachments'][0]['state'],'failed')
        self.assertTrue(sup.verify_audit_chain())

    def test_retest_report_revision_or_raw_evidence_change_fails_closed(self):
        pid,source,fid=self.prepare()
        info,_=self.engine()._guard()
        actual=Path(info['report_directory'])/'runs'/source/'bounded-fuzz.json'
        actual.write_bytes(b'{}')
        with self.assertRaises(ExecutionDenied):self.engine().evidence_snapshot(pid)
        with self.assertRaises(ExecutionDenied):self.engine().retest(pid,source)

    def test_retest_observation_does_not_close_operator_checkpoint(self):
        pid,source,fid=self.prepare()
        self.assertEqual(self.engine().retest(pid,source)['status'],'RETEST_OBSERVATION_RECORDED')
        snap=self.engine().snapshot(pid)
        blocked=[x for x in snap['steps'] if x['kind']=='await_remediation_retest']
        self.assertEqual(len(blocked),1)
        self.assertEqual(blocked[0]['state'],'awaiting_operator')

    def test_retest_rejects_wrong_finding_and_policy_rebinding(self):
        pid,source,fid=self.prepare()
        with self.assertRaises(ExecutionDenied):
            self.engine().attach(pid,source,purpose='remediation_retest',finding_id='A18-'+'a'*20)
        with self.engine()._database() as con:
            con.execute("UPDATE investigation_evidence SET lease_until=0 WHERE plan_id=? AND source_run_id=?",(pid,source))
        first=self.engine()._claim_retest(pid,source,{'max_attempts':2,'lease_seconds':90})
        self.assertEqual(first['status'],'RETEST_CLAIMED')
        with self.engine()._database() as con:
            con.execute('UPDATE investigation_evidence SET lease_until=0 WHERE source_run_id=?',(source,))
        newer=self.engine()._claim_retest(pid,source,{'max_attempts':2,'lease_seconds':90})
        self.assertEqual(newer['status'],'RETEST_CLAIMED')
        stale=self.engine()._finish_retest(pid,source,first['token'],{'status':'RETEST_DENIED'},success=True)
        self.assertEqual(stale['status'],'RETEST_LEASE_SUPERSEDED')
        current=self.engine()._finish_retest(pid,source,newer['token'],{'status':'RETEST_MANUAL_VALIDATION_REQUIRED'},success=True)
        self.assertEqual(current['status'],'RETEST_OBSERVATION_RECORDED')


if __name__=='__main__': unittest.main()
