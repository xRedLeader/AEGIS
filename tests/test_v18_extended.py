"""v1.8 adversarial receiver, reporting, promotion, retry and crash-recovery checks."""
from __future__ import annotations
from datetime import datetime, timezone
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
import time
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_reporting import canonical, verified_package
from aegis_finding_promotion import FindingPromotionSupervisor, VERIFY_CONTEXT, APPROVE_CONTEXT
from aegis_notification_receiver import DurableReceiver
from aegis_supervisor import ExecutionDenied
from test_v18_reporting import ReportFixture


class AdvancedNotificationTests(ReportFixture):
    def test_all_package_files_and_unexpected_file_fail_before_transport(self):
        for filename in ("REPORT.md", "NEEDS-VALIDATION.md", "FINDINGS-DETAIL.md", "integrity.json"):
            with self.subTest(file=filename):
                out,run=self.report()
                path=Path(out["report"]).parent/filename
                path.write_bytes(path.read_bytes()+b"injected")
                with self.assertRaises(ExecutionDenied):
                    self.sender.deliver(out['notice_id'],self.policy_file)
                with self.sender._database() as con:
                    row=con.execute('SELECT attempts FROM notification_outbox WHERE notice_id=?',(out['notice_id'],)).fetchone()
                    self.assertEqual(row,(0,))

    def test_extra_file_or_missing_file_rejected_before_delivery(self):
        out,run=self.report()
        folder=Path(out['report']).parent
        (folder/'unauthorized.txt').write_text('not permitted')
        with self.assertRaises(ExecutionDenied):self.sender.deliver(out['notice_id'],self.policy_file)
        (folder/'unauthorized.txt').unlink()
        (folder/'REPORT.md').unlink()
        with self.assertRaises((ExecutionDenied,OSError)):
            self.sender.deliver(out['notice_id'],self.policy_file)

    def test_stale_sender_cannot_complete_newer_lease(self):
        out,run=self.report()
        started=threading.Event()
        proceed=threading.Event()
        from aegis_notifications import _trusted_socket
        outcome=[]
        def delayed(path,uids):
            started.set()
            if not proceed.wait(4):raise AssertionError('lease test stalled')
            return _trusted_socket(path,uids)
        def send():
            with patch('aegis_notifications._trusted_socket',side_effect=delayed):
                outcome.append(self.sender.deliver(out['notice_id'],self.policy_file))
        worker=threading.Thread(target=send,daemon=True)
        worker.start()
        self.assertTrue(started.wait(4))
        with self.sender._database() as con:
            con.execute("""UPDATE notification_outbox SET lease_token='recovered-attempt',
                attempts=attempts+1,lease_until=0 WHERE notice_id=?""", (out['notice_id'],))
        proceed.set()
        worker.join(6)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcome[0]['status'],'DELIVERY_ATTEMPT_SUPERSEDED')
        with self.sender._database() as con:
            status,token,attempts=con.execute('SELECT status,lease_token,attempts FROM notification_outbox').fetchone()
        self.assertEqual((status,token,attempts),('leased','recovered-attempt',2))

    def test_outbox_drain_obeys_backoff_and_recovers_expired_lease(self):
        out,run=self.report()
        self.assertEqual(self.sender.deliver(out['notice_id'],self.policy_file)['status'],'DELIVERY_FAILED_PENDING')
        self.assertEqual(self.sender.drain(self.policy_file)['processed'],0)
        with self.sender._database() as con:
            con.execute("UPDATE notification_outbox SET next_attempt_at=0")
        self.assertEqual(self.sender.drain(self.policy_file)['results'][0]['status'],'DELIVERY_FAILED_PENDING')
        with self.sender._database() as con:
            con.execute("UPDATE notification_outbox SET status='leased',lease_until=0,lease_token='expired',next_attempt_at=0")
        seen,done=self.listener()
        self.assertEqual(self.sender.drain(self.policy_file)['results'][0]['status'],'DELIVERY_ACKNOWLEDGED')
        self.assertTrue(done.wait(2))
        self.assertEqual(len(seen),1)
        self.assertEqual(self.sender.drain(self.policy_file)['processed'],0)

    def test_expired_last_lease_becomes_permanent_failure_without_resend(self):
        out,run=self.report()
        with self.sender._database() as con:
            self.sender._tables(con)
            con.execute("""UPDATE notification_outbox SET status='leased',attempts=3,
                lease_until=0,lease_token='expired-last-attempt' WHERE notice_id=?""",(out['notice_id'],))
        self.assertEqual(self.sender.drain(self.policy_file)['processed'],0)
        with self.sender._database() as con:
            self.assertEqual(con.execute("SELECT status,last_failure FROM notification_outbox").fetchone(),
                             ('failed','EXPIRED_LEASE_RETRY_LIMIT'))

    def test_outbox_drain_validates_count_and_scope(self):
        with self.assertRaises(ExecutionDenied):self.sender.drain(self.policy_file,0)
        with self.assertRaises(ExecutionDenied):self.sender.drain(self.policy_file,51)


class ReceiverTests(ReportFixture):
    def setUp(self):
        super().setUp()
        self.receiver_state=self.fx.fx.p/'receiver-private-state'
        self.receiver_state.mkdir(mode=0o700)
        self.receiver_policy=self.fx.fx.p/'receiver-policy.json'
        self.receiver_conf={"schema_version":1,"configured":True,"socket_path":str(self.sock),
            "state_root":str(self.receiver_state),"shared_gid":None,
            "allowed_sender_uids":[os.geteuid()],
            "allowed_engagement_ids":[self.fx.fx.manifest['engagement']['id']]}
        self.receiver_policy.write_bytes(canonical(self.receiver_conf))
        self.receiver_policy.chmod(0o600)
        self.receiver=DurableReceiver(self.receiver_policy)
        self.stop=None
        self.thread=None

    def serve(self,service=None):
        service=service or self.receiver
        self.stop=threading.Event()
        self.thread=threading.Thread(target=service.serve,kwargs={'stop_event':self.stop},daemon=True)
        self.thread.start()
        for attempt in range(120):
            if self.sock.is_socket():break
            time.sleep(.025)
        self.assertTrue(self.sock.is_socket())
        self.addCleanup(self.stop_service)

    def stop_service(self):
        if self.stop:self.stop.set()
        if self.thread:self.thread.join(3)
        self.stop=None
        self.thread=None

    def raw_send(self,msg):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
            c.settimeout(.4)
            c.connect(str(self.sock))
            c.sendall(canonical(msg)+b'\n')
            try:return c.recv(512)
            except OSError:return b''

    def payload(self,report):
        return {"type":"aegis_assessment_v1","notice_id":report['notice_id'],
            "engagement_id":self.fx.fx.manifest['engagement']['id'],
            "source_run_id":self.original_run,"report_sha256":report['sha256'],
            "lead_count":report['lead_count'],"assessment_status":"limited_source_evidence_only",
            "challenge":'c'*32}

    def test_receiver_durably_commits_before_ack_and_idempotent_restart(self):
        out,self.original_run=self.report()
        self.serve()
        self.assertEqual(self.sender.deliver(out['notice_id'],self.policy_file)['status'],'DELIVERY_ACKNOWLEDGED')
        with closing(self.receiver._database()) as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM received').fetchone()[0],1)
        self.stop_service()
        self.serve()
        msg=self.payload(out)
        ack=json.loads(self.raw_send(msg))
        self.assertEqual(ack['challenge'],'c'*32)
        self.assertEqual(ack['report_sha256'],out['sha256'])
        with closing(self.receiver._database()) as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM received').fetchone()[0],1)

    def test_receiver_rejects_conflicting_same_id_or_wrong_engagement(self):
        out,self.original_run=self.report()
        self.serve()
        msg=self.payload(out)
        self.assertTrue(self.raw_send(msg))
        msg['report_sha256']='0'*64
        self.assertEqual(self.raw_send(msg),b'')
        msg['report_sha256']=out['sha256'];msg['engagement_id']='other-engagement-001'
        self.assertEqual(self.raw_send(msg),b'')
        with closing(self.receiver._database()) as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM received').fetchone()[0],1)

    def test_receiver_rejects_wrong_sender_uid_from_peercred(self):
        self.receiver_conf['allowed_sender_uids']=[os.geteuid()+10000]
        self.receiver_policy.write_bytes(canonical(self.receiver_conf))
        self.receiver=DurableReceiver(self.receiver_policy)
        out,self.original_run=self.report()
        self.serve()
        self.assertEqual(self.raw_send(self.payload(out)),b'')
        with closing(self.receiver._database()) as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM received').fetchone()[0],0)

    def test_crash_after_durable_commit_before_ack_retry_is_idempotent(self):
        out,self.original_run=self.report()
        class DisconnectAfterCommit(DurableReceiver):
            def _commit_notice(self,msg):
                super()._commit_notice(msg)
                raise ExecutionDenied('simulated crash between persistence and acknowledgment')
        self.serve(DisconnectAfterCommit(self.receiver_policy))
        self.assertEqual(self.raw_send(self.payload(out)),b'')
        self.stop_service()
        self.serve()
        self.assertTrue(self.raw_send(self.payload(out)))
        with closing(self.receiver._database()) as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM received').fetchone()[0],1)


class ReviewTests(ReportFixture):
    def setUp(self):
        super().setUp()
        self.promotion=FindingPromotionSupervisor(self.fx.fx.manifest_path,self.fx.fx.sig_path,self.fx.fx.trust_path,self.fx.state)
        self.reviews=self.fx.fx.p/'review-documents';self.reviews.mkdir(mode=0o700)
        self.review_policy=self.fx.fx.p/'review-policy.json'
        self.verifier=Ed25519PrivateKey.generate()
        self.operator=Ed25519PrivateKey.generate()
        self.vpub=self.fx.fx.p/'verifier.pub';self.opub=self.fx.fx.p/'operator.pub'
        self.vpub.write_bytes(self.verifier.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
        self.opub.write_bytes(self.operator.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
        self.vpub.chmod(0o600);self.opub.chmod(0o600)
        self.review_conf={"schema_version":1,"configured":True,"review_dir":str(self.reviews),
            "verifier_public_key_path":str(self.vpub),"operator_public_key_path":str(self.opub),
            "max_age_seconds":3600,"allowed_engagement_ids":[self.fx.fx.manifest['engagement']['id']]}
        self.review_policy.write_bytes(canonical(self.review_conf));self.review_policy.chmod(0o600)
        self.review_name='review-001.json'

    def signed_review(self,document,run,verdict='confirmed',proof_kind='operator_verified_staging'):
        finding=document['findings'][0]
        proof={"version":1,"kind":proof_kind,"source_reference":"staging/release-1234",
            "starting_access":"Test account with no cross-tenant privilege",
            "observed_behavior":"Authorized isolated staging reproduction permitted cross tenant read",
            "affected_principal":"Separate synthetic tenant owner account",
            "conditions":"Controlled staging fixture with operator permission"}
        raw_proof=canonical(proof)
        raw=canonical({"version":1,"engagement_id":document['engagement_id'],"source_run_id":run,
            "prior_report_sha256":hashlib.sha256(canonical(document)).hexdigest(),
            "source_evidence_sha256":document['source_evidence']['sha256'],"finding_id":finding['id'],
            "verdict":verdict,"verifier_id":"independentReviewer001","operator_id":"releaseOwner001",
            "reviewed_at_utc":datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "verification_evidence_sha256":hashlib.sha256(raw_proof).hexdigest(),
            "severity":"medium" if verdict=='confirmed' else 'none',
            "demonstrated_impact":"Cross tenant read authorized for synthetic caller" if verdict=='confirmed' else 'not_applicable',
            "remediation":"Check resource ownership before returning data" if verdict=='confirmed' else 'not_applicable',
            "rejection_reason":"not_applicable" if verdict=='confirmed' else 'Effective independent owner validation blocks the candidate'})
        for name,data in ((self.review_name,raw), (self.review_name+'.proof',raw_proof),
            (self.review_name+'.verifier.sig',self.verifier.sign(VERIFY_CONTEXT+raw)),
            (self.review_name+'.operator.sig',self.operator.sign(APPROVE_CONTEXT+raw))):
            f=self.reviews/name;f.write_bytes(data);f.chmod(0o600)
        return raw

    def test_confirmed_review_is_signed_attested_and_renders_consistent_artifacts(self):
        out,run=self.report()
        doc=json.loads(Path(out['report']).read_bytes())
        self.signed_review(doc,run)
        promoted=self.promotion.promote(run,self.review_policy,self.review_name)
        self.assertEqual(promoted['status'],'FINDING_REVIEW_PUBLISHED')
        document=verified_package(Path(promoted['report']).parent,promoted['sha256'])
        self.assertEqual(document['findings'][0]['verdict'],'confirmed')
        self.assertEqual(document['findings'][0]['severity'],'medium')
        self.assertIn('Cross tenant read',(Path(promoted['report']).parent/'FINDINGS-DETAIL.md').read_text())
        self.assertEqual(json.loads(Path(out['report']).read_bytes())['findings'][0]['verdict'],'needs_validation')
        seen,done=self.listener()
        self.assertEqual(self.sender.deliver(promoted['notice_id'],self.policy_file)['status'],'DELIVERY_ACKNOWLEDGED')
        self.assertTrue(done.wait(3))
        self.assertEqual(seen[0]['assessment_status'],'independently_reviewed_limited_evidence')
        self.assertTrue(self.promotion.verify_audit_chain())

    def test_rejected_review_renders_without_severity_and_stale_review_fails(self):
        out,run=self.report()
        doc=json.loads(Path(out['report']).read_bytes())
        self.signed_review(doc,run,verdict='rejected',proof_kind='isolated_local_fixture')
        promoted=self.promotion.promote(run,self.review_policy,self.review_name)
        record=json.loads(Path(promoted['report']).read_bytes())['findings'][0]
        self.assertEqual(record['verdict'],'rejected')
        self.assertNotIn('severity',record)
        with self.assertRaises(ExecutionDenied):
            self.promotion.promote(run,self.review_policy,self.review_name)

    def test_promoted_review_proof_is_retained_and_tampering_blocks_delivery(self):
        out,run=self.report(); doc=json.loads(Path(out['report']).read_bytes())
        self.signed_review(doc,run)
        promoted=self.promotion.promote(run,self.review_policy,self.review_name)
        folder=Path(promoted['report']).parent
        proof_files=list(folder.glob('proof-*.json'))
        self.assertEqual(len(proof_files),1)
        self.assertEqual(proof_files[0].read_bytes(),(self.reviews/(self.review_name+'.proof')).read_bytes())
        (self.reviews/(self.review_name+'.proof')).unlink()  # retained report is self-contained
        self.assertEqual(verified_package(folder,promoted['sha256'])['findings'][0]['verdict'],'confirmed')
        proof_files[0].write_bytes(b'{}')
        with self.assertRaises(ExecutionDenied):
            self.sender.deliver(promoted['notice_id'],self.policy_file)
        with self.sender._database() as con:
            self.assertEqual(con.execute('SELECT attempts FROM notification_outbox WHERE notice_id=?',
                                         (promoted['notice_id'],)).fetchone()[0],0)

    def test_v2_report_validator_accepts_promoted_package(self):
        import subprocess,sys
        out,run=self.report();doc=json.loads(Path(out['report']).read_bytes())
        self.signed_review(doc,run)
        accepted=self.promotion.promote(run,self.review_policy,self.review_name)
        validator=Path(__file__).resolve().parents[1]/'aegis_report_validate.py'
        run=subprocess.run([sys.executable,str(validator),accepted['report']],
                           capture_output=True,text=True,timeout=6)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertIn('v2',run.stdout)

    def test_unsigned_tampered_or_same_signing_key_review_denied(self):
        out,run=self.report(); doc=json.loads(Path(out['report']).read_bytes())
        self.signed_review(doc,run)
        sig=self.reviews/(self.review_name+'.verifier.sig')
        sig.write_bytes(b'garbage')
        with self.assertRaises(ExecutionDenied):self.promotion.promote(run,self.review_policy,self.review_name)
        self.signed_review(doc,run)
        self.opub.write_bytes(self.vpub.read_bytes())
        with self.assertRaises(ExecutionDenied):self.promotion.promote(run,self.review_policy,self.review_name)
        self.assertFalse((Path(out['report']).parent/'revisions').exists())

    def test_local_only_fixture_must_not_be_promoted_as_deployed_confirmed(self):
        out,run=self.report();doc=json.loads(Path(out['report']).read_bytes())
        self.signed_review(doc,run,proof_kind='isolated_local_fixture')
        with self.assertRaises(ExecutionDenied):self.promotion.promote(run,self.review_policy,self.review_name)

    def test_invalid_proof_and_wrong_prior_report_cannot_promote(self):
        out,run=self.report();doc=json.loads(Path(out['report']).read_bytes())
        self.signed_review(doc,run)
        (self.reviews/(self.review_name+'.proof')).write_bytes(b'{}')
        with self.assertRaises(ExecutionDenied):self.promotion.promote(run,self.review_policy,self.review_name)
        self.signed_review(doc,run)
        # Tampering with prior source evidence invalidates the signed review.
        Path(out['report']).write_bytes(b'{}')
        with self.assertRaises(ExecutionDenied):self.promotion.promote(run,self.review_policy,self.review_name)


if __name__=='__main__':unittest.main()
