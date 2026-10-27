"""v1.8: canonical source evidence, report integrity and durable local notices."""
from __future__ import annotations
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
import uuid

from jsonschema import Draft202012Validator
from aegis_reporting import ReportingSupervisor, projection, canonical
from aegis_notifications import NotificationSupervisor
from aegis_supervisor import ExecutionDenied
import test_runtime

ROOT=Path(__file__).resolve().parents[1]


class ReportFixture(unittest.TestCase):
    def setUp(self):
        self.fx=test_runtime.AegisRuntimeTests('test_real_readonly_review_and_canonical_artifact')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.sup=ReportingSupervisor(self.fx.fx.manifest_path,self.fx.fx.sig_path,self.fx.fx.trust_path,self.fx.state)
        self.sender=NotificationSupervisor(self.fx.fx.manifest_path,self.fx.fx.sig_path,self.fx.fx.trust_path,self.fx.state)
        self.socket_dir=self.fx.fx.p / 'notification-socket'
        self.socket_dir.mkdir(mode=0o700)
        self.sock=self.socket_dir / 'receiver.sock'
        self.policy_file=self.fx.fx.p / 'notice-policy.json'
        self.policy={"schema_version":1,"configured":True,"socket_path":str(self.sock),
                     "allowed_peer_uids":[os.geteuid()],"max_attempts":3,"timeout_seconds":2}
        self.save_policy()

    def save_policy(self):
        self.policy_file.write_text(json.dumps(self.policy))
        self.policy_file.chmod(0o600)

    @staticmethod
    def static_raw():
        return canonical({"status":"STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES",
            "summary":{"files_examined":1},
            "candidates":[{"id":"PY-EVAL","status":"unverified_static_lead",
                           "file":"app.py","line":2,"description":"user input ignored"}]})

    @staticmethod
    def osv_raw():
        return canonical({"status":"SIGNED_OSV_ADVISORY_LEADS_NOT_EXPLOIT_VERIFICATION",
            "bundle_sha256":"a"*64,"leads":[{"advisory_id":"GHSA-TEST-1234",
            "ecosystem":"npm","package":"@types/node","version":"18.1.0",
            "classification":"OSV_ENUMERATED_VERSION_LEAD_NOT_CONFIRMED_EXPLOITABLE"}],
            "summary":{"range_only_associations_unresolved":2}})

    def completed(self, evidence=None, filename='source-review.json'):
        info,_,run=self.sup.reserve(2)
        self.sup._write_report(info,run,evidence if evidence is not None else self.static_raw(),filename)
        self.sup._finish(info['engagement_id'],run,'completed')
        return run

    def report(self, evidence=None, filename='source-review.json'):
        run=self.completed(evidence,filename)
        return self.sup.generate(run,filename),run

    def listener(self, *, success=True, delay=0):
        ready=threading.Event(); done=threading.Event(); received=[]
        def run():
            server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                server.bind(str(self.sock))
                os.chmod(self.sock,0o600)
                server.listen(2)
                server.settimeout(5)
                ready.set()
                conn,_=server.accept()
                with conn:
                    conn.settimeout(4)
                    data=b''
                    while b'\n' not in data and len(data)<2048:
                        t=conn.recv(2048)
                        if not t:break
                        data+=t
                    req=json.loads(data)
                    received.append(req)
                    if delay:time.sleep(delay)
                    ack={"received":True,"notice_id":req['notice_id'],
                         "report_sha256":req['report_sha256'] if success else '0'*64,
                         "challenge":req['challenge']}
                    conn.sendall(canonical(ack)+b'\n')
            except (OSError,ValueError,KeyError,BrokenPipeError):
                pass
            finally:
                server.close()
                try:self.sock.unlink()
                except FileNotFoundError:pass
                done.set()
        t=threading.Thread(target=run,daemon=True)
        t.start()
        if not ready.wait(3):raise AssertionError('fixture socket failed to start')
        self.addCleanup(lambda: t.join(7))
        return received,done


class ReportTests(ReportFixture):
    def test_v2_schema_rejects_invented_severity_on_unverified_lead(self):
        schema=json.loads((ROOT/'findings-v2.schema.json').read_text())
        doc=projection(self.static_raw(),'source-review.json','example-engagement-001',str(uuid.uuid4()),'2026-10-27T19:00:00+00:00')
        v=Draft202012Validator(schema)
        self.assertFalse(list(v.iter_errors(doc)))
        doc['findings'][0]['severity']='critical'
        self.assertTrue(list(v.iter_errors(doc)))
        doc['findings'][0].pop('severity')
        doc['findings'][0]['verdict']='confirmed'
        self.assertTrue(list(v.iter_errors(doc)))

    def test_report_and_views_share_canonical_source(self):
        result,run=self.report()
        source=Path(result['report'])
        doc=json.loads(source.read_bytes())
        self.assertEqual(doc['schema_version'],2)
        self.assertEqual(doc['assessment_status'],'limited_source_evidence_only')
        self.assertEqual(len(doc['findings']),1)
        self.assertEqual(doc['findings'][0]['verdict'],'needs_validation')
        self.assertNotIn('severity',doc['findings'][0])
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),result['sha256'])
        text=(source.parent/'REPORT.md').read_text()
        self.assertIn('Needs validation',text)
        self.assertIn('limited, not a clean bill',text)
        self.assertNotIn('user input ignored',text)
        self.assertIn(doc['findings'][0]['id'],(source.parent/'NEEDS-VALIDATION.md').read_text())
        self.assertEqual(self.sup.generate(run,'source-review.json')['status'],'ASSESSMENT_ALREADY_QUEUED')
        with self.sup._database() as con:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM notification_outbox').fetchone()[0],1)
        self.assertTrue(self.sup.verify_audit_chain())

    def test_osv_lead_and_scoped_npm_package(self):
        info,_,run=self.sup.reserve(2)
        self.sup._write_report(info,run,b'{}','dependency-inventory.json')
        evidence_path=Path(info['report_directory'])/'runs'/run/'advisory-candidates.json'
        evidence_path.write_bytes(self.osv_raw());evidence_path.chmod(0o600)
        self.sup._finish(info['engagement_id'],run,'completed')
        result=self.sup.generate(run,'advisory-candidates.json')
        doc=json.loads(Path(result['report']).read_bytes())
        self.assertIn('@types/node',doc['findings'][0]['affected_asset'])
        self.assertIn('needs_validation',doc['findings'][0]['verdict'])

    def test_missing_or_foreign_or_active_run_denied(self):
        with self.assertRaises(ExecutionDenied):self.sup.generate(str(uuid.uuid4()),'source-review.json')
        info,_,run=self.sup.reserve(1)
        with self.assertRaises(ExecutionDenied):self.sup.generate(run,'source-review.json')
        self.assertFalse((Path(info['report_directory'])/'assessments'/run).exists())

    def test_symlink_and_hardlinked_source_denied(self):
        run=self.completed()
        info,_=self.sup._guard()
        fp=Path(info['report_directory'])/'runs'/run/'source-review.json'
        target=self.fx.fx.p/'outside'
        target.write_bytes(fp.read_bytes())
        fp.unlink(); fp.symlink_to(target)
        with self.assertRaises((ExecutionDenied,OSError)):
            self.sup.generate(run,'source-review.json')
        fp.unlink();os.link(target,fp)
        with self.assertRaises(ExecutionDenied):self.sup.generate(run,'source-review.json')

    def test_incompatible_source_and_injection_disallowed(self):
        run=self.completed(canonical({'status':'random','candidates':[]}), 'source-review.json')
        with self.assertRaises(ExecutionDenied):self.sup.generate(run,'source-review.json')
        run=self.completed(canonical({'status':'STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES',
                       'candidates':[{'id':'PY-EVAL','file':'../../secrets','line':1,'status':'unverified_static_lead'}]}))
        with self.assertRaises(ExecutionDenied):self.sup.generate(run,'source-review.json')

    def test_zero_leads_does_not_mean_secure(self):
        raw=canonical({'status':'STATIC_LEADS_NOT_CONFIRMED_VULNERABILITIES','candidates':[]})
        result,_=self.report(raw)
        self.assertEqual(result['lead_count'],0)
        self.assertIn('limited',Path(result['report']).read_text())
        self.assertIn('No leads in this bounded source artifact',(Path(result['report']).parent/'REPORT.md').read_text())

    def test_tampering_old_report_does_not_silently_reuse_it(self):
        result,run=self.report()
        Path(result['report']).write_bytes(b'{}')
        with self.assertRaises(ExecutionDenied):self.sup.generate(run,'source-review.json')


class NotificationTests(ReportFixture):
    def test_delivered_only_after_correct_ack_and_no_sensitive_payload(self):
        result,run=self.report()
        received,done=self.listener()
        delivered=self.sender.deliver(result['notice_id'],self.policy_file)
        self.assertEqual(delivered['status'],'DELIVERY_ACKNOWLEDGED')
        self.assertTrue(done.wait(3));self.assertEqual(len(received),1)
        self.assertEqual(received[0]['report_sha256'],result['sha256'])
        self.assertNotIn('Authorization',str(received))
        self.assertEqual(self.sender.deliver(result['notice_id'],self.policy_file)['status'],'DELIVERY_ALREADY_ACKNOWLEDGED')
        with self.sender._database() as con:
            row=con.execute('SELECT attempts,status FROM notification_outbox WHERE notice_id=?',(result['notice_id'],)).fetchone()
        self.assertEqual(row,(1,'delivered'))

    def test_wrong_ack_remains_pending_and_can_retry(self):
        result,_=self.report()
        seen,done=self.listener(success=False)
        failure=self.sender.deliver(result['notice_id'],self.policy_file)
        self.assertEqual(failure['status'],'DELIVERY_FAILED_PENDING')
        self.assertTrue(done.wait(3))
        seen2,done2=self.listener()
        self.assertEqual(self.sender.deliver(result['notice_id'],self.policy_file)['status'],'DELIVERY_ACKNOWLEDGED')
        self.assertTrue(done2.wait(3))
        with self.sender._database() as con:
            self.assertEqual(con.execute('SELECT attempts FROM notification_outbox').fetchone()[0],2)

    def test_missing_destination_preserves_pending_then_fails_at_limit(self):
        result,_=self.report()
        for expected in ['DELIVERY_FAILED_PENDING','DELIVERY_FAILED_PENDING','DELIVERY_FAILED_PERMANENT']:
            self.assertEqual(self.sender.deliver(result['notice_id'],self.policy_file)['status'],expected)
        with self.assertRaises(ExecutionDenied):self.sender.deliver(result['notice_id'],self.policy_file)

    def test_refuse_untrusted_peer_policy_and_symlink(self):
        result,_=self.report()
        self.policy['allowed_peer_uids']=[os.geteuid()+10000]
        self.save_policy()
        seen,done=self.listener()
        self.assertEqual(self.sender.deliver(result['notice_id'],self.policy_file)['status'],'DELIVERY_FAILED_PENDING')
        self.assertTrue(done.wait(3))
        self.policy['allowed_peer_uids']=[os.geteuid()]
        self.save_policy()
        alias=self.fx.fx.p/'alias.json'
        alias.symlink_to(self.policy_file)
        with self.assertRaises((ExecutionDenied,OSError)):
            self.sender.deliver(result['notice_id'],alias)

    def test_report_tampering_prevents_delivery_without_attempt(self):
        result,_=self.report()
        Path(result['report']).write_bytes(b'{}')
        with self.assertRaises(ExecutionDenied):self.sender.deliver(result['notice_id'],self.policy_file)
        with self.sender._database() as con:
            self.assertEqual(con.execute('SELECT attempts FROM notification_outbox').fetchone()[0],0)

if __name__=='__main__':unittest.main()
