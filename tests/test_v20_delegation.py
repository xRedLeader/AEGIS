"""v2.0 delegated agent API: independently signed authority, OS peer, replay and action binding."""
from __future__ import annotations
from datetime import datetime,timedelta,timezone
import base64
import json
import os
from pathlib import Path
import socket
import threading
import time
import unittest
import uuid

from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from aegis_agent_gateway import DelegatedAssessmentService, GRANT_DOMAIN, REQUEST_DOMAIN
from aegis_agent_client import signed_grant,signed_request,envelope,send
from aegis_reporting import canonical
from aegis_supervisor import ExecutionDenied
from test_v20_integrated import IntegratedFixture


class DelegationTests(IntegratedFixture):
    def setUp(self):
        super().setUp()
        self.operator=Ed25519PrivateKey.generate()
        self.agent=Ed25519PrivateKey.generate()
        self.signer_pub=self.fx.fx.p/'delegation-signer.pem'
        self.signer_pub.write_bytes(self.operator.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
        self.signer_pub.chmod(0o600)
        self.delegation_policy=self.fx.fx.p/'delegation-policy.json'
        self.socket_dir=self.fx.fx.p/'agent-socket-dir'
        self.socket_dir.mkdir(mode=0o700)
        self.agent_socket=self.socket_dir/'agent.sock'
        self.delegate_policy={"version":1,"configured":True,"socket_path":str(self.agent_socket),
            "signer_public_key_path":str(self.signer_pub),"allowed_peer_uids":[os.geteuid()],
            "allowed_engagement_ids":[self.fx.fx.manifest['engagement']['id']],
            "max_grant_seconds":600,"max_request_seconds":20,"shared_gid":None}
        self.save_delegate()
        self.assessment=self.controller().create()['assessment_id']
        self.gateway=self.service()

    def save_delegate(self):
        self.delegation_policy.write_bytes(canonical(self.delegate_policy))
        self.delegation_policy.chmod(0o600)

    def service(self):
        return DelegatedAssessmentService(self.controller(),self.delegation_policy)

    def authorize(self,permissions=('snapshot','propose'),*,uid=None,ttl=120):
        info,policy,sha=self.controller()._admit()
        return signed_grant(self.operator,self.agent.public_key(),
            engagement_id=info['engagement_id'],assessment_id=self.assessment,
            manifest_sha256=info['manifest_sha256'],assessment_policy_sha256=sha,
            client_uid=os.geteuid() if uid is None else uid,
            permissions=permissions,seconds=ttl)

    def signed(self,operation='snapshot',*,step_id=None,expected_action=None,
               permissions=('snapshot','propose'),uid=None,grant=None,agent=None):
        blob,sig=grant or self.authorize(permissions,uid=uid)
        req,rsig=signed_request(agent or self.agent,json.loads(blob),operation,
                                step_id=step_id,expected_action=expected_action)
        return envelope(blob,sig,req,rsig)

    def test_signed_snapshot_is_structural_and_replay_protected(self):
        payload=self.signed()
        answer=self.gateway.handle(payload,os.geteuid())
        self.assertEqual(answer['status'],'DELEGATED_WORKFLOW_SNAPSHOT')
        self.assertEqual(answer['completed'],0)
        self.assertNotIn('Bearer',repr(answer))
        self.assertNotIn(str(self.fx.fx.p),repr(answer))
        with self.assertRaisesRegex(ExecutionDenied,'replay'):
            self.service().handle(payload,os.geteuid())
        self.assertTrue(self.gateway.controller.verify_audit_chain())

    def test_agent_can_propose_only_exact_next_step_and_never_edit_plan(self):
        with self.assertRaises(ExecutionDenied):
            self.gateway.handle(self.signed('propose',step_id='render',expected_action='report'),os.geteuid())
        with self.assertRaises(ExecutionDenied):
            self.gateway.handle(self.signed('propose',step_id='scan',expected_action='notify'),os.geteuid())
        result=self.gateway.handle(self.signed('propose',step_id='scan',expected_action='source_review'),os.geteuid())
        self.assertEqual(result['status'],'DELEGATED_STEP_COMPLETED')
        self.assertEqual(result['step_id'],'scan')
        next_result=self.service().handle(self.signed('propose',step_id='render',expected_action='report'),os.geteuid())
        self.assertEqual(next_result['step_id'],'render')
        with self.gateway.controller._database() as con:
            self.assertEqual(con.execute('SELECT count(*) FROM integrated_steps WHERE status="completed"').fetchone()[0],2)
        self.assertTrue(self.gateway.controller.verify_audit_chain())

    def test_raced_proposal_never_runs_new_next_step(self):
        # A separate operator progresses the plan after proposal admission but
        # before this worker claims it. The gateway must fail *before* doing
        # work, not discover the mismatch after running the wrong next action.
        from unittest.mock import patch
        payload=self.signed('propose',step_id='scan',expected_action='source_review')
        consume=self.gateway._consume
        def concurrent_progress(*args):
            outcome=self.controller().advance(self.assessment)
            self.assertEqual(outcome['step_id'],'scan')
            return consume(*args)
        with patch.object(self.gateway,'_consume',side_effect=concurrent_progress):
            with self.assertRaisesRegex(ExecutionDenied,'no longer names'):
                self.gateway.handle(payload,os.geteuid())
        steps=self.controller().snapshot(self.assessment)['steps']
        self.assertEqual(steps[0]['state'],'completed')
        self.assertEqual(steps[1]['state'],'pending')
        with self.controller()._database() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM agent_delegated_requests").fetchone()[0],1)
        self.assertTrue(self.controller().verify_audit_chain())

    def test_wrong_peer_key_and_signature_are_denied(self):
        payload=self.signed()
        with self.assertRaises(ExecutionDenied):self.gateway.handle(payload,os.geteuid()+10000)
        other=Ed25519PrivateKey.generate()
        with self.assertRaises(ExecutionDenied):
            self.gateway.handle(self.signed(agent=other),os.geteuid())
        body=json.loads(payload)
        body['grant_signature_b64']=base64.b64encode(b'0'*64).decode()
        with self.assertRaises(ExecutionDenied):self.gateway.handle(canonical(body),os.geteuid())
        body=json.loads(payload);body['attack']='shell'
        with self.assertRaises(ExecutionDenied):self.gateway.handle(canonical(body),os.geteuid())

    def test_signed_grants_pin_policy_and_expire(self):
        old=self.authorize()
        self.policy['lease_seconds']=120;self.save()
        with self.assertRaises(ExecutionDenied):
            self.gateway.handle(self.signed(grant=old),os.geteuid())
        self.policy['lease_seconds']=90;self.save()
        old_grant,sig=self.authorize()
        data=json.loads(old_grant)
        data['not_before_utc']='2000-01-01T00:00:00Z'
        data['expires_at_utc']='2000-01-01T00:00:10Z'
        modified=canonical(data)
        invalid=envelope(modified,self.operator.sign(GRANT_DOMAIN+modified),*signed_request(self.agent,data,'snapshot'))
        with self.assertRaises(ExecutionDenied):self.gateway.handle(invalid,os.geteuid())

    def test_request_cannot_expand_permissions_or_live_action(self):
        grant=self.authorize(('snapshot',))
        with self.assertRaises(ExecutionDenied):
            self.gateway.handle(self.signed('propose',step_id='scan',expected_action='source_review',grant=grant),os.geteuid())
        doc=json.loads(grant[0]);doc['client_uid']=os.geteuid()+10000
        blob=canonical(doc)
        with self.assertRaises(ExecutionDenied):
            self.gateway.handle(self.signed(grant=(blob,self.operator.sign(GRANT_DOMAIN+blob))),os.geteuid())
        with self.assertRaises(ExecutionDenied):
            self.gateway.handle(self.signed('propose',step_id='shell',expected_action='shell'),os.geteuid())

    def test_agent_policy_must_be_private_and_rejects_revocation(self):
        self.delegation_policy.chmod(0o644)
        with self.assertRaises(ExecutionDenied):self.gateway.handle(self.signed(),os.geteuid())
        self.delegation_policy.chmod(0o600)
        self.delegate_policy['configured']=False;self.save_delegate()
        with self.assertRaises(ExecutionDenied):self.gateway.handle(self.signed(),os.geteuid())
        self.delegate_policy['configured']=True;self.save_delegate()
        self.fx.fx.trust['approved_methods']=[]
        self.fx.fx.save()
        with self.assertRaises(ExecutionDenied):self.gateway.handle(self.signed(),os.geteuid())

    def test_model_output_is_a_pure_bounded_proposal_not_an_authority_source(self):
        from aegis_model_adapter import parse_model_decision,run
        self.assertEqual(parse_model_decision(b'{"operation":"snapshot"}'),('snapshot',None,None))
        self.assertEqual(parse_model_decision(b'{"operation":"propose","step_id":"scan","expected_action":"source_review"}'),
                         ('propose','scan','source_review'))
        for value in (b'{"operation":"shell","command":"id"}',
                      b'{"operation":"propose","step_id":"scan","expected_action":"shell"}',
                      b'{"operation":"snapshot","credential_ref":"vault://x"}',
                      b'{"operation":"snapshot","operation":"propose"}',
                      b'<script>alert(1)</script>', b'x'*769):
            with self.subTest(value=value[:60]), self.assertRaises(ExecutionDenied):
                parse_model_decision(value)
        original,sig=self.authorize()
        with self.assertRaises(ExecutionDenied):
            run(model_output=b'{"operation":"propose","step_id":"../../bad","expected_action":"source_review"}',
                grant_bytes=original,grant_signature=sig,client_key=self.agent,
                socket_path=str(self.agent_socket),expected_service_uid=os.geteuid())

    def test_concurrent_identical_signed_request_is_consumed_once(self):
        from concurrent.futures import ThreadPoolExecutor
        packet=self.signed()
        def attempt(_):
            try:self.service().handle(packet,os.geteuid());return True
            except ExecutionDenied:return False
        with ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(attempt,range(4)))
        self.assertEqual(results.count(True),1)
        self.assertTrue(self.gateway.controller.verify_audit_chain())

    def test_operator_abandon_is_terminal_audited_and_not_delegated(self):
        self.assertNotIn('abandon',__import__('aegis_agent_gateway').SAFE_OPS)
        engine=self.controller()
        result=engine.abandon(self.assessment,'operator_cancelled')
        self.assertEqual(result['status'],'ABANDONED_REQUIRES_OPERATOR_REVIEW')
        self.assertEqual(engine.abandon(self.assessment,'operator_cancelled')['status'],
                         'ABANDONED_REQUIRES_OPERATOR_REVIEW')
        with self.assertRaises(ExecutionDenied):
            engine.abandon(self.assessment,'deployment_recovery_required')
        with self.assertRaises(ExecutionDenied):
            engine.advance(self.assessment)
        with self.assertRaises(ExecutionDenied):
            self.gateway.handle(self.signed('propose',step_id='scan',expected_action='source_review'),os.geteuid())
        self.assertTrue(engine.verify_audit_chain())

    def test_real_unix_socket_round_trip_and_restart_guard(self):
        ready=threading.Event();stop=threading.Event()
        worker=threading.Thread(target=self.gateway.serve,kwargs={'stop_event':stop},daemon=True)
        worker.start()
        try:
            for _ in range(100):
                if self.agent_socket.is_socket():break
                time.sleep(.03)
            self.assertTrue(self.agent_socket.is_socket())
            result=send(str(self.agent_socket),self.signed(),os.geteuid())
            self.assertEqual(result['status'],'DELEGATED_WORKFLOW_SNAPSHOT')
            with self.assertRaises(ExecutionDenied):
                send(str(self.agent_socket),self.signed(),os.geteuid()+10000)
        finally:
            stop.set();worker.join(3)
            self.assertFalse(worker.is_alive())
        self.assertFalse(self.agent_socket.exists())

if __name__=='__main__':unittest.main()
