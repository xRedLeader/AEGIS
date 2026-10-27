"""Operator API signatures, peer identity, durable nonce replay and Unix socket."""
from datetime import datetime, timedelta, timezone
import base64
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_operator_service import OperatorService, encode_signed_command, issue_command, _json_bytes
from aegis_operator_client import send
from aegis_supervisor import ExecutionDenied
from test_credentials import CredentialSessionTests


class BaseOperatorFixture:
    def setUp(self):
        self.fx = CredentialSessionTests('test_operator_revocation')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.authority = self.fx.broker()
        (self.fx.fx.p / 'approval.json.sig').write_bytes(self.fx.signature.read_bytes())
        self.key = Ed25519PrivateKey.generate()
        self.public = self.fx.fx.p / 'api-key.pem'
        self.public.write_bytes(self.key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
        self.dir = self.fx.fx.p / 'service-socket'
        self.dir.mkdir(mode=0o700)
        self.socket = self.dir / 'operator.sock'
        self.api_policy_file = self.fx.fx.p / 'api-policy.json'
        self.policy = {'version':1,'configured':True,'principal':'operator-identity',
            'public_key_pem_path':str(self.public),'allowed_peer_uids':[os.geteuid()],
            'allowed_engagement_ids':[self.fx.fx.manifest['engagement']['id']],
            'socket_path':str(self.socket),'approval_dir':str(self.fx.fx.p),
            'max_request_window_seconds':60}
        self.save()
        self.svc = OperatorService(self.authority, self.api_policy_file)

    def save(self):
        self.api_policy_file.write_text(json.dumps(self.policy))
        self.api_policy_file.chmod(0o600)

    def signed(self, op='session.create', args=None, **kwargs):
        if args is None:
            args={'approval_name':'approval.json'}
        return issue_command(self.key, self.policy['principal'],
            self.fx.fx.manifest['engagement']['id'],op,args,**kwargs)


class OperatorSecurityTests(BaseOperatorFixture, unittest.TestCase):
    def test_create_session_signed_operator(self):
        result = self.svc.handle(self.signed(),os.geteuid())
        self.assertEqual(result['status'],'SESSION_CREATED')
        self.assertTrue(result['handle'])
        self.assertNotIn(self.fx.secret.read_text(),json.dumps(result))
        self.assertNotIn('vault://',json.dumps(result))

    def test_wrong_peer_is_rejected(self):
        with self.assertRaisesRegex(ExecutionDenied,'peer identity'):
            self.svc.handle(self.signed(),os.geteuid()+125)

    def test_unsigned_wrong_key_and_tampered_commands_rejected(self):
        other=Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(ExecutionDenied,'signature'):
            self.svc.handle(issue_command(other,'operator-identity',
                self.fx.fx.manifest['engagement']['id'],'session.create',
                {'approval_name':'approval.json'}),os.geteuid())
        payload=json.loads(self.signed())
        obj=json.loads(base64.b64decode(payload['payload_b64']))
        obj['args']={'approval_name':'../../etc/passwd'}
        payload['payload_b64']=base64.b64encode(_json_bytes(obj)).decode()
        with self.assertRaisesRegex(ExecutionDenied,'signature'):
            self.svc.handle(_json_bytes(payload),os.geteuid())

    def test_replay_survives_restart(self):
        cmd = self.signed()
        self.svc.handle(cmd,os.geteuid())
        new_service=OperatorService(self.fx.broker(),self.api_policy_file)
        with self.assertRaisesRegex(ExecutionDenied,'replay'):
            new_service.handle(cmd,os.geteuid())

    def test_parallel_requests_cannot_replay(self):
        cmd=self.signed()
        def attempt(_):
            try:
                return self.svc.handle(cmd,os.geteuid())['status']
            except ExecutionDenied:
                return 'DENIED'
        with ThreadPoolExecutor(max_workers=8) as executor:
            values=list(executor.map(attempt,range(8)))
        self.assertEqual(values.count('SESSION_CREATED'),1)
        self.assertEqual(values.count('DENIED'),7)

    def test_expired_wrong_scope_and_unsupported_operation(self):
        data=json.loads(base64.b64decode(json.loads(self.signed())['payload_b64']))
        data['not_before']='2020-01-01T00:00:00Z'
        data['expires_at']='2020-01-01T00:00:30Z'
        with self.assertRaisesRegex(ExecutionDenied,'expired'):
            self.svc.handle(encode_signed_command(data,self.key),os.geteuid())
        data['not_before']=(datetime.now(timezone.utc)-timedelta(seconds=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        data['expires_at']=(datetime.now(timezone.utc)+timedelta(seconds=25)).strftime('%Y-%m-%dT%H:%M:%SZ')
        data['engagement_id']='wrong-engagement-123'
        with self.assertRaisesRegex(ExecutionDenied,'scope'):
            self.svc.handle(encode_signed_command(data,self.key),os.geteuid())
        data['engagement_id']=self.fx.fx.manifest['engagement']['id']
        data['operation']='arbitrary.exec'
        with self.assertRaises(ExecutionDenied):
            self.svc.handle(encode_signed_command(data,self.key),os.geteuid())

    def test_traversal_and_extra_fields_rejected(self):
        for name in ('../approval.json','/tmp/approval.json','a..b.json','.hidden.json'):
            with self.subTest(name=name),self.assertRaises(ExecutionDenied):
                self.svc.handle(self.signed(args={'approval_name':name}),os.geteuid())
        with self.assertRaises(ExecutionDenied):
            self.svc.handle(self.signed(args={'approval_name':'approval.json','shell':'true'}),os.geteuid())
        with self.assertRaises(ExecutionDenied):
            self.svc.handle(self.signed('session.fetch',{'session_handle':'fake','url':'https://example.invalid','method':'POST','budget_seconds':1}),os.geteuid())

    def test_policy_symlink_and_missing_identity_fails_closed(self):
        self.policy['allowed_peer_uids']=[os.geteuid()+1]
        self.save()
        with self.assertRaisesRegex(ExecutionDenied,'peer identity'):
            self.svc.handle(self.signed(),os.geteuid())
        self.policy['allowed_peer_uids']=[os.geteuid()]
        self.save()
        self.api_policy_file.unlink()
        self.api_policy_file.symlink_to(self.public)
        with self.assertRaises(ExecutionDenied):
            self.svc.handle(self.signed(),os.geteuid())

    def test_real_unix_socket_round_trip(self):
        if os.geteuid()==0: self.skipTest('non-root Linux service required')
        stopper=threading.Event()
        t=threading.Thread(target=lambda:self.svc.serve(stop_event=stopper),daemon=True)
        t.start()
        self.addCleanup(stopper.set)
        t0=time.monotonic()
        while not self.socket.exists() and time.monotonic()-t0<3:
            time.sleep(.02)
        self.assertTrue(self.socket.exists(),'operator socket did not start')
        self.assertEqual(self.socket.stat().st_mode & 0o777,0o600)
        answer=send(self.socket,self.signed())
        self.assertTrue(answer['ok'])
        self.assertEqual(answer['result']['status'],'SESSION_CREATED')
        again=send(self.socket,self.signed('session.create',{'approval_name':'approval.json'}))
        self.assertFalse(again['ok'])
        stopper.set()
        t.join(timeout=3)
        self.assertFalse(t.is_alive(),'socket service did not stop')


class CredentialLifecycleTests(BaseOperatorFixture, unittest.TestCase):
    def test_credential_fingerprint_change_rejected(self):
        session=self.fx.create()['handle']
        self.fx.secret.write_text('ROTATED-TEST-TOKEN-xyz-246810')
        with self.assertRaisesRegex(ExecutionDenied,'fingerprint'):
            self.authority._open_secret_fd(session,{'origin':'https://staging.test.example','target':'/secure/status'})

    def test_sealed_credential_snapshot(self):
        session=self.fx.create()['handle']
        fd=self.authority._open_secret_fd(session,{'origin':'https://staging.test.example','target':'/secure/status'})
        try:
            expected=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
            self.assertEqual(fcntl.fcntl(fd,fcntl.F_GET_SEALS)&expected,expected)
            with self.assertRaises(OSError): os.write(fd,b'MUTATION')
            self.assertEqual(os.read(fd,4096),self.fx.secret.read_bytes())
        finally: os.close(fd)

    def test_expired_unclassified_and_permanent_profiles_denied(self):
        for classification in ('production','unclassified','permanent'):
            with self.subTest(classification=classification):
                self.fx.policy['credential_profiles']['vault://aegis/example/ordinary']['classification']=classification
                self.fx.policy_write()
                with self.assertRaises(ExecutionDenied): self.fx.create()
        self.fx.policy['credential_profiles']['vault://aegis/example/ordinary']['classification']='synthetic'
        self.fx.policy['credential_profiles']['vault://aegis/example/ordinary']['expires_at_utc']='2020-01-01T00:00:00Z'
        self.fx.policy_write()
        with self.assertRaises(ExecutionDenied): self.fx.create()

    def test_profile_rotation_invalidates_existing_session(self):
        handle = self.fx.create()['handle']
        replacement = b'ROTATED-TEST-CREDENTIAL-567890'
        self.fx.secret.write_bytes(replacement)
        profile = self.fx.policy['credential_profiles']['vault://aegis/example/ordinary']
        profile['fingerprint_sha256'] = hashlib.sha256(replacement).hexdigest()
        self.fx.policy_write()
        with self.assertRaisesRegex(ExecutionDenied,'expired, revoked'):
            self.authority.authorize_operation(handle,'https://staging.test.example/secure/status')

    def test_staging_profile_lifetime_and_acknowledgement(self):
        profile=self.fx.policy['credential_profiles']['vault://aegis/example/ordinary']
        profile['classification']='disposable_staging'
        profile['exposure_acknowledged']=False
        self.fx.policy_write()
        with self.assertRaises(ExecutionDenied):self.fx.create()
        profile['exposure_acknowledged']=True
        profile['expires_at_utc']=(datetime.now(timezone.utc)+timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.fx.policy_write()
        with self.assertRaises(ExecutionDenied):self.fx.create()

    def test_broker_rejects_mutable_vault_descriptor(self):
        import aegis_http_broker as b
        fd=os.open(self.fx.secret,os.O_RDONLY)
        try:
            with self.assertRaisesRegex(b.TransportError,'sealed'):
                b.fetch({'scheme':'https','address':'127.0.0.1','port':443,'timeout':2},fd)
        finally:
            try:os.close(fd)
            except OSError:pass


if __name__=='__main__': unittest.main()
