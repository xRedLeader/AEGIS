"""Deployment evidence collection must fail closed and never self-certify."""
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import pwd
import socket
import stat
import unittest
from unittest.mock import patch

from aegis_host_acceptance import (
    _code_installation, _protected_parent_chain, _protected_read_only,
    _live_delegation_socket, inspect_operator, inspect_receiver)
from test_v20_integrated import IntegratedFixture
from aegis_reporting import canonical


class ReadOnlyDeploymentEvidenceTests(IntegratedFixture):
    def setUp(self):
        super().setUp()
        # Minimal protected operator policy fixture: no signing keys in scope.
        self.delegation_policy=self.fx.fx.p/'delegate.json'
        self.delegate_policy={'version':1,'configured':False,
            'socket_path':str(self.fx.fx.p/'agent.sock'),
            'signer_public_key_path':str(self.fx.fx.p/'pub.pem'),
            'allowed_peer_uids':[10001],
            'allowed_engagement_ids':[self.fx.fx.manifest['engagement']['id']],
            'max_grant_seconds':60,'max_request_seconds':10,'shared_gid':None}
        self.delegation_policy.write_bytes(canonical(self.delegate_policy))
        self.delegation_policy.chmod(0o600)

    def test_operator_evidence_reports_independent_gates_unapproved(self):
        # No real external host, independently retained audit anchor, production
        # agent UID, or human staging evidence exists in this synthetic fixture.
        self.controller().create()
        evidence=self.operator_evidence()
        self.assertEqual(evidence['status'],'NOT_PRODUCTION_APPROVED')
        checks={x['check']:x['result'] for x in evidence['checks']}
        self.assertEqual(checks['signed-scope-operator-policy-and-audit-chain'],'PASS')
        self.assertEqual(checks['real-rootless-kernel-namespace-seccomp-probe'],
                         'REQUIRES_EXTERNAL_EVIDENCE')
        self.assertEqual(checks['human-staging-verification'],'REQUIRES_EXTERNAL_EVIDENCE')
        self.assertEqual(checks['off-host-checkpoint-retention'],'REQUIRES_EXTERNAL_EVIDENCE')
        self.assertEqual(checks['service-cannot-rewrite-assessment-policy'],'FAIL')
        self.assertNotIn('synthetic-key',str(evidence))

    def operator_evidence(self):
        return inspect_operator(
            manifest=self.fx.fx.manifest_path,signature=self.fx.fx.sig_path,
            trust=self.fx.fx.trust_path,state_root=self.fx.state,
            assessment_policy=self.policy_path,delegation_policy=self.delegation_policy,
            expected_agent_uid=12345,expected_receiver_uid=12346,kernel=False)

    def test_missing_audit_ledger_is_not_created_or_accepted(self):
        ledger=self.fx.state/'ledger.sqlite3'
        self.assertFalse(ledger.exists())
        before=set(self.fx.state.iterdir())
        evidence=self.operator_evidence()
        checks={x['check']:x['result'] for x in evidence['checks']}
        self.assertEqual(checks['signed-scope-operator-policy-and-audit-chain'],'FAIL')
        self.assertFalse(ledger.exists())
        self.assertEqual(set(self.fx.state.iterdir()),before)

    def test_existing_audit_ledger_remains_byte_identical(self):
        self.controller().create()
        ledger=self.fx.state/'ledger.sqlite3'
        before=ledger.read_bytes()
        timestamp=ledger.stat().st_mtime_ns
        files=set(self.fx.state.iterdir())
        evidence=self.operator_evidence()
        checks={x['check']:x['result'] for x in evidence['checks']}
        self.assertEqual(checks['signed-scope-operator-policy-and-audit-chain'],'PASS')
        self.assertEqual(ledger.read_bytes(),before)
        self.assertEqual(ledger.stat().st_mtime_ns,timestamp)
        self.assertEqual(set(self.fx.state.iterdir()),files)

    def test_mutable_referenced_signer_keys_are_reported(self):
        self.controller().create()
        self.fx.fx.pub.chmod(0o600)
        self.delegate_policy['configured']=True
        self.delegate_policy['signer_public_key_path']=str(self.fx.fx.pub)
        self.delegation_policy.write_bytes(canonical(self.delegate_policy))
        evidence=self.operator_evidence()
        checks={x['check']:x['result'] for x in evidence['checks']}
        self.assertEqual(checks['signed-scope-operator-policy-and-audit-chain'],'PASS')
        self.assertEqual(checks['service-cannot-rewrite-scope-signer-public-key'],'FAIL')
        self.assertEqual(checks['service-cannot-rewrite-delegation-signer-public-key'],'FAIL')

    def test_writable_policy_fails_without_a_read_only_mount(self):
        with TemporaryDirectory() as name:
            path=Path(name)/'operator-policy.json'
            path.write_text('synthetic')
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                _protected_read_only(path)
            alias=Path(name)/'alias.json'
            alias.symlink_to(path)
            with self.assertRaises((OSError, ValueError)):
                _protected_read_only(alias)

    def test_immutable_python_file_is_not_protected_by_writable_install_dir(self):
        with TemporaryDirectory() as name:
            root = Path(name) / "install"
            root.mkdir(mode=0o700)
            for fname in ("aegis_supervisor.py", "aegis_integrated_assessment.py",
                          "aegis_agent_gateway.py", "aegis_sandbox.py",
                          "aegis_audit.py", "aegis_host_acceptance.py"):
                source = root / fname
                source.write_text("# synthetic fixture only\n")
                source.chmod(0o444)
            # The service owns the directory and can rename a read-only module.
            with self.assertRaises(ValueError):
                _code_installation(root)
            with self.assertRaises(ValueError):
                _protected_parent_chain(root)

    def test_live_delegation_socket_identity_and_mode(self):
        with TemporaryDirectory() as name:
            parent = Path(name) / "sockdir"
            parent.mkdir(mode=0o700)
            target = parent / "delegate.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(target))
                target.chmod(0o600)
                _live_delegation_socket(target, {"shared_gid": None})
                target.chmod(0o666)
                with self.assertRaises(ValueError):
                    _live_delegation_socket(target, {"shared_gid": None})
                target.chmod(0o600)
                with self.assertRaises(ValueError):
                    _live_delegation_socket(target, {"shared_gid": os.getegid()})
                target.unlink()
                target.symlink_to(parent / "missing.sock")
                with self.assertRaises(ValueError):
                    _live_delegation_socket(target, {"shared_gid": None})

    def test_receiver_fails_self_uid_and_missing_live_socket(self):
        with TemporaryDirectory() as name:
            root=Path(name)
            (root/'state').mkdir(mode=0o700)
            (root/'socket').mkdir(mode=0o700)
            policy=root/'receiver-policy.json'
            import json
            policy.write_text(json.dumps({'schema_version':1,'configured':True,
                'socket_path':str(root/'socket'/'receiver.sock'),
                'state_root':str(root/'state'),'shared_gid':None,
                'allowed_sender_uids':[os.geteuid()],
                'allowed_engagement_ids':['test-engagement-01']}))
            policy.chmod(0o600)
            answer=inspect_receiver(policy_path=policy,expected_operator_uid=os.geteuid())
            self.assertEqual(answer['status'],'NOT_PRODUCTION_APPROVED')
            checks={x['check']:x['result'] for x in answer['checks']}
            self.assertEqual(checks['live-separate-uid-receiver-socket-and-state-directory'],'FAIL')
            self.assertEqual(checks['independently-confirmed-durable-receipt'],
                             'REQUIRES_EXTERNAL_EVIDENCE')

    def test_receiver_rejects_socket_group_mismatch(self):
        with TemporaryDirectory() as name:
            root=Path(name)
            state=root/'state'
            state.mkdir(mode=0o700)
            parent=root/'socket'
            parent.mkdir(mode=0o710)
            target=parent/'receiver.sock'
            operator_uid=next(p.pw_uid for p in pwd.getpwall()
                              if 0<p.pw_uid<2**31 and p.pw_uid!=os.geteuid())
            policy={'state_root':str(state),'socket_path':str(target),
                    'shared_gid':os.getegid(),'allowed_sender_uids':[operator_uid]}
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
                server.bind(str(target))
                target.chmod(0o660)
                # Keep this socket/OS-metadata check usable under root test
                # launchers too; positive configuration parsing is tested in
                # the receiver suite and real distinct-UID CI acceptance.
                with patch('aegis_host_acceptance.receiver_policy',return_value=policy):
                    answer=inspect_receiver(policy_path=root/'policy.json',
                                            expected_operator_uid=operator_uid)
                    key='live-separate-uid-receiver-socket-and-state-directory'
                    self.assertEqual({c['check']:c['result'] for c in answer['checks']}[key],'PASS')
                    actual_stat=os.stat
                    def wrong_socket_group(path,*args,**kwargs):
                        st=actual_stat(path,*args,**kwargs)
                        if path==target.name and kwargs.get('dir_fd') is not None:
                            fields=list(st)
                            fields[5]=st.st_gid+1
                            return os.stat_result(fields)
                        return st
                    with patch('os.stat',side_effect=wrong_socket_group):
                        answer=inspect_receiver(policy_path=root/'policy.json',
                                                expected_operator_uid=operator_uid)
                    self.assertEqual({c['check']:c['result'] for c in answer['checks']}[key],'FAIL')


if __name__=='__main__':unittest.main()
