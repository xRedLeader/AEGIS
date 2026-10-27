"""v1.7 offline bounded runtime validation and fail-closed sandbox acceptance."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from aegis_bounded_fuzz_worker import cases, expected, validate_plan, HarnessDenied
from aegis_fuzz_runtime import AegisFuzzSupervisor, load_operator_policy
from aegis_supervisor import ExecutionDenied, operator_stop
import test_preflight


SAFE_TARGET = '''def can_read_tenant(actor_id, resource_owner_id):
    return (actor_id is not None and resource_owner_id is not None
            and type(actor_id) is type(resource_owner_id)
            and actor_id == resource_owner_id)
'''
VULNERABLE_TARGET = '''def can_read_tenant(actor_id, resource_owner_id):
    return str(actor_id).casefold() == str(resource_owner_id).casefold()
'''


class BaseFuzzFixture:
    def setUp(self):
        self.fx = test_preflight.AegisPreflightTests('test_valid_signed_scope')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.state = self.fx.p / 'state'
        self.state.mkdir(mode=0o700)
        self.fx.manifest['targets']['origins'] = []
        self.fx.manifest['accounts'] = []
        self.fx.manifest['methods']['allowed'] = ['bounded_fuzzing']
        self.fx.trust['approved_methods'] = ['bounded_fuzzing']
        self.fx.manifest['limits'].update(max_total_requests=0,
             max_requests_per_minute_per_origin=0, max_concurrent_requests=0,
             engagement_runtime_minutes=2, max_single_run_minutes=1,
             deterministic_hypothesis_minutes=1)
        self.fx.save()
        (self.fx.repo / 'auth').mkdir()
        self.target = self.fx.repo / 'auth' / 'guard.py'
        self.target.write_text(VULNERABLE_TARGET)
        self.policy_path = self.fx.p / 'fuzz-policy.json'
        self.policy = {'schema_version': 1, 'configured': True,
            'authorized_repository': str(self.fx.repo),
            'targets': {'auth/guard.py': {'sha256': hashlib.sha256(self.target.read_bytes()).hexdigest(),
                'callable': 'can_read_tenant', 'contract': 'strict_tenant_owner_v1',
                'max_cases': 32}}}
        self.save()

    def save(self):
        self.policy_path.write_text(json.dumps(self.policy))
        self.policy_path.chmod(0o600)

    def supervisor(self):
        return AegisFuzzSupervisor(self.fx.manifest_path, self.fx.sig_path,
                   self.fx.trust_path, self.state, self.policy_path)

    def run_fuzz(self, **kwargs):
        return self.supervisor().execute(self.fx.repo, 'auth/guard.py', seed=42,
                                         max_cases=24, seconds=5, **kwargs)


class FuzzPlanningTests(BaseFuzzFixture, unittest.TestCase):
    def test_reproducible_fixed_synthetic_cases(self):
        a, b = cases(5, 32), cases(5, 32)
        self.assertEqual(a, b)
        self.assertNotEqual(a, cases(6, 32))
        self.assertFalse(expected(None, None))
        self.assertFalse(expected(True, 1))
        self.assertFalse(expected('TENANT', 'tenant'))
        self.assertTrue(expected('tenant', 'tenant'))

    def test_untrusted_result_cannot_forge_oracle(self):
        plan = {"contract":"strict_tenant_owner_v1", "module":"auth/guard.py",
                "callable":"can_read_tenant", "source_sha256":"0"*64,
                "seed":3, "max_cases":16, "mode":"replay", "case_index":0}
        forged = {"status":"BOUNDED_OFFLINE_AUTHORIZATION_REPRODUCTION_ONLY",
                  "contract":"strict_tenant_owner_v1", "source_sha256":"0"*64,
                  "seed":3,"mode":"replay", "cases_requested":1,"cases_executed":1,
                  "mismatches":1,"non_boolean_or_exception":0,"unstable_repetitions":0,
                  "summary":{"synthetic_cases":1,"repeated_mismatches":1,
                             "deployment_impact":"NOT_ESTABLISHED",
                             "finding_status":"needs_validation"},
                  "candidates":[{"case_index":0,"synthetic_actor":"forged",
                                 "synthetic_owner":"forged","expected_authorized":False,
                                 "observed_authorized":True,"repeated_same_result":True,
                                 "classification":"local_oracle_mismatch_needs_validation"}]}
        with self.assertRaisesRegex(ExecutionDenied,"synthetic candidate"):
            self.supervisor()._check_result(forged,plan)

    def test_unapproved_plans_rejected(self):
        good = {'contract':'strict_tenant_owner_v1', 'module':'auth/guard.py',
                'callable':'can_read_tenant', 'source_sha256':'0'*64,
                'seed':2, 'max_cases':16, 'mode':'fuzz', 'case_index':None}
        validate_plan(good)
        for diff in [dict(module='../escape.py'), dict(module='auth/../../secret.py'),
                     dict(module='/etc/passwd'), dict(seed=-1), dict(max_cases=1000),
                     dict(mode='arbitrary'), dict(case_index=0),
                     dict(source_sha256='not-a-hash'),dict(callable='__import__("os")')]:
            with self.subTest(diff=diff), self.assertRaises(HarnessDenied):
                validate_plan({**good, **diff})

    def test_strict_policy_requires_exact_repo_and_pinned_targets(self):
        policy = load_operator_policy(self.policy_path, self.fx.repo, self.state)
        self.assertEqual(list(policy['targets']), ['auth/guard.py'])
        self.policy['configured'] = False
        self.save()
        with self.assertRaises(ExecutionDenied):
            load_operator_policy(self.policy_path, self.fx.repo, self.state)

    def test_policy_symlink_and_permissions_denied(self):
        self.policy_path.chmod(0o644)
        with self.assertRaises(ExecutionDenied):
            load_operator_policy(self.policy_path, self.fx.repo, self.state)
        self.policy_path.chmod(0o600)
        alias = self.fx.p / 'alias.json'
        alias.symlink_to(self.policy_path)
        with self.assertRaises(OSError):
            load_operator_policy(alias, self.fx.repo, self.state)

    def test_disabled_or_unsupported_contract_rejected(self):
        self.policy['targets']['auth/guard.py']['contract'] = 'execute_shell'
        self.save()
        with self.assertRaises(ExecutionDenied):
            load_operator_policy(self.policy_path, self.fx.repo, self.state)


@unittest.skipUnless(__import__('sys').platform == 'linux' and hasattr(os, 'geteuid') and os.geteuid() != 0,
                     'NOT EXECUTED: genuine Linux non-root sandbox required')
class KernelFuzzTests(BaseFuzzFixture, unittest.TestCase):
    def test_real_isolated_mismatch_and_independent_replay(self):
        sup = self.supervisor()
        result = sup.execute(self.fx.repo, 'auth/guard.py', seed=42, max_cases=24, seconds=5)
        self.assertEqual(result['status'], 'COMPLETED_BOUNDED_LOCAL_VALIDATION_ONLY')
        evidence = json.loads(Path(result['report']).read_text())
        self.assertGreater(evidence['mismatches'], 0)
        self.assertEqual(evidence['summary']['deployment_impact'], 'NOT_ESTABLISHED')
        self.assertEqual(evidence['status'], 'BOUNDED_OFFLINE_AUTHORIZATION_REPRODUCTION_ONLY')
        reproducible = next(c for c in evidence['candidates'] if c['repeated_same_result'])
        replay = sup.execute(self.fx.repo, 'auth/guard.py', seed=42, max_cases=24,
                             seconds=5, mode='replay', case_index=reproducible['case_index'])
        replay_evidence = json.loads(Path(replay['report']).read_text())
        self.assertEqual(replay_evidence['cases_executed'], 1)
        self.assertEqual(replay_evidence['candidates'][0], reproducible)
        self.assertEqual(sup.usage(result['engagement_id'])['reserved_seconds'], 10)
        self.assertTrue(sup.verify_audit_chain())

    def test_correct_fixture_has_no_mismatches(self):
        self.target.write_text(SAFE_TARGET)
        self.policy['targets']['auth/guard.py']['sha256'] = hashlib.sha256(self.target.read_bytes()).hexdigest()
        self.save()
        result = self.run_fuzz()
        evidence = json.loads(Path(result['report']).read_text())
        self.assertEqual(evidence['mismatches'], 0)
        self.assertEqual(evidence['candidates'], [])
        self.assertEqual(evidence['summary']['finding_status'], 'needs_validation')

    def test_source_fingerprint_change_fails_closed(self):
        self.target.write_text(SAFE_TARGET)
        with self.assertRaises(ExecutionDenied):
            self.run_fuzz()

    def test_repository_symlink_fails_closed(self):
        other = self.fx.p / 'outside.py'
        other.write_text(VULNERABLE_TARGET)
        self.target.unlink()
        self.target.symlink_to(other)
        with self.assertRaises(ExecutionDenied):
            self.run_fuzz()

    def test_no_network_or_host_writes_from_target(self):
        target = '''import os
import socket

def can_read_tenant(actor, owner):
    try:
        socket.socket()
        return True
    except OSError:
        pass
    try:
        open('/tmp/aegis-fuzz-escaped', 'w').write('fail')
        return True
    except OSError:
        pass
    return (actor is not None and owner is not None and
            type(actor) is type(owner) and actor == owner)
'''
        self.target.write_text(target)
        self.policy['targets']['auth/guard.py']['sha256'] = hashlib.sha256(self.target.read_bytes()).hexdigest()
        self.save()
        result = self.run_fuzz()
        evidence = json.loads(Path(result['report']).read_text())
        self.assertEqual(evidence['mismatches'], 0)
        self.assertFalse(Path('/tmp/aegis-fuzz-escaped').exists())

    def test_source_attempted_stdout_flood_is_rejected(self):
        target = '''import os

def can_read_tenant(actor, owner):
    os.write(1, b'x' * 70000)
    return False
'''
        self.target.write_text(target)
        self.policy['targets']['auth/guard.py']['sha256'] = hashlib.sha256(self.target.read_bytes()).hexdigest()
        self.save()
        with self.assertRaises(ExecutionDenied):
            self.run_fuzz()

    def test_method_scope_and_operator_policy_are_required(self):
        self.fx.manifest['methods']['allowed'] = ['source_review']
        self.fx.trust['approved_methods'] = ['source_review']
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, 'bounded_fuzzing'):
            self.run_fuzz()
        self.assertFalse((self.state/'ledger.sqlite3').exists())

    def test_emergency_stop_prevents_test(self):
        operator_stop(self.state, self.fx.manifest['engagement']['id'])
        with self.assertRaisesRegex(ExecutionDenied, 'emergency stop'):
            self.run_fuzz()

    def test_target_missing_or_unlisted_denied(self):
        with self.assertRaisesRegex(ExecutionDenied, 'unregistered'):
            self.supervisor().execute(self.fx.repo, '../escape.py', seed=42,
                                      max_cases=24, seconds=5)


if __name__ == '__main__':
    unittest.main()
