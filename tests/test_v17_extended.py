"""v1.7 bounded JSON contracts, serializable interleavings and fresh-jail replay."""
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor

from aegis_bounded_fuzz_worker import _execute_fixed_contract, HarnessDenied, validate_plan
from aegis_local_contracts import fixtures, oracle, case_digest
from aegis_fuzz_runtime import AegisFuzzSupervisor
from aegis_supervisor import ExecutionDenied
from test_v17_fuzz import BaseFuzzFixture

GOOD_JSON = '''def access(req):
    return (type(req) is dict and set(req) == {"actor", "owner", "operation"}
            and req["operation"] == "read" and type(req["actor"]) is str
            and bool(req["actor"]) and type(req["owner"]) is str
            and req["actor"] == req["owner"])
'''
BAD_JSON = '''def access(req):
    return str(req.get("actor")).casefold() == str(req.get("owner")).casefold()
'''
GOOD_CAS = '''def update(state, version, delta):
    allowed = (type(version) is int and version == state["version"]
               and type(delta) is int and delta == 1)
    if allowed:
        state["version"] += 1
        state["value"] += 1
    return allowed
'''
BAD_CAS = '''def update(state, version, delta):
    state["version"] += 1
    state["value"] += 1
    return True
'''
FLAKY_JSON = '''calls = 0
def access(req):
    global calls
    calls += 1
    return calls % 2 == 0
'''


class ContractUnitTests(unittest.TestCase):
    def test_generated_contract_fixtures_are_seeded_and_bounded(self):
        for contract in ("json_resource_access_v1", "versioned_cas_v1"):
            a = fixtures(contract, 42, 40)
            self.assertEqual(len(a), 40)
            self.assertEqual(a, fixtures(contract, 42, 40))
            self.assertNotEqual(a, fixtures(contract, 43, 40))
            self.assertEqual(len(case_digest(a)), 64)

    def test_json_oracle_enforces_exact_string_and_schema(self):
        self.assertTrue(oracle('json_resource_access_v1',
            {'actor':'a', 'owner':'a', 'operation':'read'}))
        for d in ({'actor':'a','owner':'A','operation':'read'},
                  {'actor':'','owner':'','operation':'read'},
                  {'actor':0,'owner':'0','operation':'read'},
                  {'actor':'a','owner':'a','operation':'read','role':'admin'},
                  {'actor':'a','owner':'a','operation':'write'}):
            self.assertFalse(oracle('json_resource_access_v1', d))

    def test_cas_oracle_models_stale_read_interleavings(self):
        example = {'initial': {'version':2,'value':5},
                   'steps':[{'version':2,'delta':1},{'version':2,'delta':1},
                            {'version':3,'delta':1}]}
        self.assertEqual(oracle('versioned_cas_v1', example),
                         {'decisions':[True,False,True], 'state':{'version':4,'value':7}})

    def test_both_contracts_detect_bad_and_accept_good_local_fixtures(self):
        def good_json(q):
            return oracle('json_resource_access_v1', q)
        def bad_json(q):
            return str(q.get('actor')).casefold() == str(q.get('owner')).casefold()
        def good_cas(state,v,d):
            if type(v) is int and v == state['version'] and type(d) is int and d == 1:
                state['version'] += 1; state['value'] += 1
                return True
            return False
        def bad_cas(state,v,d):
            state['version'] += 1; state['value'] += 1
            return True
        for contract,good,bad in [('json_resource_access_v1',good_json,bad_json),
                                  ('versioned_cas_v1',good_cas,bad_cas)]:
            plan = {'contract':contract,'source_sha256':'0'*64,'seed':7,
                    'max_cases':32,'mode':'fuzz','case_index':None,'trials':3}
            self.assertEqual(_execute_fixed_contract(plan,good)['mismatches'],0)
            out = _execute_fixed_contract(plan,bad)
            self.assertGreater(out['mismatches'],0)
            self.assertTrue(all(c['classification']=='local_contract_mismatch_needs_validation'
                                for c in out['candidates']))

    def test_flaky_code_marked_unstable_and_not_confirmed(self):
        counter={'n':0}
        def flip(_):
            counter['n'] += 1
            return counter['n'] % 2 == 0
        plan={'contract':'json_resource_access_v1', 'source_sha256':'0'*64,
              'seed':0,'max_cases':16,'mode':'fuzz','case_index':None,'trials':3}
        out=_execute_fixed_contract(plan,flip)
        self.assertGreater(out['unstable_repetitions'],0)
        self.assertTrue(any(x['classification']=='local_nondeterministic_case_needs_validation'
                            for x in out['candidates']))
        self.assertEqual(out['summary']['deployment_impact'],'NOT_ESTABLISHED')

    def test_trial_and_contract_validation_fail_closed(self):
        p={'contract':'json_resource_access_v1','module':'auth/guard.py',
           'callable':'access','source_sha256':'0'*64,'seed':42,'max_cases':16,
           'mode':'fuzz','case_index':None,'trials':3}
        validate_plan(p)
        for change in ({'trials':0},{'trials':6},{'trials':True},
                       {'max_cases':64,'trials':5},
                       {'contract':'arbitrary_code_v1'}, {'module':'../../escape.py'}):
            with self.subTest(change=change), self.assertRaises(HarnessDenied):
                validate_plan({**p, **change})


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() != 0,
                     'NOT EXECUTED: requires rootless Linux kernel containment')
class ContractKernelTests(BaseFuzzFixture, unittest.TestCase):
    def configure(self, contract, source, callable_name):
        self.target.write_text(source)
        self.policy['targets']['auth/guard.py'].update({
            'sha256':hashlib.sha256(self.target.read_bytes()).hexdigest(),
            'contract':contract, 'callable':callable_name, 'max_cases':32,
            'max_trials':5})
        self.save()
        return self.supervisor()

    def evidence(self, response):
        return json.loads(Path(response['report']).read_text())

    def test_json_contract_good_bad_and_independent_minimal_replay(self):
        sup=self.configure('json_resource_access_v1',GOOD_JSON,'access')
        self.assertEqual(self.evidence(sup.execute(self.fx.repo,'auth/guard.py',
                            seed=12,max_cases=24,seconds=5))['mismatches'],0)
        self.target.write_text(BAD_JSON)
        self.policy['targets']['auth/guard.py']['sha256']=hashlib.sha256(self.target.read_bytes()).hexdigest()
        self.save()
        response=sup.execute(self.fx.repo,'auth/guard.py',seed=12,max_cases=24,seconds=5)
        record=self.evidence(response)
        self.assertGreater(record['mismatches'],0)
        self.assertIn('minimal_reproducer',record)
        verified=sup.verify_evidence(self.fx.repo,'auth/guard.py',response['run_id'],seconds=5)
        self.assertEqual(verified['status'],'LOCAL_REPRODUCED_NEEDS_DEPLOYMENT_VALIDATION')
        self.assertNotEqual(response['run_id'],verified['replay_run_id'])
        self.assertTrue(sup.verify_audit_chain())

    def test_cas_contract_detects_stale_double_commit_then_replays(self):
        sup=self.configure('versioned_cas_v1',BAD_CAS,'update')
        response=sup.execute(self.fx.repo,'auth/guard.py',seed=21,max_cases=24,
                             seconds=5,trials=4)
        record=self.evidence(response)
        self.assertGreater(record['mismatches'],0)
        self.assertEqual(record['trials_per_case'],4)
        replay=sup.verify_evidence(self.fx.repo,'auth/guard.py',response['run_id'],seconds=5)
        self.assertEqual(replay['status'],'LOCAL_REPRODUCED_NEEDS_DEPLOYMENT_VALIDATION')
        self.assertTrue(sup.verify_audit_chain())

    def test_json_target_cannot_use_host_network_or_write_files(self):
        source = '''import socket
import os

def access(req):
    try:
        socket.socket()
        return True
    except OSError:
        pass
    try:
        open('/tmp/aegis-v17-extended-escape', 'w').write('oops')
        return True
    except OSError:
        pass
    return (type(req) is dict and set(req) == {'actor', 'owner', 'operation'}
            and req['operation'] == 'read' and type(req['actor']) is str
            and bool(req['actor']) and type(req['owner']) is str
            and req['actor'] == req['owner'])
'''
        sup=self.configure('json_resource_access_v1',source,'access')
        result=sup.execute(self.fx.repo,'auth/guard.py',seed=21,max_cases=24,seconds=5)
        self.assertEqual(self.evidence(result)['mismatches'],0)
        self.assertFalse(Path('/tmp/aegis-v17-extended-escape').exists())

    def test_correct_cas_is_clean_for_selected_invariant(self):
        sup=self.configure('versioned_cas_v1',GOOD_CAS,'update')
        result=sup.execute(self.fx.repo,'auth/guard.py',seed=21,max_cases=24,seconds=5)
        self.assertEqual(self.evidence(result)['mismatches'],0)

    def test_unstable_run_not_false_confirmed_by_independent_replay(self):
        sup=self.configure('json_resource_access_v1',FLAKY_JSON,'access')
        response=sup.execute(self.fx.repo,'auth/guard.py',seed=12,max_cases=24,seconds=5)
        result=self.evidence(response)
        self.assertGreater(result['unstable_repetitions'],0)
        verification=sup.verify_evidence(self.fx.repo,'auth/guard.py',response['run_id'],seconds=5)
        self.assertEqual(verification['status'],'LOCAL_NOT_INDEPENDENTLY_REPRODUCED')

    def test_verified_evidence_rejects_modified_source(self):
        sup=self.configure('json_resource_access_v1',BAD_JSON,'access')
        original=sup.execute(self.fx.repo,'auth/guard.py',seed=12,max_cases=24,seconds=5)
        self.target.write_text(GOOD_JSON)
        with self.assertRaises(ExecutionDenied):
            sup.verify_evidence(self.fx.repo,'auth/guard.py',original['run_id'],seconds=5)

    def test_verified_evidence_rejects_changed_candidate(self):
        sup=self.configure('json_resource_access_v1',BAD_JSON,'access')
        original=sup.execute(self.fx.repo,'auth/guard.py',seed=12,max_cases=24,seconds=5)
        evidence=Path(original['report'])
        record=json.loads(evidence.read_text())
        record['candidates'][0]['synthetic_input']['actor']='forged'
        evidence.write_text(json.dumps(record))
        with self.assertRaisesRegex(ExecutionDenied,'untrusted|candidate'):
            sup.verify_evidence(self.fx.repo,'auth/guard.py',original['run_id'],seconds=5)

    def test_verifier_denies_cross_scope_and_invalid_run_id(self):
        sup=self.configure('json_resource_access_v1',BAD_JSON,'access')
        with self.assertRaises(ExecutionDenied):
            sup.verify_evidence(self.fx.repo,'auth/guard.py','../other',seconds=5)
        with self.assertRaises(ExecutionDenied):
            sup.verify_evidence(self.fx.repo,'auth/guard.py','12345678-1234-1234-1234-123456789abc',seconds=5)

    def test_concurrent_sandbox_trials_have_atomic_reservations(self):
        self.configure('json_resource_access_v1',BAD_JSON,'access')
        def attempt(_):
            return self.supervisor().execute(self.fx.repo,'auth/guard.py',
                seed=17,max_cases=24,seconds=5)
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes=list(pool.map(attempt,range(2)))
        self.assertEqual(len({x['run_id'] for x in outcomes}),2)
        self.assertEqual(self.supervisor().usage(outcomes[0]['engagement_id'])['reserved_seconds'],10)
        self.assertTrue(self.supervisor().verify_audit_chain())

if __name__=='__main__': unittest.main()
