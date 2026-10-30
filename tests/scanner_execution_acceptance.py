"""Real pinned Gitleaks positive/control acceptance; run as isolated non-root CI identity."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from aegis_audit_contract import canonical
from aegis_scanner_execution import ScannerExecutionSupervisor,GITLEAKS_SHA256
from aegis_supervisor import ExecutionDenied
from test_runtime import AegisRuntimeTests


def run(binary):
    fixture=AegisRuntimeTests();fixture.setUp()
    try:
        fx=fixture.fx
        fx.manifest['limits']['engagement_runtime_minutes']=5
        fx.manifest['limits']['max_single_run_minutes']=1;fx.save()
        canary='AEGIS_TEST_SECRET_'+'A'*32
        (fx.repo/'vulnerable.env').write_text('SYNTHETIC_ONLY='+canary+'\n')
        (fx.repo/'safe.env').write_text('SYNTHETIC_ONLY=example-placeholder\n')
        (fx.repo/'unselected.env').write_text('SYNTHETIC_ONLY='+canary+'\n')
        rules=fx.p/'rules.toml';rules.write_bytes((ROOT/'tests/fixtures/source_scanners/gitleaks.toml').read_bytes());rules.chmod(0o600)
        policy_path=fx.p/'scanner-execution.json'
        engine=ScannerExecutionSupervisor(fx.manifest_path,fx.sig_path,fx.trust_path,fixture.state)
        results=[]
        for name,expected in (('vulnerable.env',1),('safe.env',0)):
            policy={'schema_version':1,'configured':True,'engagement_id':fx.manifest['engagement']['id'],'operation_id':str(uuid.uuid4()),
                    'profile':'gitleaks-dir-v8.24.3','executable':{'path':str(binary),'sha256':GITLEAKS_SHA256},
                    'configuration':{'path':str(rules),'sha256':hashlib.sha256(rules.read_bytes()).hexdigest()},
                    'input':{'kind':'source','repository':str(fx.repo),'files':{name:hashlib.sha256((fx.repo/name).read_bytes()).hexdigest()}},
                    'allowed_rule_ids':['aegis-synthetic-canary'],'seconds':15}
            policy_path.write_bytes(canonical(policy));policy_path.chmod(0o600)
            outcome=engine.execute(policy_path)
            assert outcome['observations']==expected,outcome
            assert outcome['import']['status']=='SCANNER_IMPORT_RECORDED',outcome
            try:engine.execute(policy_path)
            except ExecutionDenied:pass
            else:raise AssertionError('completed operation silently reran')
            results.append({'control':name,'observations':expected,'governed_import':True,'replay_denied':True})
        for root in (Path(fx.manifest['reporting']['output_dir']),fixture.state):
            for path in root.rglob('*'):
                if path.is_file():assert canary.encode() not in path.read_bytes(),str(path)
        assert engine.verify_audit_chain()
        return {'status':'REAL_PINNED_GITLEAKS_ACCEPTANCE_PASSED','binary_sha256':GITLEAKS_SHA256,'cases':results,
                'raw_secret_absent_from_artifacts_and_ledger':True,'assessment_status':'unverified_only'}
    finally:fixture.tearDown();fixture.doCleanups()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,required=True)
    print(json.dumps(run(parser.parse_args().binary),sort_keys=True))
