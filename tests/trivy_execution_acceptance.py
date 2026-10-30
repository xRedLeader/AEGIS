"""Actual offline SBOM positive/control using an explicitly prepared immutable DB."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from aegis_audit_contract import canonical
from aegis_scanner_execution import ScannerExecutionSupervisor,TRIVY_SHA256
from test_runtime import AegisRuntimeTests


def file_sha(path):
    digest=hashlib.sha256()
    with open(path,'rb') as stream:
        while chunk:=stream.read(16*1024**2):digest.update(chunk)
    return digest.hexdigest()


def run(binary,database):
    fixture=AegisRuntimeTests();fixture.setUp();fx=fixture.fx
    try:
        fx.manifest['limits']['engagement_runtime_minutes']=5
        fx.manifest['methods']['allowed'].append('dependency_analysis');fx.trust['approved_methods'].append('dependency_analysis');fx.save()
        files={name:file_sha(database/name) for name in ('trivy.db','metadata.json')}
        metadata=json.loads((database/'metadata.json').read_bytes())
        database_policy={'path':str(database),'files':files,'built_at_utc':metadata['UpdatedAt'][:19]+'Z','max_age_seconds':86400}
        rules=fx.p/'rules.json';rules.write_bytes(b'{}');rules.chmod(0o600)
        bom_path=fx.p/'bom.json';policy_path=fx.p/'execution.json'
        engine=ScannerExecutionSupervisor(fx.manifest_path,fx.sig_path,fx.trust_path,fixture.state)
        cases=[]
        for version,positive in (('5.3',True),('6.0.3',False)):
            bom={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,
                 'metadata':{'component':{'type':'application','name':'aegis-synthetic-sbom'}},
                 'components':[{'type':'library','name':'pyyaml','version':version,'purl':'pkg:pypi/pyyaml@'+version}]}
            bom_path.write_bytes(canonical(bom));bom_path.chmod(0o600)
            policy={'schema_version':1,'configured':True,'engagement_id':fx.manifest['engagement']['id'],'operation_id':str(uuid.uuid4()),
                    'profile':'trivy-sbom-v0.76.1','executable':{'path':str(binary),'sha256':TRIVY_SHA256},
                    'configuration':{'path':str(rules),'sha256':hashlib.sha256(b'{}').hexdigest()},'database':database_policy,
                    'input':{'kind':'sbom','artifact_path':str(bom_path),'artifact_sha256':hashlib.sha256(bom_path.read_bytes()).hexdigest(),
                             'format':'cyclonedx-1.5','image_digest':None},
                    'allowed_rule_ids':['CVE-2017-18342','CVE-2020-14343','CVE-2020-1747'],'seconds':30}
            policy_path.write_bytes(canonical(policy));policy_path.chmod(0o600)
            result=engine.execute(policy_path)
            assert (result['observations']>0)==positive,result
            assert result['import']['status']=='SCANNER_IMPORT_RECORDED',result
            cases.append({'package':'pyyaml','version':version,'observations':result['observations'],'governed_import':True})
        assert engine.verify_audit_chain()
        return {'status':'REAL_PINNED_TRIVY_SBOM_ACCEPTANCE_PASSED','binary_sha256':TRIVY_SHA256,
                'database':database_policy,'cases':cases,'assessment_status':'unverified_only','network':'denied'}
    finally:fixture.tearDown();fixture.doCleanups()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--database',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(run(args.binary,args.database),sort_keys=True))
