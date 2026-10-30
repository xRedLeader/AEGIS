"""Actual native confinement and supervisor failure drills using a trusted C probe."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
from aegis_audit_contract import canonical
from aegis_scanner_execution import ScannerExecutionSupervisor,sealed_file
from aegis_scanner_sandbox import launch
from aegis_supervisor import ExecutionDenied,operator_stop
from test_runtime import AegisRuntimeTests


def confinement(binary):
    fds=[]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'source').mkdir();(root/'source/safe.env').write_text('EXAMPLE=value\n');(root/'jail').mkdir(mode=0o700)
            fds=[sealed_file('test-probe',binary.read_bytes(),True),sealed_file('test-rules',b'probe'),os.open(root/'source',os.O_RDONLY|os.O_DIRECTORY)]
            result=subprocess.run(launch('gitleaks-dir-v8.24.3',*fds,root/'jail',10),pass_fds=fds,capture_output=True,timeout=15)
            assert result.returncode==0,(result.returncode,result.stderr.decode(),result.stdout.decode())
            proof=json.loads(result.stdout);assert all(proof['checks'].values()),proof
            assert (root/'source/safe.env').read_text()=='EXAMPLE=value\n'
            return proof['checks']
    finally:
        for fd in fds:os.close(fd)


def fixture_policy(binary,mode,seconds):
    fixture=AegisRuntimeTests();fixture.setUp();fx=fixture.fx
    fx.manifest['limits']['engagement_runtime_minutes']=5;fx.save()
    (fx.repo/'safe.env').write_text('EXAMPLE=value\n')
    rules=fx.p/'rules.toml';raw=(ROOT/'tests/fixtures/source_scanners/gitleaks.toml').read_bytes().split(b'\n',1)[1]
    raw=('title = "native_test_'+mode+'"\n').encode()+raw;rules.write_bytes(raw);rules.chmod(0o600)
    sha=hashlib.sha256(binary.read_bytes()).hexdigest()
    policy={'schema_version':1,'configured':True,'engagement_id':fx.manifest['engagement']['id'],'operation_id':str(uuid.uuid4()),
            'profile':'gitleaks-dir-v8.24.3','executable':{'path':str(binary),'sha256':sha},
            'configuration':{'path':str(rules),'sha256':hashlib.sha256(raw).hexdigest()},
            'input':{'kind':'source','repository':str(fx.repo),'files':{'safe.env':hashlib.sha256((fx.repo/'safe.env').read_bytes()).hexdigest()}},
            'allowed_rule_ids':['aegis-synthetic-canary'],'seconds':seconds}
    path=fx.p/'execution.json';path.write_bytes(canonical(policy));path.chmod(0o600)
    engine=ScannerExecutionSupervisor(fx.manifest_path,fx.sig_path,fx.trust_path,fixture.state)
    return fixture,engine,path,sha,policy


def failures(binary):
    results={}
    for mode,seconds in (('flood',8),('timeout',1),('stop',8),('revocation',8)):
        fixture,engine,path,sha,policy=fixture_policy(binary,'flood' if mode=='flood' else 'wait',seconds)
        timer=None
        try:
            if mode in ('stop','revocation'):
                def revoke():
                    if mode=='stop':operator_stop(fixture.state,policy['engagement_id'])
                    else:
                        fixture.fx.trust['revoked_engagement_ids']=[policy['engagement_id']];fixture.fx.save()
                timer=threading.Timer(.4,revoke);timer.start()
            start=time.monotonic()
            with patch('aegis_scanner_execution.GITLEAKS_SHA256',sha):
                try:engine.execute(path,import_result=False)
                except ExecutionDenied:pass
                else:raise AssertionError(mode+' unexpectedly completed')
                if mode in ('flood','timeout'):
                    try:engine.execute(path,import_result=False)
                    except ExecutionDenied:pass
                    else:raise AssertionError('failed operation silently reran')
            with engine._database() as db:
                row=db.execute('SELECT run_id,status FROM scanner_executions WHERE operation_id=?',(policy['operation_id'],)).fetchone()
                assert row and row[1]=='failed_requires_reconciliation',row
                assert db.execute('SELECT status FROM runs WHERE run_id=?',(row[0],)).fetchone()==('aborted',)
                events=[json.loads(value) for (value,) in db.execute('SELECT event FROM audit')]
                assert not any(e['type']=='scanner_execution_completed' for e in events)
                failure=next(e for e in events if e['type']=='scanner_execution_failed')
                assert failure['partial_output_sha256'] is not None
            assert engine.verify_audit_chain()
            results[mode]={'denied':True,'elapsed_ms':int((time.monotonic()-start)*1000),'reconciliation_required':True}
        finally:
            if timer is not None:timer.join(timeout=2)
            fixture.tearDown();fixture.doCleanups()
    return results


def descendants(pid):
    found=[]
    try:
        children=Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
    except FileNotFoundError:return found
    for child in children:
        value=int(child);found.append(value);found.extend(descendants(value))
    return found


def crash(binary):
    fixture,engine,path,sha,policy=fixture_policy(binary,'wait',15);child=None
    try:
        fx=fixture.fx
        script="import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import aegis_scanner_execution as m;m.GITLEAKS_SHA256=sys.argv[2];m.ScannerExecutionSupervisor(*map(Path,sys.argv[3:7])).execute(Path(sys.argv[7]),import_result=False)"
        child=subprocess.Popen([sys.executable,'-I','-c',script,str(ROOT),sha,str(fx.manifest_path),str(fx.sig_path),str(fx.trust_path),str(fixture.state),str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        limit=time.monotonic()+5;workers=[]
        while time.monotonic()<limit:
            workers=descendants(child.pid)
            if len(workers)>=2:break
            assert child.poll() is None,'supervisor exited before crash drill';time.sleep(.05)
        assert len(workers)>=2,'native child was not launched'
        time.sleep(.2);child.kill();child.wait(timeout=3)
        limit=time.monotonic()+3
        while time.monotonic()<limit:
            live=[]
            for pid in workers:
                try:
                    status=Path(f'/proc/{pid}/status').read_text()
                    if '\nState:\tZ' not in '\n'+status:live.append(pid)
                except FileNotFoundError:pass
            if not live:break
            time.sleep(.05)
        assert not live,'supervisor death left native execution alive'
        with engine._database() as db:
            assert db.execute('SELECT status FROM scanner_executions WHERE operation_id=?',(policy['operation_id'],)).fetchone()==('launched',)
        with patch('aegis_scanner_execution.GITLEAKS_SHA256',sha):
            try:engine.execute(path,import_result=False)
            except ExecutionDenied:pass
            else:raise AssertionError('uncertain crashed operation silently reran')
        assert engine.verify_audit_chain()
        return {'parent_death_killed_native_children':True,'uncertain_reservation_retained':True,'automatic_rerun_denied':True}
    finally:
        if child is not None and child.poll() is None:child.kill();child.wait()
        fixture.tearDown();fixture.doCleanups()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--probe',type=Path,required=True)
    binary=parser.parse_args().probe
    print(json.dumps({'status':'NATIVE_SCANNER_CONFINEMENT_AND_RECOVERY_PASSED','kernel':confinement(binary),
                      'failure_drills':failures(binary),'crash':crash(binary)},sort_keys=True))
