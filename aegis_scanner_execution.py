"""Operator-approved, bounded offline native execution with audited import handoff."""
from __future__ import annotations
import argparse
import ctypes
from datetime import datetime,timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import sqlite3
import stat
import struct
import subprocess
import tempfile
import time
import uuid

from aegis_agent_gateway import _protected
from aegis_audit_contract import canonical,digest,fields,read_relative,require
from aegis_scanner_contract import attestation,normalize,parse_report,sha256,strict_json
from aegis_scanner_import import ScannerImportSupervisor,selected_input
from aegis_scanner_sandbox import launch
from aegis_supervisor import ExecutionDenied,open_directory_nofollow,private_directory

GITLEAKS_SHA256='e18325d568268b6efb6cd0cc721f8bea5667f4cd1c8d03618ab61987f41269ad'
PROFILES={'gitleaks-dir-v8.24.3':('gitleaks','8.24.3','gitleaks-json-v8'),
          'semgrep-core-v1.125.0':('semgrep','1.125.0','semgrep-json-v1'),
          'trivy-sbom-v0.76.1':('trivy','0.76.1','trivy-json-v2')}
SEMGREP_SHA256='313bf3bbb50648fb5c3f43bd1d72dfee28dae436e10a096acb7d9a5839d18f11'
TRIVY_SHA256='d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83'
MAX_ARTIFACTS=131072
LIBC=ctypes.CDLL(None,use_errno=True)


def report_observed_at(raw,profile,started_at,finished_at):
    if profile=='trivy-sbom-v0.76.1':
        from aegis_extended_scanner_adapters import _stamp
        report=strict_json(raw);require(isinstance(report,dict),'native Trivy report must be an object')
        observed=_stamp(report.get('CreatedAt'))
        require(_stamp(started_at.isoformat())<=observed<=_stamp(finished_at.isoformat()),
                'native Trivy report time is outside its execution interval')
        return datetime.fromtimestamp(observed//1_000_000_000,timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return finished_at.strftime('%Y-%m-%dT%H:%M:%SZ')


def sealed_file(name,raw,executable=False):
    fd=os.memfd_create(name,os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(fd),'wb') as stream:stream.write(raw);stream.flush()
        os.fchmod(fd,0o500 if executable else 0o400)
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        os.lseek(fd,0,os.SEEK_SET);return fd
    except BaseException:os.close(fd);raise


def binary_bytes(path,expected):
    path=Path(path)
    require(path.is_absolute() and str(path.resolve())==str(path),'scanner executable must be an absolute nonsymlink path')
    for parent in (path.parent,*path.parent.parents):
        st=parent.stat()
        require(st.st_uid in (0,os.geteuid()) and not st.st_mode&0o022,'scanner executable parent is writable')
    with open_directory_nofollow(path.parent) as folder:
        raw=read_relative(folder,path.name,224*1024*1024)
        st=os.stat(path.name,dir_fd=folder,follow_symlinks=False)
        require(st.st_uid in (0,os.geteuid()) and not st.st_mode&0o022,'scanner executable custody denied')
    require(hashlib.sha256(raw).hexdigest()==expected,'scanner executable digest differs')
    require(raw[:6]==b'\x7fELF\x02\x01' and len(raw)>=64 and struct.unpack_from('<H',raw,18)[0]==62,'only pinned static Linux x86-64 ELF supported')
    offset=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
    require(size==56 and 1<=count<=128 and offset+size*count<=len(raw),'invalid native program headers')
    require(all(struct.unpack_from('<I',raw,offset+size*n)[0]!=3 for n in range(count)),'dynamic native runtime is unsupported')
    return raw


def validate_execution(value):
    require(isinstance(value,dict),'scanner execution policy must be an object')
    fields(value,{'schema_version','configured','engagement_id','operation_id','profile','executable','configuration','input','allowed_rule_ids','seconds'} |
           ({'database'} if value.get('profile')=='trivy-sbom-v0.76.1' else set()))
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['configured'] is True,'scanner execution disabled')
    require(value['profile'] in PROFILES,'scanner profile unsupported; no unrestricted fallback')
    require(isinstance(value['operation_id'],str) and str(uuid.UUID(value['operation_id']))==value['operation_id'],'execution needs a unique operator operation ID')
    require(type(value['seconds']) is int and 1<=value['seconds']<=120,'scanner runtime bound invalid')
    for key in ('executable','configuration'):
        fields(value[key],{'path','sha256'});sha256(value[key]['sha256'])
        require(isinstance(value[key]['path'],str) and Path(value[key]['path']).is_absolute(),'scanner capability path invalid')
    expected={'gitleaks-dir-v8.24.3':GITLEAKS_SHA256,'semgrep-core-v1.125.0':SEMGREP_SHA256,'trivy-sbom-v0.76.1':TRIVY_SHA256}[value['profile']]
    require(value['executable']['sha256']==expected,'unreviewed executable for compiled scanner profile')
    require(isinstance(value['allowed_rule_ids'],list) and 1<=len(value['allowed_rule_ids'])<=64 and
            len(set(value['allowed_rule_ids']))==len(value['allowed_rule_ids']) and
            all(isinstance(x,str) and re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}',x) for x in value['allowed_rule_ids']),
            'explicit bounded scanner rule selection required')
    require(isinstance(value['input'],dict) and value['input'].get('kind')==('sbom' if value['profile']=='trivy-sbom-v0.76.1' else 'source'),
            'scanner profile does not admit this input kind')


def _rules_only(raw,allowed):
    """Conservative TOML subset: data-only rules, no includes, extensions or credentials."""
    require(0<len(raw)<=32768,'scanner rules exceed bound')
    rules=[];current=None
    for line in raw.decode('utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        if line=='[[rules]]':current={};rules.append(current);continue
        match=re.fullmatch(r'(title|id|description|regex|keywords)\s*=\s*(.+)',line)
        require(match is not None,'unsupported ruleset field, section or multiline value')
        key,value=match.groups()
        if key=='regex':require(value.startswith("'''") and value.endswith("'''") and len(value)<=2048,'use bounded literal one-line rule regex')
        else:
            decoded=json.loads(value)
            require((key=='keywords' and isinstance(decoded,list) and len(decoded)<=16 and all(isinstance(x,str) and len(x)<=80 for x in decoded)) or
                    (key!='keywords' and isinstance(decoded,str) and len(decoded)<=256),'ruleset metadata is invalid')
        if current is None:require(key=='title','ruleset data outside rule')
        else:
            require(key in {'id','description','regex','keywords'} and key not in current,'duplicate or unsupported rule field')
            current[key]=json.loads(value) if key!='regex' else value
    require(1<=len(rules)<=64 and all({'id','regex'}<=set(r) for r in rules),'bounded explicit rules required')
    require(sorted(r['id'] for r in rules)==sorted(allowed),'executed rules differ from approved finding IDs')


def _write_artifacts(info,run_id,artifacts):
    require(set(artifacts)=={'scanner-execution.json','scanner-report.json','scanner-config.bin'} and sum(map(len,artifacts.values()))<=MAX_ARTIFACTS,
            'scanner handoff exceeds reserved evidence')
    with open_directory_nofollow(Path(info['report_directory']),create=True) as root:
        private_directory(root)
        try:os.mkdir('runs',0o700,dir_fd=root)
        except FileExistsError:pass
        with_fd=os.open('runs',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
        try:
            private_directory(with_fd);os.mkdir(run_id,0o700,dir_fd=with_fd)
            run=os.open(run_id,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=with_fd)
            try:
                for name,raw in artifacts.items():
                    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=run)
                    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                os.fsync(run)
            finally:os.close(run)
            os.fsync(with_fd)
        finally:os.close(with_fd)


class ScannerExecutionSupervisor(ScannerImportSupervisor):
    def execute(self,policy_path,*,import_result=True,expected_repository=None,max_seconds=None):
        require(os.geteuid()!=0 and hasattr(os,'memfd_create'),'native scanner requires non-root supported Linux')
        info,scope=self._guard();policy_path=Path(policy_path)
        policy_raw=_protected(policy_path,32768,info,self.state_root);policy=strict_json(policy_raw)
        validate_execution(policy)
        if expected_repository is not None and policy['input'].get('kind')=='source':
            require(policy['input'].get('repository')==str(expected_repository),'scanner source differs from approved assessment repository')
        if max_seconds is not None:
            require(type(max_seconds) is int and policy['seconds']<=max_seconds,'scanner profile exceeds approved assessment duration')
        require(canonical(policy)==policy_raw and policy['engagement_id']==info['engagement_id'],'scanner policy is noncanonical or foreign')
        config=_protected(Path(policy['configuration']['path']),32768,info,self.state_root)
        require(hashlib.sha256(config).hexdigest()==policy['configuration']['sha256'],'scanner rules changed')
        profile=policy['profile'];launcher=launch;db_validator=None
        if profile=='semgrep-core-v1.125.0':
            from aegis_semgrep_sandbox import launch as launcher,validate_rules
        elif profile=='trivy-sbom-v0.76.1':
            from aegis_trivy_sandbox import launch as launcher,validate_rules,validate_database as db_validator
        else:validate_rules=_rules_only
        validate_rules(config,policy['allowed_rule_ids'])
        operation=policy['operation_id'];eid=info['engagement_id']
        with self._database() as db:
            db.execute('CREATE TABLE IF NOT EXISTS scanner_executions (engagement_id TEXT NOT NULL,operation_id TEXT NOT NULL,run_id TEXT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(engagement_id,operation_id))')
            require(db.execute('SELECT run_id FROM scanner_executions WHERE engagement_id=? AND operation_id=?',(eid,operation)).fetchone() is None,
                    'operation already reserved; inspect durable receipt and reconcile, never silently rerun')
        info,scope,run_id=self.reserve(policy['seconds'],'dependency_analysis' if policy['input']['kind']=='sbom' else 'source_review',evidence_bytes=MAX_ARTIFACTS)
        started=time.monotonic();deadline=started+policy['seconds'];worker=None;fds=[];stats={};partial_sha=None;output_fd=None
        def guard():
            self._guard();require(time.monotonic()<deadline,'native scanner exceeded wall-clock reservation')
        try:
            with self._database() as db:
                db.execute('BEGIN IMMEDIATE')
                db.execute('INSERT INTO scanner_executions VALUES(?,?,?,?)',(eid,operation,run_id,'reserved'))
                self._event(db,{'type':'scanner_execution_reserved','engagement_id':eid,'run_id':run_id,'operation_id':operation,'profile':policy['profile'],
                               'policy_sha256':hashlib.sha256(policy_raw).hexdigest(),'executable_sha256':policy['executable']['sha256']})
                db.commit()
            identity,context=selected_input(policy,info,self.state_root,guard,scope)
            binary=binary_bytes(policy['executable']['path'],policy['executable']['sha256']);guard()
            database_fd=None;database_identity=None
            if db_validator:
                database_fd,database_identity=db_validator(policy['database'],guard);fds.append(database_fd)
            with tempfile.TemporaryDirectory(prefix='native-',dir=self.state_root) as tmp:
                scratch=Path(tmp);source=scratch/'input';source.mkdir(mode=0o700);jail=scratch/'jail';jail.mkdir(mode=0o700)
                if policy['input']['kind']=='source':
                    with open_directory_nofollow(Path(policy['input']['repository'])) as origin:
                        for name,expected in identity['files'].items():
                            guard();raw=read_relative(origin,name)
                            require(hashlib.sha256(raw).hexdigest()==expected,'source changed while preparing immutable scanner input')
                            path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o400)
                else:
                    raw=_protected(Path(policy['input']['artifact_path']),524288,info,self.state_root)
                    require(hashlib.sha256(raw).hexdigest()==identity['artifact_sha256'],'SBOM changed before scanner launch')
                    (source/'artifact.json').write_bytes(raw);(source/'artifact.json').chmod(0o400)
                binary_fd=sealed_file('aegis-scanner',binary,True);fds.append(binary_fd)
                del binary
                config_fd=sealed_file('aegis-rules',config);fds.append(config_fd)
                output_fd=os.memfd_create('aegis-scanner-output',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);fds.append(output_fd)
                input_fd=os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(input_fd)
                extra={'database_fd':database_fd} if database_fd is not None else {}
                argv=launcher(policy['profile'],binary_fd,config_fd,input_fd,jail,policy['seconds'],source_kind=policy['input']['kind'],**extra)
                parent_pid=os.getpid()
                def death_signal():
                    if LIBC.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent_pid:os._exit(76)
                with self._database() as db:
                    db.execute("UPDATE scanner_executions SET status='launched' WHERE engagement_id=? AND operation_id=?",(eid,operation))
                    self._event(db,{'type':'scanner_execution_started','engagement_id':eid,'run_id':run_id,'profile':policy['profile'],
                                   'input_sha256':digest(identity),'configuration_sha256':policy['configuration']['sha256']})
                    db.commit()
                started_at=datetime.now(timezone.utc)
                worker=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd='/',
                                        env={'PATH':'/usr/bin:/bin'},pass_fds=(binary_fd,config_fd,input_fd)+(() if database_fd is None else (database_fd,)),start_new_session=True,preexec_fn=death_signal)
                totals={'stdout':0,'stderr':0};hashes={name:hashlib.sha256() for name in totals};head=b''
                with selectors.DefaultSelector() as selector:
                    for name in totals:
                        stream=getattr(worker,name);os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
                    while selector.get_map() or worker.poll() is None:
                        guard();require(os.fstat(output_fd).st_size<=524288,'scanner output exceeded byte bound')
                        for key,_ in selector.select(.1):
                            chunk=os.read(key.fileobj.fileno(),8192)
                            if not chunk:selector.unregister(key.fileobj);continue
                            name=key.data;totals[name]+=len(chunk);hashes[name].update(chunk)
                            require(totals[name]<=(524288 if name=='stdout' else 32768),'scanner output flood exceeded byte bound')
                            if name=='stdout':os.write(output_fd,chunk)
                            if name=='stderr' and len(head)<1024:head=(head+chunk)[:1024]
                exit_code=worker.wait(timeout=1)
                finished_at=datetime.now(timezone.utc)
                stats={'elapsed_ms':int((time.monotonic()-started)*1000),'exit_status':exit_code,
                       'started_at_utc':started_at.isoformat(),'finished_at_utc':finished_at.isoformat(),
                       'stdout_bytes':totals['stdout'],'stderr_bytes':totals['stderr'],
                       'stdout_sha256':hashes['stdout'].hexdigest(),'stderr_sha256':hashes['stderr'].hexdigest(),
                       'virtual_memory_limit_bytes':(1 if profile=='semgrep-core-v1.125.0' else 8)*1024**3,'writable_data_limit_bytes':512*1024**2,
                       'process_thread_limit':32 if profile=='semgrep-core-v1.125.0' else 64,
                       'cpu_limit_seconds':policy['seconds'],'scratch_limit_bytes':0 if profile=='trivy-sbom-v0.76.1' else 8*1024**2}
                os.lseek(output_fd,0,os.SEEK_SET);raw=os.read(output_fd,524289);partial_sha=hashlib.sha256(raw).hexdigest()
                require(exit_code==0 and b'"status":"NATIVE_OFFLINE_BOUNDARY_ENTERED"' in head.split(b'\n',1)[0],'native scanner failed or boundary receipt missing')
                require(0<len(raw)<=524288,'native scanner report empty or oversized')
                observed=report_observed_at(raw,profile,started_at,finished_at);name,version,schema=PROFILES[policy['profile']]
                admission={'schema_version':1,'configured':True,'engagement_id':eid,'detector':{'name':name,'version':version,'report_schema':schema},
                    'configuration':{'path':str(Path(info['report_directory'])/'runs'/run_id/'scanner-config.bin'),'sha256':policy['configuration']['sha256']},
                    'report_sha256':partial_sha,'observed_at_utc':observed,'max_age_seconds':3600,'input':policy['input'],
                    'allowed_rule_ids':policy['allowed_rule_ids'],'provenance':{'mode':'aegis_governed','producer':'aegis-native-offline-v1',
                    'attestation_path':None,'signature_path':None,'public_key_path':None,'execution_run_id':run_id},'database':database_identity}
                context['input_identity']=identity
                normalized=normalize(parse_report(raw,admission,context),admission,context)
                sanitized=canonical({'schema_version':1,'observations':[{k:v for k,v in item.items() if k!='fingerprint'} for item in normalized['observations']],
                                     'coverage':normalized['coverage']})
                admission['report_sha256']=hashlib.sha256(sanitized).hexdigest()
                again,_=selected_input(policy,info,self.state_root,guard,scope)
                if db_validator:
                    checked_fd,checked_identity=db_validator(policy['database'],guard);os.close(checked_fd)
                    require(checked_identity==database_identity,'vulnerability DB changed during execution')
                require(again==identity and policy_raw==_protected(policy_path,32768,info,self.state_root) and
                        config==_protected(Path(policy['configuration']['path']),32768,info,self.state_root),'scanner inputs changed during execution')
                guard()
                receipt=canonical({'admission':admission,'input_identity':identity,'original_report_sha256':partial_sha,
                        'original_report_bytes':len(raw),'profile':policy['profile'],'operation_id':operation,
                        'execution_policy_sha256':hashlib.sha256(policy_raw).hexdigest(),'executable_sha256':policy['executable']['sha256'],
                        'database_files':None if db_validator is None else policy['database']['files'],
                        'resources':stats,'network':'denied','builds':'unsupported','history':'unsupported'})
                artifacts={'scanner-execution.json':receipt,'scanner-report.json':sanitized,'scanner-config.bin':config}
                _write_artifacts(info,run_id,artifacts)
                with self._database() as db:
                    db.execute('BEGIN IMMEDIATE')
                    self._event(db,{'type':'scanner_execution_completed','engagement_id':eid,'run_id':run_id,
                                   'attestation':attestation(admission,identity),'artifacts':{k:hashlib.sha256(v).hexdigest() for k,v in artifacts.items()}})
                    db.execute("UPDATE runs SET status='completed',ended_utc=? WHERE run_id=? AND engagement_id=?",(datetime.now(timezone.utc).isoformat(),run_id,eid))
                    db.execute("UPDATE scanner_executions SET status='completed' WHERE engagement_id=? AND operation_id=?",(eid,operation));db.commit()
            result={'status':'SCANNER_EXECUTION_COMPLETED_UNVERIFIED','execution_run_id':run_id,'observations':len(normalized['observations'])}
        except BaseException:
            if worker is not None and worker.poll() is None:self._kill_worker(worker)
            if output_fd is not None:
                os.lseek(output_fd,0,os.SEEK_SET);partial_sha=hashlib.sha256(os.read(output_fd,524289)).hexdigest()
            stats.update(elapsed_ms=int((time.monotonic()-started)*1000),exit_status=None if worker is None else worker.poll())
            with self._database() as db:
                db.execute("UPDATE scanner_executions SET status='failed_requires_reconciliation' WHERE engagement_id=? AND operation_id=? AND run_id=?",(eid,operation,run_id))
                self._event(db,{'type':'scanner_execution_failed','engagement_id':eid,'run_id':run_id,'operation_id':operation,
                               'partial_output_sha256':partial_sha,'resources':stats});db.commit()
            self._finish(eid,run_id,'aborted','native scanner failed; raw output discarded; explicit reconciliation required')
            raise
        finally:
            for fd in fds:os.close(fd)
            if worker is not None:
                for stream in (worker.stdout,worker.stderr):
                    if stream is not None:stream.close()
        if import_result:result['import']=self.import_governed_report(run_id,expected_repository=expected_repository or
                            (Path(policy['input']['repository']) if policy['input']['kind']=='source' else None))
        return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('manifest','signature','trust','state-root','execution-policy'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        result=ScannerExecutionSupervisor(args.manifest,args.signature,args.trust,args.state_root).execute(args.execution_policy)
        print(json.dumps(result,sort_keys=True));return 0
    except (ExecutionDenied,OSError,ValueError,TypeError,KeyError,ImportError,RuntimeError,sqlite3.Error,subprocess.SubprocessError):
        print('SCANNER_EXECUTION_DENIED');return 2


if __name__=='__main__':raise SystemExit(main())
