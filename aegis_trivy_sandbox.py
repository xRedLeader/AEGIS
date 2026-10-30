"""Pinned offline Trivy SBOM profile; prepared vulnerability DB is read-only."""
from __future__ import annotations
import argparse
import ctypes
from datetime import datetime,timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import stat
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import aegis_sandbox as kernel
from aegis_scanner_sandbox import _bind_fd,_seccomp

PROFILE='trivy-sbom-v0.76.1'
BINARY_SHA256='d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83'


def validate_database(value,guard):
    from aegis_audit_contract import fields,canonical,require
    from aegis_scanner_contract import sha256,observed_time
    from aegis_supervisor import open_directory_nofollow
    fields(value,{'path','files','built_at_utc','max_age_seconds'})
    fields(value['files'],{'trivy.db','metadata.json'})
    for digest in value['files'].values():sha256(digest)
    observed_time(value['built_at_utc'],value['max_age_seconds'])
    folder=Path(value['path']);require(folder.is_absolute() and str(folder.resolve())==str(folder),'DB path must be absolute and nonsymlink')
    for path in (folder,*folder.parents):
        st=path.stat();require(st.st_uid==0 and not st.st_mode&0o022,'prepared DB requires root-protected custody')
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        require(set(os.listdir(fd))=={'trivy.db','metadata.json'},'prepared DB must contain exactly the pinned database and metadata')
        for name,expected in value['files'].items():
            file=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
            try:
                before=os.fstat(file)
                require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and not before.st_mode&0o022 and
                        0<before.st_size<=(2*1024**3 if name=='trivy.db' else 4096),'prepared DB file custody or size invalid')
                digest=hashlib.sha256();metadata=b''
                while chunk:=os.read(file,16*1024**2):
                    guard();digest.update(chunk)
                    if name=='metadata.json':metadata+=chunk
                after=os.fstat(file)
                require((before.st_ino,before.st_dev,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                        (after.st_ino,after.st_dev,after.st_size,after.st_mtime_ns,after.st_ctime_ns) and digest.hexdigest()==expected,
                        'prepared DB changed or differs from pin')
                if name=='metadata.json':
                    doc=json.loads(metadata)
                    require(isinstance(doc.get('UpdatedAt'),str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z',doc['UpdatedAt']),
                            'DB build time must be a UTC timestamp')
                    stamp=doc['UpdatedAt'][:19]+'Z'
                    require(doc['Version']==2 and stamp==value['built_at_utc'],'DB schema/build timestamp differs from prepared metadata')
            finally:os.close(file)
        return fd,{'sha256':hashlib.sha256(canonical(value['files'])).hexdigest(),'built_at_utc':value['built_at_utc'],'max_age_seconds':value['max_age_seconds']}
    except BaseException:os.close(fd);raise


def validate_rules(raw,allowed):
    if raw!=b'{}':raise kernel.SandboxFailure('Trivy profile requires empty canonical JSON configuration; all flags are fixed')


def launch(profile,binary_fd,config_fd,input_fd,jail,seconds,source_kind='sbom',broker_fd=None,database_fd=None):
    if profile!=PROFILE or source_kind!='sbom' or broker_fd is not None or database_fd is None:
        raise kernel.SandboxFailure('unsupported Trivy launch capability')
    baseline=','.join(str(os.stat('/proc/self/ns/'+n).st_ino) for n in ('user','mnt','net','pid'))
    return ['/usr/bin/unshare','--user','--map-root-user','--mount','--net','--pid','--fork','--kill-child','--propagation','private','--',
            '/usr/bin/python3','-I','-S',str(Path(__file__).resolve()),'--binary-fd',str(binary_fd),'--config-fd',str(config_fd),
            '--input-fd',str(input_fd),'--database-fd',str(database_fd),'--jail',str(jail),'--seconds',str(seconds),
            '--host-uid',str(os.geteuid()),'--parent-namespaces',baseline]


def _setup(args):
    if args.host_uid<=0 or os.geteuid()!=0 or not 1<=args.seconds<=120:raise kernel.SandboxFailure('invalid Trivy identity/runtime')
    baseline=args.parent_namespaces.split(',')
    if len(baseline)!=4 or not all(x.isdigit() for x in baseline):raise kernel.SandboxFailure('missing Trivy namespace baseline')
    for name,old in zip(('user','mnt','net','pid'),baseline):
        if os.stat('/proc/self/ns/'+name).st_ino==int(old):raise kernel.SandboxFailure('Trivy namespace unchanged')
    if Path('/proc/self/uid_map').read_text().split()!=['0',str(args.host_uid),'1']:raise kernel.SandboxFailure('Trivy UID mapping invalid')
    jail=Path(args.jail)
    if not jail.is_absolute() or jail.is_symlink() or not jail.is_dir() or jail.stat().st_mode&0o077:raise kernel.SandboxFailure('private Trivy jail required')
    sec=ctypes.CDLL('libseccomp.so.2',use_errno=True)
    kernel._mount(None,Path('/'),None,kernel.MS_REC|kernel.MS_PRIVATE)
    kernel._mount('tmpfs',jail,'tmpfs',kernel.MS_NOSUID|kernel.MS_NODEV,'size=256m,mode=0700')
    for fd,name,maximum,mode in ((args.binary_fd,'scanner',224*1024**2,0o500),(args.config_fd,'rules',32768,0o400)):
        needed=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK
        if fd<3 or not stat.S_ISREG(os.fstat(fd).st_mode) or fcntl.fcntl(fd,fcntl.F_GET_SEALS)&needed!=needed or os.fstat(fd).st_size>maximum:
            raise kernel.SandboxFailure('Trivy capability is unsealed or oversized')
        os.lseek(fd,0,os.SEEK_SET)
        with open(jail/name,'wb') as stream:
            while chunk:=os.read(fd,65536):stream.write(chunk)
        (jail/name).chmod(mode)
    if (jail/'rules').read_bytes()!=b'{}':raise kernel.SandboxFailure('unreviewed Trivy configuration')
    for fd in (args.input_fd,args.database_fd):
        if fd<3 or not stat.S_ISDIR(os.fstat(fd).st_mode):raise kernel.SandboxFailure('Trivy directory capability invalid')
    _bind_fd(args.input_fd,jail/'repo',directory=True)
    (jail/'cache').mkdir();_bind_fd(args.database_fd,jail/'cache/db',directory=True)
    # This SBOM-only profile needs no writable files. Keeping scratch read-only
    # also prevents upgrading a shared scratch mapping through mprotect after
    # the narrowly allowed read-only BoltDB mmap operation.
    (jail/'tmp').mkdir();kernel._mount('tmpfs',jail/'tmp','tmpfs',kernel.MS_RDONLY|kernel.MS_NOSUID|kernel.MS_NODEV|kernel.MS_NOEXEC,'size=8m,mode=0700')
    kernel._mount(None,jail,None,kernel.MS_REMOUNT|kernel.MS_RDONLY|kernel.MS_NOSUID|kernel.MS_NODEV)
    for name in os.listdir('/proc/self/fd'):
        if int(name)>2:
            try:os.close(int(name))
            except OSError:pass
    os.chroot(jail);os.chdir('/repo')
    for kind,soft,hard in ((resource.RLIMIT_CPU,args.seconds,args.seconds+1),(resource.RLIMIT_AS,8*1024**3,8*1024**3),
                          (resource.RLIMIT_DATA,512*1024**2,512*1024**2),(resource.RLIMIT_STACK,8*1024**2,8*1024**2),
                          (resource.RLIMIT_FSIZE,524288,524288),(resource.RLIMIT_NOFILE,64,64),(resource.RLIMIT_NPROC,64,64),(resource.RLIMIT_CORE,0,0)):
        resource.setrlimit(kind,(soft,hard))
    lib=kernel._libc()
    if lib.prctl(kernel.PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0:raise kernel.SandboxFailure('Trivy privilege lock failed')
    kernel._drop_capabilities(lib);_seccomp(sec,('flock','fadvise64'),readonly_shared_mappings=True)
    os.write(2,b'{"status":"NATIVE_OFFLINE_BOUNDARY_ENTERED","profile":"trivy-sbom-v0.76.1","network":"denied","database":"readonly"}\n')
    argv=['/scanner','sbom','/repo/artifact.json','--config','/rules','--cache-dir','/cache','--cache-backend','memory',
          '--format','json','--quiet','--exit-code','0','--scanners','vuln','--ignorefile','',
          '--offline-scan','--skip-db-update','--skip-java-db-update','--skip-version-check','--skip-vex-repo-update','--disable-telemetry',
          '--timeout',str(args.seconds)+'s']
    os.execve('/scanner',argv,{'PATH':'/nonexistent','HOME':'/tmp','TMPDIR':'/tmp','GOMAXPROCS':'2','GOMEMLIMIT':'256MiB'})


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('binary-fd','config-fd','input-fd','database-fd','seconds','host-uid'):parser.add_argument('--'+name,type=int,required=True)
    parser.add_argument('--jail',required=True);parser.add_argument('--parent-namespaces',required=True)
    try:_setup(parser.parse_args(argv))
    except kernel.SandboxFailure as exc:print('TRIVY_BOUNDARY_DENIED: '+str(exc),file=sys.stderr);return 76
    except (OSError,ValueError) as exc:print('TRIVY_BOUNDARY_DENIED: '+type(exc).__name__,file=sys.stderr);return 76
    return 0


if __name__=='__main__':raise SystemExit(main())
