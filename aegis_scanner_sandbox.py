"""Distinct native offline scanner boundary; never relaxes the Python worker profile."""
from __future__ import annotations
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import resource
import stat
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import aegis_sandbox as kernel

PROFILES={"gitleaks-dir-v8.24.3":("gitleaks","8.24.3","gitleaks-json-v8")}


def launch(profile, binary_fd, config_fd, input_fd, jail, seconds, source_kind="source", broker_fd=None):
    if profile not in PROFILES or source_kind!="source" or broker_fd is not None:
        raise kernel.SandboxFailure("unsupported native scanner profile or network capability")
    baseline=','.join(str(os.stat('/proc/self/ns/'+name).st_ino) for name in ('user','mnt','net','pid'))
    return ['/usr/bin/unshare','--user','--map-root-user','--mount','--net','--pid','--fork','--kill-child','--propagation','private','--',
            '/usr/bin/python3','-I','-S',str(Path(__file__).resolve()),'--profile',profile,
            '--binary-fd',str(binary_fd),'--config-fd',str(config_fd),'--input-fd',str(input_fd),
            '--jail',str(jail),'--seconds',str(seconds),'--host-uid',str(os.geteuid()),'--parent-namespaces',baseline]


def _seccomp(sec,extra_syscalls=(),readonly_shared_mappings=False):
    """Positive native Go profile: threads allowed, new processes/network denied."""
    sec.seccomp_init.argtypes=[ctypes.c_uint32];sec.seccomp_init.restype=ctypes.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p];sec.seccomp_syscall_resolve_name.restype=ctypes.c_int
    sec.seccomp_rule_add.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint]
    sec.seccomp_load.argtypes=[ctypes.c_void_p];sec.seccomp_release.argtypes=[ctypes.c_void_p]
    class Compare(ctypes.Structure):
        _fields_=[('arg',ctypes.c_uint32),('op',ctypes.c_uint32),('a',ctypes.c_uint64),('b',ctypes.c_uint64)]
    sec.seccomp_rule_add_array.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Compare)]
    ctx=sec.seccomp_init(kernel.SCMP_ACT_ERRNO_EPERM)
    if not ctx:raise kernel.SandboxFailure('native seccomp initialization failed')
    try:
        extra=('poll','ppoll','select','pselect6','epoll_create','epoll_create1','epoll_ctl','epoll_wait','epoll_pwait',
               'epoll_pwait2','eventfd','eventfd2','pipe','pipe2','ftruncate','fsync','fdatasync','sched_getaffinity',
               'getcpu','tgkill','tkill','setitimer','getitimer','umask','mkdir','mkdirat','unlink','unlinkat','rename','renameat','renameat2')
        for name in (*kernel.WORKER_SYSCALL_ALLOWLIST,*extra,*extra_syscalls):
            if name=='mmap':continue
            number=sec.seccomp_syscall_resolve_name(name.encode())
            if number>=0 and sec.seccomp_rule_add(ctx,0x7fff0000,number,0)!=0:
                raise kernel.SandboxFailure('native syscall rule failed')
        # Data memory stays within RLIMIT_DATA. Deny shared/growing-stack mmap
        # alternatives that would evade its private writable mapping accounting.
        mmap_check=Compare(3,7,0x10f,2)  # MAP_TYPE|MAP_GROWSDOWN == MAP_PRIVATE
        number=sec.seccomp_syscall_resolve_name(b'mmap')
        if number<0 or sec.seccomp_rule_add_array(ctx,0x7fff0000,number,1,ctypes.byref(mmap_check))!=0:
            raise kernel.SandboxFailure('native memory mapping restriction failed')
        if readonly_shared_mappings:
            # BoltDB uses a read-only shared FILE mapping. Anonymous/shared
            # writable mappings remain forbidden; immutable DB mounts also
            # prevent upgrading this descriptor's mapping to writable later.
            checks=(Compare*2)(Compare(3,7,0x12f,1),Compare(2,7,2,0))
            if sec.seccomp_rule_add_array(ctx,0x7fff0000,number,2,checks)!=0:
                raise kernel.SandboxFailure('read-only database mapping restriction failed')
        # clone is only a same-process thread; no fork/vfork/clone3 or namespaces.
        checks=Compare(0,7,0x7e030080,0x00010000)
        number=sec.seccomp_syscall_resolve_name(b'clone')
        if number<0 or sec.seccomp_rule_add_array(ctx,0x7fff0000,number,1,ctypes.byref(checks))!=0:
            raise kernel.SandboxFailure('thread restriction failed')
        # Only close-on-exec and nonblocking descriptor flags, not device ioctls.
        number=sec.seccomp_syscall_resolve_name(b'ioctl')
        for operation in (0x5451,0x5421):
            check=Compare(1,4,operation,0)
            if number<0 or sec.seccomp_rule_add_array(ctx,0x7fff0000,number,1,ctypes.byref(check))!=0:
                raise kernel.SandboxFailure('native ioctl restriction failed')
        if sec.seccomp_load(ctx)!=0:raise kernel.SandboxFailure('native seccomp load failed')
    finally:sec.seccomp_release(ctx)


def _bind_fd(fd,target,readonly=True,directory=False):
    before=os.fstat(fd)
    if directory:target.mkdir(mode=0o755)
    else:target.touch(mode=0o600)
    source=os.readlink('/proc/self/fd/'+str(fd))
    if not source.startswith('/') or source.endswith(' (deleted)'):
        raise kernel.SandboxFailure('named scanner capability has no stable path')
    kernel._mount(source,target,None,kernel.MS_BIND)
    after=target.stat()
    if (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino):raise kernel.SandboxFailure('scanner capability changed')
    flags=kernel.MS_BIND|kernel.MS_REMOUNT|kernel.MS_NOSUID|kernel.MS_NODEV
    if readonly:flags|=kernel.MS_RDONLY
    if directory or target.name!='scanner':flags|=kernel.MS_NOEXEC
    kernel._mount(None,target,None,flags)


def _setup(args):
    if args.profile not in PROFILES or not 1<=args.seconds<=120 or args.host_uid<=0 or os.geteuid()!=0:
        raise kernel.SandboxFailure('native launch scope invalid')
    baseline=args.parent_namespaces.split(',')
    if len(baseline)!=4 or not all(x.isdigit() for x in baseline):raise kernel.SandboxFailure('namespace baseline missing')
    for name,old in zip(('user','mnt','net','pid'),baseline):
        if os.stat('/proc/self/ns/'+name).st_ino==int(old):raise kernel.SandboxFailure('native namespace unchanged')
    if Path('/proc/self/uid_map').read_text().split()!=['0',str(args.host_uid),'1']:
        raise kernel.SandboxFailure('native UID mapping invalid')
    for fd in (args.binary_fd,args.config_fd):
        if fd<3 or not stat.S_ISREG(os.fstat(fd).st_mode):raise kernel.SandboxFailure('native file capability invalid')
    if args.input_fd<3 or not stat.S_ISDIR(os.fstat(args.input_fd).st_mode):raise kernel.SandboxFailure('native source capability invalid')
    jail=Path(args.jail)
    if not jail.is_absolute() or jail.is_symlink() or not jail.is_dir() or jail.stat().st_mode&0o077:
        raise kernel.SandboxFailure('native private jail invalid')
    sec=ctypes.CDLL('libseccomp.so.2',use_errno=True)
    kernel._mount(None,Path('/'),None,kernel.MS_REC|kernel.MS_PRIVATE)
    kernel._mount('tmpfs',jail,'tmpfs',kernel.MS_NOSUID|kernel.MS_NODEV,'size=64m,mode=0700')
    # Linux refuses bind mounts of anonymous memfds. Copy their sealed bytes
    # into this private in-memory root, then freeze it before native execution.
    import fcntl
    for fd,name,maximum,mode in ((args.binary_fd,'scanner',60*1024**2,0o500),(args.config_fd,'rules',32768,0o400)):
        seals=fcntl.fcntl(fd,fcntl.F_GET_SEALS)
        needed=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK
        if seals&needed!=needed or os.fstat(fd).st_size>maximum:raise kernel.SandboxFailure('unsealed or oversized scanner capability')
        os.lseek(fd,0,os.SEEK_SET)
        with open(jail/name,'wb') as stream:
            while chunk:=os.read(fd,65536):stream.write(chunk)
        (jail/name).chmod(mode)
    _bind_fd(args.input_fd,jail/'repo',directory=True)
    (jail/'tmp').mkdir(mode=0o700)
    kernel._mount('tmpfs',jail/'tmp','tmpfs',kernel.MS_NOSUID|kernel.MS_NODEV|kernel.MS_NOEXEC,'size=8m,mode=0700')
    kernel._mount(None,jail,None,kernel.MS_REMOUNT|kernel.MS_RDONLY|kernel.MS_NOSUID|kernel.MS_NODEV)
    for name in os.listdir('/proc/self/fd'):
        fd=int(name)
        if fd>2:
            try:os.close(fd)
            except OSError as exc:
                if exc.errno!=errno.EBADF:raise
    os.chroot(jail);os.chdir('/repo')
    resource.setrlimit(resource.RLIMIT_CPU,(args.seconds,args.seconds+1))
    # Gitleaks' reviewed RE2/Wasm runtime reserves 4GiB PROT_NONE without
    # committing it; writable data has a distinct much smaller hard limit.
    resource.setrlimit(resource.RLIMIT_AS,(8*1024**3,8*1024**3))
    resource.setrlimit(resource.RLIMIT_DATA,(512*1024**2,512*1024**2))
    resource.setrlimit(resource.RLIMIT_STACK,(8*1024**2,8*1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE,(524288,524288))
    resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    resource.setrlimit(resource.RLIMIT_NPROC,(64,64))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    lib=kernel._libc()
    if lib.prctl(kernel.PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0:raise kernel.SandboxFailure('native privilege lock failed')
    kernel._drop_capabilities(lib);_seccomp(sec)
    os.write(2,b'{"status":"NATIVE_OFFLINE_BOUNDARY_ENTERED","namespaces":4,"network":"denied","capabilities":"none","seccomp":"default_deny"}\n')
    argv=['/scanner','dir','.','--config','/rules','--no-banner','--no-color','--redact=100',
          '--report-format=json','--report-path=-','--exit-code=0','--max-target-megabytes=1','--log-level=error']
    os.execve('/scanner',argv,{'PATH':'/nonexistent','HOME':'/tmp','TMPDIR':'/tmp','GOMAXPROCS':'2','GOMEMLIMIT':'256MiB'})


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',required=True);parser.add_argument('--jail',required=True)
    for name in ('binary-fd','config-fd','input-fd','host-uid','seconds'):parser.add_argument('--'+name,type=int,required=True)
    parser.add_argument('--parent-namespaces',required=True)
    try:_setup(parser.parse_args(argv))
    except kernel.SandboxFailure as exc:
        print('NATIVE_SCANNER_BOUNDARY_DENIED: '+str(exc),file=sys.stderr);return 76
    except (OSError,ValueError) as exc:
        print('NATIVE_SCANNER_BOUNDARY_DENIED: '+type(exc).__name__+' errno='+str(getattr(exc,'errno',None)),file=sys.stderr);return 76
    return 0


if __name__=='__main__':raise SystemExit(main())
