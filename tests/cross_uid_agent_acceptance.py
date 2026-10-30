#!/usr/bin/env python3
"""CI-only distinct nonroot Unix UIDs: signed AEGIS v2 agent delegation.

Root is only the fixture organizer. The gateway and client execute as two
separate nonroot UIDs and share only a group-searchable socket directory.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]

SERVICE=r'''
import base64,json,os,sys,threading
from test_v20_delegation import DelegationTests
fixture=DelegationTests('test_signed_snapshot_is_structural_and_replay_protected')
fixture.setUp()
try:
 fixture.delegate_policy['allowed_peer_uids']=[int(sys.argv[1])]
 fixture.delegate_policy['shared_gid']=int(sys.argv[2]);fixture.save_delegate()
 # The parent fixture path is searchable by the delegated client's group,
 # but remains opaque; no private key or AEGIS state is readable.
 os.chmod(fixture.fx.fx.p,0o710)
 os.chmod(fixture.socket_dir,0o710)
 packet=fixture.signed(uid=int(sys.argv[1]))
 stop=threading.Event()
 worker=threading.Thread(target=fixture.gateway.serve,kwargs={'stop_event':stop},daemon=True)
 worker.start()
 for _ in range(100):
  if fixture.agent_socket.is_socket():break
  import time;time.sleep(.025)
 else:raise RuntimeError('gateway not ready')
 print(json.dumps({'socket':str(fixture.agent_socket),'packet':base64.b64encode(packet).decode()}),flush=True)
 sys.stdin.readline()
 stop.set();worker.join(3)
 assert not worker.is_alive(), 'gateway not stopped'
finally:fixture.doCleanups()
'''
CLIENT=r'''
import base64,json,socket,sys
path=sys.argv[1]
payload=base64.b64decode(sys.argv[2])
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
 c.settimeout(4);c.connect(path);c.sendall(payload+b'\n')
 out=b''
 while b'\n' not in out and len(out)<4096:
  part=c.recv(4096)
  if not part:break
  out+=part
assert out.endswith(b'\n'),repr(out)
status=json.loads(out)['status']
assert status==sys.argv[3],(status,sys.argv[3])
'''


def drop(uid,gid):
    def configure():
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    return configure


def main():
    args=argparse.ArgumentParser()
    args.add_argument('--sender-uid',type=int,required=True)
    args.add_argument('--sender-gid',type=int,required=True)
    a=args.parse_args()
    if os.geteuid()!=0 or a.sender_uid==0:raise RuntimeError('root fixture and non-root client required')
    service_uid=pwd.getpwnam('nobody').pw_uid
    if service_uid==a.sender_uid:raise RuntimeError('service and agent identities must differ')
    env={'PATH':'/usr/bin:/bin','PYTHONPATH':str(ROOT)+':'+str(ROOT/'tests'),
         'PYTHONDONTWRITEBYTECODE':'1'}
    service=subprocess.Popen([sys.executable,'-u','-c',SERVICE,str(a.sender_uid),str(a.sender_gid)],
         preexec_fn=drop(service_uid,a.sender_gid),cwd='/',env=env,
         stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        from concurrent.futures import ThreadPoolExecutor,TimeoutError
        with ThreadPoolExecutor(max_workers=1) as pool:
            f=pool.submit(service.stdout.readline)
            try:line=f.result(timeout=8)
            except TimeoutError:raise RuntimeError('gateway did not start')
        if not line:raise RuntimeError('gateway setup failed: '+service.stderr.read())
        doc=json.loads(line)
        path=doc['socket'];packet=doc['packet']
        assert Path(path).is_socket()
        assert Path(path).stat().st_mode & 0o777 == 0o660
        assert Path(path).parent.stat().st_mode & 0o777 == 0o710
        for uid,gid,expect in [(a.sender_uid,a.sender_gid,'DELEGATED_WORKFLOW_SNAPSHOT'),
                               (a.sender_uid,a.sender_gid,'DELEGATED_REQUEST_DENIED'),
                               (service_uid,a.sender_gid,'DELEGATED_REQUEST_DENIED')]:
            proc=subprocess.run([sys.executable,'-c',CLIENT,path,packet,expect],
                preexec_fn=drop(uid,gid),cwd='/',env=env,capture_output=True,text=True,timeout=7)
            if proc.returncode:
                raise AssertionError(f'UID {uid}: {proc.stderr}')
        print('PASS: separate unprivileged service/client UIDs; private signer; exact signed grant, replay and wrong-peer rejection')
    finally:
        if service.poll() is None:
            try:service.stdin.write('\n');service.stdin.flush();service.wait(timeout=4)
            except (BrokenPipeError,subprocess.TimeoutExpired):service.kill();service.wait()
        if service.returncode:
            raise AssertionError('gateway exit failure: '+service.stderr.read())

if __name__=='__main__':main()
