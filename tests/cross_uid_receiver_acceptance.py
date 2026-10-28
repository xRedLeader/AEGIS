#!/usr/bin/env python3
"""CI-only real Unix SO_PEERCRED integration across distinct non-root Linux UIDs.

Run as root solely to set up disposable separate service identities. The actual
receiver and sender never run as root. No actual AEGIS credentials are used.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import pwd
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def invoke(uid, gid, source, *args):
    def drop():
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    p = subprocess.run([sys.executable, '-c', source, *map(str,args)],
        preexec_fn=drop, cwd='/', env={'PATH':'/usr/bin:/bin'}, capture_output=True, text=True, timeout=6)
    return p


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--sender-uid',type=int,required=True)
    parser.add_argument('--sender-gid',type=int,required=True)
    args=parser.parse_args()
    if os.geteuid()!=0 or args.sender_uid==0:
        raise RuntimeError('root setup and an actual unprivileged sender required')
    uid=pwd.getpwnam('nobody').pw_uid
    assert uid!=args.sender_uid
    with tempfile.TemporaryDirectory(prefix='aegis-xuid-') as root_str:
        root=Path(root_str);os.chmod(root,0o755)
        sockdir=root/'sock';sockdir.mkdir();os.chown(sockdir,uid,args.sender_gid);os.chmod(sockdir,0o710)
        dbroot=root/'state';dbroot.mkdir();os.chown(dbroot,uid,args.sender_gid);os.chmod(dbroot,0o700)
        sock=sockdir/'receiver.sock'
        policy=root/'receiver.json'
        engagement='local-xuid-verification-001'
        cfg={'schema_version':1,'configured':True,'socket_path':str(sock),
            'state_root':str(dbroot),'shared_gid':args.sender_gid,
            'allowed_sender_uids':[args.sender_uid], 'allowed_engagement_ids':[engagement]}
        policy.write_text(json.dumps(cfg,sort_keys=True,separators=(',',':')))
        os.chown(policy,uid,args.sender_gid);os.chmod(policy,0o600)
        def drop_receiver():
            os.setgroups([]);os.setgid(args.sender_gid);os.setuid(uid)
        child=subprocess.Popen([sys.executable,'-u',str(ROOT/'aegis_notification_receiver.py'),
            '--policy',str(policy)],preexec_fn=drop_receiver,cwd='/',env={'PATH':'/usr/bin:/bin'},
            stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        try:
            for _ in range(160):
                if sock.is_socket():break
                if child.poll() is not None:raise RuntimeError('receiver failed early: '+child.stderr.read())
                time.sleep(.025)
            if not sock.is_socket():raise RuntimeError('receiver never bound socket')
            payload={'type':'aegis_assessment_v1','notice_id':'a'*64,'engagement_id':engagement,
                'source_run_id':'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
                'report_sha256':'b'*64, 'lead_count':1,
                'assessment_status':'limited_source_evidence_only','challenge':'c'*32}
            source=r'''
import json,socket,sys
sock=json.dumps(dict(json.loads(sys.argv[2])),sort_keys=True,separators=(',',':')).encode()+b'\n'
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
 c.settimeout(2)
 c.connect(sys.argv[1]);c.sendall(sock)
 try:answer=c.recv(512)
 except OSError:answer=b''
if sys.argv[3]=='ack':
 assert json.loads(answer)['challenge']==json.loads(sys.argv[2])['challenge'],repr(answer)
else:assert answer==b'',repr(answer)
'''
            for challenge in ('c'*32,'d'*32):
                payload['challenge']=challenge
                v=invoke(args.sender_uid,args.sender_gid,source,sock,json.dumps(payload),'ack')
                if v.returncode:raise AssertionError('separate-UID sender denied: '+v.stderr)
            # A privileged but NON-ALLOWLISTED local principal must not be accepted.
            # Test with receiver UID itself, which can traverse its own socket path.
            v=invoke(uid,args.sender_gid,source,sock,json.dumps(payload),'denied')
            if v.returncode:raise AssertionError('peer UID check bypass or test error: '+v.stderr)
            payload['report_sha256']='0'*64
            v=invoke(args.sender_uid,args.sender_gid,source,sock,json.dumps(payload),'denied')
            if v.returncode:raise AssertionError('conflicting duplicate was acked: '+v.stderr)
            with sqlite3.connect(str(dbroot/'received.sqlite3')) as con:
                row=con.execute('SELECT notice_id,report_sha256 FROM received').fetchall()
            assert row==[('a'*64,'b'*64)], row
            assert (sockdir.stat().st_mode & 0o777)==0o710
            assert (sock.stat().st_mode & 0o777)==0o660
            print('PASS: different unprivileged UIDs, authorized group socket, durable idempotent ACK, denied wrong UID/replay')
        finally:
            child.terminate()
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();child.wait()


if __name__=='__main__':main()
