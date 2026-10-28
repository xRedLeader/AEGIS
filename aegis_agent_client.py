#!/usr/bin/env python3
"""Offline AEGIS delegation issuer and signed, restricted Unix gateway client.

The offline grant signer is operator-controlled; never install its private key on
an agent host. The delegated private key is held by a constrained agent adapter,
not placed in model input. The gateway verifies both independently.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import sys

from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, Encoding, PublicFormat,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from aegis_reporting import canonical
from aegis_agent_gateway import GRANT_DOMAIN, REQUEST_DOMAIN, _decode, _b64
from aegis_supervisor import ExecutionDenied, deny, open_directory_nofollow


def _time(t):return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def signed_grant(signer:Ed25519PrivateKey, client:Ed25519PublicKey, *,
                 engagement_id:str, assessment_id:str, manifest_sha256:str,
                 assessment_policy_sha256:str, client_uid:int,
                 permissions=("snapshot","propose"), seconds=180):
    if not 1<=seconds<=900:deny("grant TTL invalid")
    now=datetime.now(timezone.utc)
    doc={"version":1,"grant_id":secrets.token_hex(16),"engagement_id":engagement_id,
         "assessment_id":assessment_id,"manifest_sha256":manifest_sha256,
         "assessment_policy_sha256":assessment_policy_sha256,
         "client_public_key_b64":base64.b64encode(client.public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)).decode(),
         "client_uid":client_uid,"permissions":list(permissions),
         "not_before_utc":_time(now-timedelta(seconds=2)),
         "expires_at_utc":_time(now+timedelta(seconds=seconds))}
    data=canonical(doc)
    return data, signer.sign(GRANT_DOMAIN+data)


def signed_request(client:Ed25519PrivateKey, grant:dict, operation:str,
                   *, step_id=None, expected_action=None, seconds=10):
    if operation not in ("snapshot","propose") or not 1<=seconds<=30:
        deny("invalid delegated request operation or lifetime")
    now=datetime.now(timezone.utc)
    doc={"version":1,"request_id":secrets.token_hex(16),
         "engagement_id":grant["engagement_id"],"assessment_id":grant["assessment_id"],
         "operation":operation,"step_id":step_id,"expected_action":expected_action,
         "not_before_utc":_time(now-timedelta(seconds=2)),
         "expires_at_utc":_time(now+timedelta(seconds=seconds))}
    data=canonical(doc)
    return data,client.sign(REQUEST_DOMAIN+data)


def envelope(grant:bytes, grant_sig:bytes, req:bytes, req_sig:bytes):
    return canonical({"grant_b64":base64.b64encode(grant).decode(),
        "grant_signature_b64":base64.b64encode(grant_sig).decode(),
        "request_b64":base64.b64encode(req).decode(),
        "request_signature_b64":base64.b64encode(req_sig).decode()})


def send(socket_path:str,payload:bytes,expected_service_uid:int):
    if not isinstance(payload,bytes) or len(payload)>16384:
        deny("invalid delegated client payload size")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(socket_path)
        if not hasattr(socket,"SO_PEERCRED"):deny("no OS peer credentials")
        import struct
        pid,uid,gid=struct.unpack("3i",conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=expected_service_uid:deny("untrusted delegation service UID")
        conn.sendall(payload+b"\n")
        data=b""
        while b"\n" not in data and len(data)<=4096:
            part=conn.recv(1024)
            if not part:break
            data+=part
        if not data.endswith(b"\n") or data.count(b"\n")!=1 or len(data)>4097:
            deny("invalid delegated service reply framing")
        return _decode(data[:-1],4096)


def _private_file(path:Path,max_bytes=8192):
    """Read a stable private key by no-follow directory-relative descriptors.

    lstat(path) followed by open(path) is a race: an attacker with write access
    to a key directory could replace a checked regular file with a symlink.
    Reject links, permission drift and size changes before parsing key bytes.
    """
    path = Path(path)
    if not path.is_absolute() or not 0 < max_bytes <= 8192:
        deny("private signing material requires a bounded absolute path")
    with open_directory_nofollow(path.parent) as parent:
        pst = os.fstat(parent)
        if pst.st_uid not in (0, os.geteuid()) or pst.st_mode & 0o022:
            deny("private key directory is not trusted")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid not in (0, os.geteuid()) or before.st_mode & 0o077 or
                not 0 < before.st_size <= max_bytes):
                deny("private signing material file must be private and bounded")
            data = os.read(fd, max_bytes + 1)
            after = os.fstat(fd)
            if (len(data) != before.st_size or
                    (before.st_dev, before.st_ino, before.st_size) !=
                    (after.st_dev, after.st_ino, after.st_size)):
                deny("private signing material changed during read")
            return data
        finally:
            os.close(fd)


def _exclusive_file(path,data):
    path=Path(path)
    p=path.parent.lstat()
    if not stat.S_ISDIR(p.st_mode) or p.st_mode & 0o077:deny("operator grant output directory is not private")
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    except BaseException:
        try:os.unlink(path)
        except OSError:pass
        raise


def main(argv=None):
    ap=argparse.ArgumentParser(description="Offline v2 delegated grant/client signer")
    cmds=ap.add_subparsers(dest='action',required=True)
    grant=cmds.add_parser('issue-grant',help='operator-only offline grant signing')
    for key in ('signer-key','client-public-key','engagement-id','assessment-id','manifest-sha256',
                'assessment-policy-sha256','client-uid','output'):
        grant.add_argument('--'+key,required=True)
    grant.add_argument('--seconds',type=int,default=180)
    request=cmds.add_parser('send',help='signed bounded request, no operator privileges')
    for key in ('socket','expected-service-uid','client-key','grant','grant-signature'):
        request.add_argument('--'+key,required=True)
    request.add_argument('--operation',choices=('snapshot','propose'),required=True)
    request.add_argument('--step-id');request.add_argument('--expected-action')
    args=ap.parse_args(argv)
    try:
        if args.action=='issue-grant':
            signer=load_pem_private_key(_private_file(Path(args.signer_key)),password=None)
            client=load_pem_public_key(Path(args.client_public_key).read_bytes())
            if not isinstance(signer,Ed25519PrivateKey) or not isinstance(client,Ed25519PublicKey):
                deny("invalid grant signing identity")
            data,sig=signed_grant(signer,client,engagement_id=args.engagement_id,
                assessment_id=args.assessment_id,manifest_sha256=args.manifest_sha256,
                assessment_policy_sha256=args.assessment_policy_sha256,
                client_uid=int(args.client_uid),seconds=args.seconds)
            _exclusive_file(Path(args.output),data)
            _exclusive_file(Path(args.output+'.sig'),sig)
            print("DELEGATION_ISSUED")
        else:
            key=load_pem_private_key(_private_file(Path(args.client_key)),password=None)
            if not isinstance(key,Ed25519PrivateKey):deny("invalid client key")
            raw=Path(args.grant).read_bytes()
            grant=_decode(raw,4096)
            sig=Path(args.grant_signature).read_bytes()
            req,rsig=signed_request(key,grant,args.operation,
                step_id=args.step_id,expected_action=args.expected_action)
            print(json.dumps(send(args.socket,envelope(raw,sig,req,rsig),int(args.expected_service_uid)),
                sort_keys=True,separators=(',',':')))
        return 0
    except (ExecutionDenied,OSError,ValueError,TypeError,KeyError):
        print("DELEGATED_CLIENT_DENIED",file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
