#!/usr/bin/env python3
"""Provider-neutral v2 model-output adapter; the model receives no signing key.

Only a fixed, one-shot JSON decision is accepted from stdin. The operator-owned
adapter holds a narrow delegated client key and sends a short-lived signed
request to the separately authenticated AEGIS delegation service. The service,
not this adapter or a prompt, authorizes the selected next workflow action.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from aegis_agent_gateway import _decode
from aegis_agent_client import _private_file, signed_request, envelope, send
from aegis_reporting import canonical
from aegis_supervisor import ExecutionDenied, deny

MAX_MODEL = 768
ACTIONS=frozenset({"source_review","source_audit","dependency_intelligence","local_contract",
    "http_metadata","report","admit_report","investigate","progress_investigation",
    "remediation_retest","notify"})


def parse_model_decision(raw:bytes):
    if not isinstance(raw,bytes) or not 0<len(raw)<=MAX_MODEL:
        deny("model proposal is unbounded")
    try:
        def unique(pairs):
            obj={}
            for key,value in pairs:
                if key in obj:raise ValueError("duplicate model proposal field")
                obj[key]=value
            return obj
        obj=json.loads(raw,object_pairs_hook=unique,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite number")))
    except (ValueError,UnicodeError,TypeError,RecursionError) as exc:
        raise ExecutionDenied("model proposal is not a supported JSON object") from exc
    if not isinstance(obj,dict):deny("model decision must be a JSON object")
    if obj=={"operation":"snapshot"}:
        return "snapshot",None,None
    if (set(obj)!={"operation","step_id","expected_action"} or obj.get("operation")!="propose" or
        not isinstance(obj["step_id"],str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}",obj["step_id"]) or
        obj["expected_action"] not in ACTIONS):
        deny("model proposal may only name an approved fixed action")
    return "propose",obj["step_id"],obj["expected_action"]


def run(*,model_output:bytes,grant_bytes:bytes,grant_signature:bytes,
        client_key:Ed25519PrivateKey,socket_path:str,expected_service_uid:int):
    operation,step_id,expected_action=parse_model_decision(model_output)
    grant=_decode(grant_bytes,4096)
    req,sig=signed_request(client_key,grant,operation,step_id=step_id,
                           expected_action=expected_action)
    return send(socket_path,envelope(grant_bytes,grant_signature,req,sig),expected_service_uid)


def main(argv=None):
    ap=argparse.ArgumentParser(description="One-shot bounded AEGIS model decision adapter")
    for name in ("client-key","grant","grant-signature","socket","expected-service-uid"):
        ap.add_argument("--"+name,required=True)
    a=ap.parse_args(argv)
    try:
        data=sys.stdin.buffer.read(MAX_MODEL+1)
        key=load_pem_private_key(_private_file(Path(a.client_key)),password=None)
        if not isinstance(key,Ed25519PrivateKey):deny("client signing key must be Ed25519")
        outcome=run(model_output=data,grant_bytes=Path(a.grant).read_bytes(),
            grant_signature=Path(a.grant_signature).read_bytes(),client_key=key,
            socket_path=a.socket,expected_service_uid=int(a.expected_service_uid))
        print(canonical(outcome).decode("ascii"))
        return 0 if outcome.get("status") in ("DELEGATED_WORKFLOW_SNAPSHOT","DELEGATED_STEP_COMPLETED") else 2
    except (ExecutionDenied,OSError,ValueError,TypeError,KeyError):
        print("MODEL_DELEGATION_DENIED",file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
