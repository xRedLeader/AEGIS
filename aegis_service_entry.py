"""Fixed installed service entry point; no model-selected module or command."""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import threading

# -I intentionally omits script paths; this root-owned installation is explicit.
sys.path.insert(0,str(Path(__file__).resolve().parent))
from aegis_install import config, release_path, source_files, protected_parents
from aegis_audit_contract import canonical, decode, require, read_relative
from aegis_supervisor import ExecutionDenied, open_directory_nofollow


def installed_config(path, role):
    path=Path(path)
    protected_parents(path.parent)
    with open_directory_nofollow(path.parent) as parent:
        raw=read_relative(parent,path.name,16384)
    require(path.stat().st_uid==0 and not path.stat().st_mode & 0o022,"installed configuration must remain root protected")
    cfg=config(decode(raw,16384))
    require(cfg["configured"] and canonical(cfg)==raw,"installed configuration is disabled or noncanonical")
    require(path==Path(cfg["policy_root"])/"install.json" and Path(__file__).resolve().parent==release_path(cfg),
            "service is not running the selected installed release")
    require(os.geteuid()!=0,"service cannot run as root")
    identity="operator" if role in {"gateway","provider"} else role
    actor=cfg["accounts"][identity]
    require(os.geteuid()==actor["uid"] and os.getegid()==actor["gid"],"effective service identity mismatch")
    names={"gateway":["gateway","receiver"],"receiver":["receiver"],"agent":["gateway"],"provider":["receiver"]}[role]
    expected={cfg["socket_groups"][name]["gid"] for name in names}
    require(expected <= set(os.getgroups()) and set(os.getgroups()) <= expected|{actor["gid"]},"unexpected service supplementary groups")
    for value in (path,release_path(cfg),Path(cfg["python"]).parent.parent):
        require(os.statvfs(value).f_flag & os.ST_RDONLY,"service policy, code and runtime must be mounted read-only")
    expected_marker=canonical({"source_commit":cfg["source_commit"],"configuration_sha256":hashlib.sha256(raw).hexdigest()})
    for name in (["enabled","provider-enabled"] if role=="provider" else ["enabled"]):
        marker=Path(cfg["policy_root"])/name
        require(marker.lstat().st_uid==0 and not marker.lstat().st_mode & 0o022,"activation marker must remain root protected")
    with open_directory_nofollow(Path(cfg["policy_root"])) as parent:
        require(read_relative(parent,"enabled",4096)==expected_marker,"installation enable record does not match configuration")
        if role=="provider":require(read_relative(parent,"provider-enabled",4096)==expected_marker,"provider needs its own operator enable record")
    source_files(release_path(cfg),cfg["source_manifest_sha256"])
    return cfg


def prepare_socket(path, uid, gid):
    """A crashed listener's socket is removable only after refusing a live peer."""
    path=Path(path)
    with open_directory_nofollow(path.parent) as parent:
        st=os.fstat(parent)
        require(st.st_uid==uid and st.st_gid==gid and stat.S_IMODE(st.st_mode)==0o710,"socket directory custody mismatch")
        try:before=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:return
        require(stat.S_ISSOCK(before.st_mode) and before.st_uid==uid and before.st_gid==gid and
                stat.S_IMODE(before.st_mode)==0o660,"refusing to remove an unexpected socket artifact")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(.2)
            try:client.connect(str(path))
            except OSError as exc:
                require(exc.errno==errno.ECONNREFUSED,"cannot prove listener is stopped")
            else:raise ExecutionDenied("listener already active")
        after=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        require((before.st_ino,before.st_dev)==(after.st_ino,after.st_dev),"stale socket changed during recovery")
        os.unlink(path.name,dir_fd=parent)


def execute(cfg, role, stop):
    policy=Path(cfg["policy_root"])
    if role=="gateway":
        from aegis_integrated_assessment import IntegratedAssessment
        from aegis_agent_gateway import DelegatedAssessmentService
        folder=policy/"operator"
        controller=IntegratedAssessment(folder/"scope.yaml",folder/"scope.sig",folder/"trust.json",
                                        Path(cfg["state_root"]),folder/"assessment.json")
        gateway=DelegatedAssessmentService(controller,folder/"delegation.json")
        info,_,_=controller._admit()
        actual,_,path=gateway._policy(info)
        require(str(path)==cfg["run_root"]+"/gateway/agent.sock" and
                actual["shared_gid"]==cfg["socket_groups"]["gateway"]["gid"] and
                actual["allowed_peer_uids"]==[cfg["accounts"]["agent"]["uid"]],"gateway policy differs from installed socket/peer")
        prepare_socket(path,os.geteuid(),actual["shared_gid"])
        gateway.serve(stop_event=stop)
    elif role=="receiver":
        from aegis_notification_receiver import DurableReceiver
        receiver=DurableReceiver(policy/"receiver"/"receiver.json")
        actual=receiver.policy
        require(actual["socket_path"]==cfg["run_root"]+"/receiver/receiver.sock" and
                actual["state_root"]==cfg["receiver_state_root"] and
                actual["shared_gid"]==cfg["socket_groups"]["receiver"]["gid"] and
                actual["allowed_sender_uids"]==[cfg["accounts"]["operator"]["uid"]],"receiver policy differs from installed identity")
        prepare_socket(actual["socket_path"],os.geteuid(),actual["shared_gid"])
        receiver.serve(stop_event=stop)
    elif role=="agent":
        from aegis_agent_client import _private_file
        from aegis_model_adapter import run, MAX_MODEL
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        folder=policy/"agent"
        key=load_pem_private_key(_private_file(folder/"client.pem"),password=None)
        require(isinstance(key,Ed25519PrivateKey),"agent client key must be Ed25519")
        result=run(model_output=_private_file(Path(cfg["agent_state_root"])/"decision.json",MAX_MODEL),
                   grant_bytes=_private_file(folder/"grant.json"),grant_signature=_private_file(folder/"grant.sig"),
                   client_key=key,socket_path=cfg["run_root"]+"/gateway/agent.sock",
                   expected_service_uid=cfg["accounts"]["operator"]["uid"])
        require(result.get("status") in {"DELEGATED_WORKFLOW_SNAPSHOT","DELEGATED_STEP_COMPLETED"},"delegated operation was denied")
        print(canonical(result).decode())
    else:
        from aegis_provider_runner import main
        folder=policy/"operator"
        return main(["--manifest",str(folder/"scope.yaml"),"--signature",str(folder/"scope.sig"),
                     "--runner-policy",str(folder/"provider-runner.json"),"run"])
    return 0


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role",choices=("gateway","receiver","agent","provider"))
    parser.add_argument("--config",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        cfg=installed_config(args.config,args.role)
        health={"event":"AEGIS_INSTALLED_PREFLIGHT","role":args.role,"uid":os.geteuid(),"gid":os.getegid(),
                "source_commit":cfg["source_commit"],"configuration_sha256":hashlib.sha256(canonical(cfg)).hexdigest(),
                "policy_read_only":True,"code_read_only":True,"runtime_read_only":True}
        if args.role=="gateway":
            from aegis_sandbox_check import run_check
            try:health["kernel"]=run_check()
            except (RuntimeError,OSError,ValueError,subprocess.TimeoutExpired) as exc:
                # The fixed probe contains only synthetic paths/data. Preserve
                # its bounded diagnostic so host mount-policy failures can be
                # distinguished without logging engagement or model material.
                print(json.dumps({"event":"AEGIS_INSTALLED_PREFLIGHT_FAILED","role":args.role,
                                  "check":"kernel","detail":str(exc)[:512]},sort_keys=True),file=sys.stderr,flush=True)
                raise
        print(json.dumps(health,sort_keys=True),flush=True)
        stop=threading.Event()
        if args.role in {"gateway","receiver"}:
            for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
        return execute(cfg,args.role,stop)
    except (ExecutionDenied,OSError,ValueError,TypeError,KeyError,ImportError,RuntimeError,subprocess.TimeoutExpired):
        print("INSTALLED_SERVICE_DENIED",file=sys.stderr);return 2


if __name__=="__main__":raise SystemExit(main())
