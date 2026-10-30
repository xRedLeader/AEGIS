"""Root-only native Ubuntu CI fixture exercising the installed systemd units.

This creates explicitly named disposable CI accounts/paths. It must never run on
an operator's existing deployment; pre-existing fixture paths are refused.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import yaml
from aegis_audit_contract import canonical
from aegis_install import config, install, release_path, service_action
from aegis_agent_client import signed_grant, signed_request, envelope
from aegis_preflight import SIGNING_CONTEXT


def require(value,message):
    if not value:raise RuntimeError(message)


def systemctl(*args,check=True):
    return subprocess.run(["/usr/bin/systemctl",*args],check=check,capture_output=True,text=True,timeout=90)


def wait_socket(path,uid,gid):
    until=time.monotonic()+40
    while time.monotonic()<until:
        try:
            st=Path(path).lstat()
            require(stat.S_ISSOCK(st.st_mode) and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(uid,gid,0o660),"socket custody mismatch")
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
                probe.settimeout(.2);probe.connect(str(path))
            return
        except (FileNotFoundError,ConnectionRefusedError):time.sleep(.1)
    raise RuntimeError("installed listener did not become ready")


def run(args):
    require(os.geteuid()==0 and Path("/run/systemd/system").is_dir(),"native systemd CI host and root required")
    require(os.environ.get("GITHUB_ACTIONS")=="true","this destructive fixture is only for ephemeral GitHub Actions hosts")
    cfg=json.loads((args.source/"deployment/install.example.json").read_bytes())
    cfg.update(configured=True,source_commit=args.commit,
               source_manifest_sha256=hashlib.sha256((args.source/"SHA256SUMS.txt").read_bytes()).hexdigest(),
               python=sys.executable,install_root="/srv/aegis-package-ci",policy_root="/etc/aegis-package-ci",
               state_root="/var/lib/aegis-package-controller",report_root="/var/lib/aegis-package-reports",
               receiver_state_root="/var/lib/aegis-package-receiver",agent_state_root="/var/lib/aegis-package-agent",
               runner_root="/var/lib/aegis-package-runner",run_root="/run/aegis-package-ci",
               repository_roots=["/srv/aegis-package-targets"])
    for n,role in enumerate(("operator","agent","receiver"),58501):
        cfg["accounts"][role]={"user":"aegis-ci-"+role,"uid":n,"group":"aegis-ci-"+role,"gid":n}
    cfg["socket_groups"]={"gateway":{"name":"aegis-ci-gateway","gid":58504},"receiver":{"name":"aegis-ci-notify","gid":58505}}
    cfg["apparmor_profile"]="aegis-supervisor" if 'VERSION_ID="24.04"' in Path("/etc/os-release").read_text() else "none"
    config(cfg)
    for key in ("install_root","policy_root","state_root","report_root","receiver_state_root","agent_state_root","runner_root","run_root"):
        require(not Path(cfg[key]).exists(),"fixture path already exists: "+key)
    require(not Path(cfg["repository_roots"][0]).exists(),"fixture source root exists")
    repository=Path(cfg["repository_roots"][0])/"application"
    repository.mkdir(parents=True,mode=0o755)
    (repository/"app.py").write_text("import subprocess\ndef vulnerable(user_value):\n    subprocess.run(user_value, shell=True)\n")
    receipt=install(cfg,args.source)
    release=release_path(cfg);policy=Path(cfg["policy_root"]);op=cfg["accounts"]["operator"]
    require(not (policy/"enabled").exists(),"installation unexpectedly enabled engagement")
    systemctl("start","aegis-gateway.service","aegis-receiver.service")
    require(all(systemctl("is-active","--quiet","aegis-"+r+".service",check=False).returncode!=0 for r in ("gateway","receiver")),"disabled services started")

    def private(path,raw,role="operator",mode=0o400):
        path=Path(path);path.write_bytes(raw);actor=cfg["accounts"][role]
        os.chown(path,actor["uid"],actor["gid"]);path.chmod(mode)

    def as_role(role,body,data=None,groups=None):
        actor=cfg["accounts"][role]
        shared={"operator":[58504,58505],"agent":[58504],"receiver":[58505]}[role] if groups is None else groups
        def demote():
            os.setgroups(shared);os.setgid(actor["gid"]);os.setuid(actor["uid"])
        prefix="import sys,json,os;from pathlib import Path;sys.path.insert(0,sys.argv[1]);cfg=json.loads(sys.argv[2]);"
        result=subprocess.run([cfg["python"],"-I","-c",prefix+body,str(release),canonical(cfg).decode()],
                              input=None if data is None else canonical(data),capture_output=True,timeout=60,cwd="/",preexec_fn=demote,
                              env={"PATH":"/usr/bin:/bin","PYTHONDONTWRITEBYTECODE":"1"})
        require(result.returncode==0,"fixture client failed: "+result.stderr.decode(errors="replace")[-1800:])
        # A framed receiver ACK already ends in a newline; print adds another.
        # Parse the complete JSON document, including legal trailing whitespace.
        return json.loads(result.stdout)

    folder=policy/"operator";eid="packaged-ci-only"
    alert=Path(cfg["report_root"])/"alerts";alert.mkdir();os.chown(alert,op["uid"],op["gid"]);alert.chmod(0o700)
    now=datetime.now(timezone.utc)
    timestamp=lambda value:value.strftime("%Y-%m-%dT%H:%M:%SZ")
    scope=yaml.safe_load((release/"security-scope.example.yaml").read_bytes())
    scope["engagement"].update(id=eid,valid_from_utc=timestamp(now-timedelta(minutes=1)),valid_until_utc=timestamp(now+timedelta(hours=1)))
    scope["targets"].update(repositories=[str(repository)],origins=[])
    scope["accounts"]=[];scope["methods"]["allowed"]=["source_review"]
    scope["limits"].update(engagement_runtime_minutes=5,max_single_run_minutes=1,deterministic_hypothesis_minutes=1,
                            max_total_requests=0,max_requests_per_minute_per_origin=0,max_concurrent_requests=0)
    scope["reporting"]["output_dir"]=cfg["report_root"]+"/"+eid
    scope["reporting"]["critical_alert"]["path"]=str(alert/(eid+".ndjson"))
    signer=Ed25519PrivateKey.generate();delegator=Ed25519PrivateKey.generate();agent=Ed25519PrivateKey.generate()
    scope_bytes=yaml.safe_dump(scope).encode()
    private(folder/"scope.yaml",scope_bytes);private(folder/"scope.sig",signer.sign(SIGNING_CONTEXT+scope_bytes))
    for name,key in (("scope.pub.pem",signer),("delegation.pub.pem",delegator)):
        private(folder/name,key.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
    trust=json.loads((release/"trust-policy.example.json").read_bytes())
    trust.update(configured=True,approved_engagement_ids=[eid],allowed_repository_roots=cfg["repository_roots"],
                 allowed_origins=[],approved_methods=["source_review"],allowed_report_roots=[cfg["report_root"]],allowed_alert_roots=[str(alert)])
    trust["operator"]["public_key_pem_path"]=str(folder/"scope.pub.pem")
    trust["revocation"]["last_checked_utc"]=timestamp(now)
    private(folder/"trust.json",canonical(trust))
    assessment={"schema_version":1,"configured":True,"engagement_ids":[eid],"repository":str(repository),"lease_seconds":90,
                "steps":[{"id":"scan","action":"source_review","seconds":5},{"id":"render","action":"report","source":"scan"}]}
    private(folder/"assessment.json",canonical(assessment))
    gateway_socket=cfg["run_root"]+"/gateway/agent.sock";receiver_socket=cfg["run_root"]+"/receiver/receiver.sock"
    private(folder/"delegation.json",canonical({"version":1,"configured":True,"socket_path":gateway_socket,
             "signer_public_key_path":str(folder/"delegation.pub.pem"),"allowed_peer_uids":[cfg["accounts"]["agent"]["uid"]],
             "allowed_engagement_ids":[eid],"max_grant_seconds":600,"max_request_seconds":20,"shared_gid":58504}))
    private(policy/"receiver/receiver.json",canonical({"schema_version":1,"configured":True,"socket_path":receiver_socket,
             "state_root":cfg["receiver_state_root"],"shared_gid":58505,"allowed_sender_uids":[op["uid"]],"allowed_engagement_ids":[eid]}),"receiver")
    private(folder/"notification.json",canonical({"schema_version":1,"configured":True,"socket_path":receiver_socket,
             "allowed_peer_uids":[cfg["accounts"]["receiver"]["uid"]],"timeout_seconds":1,"max_attempts":4}))
    controller="from aegis_integrated_assessment import IntegratedAssessment;f=Path(cfg['policy_root'])/'operator';c=IntegratedAssessment(f/'scope.yaml',f/'scope.sig',f/'trust.json',Path(cfg['state_root']),f/'assessment.json');"
    created=as_role("operator",controller+"a=c.create();i,p,h=c._admit();print(json.dumps({'assessment_id':a['assessment_id'],'manifest_sha256':i['manifest_sha256'],'policy_sha256':h}))")
    grant,signature=signed_grant(delegator,agent.public_key(),engagement_id=eid,assessment_id=created["assessment_id"],
                                manifest_sha256=created["manifest_sha256"],assessment_policy_sha256=created["policy_sha256"],
                                client_uid=cfg["accounts"]["agent"]["uid"],permissions=("snapshot","propose"),seconds=600)
    private(policy/"agent/client.pem",agent.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()),"agent")
    private(policy/"agent/grant.json",grant,"agent");private(policy/"agent/grant.sig",signature,"agent")
    service_action(cfg,"enable")
    wait_socket(gateway_socket,op["uid"],58504);wait_socket(receiver_socket,cfg["accounts"]["receiver"]["uid"],58505)
    identities={}
    for role,actor in (("gateway",op),("receiver",cfg["accounts"]["receiver"])):
        pid=int(systemctl("show","--property=MainPID","--value","aegis-"+role+".service").stdout)
        status=dict(line.split(":",1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
        require(set(map(int,status["Uid"].split()))=={actor["uid"]} and status["NoNewPrivs"].strip()=="1","actual service UID or privilege bound mismatch")
        identities[role]={"uid":actor["uid"],"gid":actor["gid"],"supplementary_groups":list(map(int,status["Groups"].split())),"no_new_privileges":True}
    req,sig=signed_request(agent,json.loads(grant),"snapshot");packet=envelope(grant,signature,req,sig)
    client="from aegis_agent_client import send;from aegis_audit_contract import canonical;print(json.dumps(send(cfg['run_root']+'/gateway/agent.sock',canonical(json.load(sys.stdin)),cfg['accounts']['operator']['uid'])))"
    require(as_role("agent",client,json.loads(packet))["status"]=="DELEGATED_WORKFLOW_SNAPSHOT","signed agent was denied")
    require(as_role("agent",client,json.loads(packet))["status"]=="DELEGATED_REQUEST_DENIED","replayed request accepted")
    fresh_req,fresh_sig=signed_request(agent,json.loads(grant),"snapshot")
    wrong=as_role("receiver",client,json.loads(envelope(grant,signature,fresh_req,fresh_sig)),groups=[58504,58505])
    require(wrong["status"]=="DELEGATED_REQUEST_DENIED","wrong peer accepted")
    for decision in ({"operation":"snapshot"},{"operation":"propose","step_id":"scan","expected_action":"source_review"},
                     {"operation":"propose","step_id":"render","expected_action":"report"}):
        private(Path(cfg["agent_state_root"])/"decision.json",canonical(decision),"agent",0o600)
        systemctl("start","aegis-agent.service")
        require(systemctl("show","--property=ExecMainStatus","--value","aegis-agent.service").stdout.strip()=="0","actual agent unit failed")
    snapshot=as_role("operator",controller+"print(json.dumps(c.snapshot(json.load(sys.stdin)['id'])))",{"id":created["assessment_id"]})
    require(all(step["state"]=="completed" for step in snapshot["steps"]),"installed workflow did not complete")
    report=snapshot["steps"][1]["result"]
    queued=as_role("operator",controller+"x=json.load(sys.stdin);\nwith c._database() as db:\n print(json.dumps({'notice':db.execute('SELECT notice_id FROM notification_outbox WHERE source_run_id=? AND report_sha256=?',(x['run_id'],x['report_sha256'])).fetchone()[0]}))",report)
    notice=queued["notice"]
    delivery=controller+"from aegis_notifications import NotificationSupervisor;n=NotificationSupervisor(f/'scope.yaml',f/'scope.sig',f/'trust.json',Path(cfg['state_root']));print(json.dumps(n.deliver(json.load(sys.stdin)['notice'],f/'notification.json')))"
    systemctl("stop","aegis-receiver.service")
    require(as_role("operator",delivery,{"notice":notice})["status"]=="DELIVERY_FAILED_PENDING","missing receiver did not preserve pending delivery")
    systemctl("start","aegis-receiver.service");wait_socket(receiver_socket,cfg["accounts"]["receiver"]["uid"],58505)
    require(as_role("operator",delivery,{"notice":notice})["status"]=="DELIVERY_ACKNOWLEDGED","durable pending delivery did not recover")
    # Lose the client's ACK, then crash/restart the actual receiver and resend.
    raw={"type":"aegis_assessment_v1","notice_id":"a"*64,"engagement_id":eid,"source_run_id":"aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
         "report_sha256":"b"*64,"lead_count":0,"assessment_status":"limited_source_evidence_only","challenge":"c"*32}
    wire="import socket;from aegis_audit_contract import canonical;x=json.load(sys.stdin);s=socket.socket(socket.AF_UNIX);s.settimeout(5);s.connect(cfg['run_root']+'/receiver/receiver.sock');s.sendall(canonical(x['notice'])+b'\\n');\ntry:r=s.recv(8192) if x['ack'] else b'{}'\nexcept ConnectionResetError:r=b'{}'\ns.close();print(r.decode() or '{}')"
    as_role("operator",wire,{"notice":raw,"ack":False})
    received=Path(cfg["receiver_state_root"])/"received.sqlite3"
    until=time.monotonic()+5
    while time.monotonic()<until:
        with sqlite3.connect(received) as db:count=db.execute("SELECT count(*) FROM received WHERE notice_id=?",(raw["notice_id"],)).fetchone()[0]
        if count==1:break
        time.sleep(.05)
    require(count==1,"receiver did not commit before lost ACK")
    systemctl("kill","--signal=SIGKILL","aegis-receiver.service")
    time.sleep(3)
    wait_socket(receiver_socket,cfg["accounts"]["receiver"]["uid"],58505)
    raw["challenge"]="d"*32
    require(as_role("operator",wire,{"notice":raw,"ack":True}).get("challenge")==raw["challenge"],"receiver lost committed notice on restart")
    wrong=as_role("agent",wire,{"notice":raw,"ack":True},groups=[58505])
    require(wrong.get("challenge")!=raw["challenge"],"receiver accepted wrong peer")
    journal=subprocess.run(["/usr/bin/journalctl","-u","aegis-gateway.service","-u","aegis-receiver.service","--no-pager","-o","cat"],check=True,capture_output=True,text=True).stdout
    health=[json.loads(line) for line in journal.splitlines() if line.startswith('{') and '"event": "AEGIS_INSTALLED_PREFLIGHT"' in line]
    gateway_health=next(item for item in health if item["role"]=="gateway")
    require(gateway_health["kernel"]["all_passed"],"actual unit kernel probe absent")
    result={"status":"PACKAGED_SERVICE_CI_PASSED_NOT_DEPLOYMENT_APPROVAL","source_commit":args.commit,
            "source_manifest_sha256":cfg["source_manifest_sha256"],"configuration_sha256":receipt["configuration_sha256"],
            "runtime_versions":receipt["runtime_versions"],"identities":identities,"gateway_preflight":gateway_health,
            "checks":{"disabled_by_default":True,"real_agent_unit":True,"real_gateway_unit":True,"real_receiver_unit":True,
                      "wrong_peer_rejected":True,"replay_rejected":True,"durable_outbox_retry":True,"receiver_lost_ack_restart":True,
                      "socket_mode_and_group":True,"source_review_in_unit":True},
            "remaining_gates":["intended installed host","authorized application pilot","independent review","off-host retention","release-owner decision"]}
    args.output.write_bytes(canonical(result));print(json.dumps(result,indent=2))
    service_action(cfg,"uninstall")
    require(Path(cfg["state_root"]).is_dir() and received.exists() and release.is_dir(),"uninstall destroyed retained evidence")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True);parser.add_argument("--commit",required=True)
    parser.add_argument("--output",type=Path,required=True)
    try:run(parser.parse_args())
    finally:
        if os.geteuid()==0 and os.environ.get("GITHUB_ACTIONS")=="true":
            subprocess.run(["/usr/bin/journalctl","-u","aegis-gateway.service","-u","aegis-receiver.service","-u","aegis-agent.service","--no-pager","-n","80"],check=False)
            systemctl("stop","aegis-gateway.service","aegis-receiver.service","aegis-agent.service",check=False)
