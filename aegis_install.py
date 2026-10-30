"""Root-only opt-in package installation; the default command only prints a plan."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

from aegis_audit_contract import canonical, decode, fields, read_relative, require
from aegis_supervisor import ExecutionDenied, open_directory_nofollow

ROLES = ("gateway", "receiver", "agent", "provider")
PATH_FIELDS = ("install_root", "policy_root", "state_root", "report_root", "receiver_state_root",
               "agent_state_root", "runner_root", "run_root")
NAME = re.compile(r"[a-z][a-z0-9-]{2,30}\Z")
PATH = re.compile(r"/(?:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?/)*[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?\Z")
UNIT_ROOT = Path("/etc/systemd/system")
TMPFILES = Path("/etc/tmpfiles.d/aegis.conf")


def config(value):
    fields(value, {"version", "configured", "source_commit", "source_manifest_sha256", "python",
                   *PATH_FIELDS, "repository_roots", "accounts", "socket_groups", "apparmor_profile",
                   "memory_max_mb", "tasks_max", "cpu_quota_percent"})
    require(type(value["version"]) is int and value["version"] == 1 and type(value["configured"]) is bool,
            "invalid installation configuration version")
    require(isinstance(value["source_commit"], str) and re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]), "pin an exact source commit")
    require(isinstance(value["source_manifest_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["source_manifest_sha256"]), "pin the source manifest digest")
    paths = []
    for key in (*PATH_FIELDS, "python"):
        name = value[key]
        require(isinstance(name, str) and PATH.fullmatch(name) and len(name) <= 180, "unsafe installation path")
        require(len(Path(name).parts)>=3,"select a dedicated installation subtree")
        require(not name.startswith(("/home/", "/root/", "/tmp/", "/proc/", "/sys/", "/dev/")), "installation path cannot be ephemeral or hidden by service policy")
        if key != "python": paths.append(Path(name))
    runtime=Path(value["python"]).parent.parent
    require(runtime not in {Path("/"),Path("/usr"),Path("/usr/local")} and Path(value["python"]).parent.name=="bin",
            "use a dedicated protected virtual environment")
    paths.append(runtime)
    require(value["run_root"].startswith("/run/"), "socket directory must be below /run")
    require(isinstance(value["repository_roots"], list) and 1 <= len(value["repository_roots"]) <= 8,
            "explicit repository roots required")
    for name in value["repository_roots"]:
        require(isinstance(name, str) and PATH.fullmatch(name) and len(name) <= 180 and
                not name.startswith(("/home/", "/root/", "/proc/", "/sys/", "/dev/", "/run/")), "unsafe repository root")
        paths.append(Path(name))
    require(len(set(paths)) == len(paths) and not any(a in b.parents for a in paths for b in paths if a != b),
            "installation, policy, evidence, scratch and repository trees must be separated")
    fields(value["accounts"], {"operator", "agent", "receiver"})
    fields(value["socket_groups"], {"gateway", "receiver"})
    uids, gids, names, groups = set(), set(), set(), set()
    for actor in value["accounts"].values():
        fields(actor, {"user", "uid", "group", "gid"})
        require(all(isinstance(actor[k], str) and NAME.fullmatch(actor[k]) for k in ("user", "group")), "unsafe account/group name")
        require(all(type(actor[k]) is int and 100 <= actor[k] < 60000 for k in ("uid", "gid")), "explicit non-root service IDs required")
        require(actor["uid"] not in uids and actor["gid"] not in gids and actor["user"] not in names and actor["group"] not in groups,
                "service identities must be distinct")
        uids.add(actor["uid"]); gids.add(actor["gid"]); names.add(actor["user"]); groups.add(actor["group"])
    for group in value["socket_groups"].values():
        fields(group, {"name", "gid"})
        require(isinstance(group["name"], str) and NAME.fullmatch(group["name"]) and type(group["gid"]) is int
                and 100 <= group["gid"] < 60000 and group["gid"] not in gids and group["name"] not in groups,
                "socket groups must be explicit and separate")
        gids.add(group["gid"]); groups.add(group["name"])
    require(value["apparmor_profile"] in {"none", "aegis-supervisor"}, "unsupported AppArmor profile")
    for key, low, high in (("memory_max_mb",128,4096),("tasks_max",32,256),("cpu_quota_percent",10,400)):
        require(type(value[key]) is int and low <= value[key] <= high, "invalid service resource bound")
    return value


def release_path(cfg):
    return Path(cfg["install_root"])/"releases"/cfg["source_commit"]


def render_units(cfg, template=None):
    if template is None:template=(Path(__file__).parent/"deployment/systemd/aegis-service.in").read_text()
    rendered = {}
    for role in ROLES:
        identity = "operator" if role in {"gateway", "provider"} else role
        actor = cfg["accounts"][identity]
        writable = {"gateway": [cfg["state_root"],cfg["report_root"],cfg["run_root"]+"/gateway"],
                    "receiver": [cfg["receiver_state_root"],cfg["run_root"]+"/receiver"],
                    "agent": [cfg["agent_state_root"]],
                    "provider": [cfg["state_root"],cfg["report_root"],cfg["runner_root"]]}[role]
        groups = {"gateway": ["gateway","receiver"], "agent": ["gateway"], "receiver": ["receiver"], "provider": ["receiver"]}[role]
        substitutions = {"ROLE":role, "COMMIT":cfg["source_commit"], "POLICY":cfg["policy_root"],
            "USER":actor["user"], "GROUP":actor["group"], "STATE":cfg["state_root"], "PYTHON":cfg["python"],
            "RELEASE":str(release_path(cfg)), "RUNTIME":str(Path(cfg["python"]).parent.parent),
            "TYPE":"simple" if role in {"gateway","receiver"} else "oneshot",
            "RESTART":"on-failure" if role in {"gateway","receiver"} else "no",
            "SUPPLEMENTARY":" ".join(cfg["socket_groups"][g]["name"] for g in groups),
            "WRITABLE":" ".join(writable), "REPOSITORIES":" ".join(cfg["repository_roots"]),
            "MEMORY":str(cfg["memory_max_mb"]), "TASKS":str(cfg["tasks_max"]), "CPU":str(cfg["cpu_quota_percent"]),
            "APPARMOR":"AppArmorProfile=aegis-supervisor" if cfg["apparmor_profile"] != "none" else ""}
        result = template
        for key, value in substitutions.items(): result=result.replace("@"+key+"@",value)
        require("@" not in result, "unexpanded service template")
        if role == "provider": result=result.replace("[Service]", "ConditionPathExists="+cfg["policy_root"]+"/provider-enabled\n\n[Service]")
        rendered["aegis-"+role+".service"] = result.encode()
    return rendered


def protected_parents(path):
    path = Path(path)
    for parent in reversed((path,*path.parents)):
        if not parent.exists(): continue
        st=parent.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
                "installation parent must be a root-owned non-writable directory")


def mkdir(path, uid=0, gid=0, mode=0o755):
    path=Path(path)
    protected_parents(path.parent)
    if path.exists():
        st=path.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == uid and st.st_gid == gid and stat.S_IMODE(st.st_mode) == mode,
                "existing directory custody differs from explicit installation configuration")
    else:
        path.mkdir(parents=True,mode=mode)
        os.chown(path,uid,gid);path.chmod(mode)


def atomic_file(path, raw, mode=0o644):
    path=Path(path);protected_parents(path.parent)
    if path.exists() or path.is_symlink():
        st=path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o022,
                "refusing to replace an unsafe operator file")
    temp=path.with_name("."+path.name+"-"+uuid.uuid4().hex)
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(fd,"wb") as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        temp.replace(path)
    finally:
        if temp.exists():temp.unlink()


def source_files(source, expected_digest):
    with open_directory_nofollow(Path(source)) as root:
        manifest=read_relative(root,"SHA256SUMS.txt",65536)
        require(hashlib.sha256(manifest).hexdigest() == expected_digest, "source manifest differs from operator pin")
        entries={}
        for line in manifest.decode("ascii").splitlines():
            sha,name=line.split("  ",1)
            require(re.fullmatch(r"[0-9a-f]{64}",sha) and name not in entries and name != "SHA256SUMS.txt", "invalid source manifest")
            entries[name]=sha
        require(0 < len(entries) <= 512, "unbounded source manifest")
        files={"SHA256SUMS.txt":manifest};total=len(manifest)
        for name,sha in entries.items():
            raw=read_relative(root,name,4*1024*1024)
            require(hashlib.sha256(raw).hexdigest()==sha,"source file differs from manifest")
            total+=len(raw);require(total<=64*1024*1024,"source package exceeds bound")
            files[name]=raw
        return files


def command(*argv):
    return subprocess.run(list(argv),check=True,timeout=120,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin"},capture_output=True,text=True)


def runtime_versions(cfg, files):
    expected={line.split("==",1)[0]:line.split("==",1)[1] for line in
              files["deployment/requirements.lock"].decode().splitlines() if line and not line.startswith("#")}
    require(1 <= len(expected) <= 32,"invalid pinned runtime requirements")
    runtime=Path(cfg["python"]).parent.parent
    count=0
    for parent,dirs,names in os.walk(runtime,followlinks=False):
        for name in [*dirs,*names]:
            path=Path(parent)/name;st=path.lstat();count+=1
            require(count<=20000 and st.st_uid==0,"runtime tree is not root-owned or exceeds file bound")
            if stat.S_ISLNK(st.st_mode):
                target=path.resolve(strict=True);protected_parents(target if target.is_dir() else target.parent)
                st=target.stat()
                require(st.st_uid==0,"runtime symlink target is not root-owned")
                require(not stat.S_ISDIR(st.st_mode) or target==runtime or runtime in target.parents,
                        "runtime directory symlink escapes validated tree")
            require(not st.st_mode & 0o022,"runtime tree contains writable code")
            if path.suffix==".pth" and path.is_file():
                for line in path.read_text().splitlines():
                    if not line.strip() or line.startswith("#"):continue
                    require(not line.startswith(("import ","import\t")),"runtime .pth executable hooks are unsupported; remove packaging-only setuptools after installing wheels")
                    target=(path.parent/line).resolve()
                    require(target==runtime or runtime in target.parents,"runtime .pth search path escapes validated tree")
    settings=dict(line.strip().split(" = ",1) for line in (runtime/"pyvenv.cfg").read_text().splitlines() if " = " in line)
    require(settings.get("include-system-site-packages")=="false","runtime must exclude ambient system packages")
    # -S prevents any .pth/sitecustomize code before the validated library path
    # is explicitly supplied. Python 3.10 computes venv prefixes in site.py, so
    # determine the interpreter version rather than trusting sys.prefix here.
    script="import sys,json;from pathlib import Path;p=Path(sys.argv[1])/'lib'/('python%d.%d'%sys.version_info[:2])/'site-packages';sys.path.insert(0,str(p));import importlib.metadata;print(json.dumps({n:importlib.metadata.version(n) for n in json.loads(sys.argv[2])},sort_keys=True))"
    actual=json.loads(command(cfg["python"],"-I","-S","-c",script,str(runtime),json.dumps(list(expected))).stdout)
    require(actual==expected,"runtime dependency versions differ from reviewed lock")
    return actual


def provision_accounts(cfg):
    import grp, pwd
    groups=[{"name":a["group"],"gid":a["gid"]} for a in cfg["accounts"].values()]+list(cfg["socket_groups"].values())
    for group in groups:
        try: by_name=grp.getgrnam(group["name"])
        except KeyError:by_name=None
        try: by_id=grp.getgrgid(group["gid"])
        except KeyError:by_id=None
        require((by_name is None and by_id is None) or (by_name and by_id and by_name.gr_gid==group["gid"] and by_id.gr_name==group["name"]), "group identity collision")
        if by_name is None:command("/usr/sbin/groupadd","--system","--gid",str(group["gid"]),group["name"])
    for actor in cfg["accounts"].values():
        try: by_name=pwd.getpwnam(actor["user"])
        except KeyError:by_name=None
        try: by_id=pwd.getpwuid(actor["uid"])
        except KeyError:by_id=None
        require((by_name is None and by_id is None) or (by_name and by_id and by_name.pw_uid==actor["uid"] and by_name.pw_gid==actor["gid"] and by_id.pw_name==actor["user"] and by_name.pw_shell in {"/usr/sbin/nologin","/bin/false"}), "service account collision")
        if by_name is None:command("/usr/sbin/useradd","--system","--no-create-home","--uid",str(actor["uid"]),"--gid",str(actor["gid"]),"--home-dir","/nonexistent","--shell","/usr/sbin/nologin",actor["user"])


def install(cfg, source):
    require(os.geteuid()==0 and sys.platform=="linux" and cfg["configured"],"apply requires root Linux and configured operator input")
    os_release=dict(line.rstrip().split("=",1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    version=os_release.get("VERSION_ID","").strip('"')
    require(os_release.get("ID","").strip('"')=="ubuntu" and version in {"22.04","24.04"},"package supports Ubuntu 22.04/24.04")
    require(version!="24.04" or cfg["apparmor_profile"]=="aegis-supervisor","Ubuntu 24.04 requires the named user-namespace profile")
    require(Path("/run/systemd/system").is_dir(),"installation requires a systemd host")
    files=source_files(source,cfg["source_manifest_sha256"])
    units=render_units(cfg,files["deployment/systemd/aegis-service.in"].decode())
    protected_parents(Path(cfg["python"]).parent)
    python=Path(cfg["python"]).resolve(strict=True)
    st=python.stat();require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,"runtime interpreter is not protected")
    versions=runtime_versions(cfg,files)
    for role in ROLES:
        active=subprocess.run(["/usr/bin/systemctl","is-active","--quiet","aegis-"+role+".service"],env={"PATH":"/usr/bin:/bin"},timeout=10).returncode
        require(active!=0,"stop installed services before selecting a new release")
    provision_accounts(cfg)
    mkdir(cfg["install_root"]);mkdir(Path(cfg["install_root"])/"releases")
    release=release_path(cfg)
    if release.exists():
        require(source_files(release,cfg["source_manifest_sha256"])==files,"installed release was altered")
    else:
        mkdir(release)
        for name,raw in files.items():
            path=release/name
            path.parent.mkdir(parents=True,exist_ok=True)
            atomic_file(path,raw,0o444)
    mkdir(cfg["policy_root"])
    # The no-follow reader opens directories read-only as well as traversing
    # them. Grant that capability only to the selected role's private group.
    for role in ("operator","agent","receiver"):
        mkdir(Path(cfg["policy_root"])/role,gid=cfg["accounts"][role]["gid"],mode=0o550)
    marker=Path(cfg["policy_root"])/"enabled"
    if marker.exists() or marker.is_symlink():
        require(marker.is_file() and not marker.is_symlink() and marker.stat().st_uid==0,"unsafe enable marker")
        marker.unlink()
    for field,identity in (("state_root","operator"),("report_root","operator"),("receiver_state_root","receiver"),("agent_state_root","agent"),("runner_root","operator")):
        actor=cfg["accounts"][identity];mkdir(cfg[field],actor["uid"],actor["gid"],0o700)
    mkdir(cfg["run_root"])
    lines=["d "+cfg["run_root"]+" 0755 root root -"]
    for role,identity in (("gateway","operator"),("receiver","receiver")):
        actor=cfg["accounts"][identity];group=cfg["socket_groups"][role]
        mkdir(Path(cfg["run_root"])/role,actor["uid"],group["gid"],0o710)
        lines.append("d "+cfg["run_root"]+"/"+role+" 0710 "+actor["user"]+" "+group["name"]+" -")
    atomic_file(TMPFILES,("\n".join(lines)+"\n").encode())
    atomic_file(Path(cfg["policy_root"])/"install.json",canonical(cfg),0o444)
    for name,body in units.items():atomic_file(UNIT_ROOT/name,body)
    if cfg["apparmor_profile"]!="none":
        profile=Path("/etc/apparmor.d/aegis-supervisor")
        atomic_file(profile,files["deployment/apparmor/aegis-supervisor"])
        command("/usr/sbin/apparmor_parser","-r",str(profile))
    command("/usr/bin/systemctl","daemon-reload")
    receipt={"source_commit":cfg["source_commit"],"source_manifest_sha256":cfg["source_manifest_sha256"],
             "configuration_sha256":hashlib.sha256(canonical(cfg)).hexdigest(),"runtime_versions":versions,
             "units":{name:hashlib.sha256(body).hexdigest() for name,body in units.items()},"enabled":False}
    mkdir(Path(cfg["install_root"])/"receipts")
    atomic_file(Path(cfg["install_root"])/"receipts"/(cfg["source_commit"]+"-"+receipt["configuration_sha256"]+".json"),canonical(receipt),0o444)
    atomic_file(Path(cfg["install_root"])/"installation.json",canonical(receipt),0o444)
    return receipt


def service_action(cfg, action):
    require(os.geteuid()==0 and cfg["configured"],"service changes require root and configured operator input")
    path=Path(cfg["policy_root"])/"install.json"
    protected_parents(path.parent)
    require(path.read_bytes()==canonical(cfg),"installed configuration differs from selected input")
    files=source_files(release_path(cfg),cfg["source_manifest_sha256"])
    units=render_units(cfg,files["deployment/systemd/aegis-service.in"].decode())
    for name,body in units.items():
        target=UNIT_ROOT/name
        require(target.is_file() and not target.is_symlink() and target.stat().st_uid==0 and target.read_bytes()==body,
                "unit differs from generated installation; preserve manual changes")
    marker=Path(cfg["policy_root"])/"enabled"
    if action=="enable":
        for identity,names in {"operator":("scope.yaml","scope.sig","trust.json","assessment.json","delegation.json"),
                               "receiver":("receiver.json",)}.items():
            for name in names:
                target=Path(cfg["policy_root"])/identity/name
                st=target.lstat()
                require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==cfg["accounts"][identity]["uid"]
                        and stat.S_IMODE(st.st_mode)==0o400,"install private read-only role policy before enabling")
        atomic_file(marker,canonical({"source_commit":cfg["source_commit"],"configuration_sha256":hashlib.sha256(canonical(cfg)).hexdigest()}),0o444)
        try:
            command("/usr/bin/systemctl","start","aegis-receiver.service","aegis-gateway.service")
            for role in ("receiver","gateway"):command("/usr/bin/systemctl","is-active","--quiet","aegis-"+role+".service")
        except BaseException:
            marker.unlink(missing_ok=True)
            command("/usr/bin/systemctl","stop","aegis-receiver.service","aegis-gateway.service")
            raise
        return {"status":"INSTALLED_SERVICES_STARTED","source_commit":cfg["source_commit"],"provider_enabled":False}
    command("/usr/bin/systemctl","stop",*["aegis-"+role+".service" for role in ROLES])
    command("/usr/bin/systemctl","disable",*["aegis-"+role+".service" for role in ROLES])
    if marker.exists() or marker.is_symlink():
        require(marker.is_file() and not marker.is_symlink() and marker.stat().st_uid==0,"unsafe enable marker")
        marker.unlink()
    if action=="uninstall":
        for name in units:(UNIT_ROOT/name).unlink()
        command("/usr/bin/systemctl","daemon-reload")
    return {"status":"SERVICES_REMOVED_EVIDENCE_PRESERVED" if action=="uninstall" else "SERVICES_STOPPED_EVIDENCE_PRESERVED",
            "preserved_paths":[cfg[k] for k in PATH_FIELDS if k!="run_root"]}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",required=True,type=Path)
    parser.add_argument("--source",required=True,type=Path)
    parser.add_argument("--action",choices=("install","enable","disable","uninstall"),default="install")
    parser.add_argument("--apply",action="store_true")
    args=parser.parse_args(argv)
    try:
        cfg=config(decode(args.config.read_bytes(),16384))
        files=source_files(args.source,cfg["source_manifest_sha256"])
        result=(install(cfg,args.source) if args.action=="install" else service_action(cfg,args.action)) if args.apply else {"status":"DRY_RUN_NO_CHANGES","action":args.action,"source_commit":cfg["source_commit"],
            "source_files":len(files),"release":str(release_path(cfg)),"accounts":cfg["accounts"],"socket_groups":cfg["socket_groups"],
            "units":list(render_units(cfg)),"services_enabled":False,"preserved_paths":[cfg[k] for k in ("state_root","report_root","receiver_state_root","agent_state_root","runner_root")]}
        print(json.dumps(result,sort_keys=True));return 0
    except (ExecutionDenied,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        print("PACKAGE_INSTALL_DENIED",file=sys.stderr);return 2


if __name__=="__main__":raise SystemExit(main())
