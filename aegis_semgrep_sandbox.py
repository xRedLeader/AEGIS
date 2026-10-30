"""Fixed offline Semgrep core profile: a static engine, no Python CLI or child processes."""
from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import resource
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aegis_sandbox as kernel
from aegis_scanner_sandbox import _bind_fd, _seccomp

PROFILE = "semgrep-core-v1.125.0"
BINARY_SHA256 = "313bf3bbb50648fb5c3f43bd1d72dfee28dae436e10a096acb7d9a5839d18f11"
MAX_BINARY = 224*1024**2
LANGUAGES = {".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript", ".cs": "csharp"}
OFFLINE_STARTUP_CA = b"""-----BEGIN CERTIFICATE-----
MIIDADCCAeigAwIBAgIEATUopjANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDDCJB
RUdJUyBvZmZsaW5lIHNjYW5uZXIgc3RhcnR1cCBvbmx5MCAXDTIwMDEwMTAwMDAw
MFoYDzIwOTAwMTAxMDAwMDAwWjAtMSswKQYDVQQDDCJBRUdJUyBvZmZsaW5lIHNj
YW5uZXIgc3RhcnR1cCBvbmx5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAvVmzJTbiJnFDpP059xsfHK/eM/YuJP5GAXHQAdIFUUTnaO17BIcIMMJjDPYE
7zXUzyY8tDp5XDNXYjeoGqyowlDVn2oTH3pajDLdB9a9URg91JC9EB/P1QBHNSad
rVZqworKuJaTkrj9SEM82dUjSDcEezFy5XQkJrM2O+t+u1bGIZ7fPXYppTIF7JB6
75ngr9/8NP88+zGGRERb/zeEOr5T+ac5p2xbFfznHdqS6eoeF0PKnll7UmZmX/Rz
rpRMPGgzhJ6oRvphTYtfUqCaZiMrzJMTmNE7RGFZpR/aqousDgHWP4fEv9r0mMhG
ROEXCg/r687KeEZB8+4TqpHUAwIDAQABoyYwJDASBgNVHRMBAf8ECDAGAQH/AgEA
MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAImQiHh8FO/N0gv8j
P8RKypx0BDWAZxcFv5p6JT+zclhJnaRy/UYkllEv3B+XfFOXzWqfVhO7LV2hzrT1
GILGrp6WYaizZrMLO9PxinsGNh3v1OBMPzsbX/Zyi4ROCkp8LhNdgf6M2dn16XFA
3Rd8ynV5donfXxRgz0Nfs8qsz24UIQK2xCq8+jf0sERa3Z0f+gw668p55lohAvnh
6oKgZo0bUi1PFUglJKTVxiZwD6e+Y086mm6b4UQQyIj/1mx+MJqshNsKcp3iTt3a
EUrtEMzTF0i2WTiJrsfmdoBfujb+HwNM0+KoFRPIMslKRdxZ4AB5PTN2KaLBDjAw
tKmQWA==
-----END CERTIFICATE-----
"""


def validate_rules(raw, allowed):
    """Canonical data-only rule subset; no Jsonnet, includes, validators or execution hooks."""
    from aegis_audit_contract import canonical, fields, require
    from aegis_scanner_contract import strict_json
    require(isinstance(raw, bytes) and 0 < len(raw) <= 32768, "Semgrep rules exceed bound")
    config = strict_json(raw)
    fields(config, {"rules"})
    require(raw == canonical(config) and isinstance(config["rules"], list) and 1 <= len(config["rules"]) <= 64,
            "Semgrep rules must be canonical bounded JSON")
    selected = []
    for rule in config["rules"]:
        fields(rule, {"id", "languages", "message", "severity", "pattern"})
        require(isinstance(rule["id"], str) and rule["id"] in allowed, "Semgrep executed rule was not selected")
        selected.append(rule["id"])
        require(isinstance(rule["languages"], list) and 1 <= len(rule["languages"]) <= 3 and
                all(isinstance(language, str) for language in rule["languages"]) and
                len(rule["languages"]) == len(set(rule["languages"])) and
                set(rule["languages"]) <= set(LANGUAGES.values()), "Semgrep language has no reviewed execution profile")
        require(isinstance(rule["severity"], str) and rule["severity"] in {"INFO", "WARNING", "ERROR"},
                "invalid inert Semgrep severity metadata")
        require(isinstance(rule["message"], str) and 1 <= len(rule["message"]) <= 400 and
                isinstance(rule["pattern"], str) and 1 <= len(rule["pattern"]) <= 2048 and
                "\x00" not in rule["pattern"], "invalid bounded Semgrep rule text")
    require(sorted(selected) == sorted(allowed) and len(selected) == len(set(selected)), "Semgrep rule selection differs")
    return config


def launch(profile, binary_fd, config_fd, input_fd, jail, seconds, source_kind="source", broker_fd=None):
    if profile != PROFILE or source_kind != "source" or broker_fd is not None:
        raise kernel.SandboxFailure("unsupported Semgrep source profile or network capability")
    baseline = ",".join(str(os.stat("/proc/self/ns/"+name).st_ino) for name in ("user", "mnt", "net", "pid"))
    return ["/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--net", "--pid", "--fork", "--kill-child",
            "--propagation", "private", "--", "/usr/bin/python3", "-I", "-S", str(Path(__file__).resolve()),
            "--profile", profile, "--binary-fd", str(binary_fd), "--config-fd", str(config_fd), "--input-fd", str(input_fd),
            "--jail", str(jail), "--seconds", str(seconds), "--host-uid", str(os.geteuid()), "--parent-namespaces", baseline]


def _copy_sealed(fd, path, maximum, mode):
    st = os.fstat(fd)
    needed = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
    if fd < 3 or not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= maximum or fcntl.fcntl(fd, fcntl.F_GET_SEALS) & needed != needed:
        raise kernel.SandboxFailure("unsealed or oversized Semgrep file capability")
    os.lseek(fd, 0, os.SEEK_SET)
    with open(path, "xb") as output:
        while chunk := os.read(fd, 65536): output.write(chunk)
    path.chmod(mode)


def _targets(root):
    targets, total = [], 0
    def unreadable(_):
        raise kernel.SandboxFailure("Semgrep source inventory could not be read")
    for folder, directories, files in os.walk(root, followlinks=False, onerror=unreadable):
        for name in directories:
            if not stat.S_ISDIR(os.stat(Path(folder)/name, follow_symlinks=False).st_mode):
                raise kernel.SandboxFailure("Semgrep source directory is not regular")
        for name in files:
            path = Path(folder)/name
            st = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 1048576:
                raise kernel.SandboxFailure("Semgrep source file is unsafe or oversized")
            relative = path.relative_to(root).as_posix()
            if len(relative) > 256 or any(c in relative for c in ("\\", ":", "\x00")) or any(p in ("", ".", "..") for p in relative.split("/")):
                raise kernel.SandboxFailure("Semgrep source path is unsafe")
            language = LANGUAGES.get(path.suffix.lower())
            if language is None: raise kernel.SandboxFailure("selected source suffix has no Semgrep execution profile")
            total += st.st_size
            targets.append(["CodeTarget", {"path": relative, "analyzer": language, "products": ["sast"]}])
            if total > 8*1024**2 or len(targets) > 128: raise kernel.SandboxFailure("Semgrep source selection exceeds bound")
    if not targets: raise kernel.SandboxFailure("Semgrep source selection is empty")
    return ["Targets", sorted(targets, key=lambda target: target[1]["path"])]


def _setup(args):
    if args.profile != PROFILE or not 1 <= args.seconds <= 120 or args.host_uid <= 0 or os.geteuid() != 0:
        raise kernel.SandboxFailure("Semgrep launch scope invalid")
    baseline = args.parent_namespaces.split(",")
    if len(baseline) != 4 or not all(n.isdigit() for n in baseline): raise kernel.SandboxFailure("namespace baseline missing")
    for name, old in zip(("user", "mnt", "net", "pid"), baseline):
        if os.stat("/proc/self/ns/"+name).st_ino == int(old): raise kernel.SandboxFailure("Semgrep namespace unchanged")
    if Path("/proc/self/uid_map").read_text().split() != ["0", str(args.host_uid), "1"]:
        raise kernel.SandboxFailure("Semgrep UID mapping invalid")
    if args.input_fd < 3 or not stat.S_ISDIR(os.fstat(args.input_fd).st_mode): raise kernel.SandboxFailure("Semgrep source capability invalid")
    jail = Path(args.jail)
    if not jail.is_absolute() or jail.is_symlink() or not jail.is_dir() or jail.stat().st_mode & 0o077:
        raise kernel.SandboxFailure("Semgrep private jail invalid")
    sec = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    kernel._mount(None, Path("/"), None, kernel.MS_REC | kernel.MS_PRIVATE)
    kernel._mount("tmpfs", jail, "tmpfs", kernel.MS_NOSUID | kernel.MS_NODEV, "size=256m,mode=0700")
    _copy_sealed(args.binary_fd, jail/"scanner", MAX_BINARY, 0o500)
    _copy_sealed(args.config_fd, jail/"rules.json", 32768, 0o400)
    _bind_fd(args.input_fd, jail/"repo", directory=True)
    (jail/"targets.json").write_text(json.dumps(_targets(jail/"repo"), sort_keys=True, separators=(",", ":")), encoding="utf-8")
    (jail/"targets.json").chmod(0o400)
    # The statically linked CA helper otherwise shells out to `uname` during
    # startup and rejects an empty store. This synthetic public certificate's
    # signing key was discarded; it is not a system/provider CA. Kernel network
    # denial remains mandatory, independently of TLS initialization.
    (jail/"offline-ca.pem").write_bytes(OFFLINE_STARTUP_CA)
    (jail/"offline-ca.pem").chmod(0o400)
    (jail/"tmp").mkdir(mode=0o700)
    kernel._mount("tmpfs", jail/"tmp", "tmpfs", kernel.MS_NOSUID | kernel.MS_NODEV | kernel.MS_NOEXEC, "size=8m,mode=0700")
    kernel._mount(None, jail, None, kernel.MS_REMOUNT | kernel.MS_RDONLY | kernel.MS_NOSUID | kernel.MS_NODEV)
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        if fd > 2:
            try: os.close(fd)
            except OSError as exc:
                if exc.errno != errno.EBADF: raise
    os.chroot(jail); os.chdir("/repo")
    for limit, values in ((resource.RLIMIT_CPU, (args.seconds, args.seconds+1)),
                          (resource.RLIMIT_AS, (1024**3, 1024**3)), (resource.RLIMIT_DATA, (512*1024**2, 512*1024**2)),
                          (resource.RLIMIT_STACK, (8*1024**2, 8*1024**2)), (resource.RLIMIT_FSIZE, (524288, 524288)),
                          (resource.RLIMIT_NOFILE, (64, 64)), (resource.RLIMIT_NPROC, (32, 32)), (resource.RLIMIT_CORE, (0, 0))):
        resource.setrlimit(limit, values)
    lib = kernel._libc()
    if lib.prctl(kernel.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0: raise kernel.SandboxFailure("Semgrep privilege lock failed")
    kernel._drop_capabilities(lib); _seccomp(sec)
    os.write(2, b'{"status":"NATIVE_OFFLINE_BOUNDARY_ENTERED","profile":"semgrep-core-v1.125.0","namespaces":4,"network":"denied","processes":"threads_only","capabilities":"none","seccomp":"default_deny"}\n')
    argv = ["/scanner", "-rules", "/rules.json", "-targets", "/targets.json", "-j", "1", "-json_nodots", "-timeout", "2",
            "-timeout_threshold", "1", "-max_memory", "384", "-max_match_per_file", "64", "-use_eio"]
    os.execve("/scanner", argv, {"PATH": "/nonexistent", "HOME": "/tmp", "TMPDIR": "/tmp", "LANG": "C.UTF-8",
                               "SSL_CERT_FILE": "/offline-ca.pem"})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True); parser.add_argument("--jail", required=True)
    for name in ("binary-fd", "config-fd", "input-fd", "seconds", "host-uid"):
        parser.add_argument("--"+name, type=int, required=True)
    parser.add_argument("--parent-namespaces", required=True)
    try: _setup(parser.parse_args(argv))
    except (kernel.SandboxFailure, OSError, ValueError):
        print("SEMgrep_BOUNDARY_DENIED", file=sys.stderr); return 76
    return 0


if __name__ == "__main__": raise SystemExit(main())
