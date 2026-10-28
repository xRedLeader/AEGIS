#!/usr/bin/env python3
"""Read-only v2.0 deployment evidence collector; never self-approves a release.

This tool checks the *current* Linux identity, protected policy/installation
paths, authorized AEGIS scope, local kernel sandbox and signed audit checkpoint.
It cannot prove that a second independently owned host retains checkpoints,
that a human independently reviewed staging impact, or that all service accounts
are continuously isolated. The operator must supply and sign those facts.

The diagnostic does not change scope, initialize/update the audit ledger, contact
external targets, launch assessments or use operator signing keys. Its optional
benign kernel probe uses disposable local fixtures.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import stat
import sys

from aegis_audit import AuditError, read_ledger, verify_checkpoint
from aegis_agent_gateway import DelegatedAssessmentService
from aegis_integrated_assessment import IntegratedAssessment
from aegis_notification_receiver import _validated_policy as receiver_policy
from aegis_preflight import PreflightError, read_protected_trust
from aegis_supervisor import ExecutionDenied, open_directory_nofollow, private_directory


class AcceptanceEvidence:
    def __init__(self, role: str):
        self.role = role
        self.checks = []

    def check(self, name: str, ok: bool, consequence: str):
        self.checks.append({"check": name, "result": "PASS" if ok else "FAIL",
                            "reason": consequence if not ok else "Verified on this host"})

    def pending(self, name: str, requirement: str):
        self.checks.append({"check": name, "result": "REQUIRES_EXTERNAL_EVIDENCE",
                            "reason": requirement})

    def task(self, name: str, fn):
        try:
            fn()
            self.check(name, True, "")
        except (ExecutionDenied, AuditError, PreflightError, OSError, ValueError,
                RuntimeError, TypeError, KeyError) as exc:
            # Do not leak trusted paths, key bytes, scope data or exception text.
            self.check(name, False, type(exc).__name__ + " while verifying protected material")

    def result(self):
        return {"schema": "AEGIS-v2-host-acceptance-evidence-v1",
                "role": self.role, "observed_utc": datetime.now(timezone.utc).isoformat(),
                "effective_uid": os.geteuid(),
                "status": "NOT_PRODUCTION_APPROVED",
                "checks": self.checks,
                "note": "Human-reviewed deployment, staging and off-host retention sign-off cannot be inferred from this diagnostic."}


def _uid(uid):
    if type(uid) is not int or not 0 < uid < 2**31:
        raise ValueError("invalid non-root service identity")
    pwd.getpwuid(uid)


def _protected_parent_chain(directory: Path):
    """Reject replaceable source/policy ancestors, not just writable leaf files.

    A mode-0444 file in a service-writable directory is replaceable by rename.
    A directory owned by the service can be chmod'ed back to writable unless
    independently mounted read-only; a DAC 0555 check alone is insufficient.
    """
    directory = Path(directory)
    if not directory.is_absolute():
        raise ValueError("protected path must be absolute")
    for parent in (*reversed(directory.parents), directory):
        with open_directory_nofollow(parent) as fd:
            st = os.fstat(fd)
            readonly = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.geteuid()) or
                    st.st_mode & 0o022 or
                    (st.st_uid == os.geteuid() and not readonly) or
                    os.access(parent, os.W_OK, effective_ids=True)):
                raise ValueError("trusted source or policy ancestor is replaceable")


def _code_installation(root=None):
    """Check all first-party Python modules and their replacement boundaries.

    This is an observed host control, not a substitute for pinning a reviewed
    Git commit or independently reviewing third-party Python import paths.
    """
    root = Path(root) if root is not None else Path(__file__).resolve().parent
    _protected_parent_chain(root)
    python_files = sorted(root.glob("aegis_*.py"))
    required = {"aegis_supervisor.py", "aegis_integrated_assessment.py",
                "aegis_agent_gateway.py", "aegis_sandbox.py", "aegis_audit.py",
                "aegis_host_acceptance.py"}
    if not required.issubset({p.name for p in python_files}):
        raise ValueError("trusted AEGIS runtime installation is incomplete")
    with open_directory_nofollow(root) as directory:
        for path in python_files:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory)
            try:
                st = os.fstat(fd)
                readonly = bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY)
                if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                        st.st_uid not in (0, os.geteuid()) or st.st_mode & 0o022 or
                        (st.st_uid == os.geteuid() and not readonly) or
                        os.access(path, os.W_OK, effective_ids=True)):
                    raise ValueError("installed AEGIS source is mutable or unsafe")
            finally:
                os.close(fd)


def _protected_read_only(path: Path):
    """Protect policy leaf AND its directory chain against service replacement."""
    path = Path(path)
    _protected_parent_chain(path.parent)
    with open_directory_nofollow(path.parent) as directory:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                    st.st_mode & 0o077 or st.st_uid not in (0, os.geteuid())):
                raise ValueError("operator policy is not privately protected")
            if not (os.fstatvfs(fd).f_flag & os.ST_RDONLY):
                raise ValueError("policy mount is writable by its service")
        finally:
            os.close(fd)


def _existing_audit_ledger(state_root: Path):
    """Verify an existing protected ledger without creating or repairing it."""
    state_root = Path(state_root)
    with open_directory_nofollow(state_root) as directory:
        private_directory(directory)
        fd = os.open("ledger.sqlite3", os.O_RDONLY | os.O_NOFOLLOW |
                     os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                    st.st_uid != os.geteuid() or st.st_mode & 0o077):
                raise ValueError("audit ledger is not privately protected")
            # The supervisor's verify_audit_chain() opens a writable database
            # and initializes a missing ledger. Evidence must use mode=ro.
            read_ledger(state_root)
        finally:
            os.close(fd)


def _live_delegation_socket(path: Path, policy: dict):
    """Observe the actual delegation endpoint without connecting or sending."""
    path = Path(path)
    with open_directory_nofollow(path.parent) as fd:
        parent = os.fstat(fd)
        group = policy["shared_gid"]
        mode = 0o710 if group is not None else 0o700
        if (parent.st_uid != os.geteuid() or
                stat.S_IMODE(parent.st_mode) != mode or
                (group is not None and parent.st_gid != group)):
            raise ValueError("live delegation directory identity or mode is invalid")
        node = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        if (not stat.S_ISSOCK(node.st_mode) or node.st_uid != os.geteuid() or
                stat.S_IMODE(node.st_mode) != (0o660 if group is not None else 0o600) or
                (group is not None and node.st_gid != group)):
            raise ValueError("live delegation socket identity or mode is invalid")

def inspect_operator(*, manifest, signature, trust, state_root, assessment_policy,
                     delegation_policy, expected_agent_uid, expected_receiver_uid,
                     checkpoint=None, audit_public_key=None, kernel=True):
    evidence = AcceptanceEvidence("assessment-operator")
    evidence.check("linux-nonroot-identity", sys.platform == "linux" and os.geteuid()!=0,
                   "The assessment service must use a non-root Linux identity")
    def identities():
        _uid(expected_agent_uid); _uid(expected_receiver_uid)
        if len({0, os.geteuid(), expected_agent_uid, expected_receiver_uid})!=4:
            raise ValueError("expected agent, receiver and operator UIDs must be separate")
    evidence.task("distinct-os-identities-configured", identities)
    evidence.task("installed-trusted-source-not-writable", _code_installation)
    def state_private():
        with open_directory_nofollow(Path(state_root)) as fd:
            private_directory(fd)
    evidence.task("protected-ledger-directory", state_private)
    engine = IntegratedAssessment(manifest, signature, trust, state_root, assessment_policy)
    def signed_scope():
        info, policy, digest=engine._admit()
        if info["engagement_id"] not in policy["engagement_ids"] or len(digest)!=64:
            raise ValueError("signed scope not bound to active operator policy")
        _existing_audit_ledger(Path(state_root))
    evidence.task("signed-scope-operator-policy-and-audit-chain", signed_scope)
    def delegation():
        info,_,_=engine._admit()
        pol, key, socket_path=DelegatedAssessmentService(engine, Path(delegation_policy))._policy(info)
        if pol["allowed_peer_uids"] != [expected_agent_uid]:
            raise ValueError("agent delegation identity not exclusive")
        if socket_path.parent == Path(state_root):
            raise ValueError("delegation socket overlaps protected state")
    evidence.task("agent-delegation-policy-and-peer-uid", delegation)
    def live_delegation():
        info, _, _ = engine._admit()
        pol, _, socket_path = DelegatedAssessmentService(engine, Path(delegation_policy))._policy(info)
        _live_delegation_socket(socket_path, pol)
    evidence.task("delegation-socket-inode-owner-group-and-mode", live_delegation)
    evidence.pending("running-delegation-service-process-identity",
                     "Operator must verify the gateway listener's actual PID, UID, service-manager unit and restart privileges")
    for name, path in (("signed-scope-manifest",manifest), ("scope-signature",signature),
                       ("trust-policy",trust), ("assessment-policy",assessment_policy),
                       ("delegation-policy",delegation_policy)):
        evidence.task("service-cannot-rewrite-"+name, lambda p=path:_protected_read_only(Path(p)))
    def scope_signer():
        policy = read_protected_trust(Path(trust))
        _protected_read_only(Path(policy["operator"]["public_key_pem_path"]))
    evidence.task("service-cannot-rewrite-scope-signer-public-key", scope_signer)
    def delegation_signer():
        info, _, _ = engine._admit()
        policy, _, _ = DelegatedAssessmentService(engine, Path(delegation_policy))._policy(info)
        _protected_read_only(Path(policy["signer_public_key_path"]))
    evidence.task("service-cannot-rewrite-delegation-signer-public-key", delegation_signer)
    if kernel:
        def kernel_probe():
            from aegis_sandbox_check import run_check
            r=run_check()
            if not r.get("all_passed") or not all(r["checks"].values()):
                raise RuntimeError("Linux sandbox failed")
        evidence.task("real-rootless-kernel-namespace-seccomp-probe", kernel_probe)
    else:
        evidence.pending("real-rootless-kernel-namespace-seccomp-probe",
                         "Must run on target service account without --skip-kernel before sign-off")
    if checkpoint and audit_public_key:
        def verify_anchor():
            v=verify_checkpoint(Path(state_root),Path(checkpoint),Path(audit_public_key))
            if v["status"]!="AUDIT_ANCHOR_VERIFIED" or v["unanchored_events"]:
                raise ValueError("audit ledger has unsigned suffix")
        evidence.task("independently-signed-current-audit-anchor", verify_anchor)
    else:
        evidence.pending("independently-signed-current-audit-anchor",
                         "Pass a verified current checkpoint and its independently pinned public key")
    evidence.pending("off-host-checkpoint-retention",
                     "An external operator must verify checkpoint retention on a distinct immutable host/store")
    evidence.pending("human-staging-verification",
                     "Independent authorized verifier must review actual staging impact, remediation and negatives")
    evidence.pending("crash-stop-service-restart-drills",
                     "Operator must run and attest the drills using intended deployment services")
    return evidence.result()


def inspect_receiver(*, policy_path, expected_operator_uid):
    evidence=AcceptanceEvidence("notification-receiver")
    evidence.check("linux-nonroot-identity", sys.platform=="linux" and os.geteuid()!=0,
                   "Receiver requires distinct non-root Linux UID")
    def ids_and_private_state():
        _uid(expected_operator_uid)
        pol=receiver_policy(Path(policy_path))
        if expected_operator_uid==os.geteuid() or pol["allowed_sender_uids"] != [expected_operator_uid]:
            raise ValueError("receiver's allowed sender must be the other specific service UID")
        with open_directory_nofollow(Path(pol["state_root"])) as fd:private_directory(fd)
        # Do not connect or send notices from an acceptance diagnostic.
        _live_delegation_socket(Path(pol["socket_path"]), pol)
    evidence.task("live-separate-uid-receiver-socket-and-state-directory", ids_and_private_state)
    evidence.task("service-cannot-rewrite-receiver-policy",lambda:_protected_read_only(Path(policy_path)))
    evidence.pending("independently-confirmed-durable-receipt",
                     "Operator must verify sender retry/ack/no-ack and receiver restart on the actual host")
    return evidence.result()


def main(argv=None):
    ap=argparse.ArgumentParser(description="Read-only AEGIS v2 deployment evidence; cannot certify production")
    sub=ap.add_subparsers(dest="role",required=True)
    p=sub.add_parser("operator")
    for name in ("manifest","signature","trust","state-root","assessment-policy",
                 "delegation-policy","expected-agent-uid","expected-receiver-uid"):
        p.add_argument("--"+name,required=True,
                       **({"type": int} if name.endswith("-uid") else {}))
    p.add_argument("--audit-checkpoint")
    p.add_argument("--audit-public-key")
    p.add_argument("--skip-kernel",action="store_true")
    p=sub.add_parser("receiver")
    p.add_argument("--receiver-policy",required=True)
    p.add_argument("--expected-operator-uid",required=True,type=int)
    args=ap.parse_args(argv)
    try:
        if args.role=="operator":
            result=inspect_operator(manifest=args.manifest,signature=args.signature,trust=args.trust,
                state_root=args.state_root,assessment_policy=args.assessment_policy,
                delegation_policy=args.delegation_policy,expected_agent_uid=args.expected_agent_uid,
                expected_receiver_uid=args.expected_receiver_uid,
                checkpoint=args.audit_checkpoint,audit_public_key=args.audit_public_key,
                kernel=not args.skip_kernel)
        else:
            result=inspect_receiver(policy_path=args.receiver_policy,
                                    expected_operator_uid=args.expected_operator_uid)
    except (ExecutionDenied, AuditError, PreflightError, OSError, ValueError,
            RuntimeError, TypeError, KeyError) as exc:
        print(json.dumps({"schema":"AEGIS-v2-host-acceptance-evidence-v1",
            "status":"NOT_PRODUCTION_APPROVED", "role":args.role,
            "checks":[{"check":"initialization","result":"FAIL",
                       "reason":type(exc).__name__+" in protected host preflight"}]},
            separators=(",",":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # Required external sign-off is never synthesized as a successful release.
    return 2 if any(c["result"]=="FAIL" for c in result["checks"]) else 3


if __name__ == "__main__":
    raise SystemExit(main())
