#!/usr/bin/env python3
"""Fixed, offline v1.7 synthetic tenant-authorization contract runner.

This is NOT a general Python execution API. The trusted supervisor selects and
pins one file+callable in a privately owned policy. Only this fixed script can
execute target-controlled Python, inside the no-network, read-only, seccomp
source sandbox. No shell, package installation, live targets or credentials.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import random
import re
import stat
import sys

sys.path.insert(0, "/app")  # trusted companion, bound read-only inside isolated jail
from aegis_local_contracts import CONTRACTS, fixtures, oracle, safe_observation, case_digest, canonical

MAX_PLAN_BYTES = 8192
MAX_SOURCE_BYTES = 131072
MAX_CASES = 64
MAX_CANDIDATES = 5
GOOD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,79}\Z")
GOOD_COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,95}\Z")


class HarnessDenied(Exception):
    pass


def _deny(reason):
    raise HarnessDenied(reason)


def validate_plan(plan):
    required = {"contract", "module", "callable", "source_sha256", "seed",
                "max_cases", "mode", "case_index"}
    if (not isinstance(plan, dict) or
            set(plan) not in (required, required | {"trials"}) or
            plan["contract"] not in CONTRACTS or
            ("trials" in plan and (type(plan["trials"]) is not int or
                                   not 2 <= plan["trials"] <= 5)) or
            (plan["contract"] != "strict_tenant_owner_v1" and
             type(plan["max_cases"]) is int and type(plan.get("trials", 3)) is int and
             plan["max_cases"] * plan.get("trials", 3) > 192) or
            not isinstance(plan["module"], str) or len(plan["module"]) > 300 or
            not plan["module"].endswith(".py") or
            plan["module"].startswith("/") or
            not isinstance(plan["callable"], str) or not GOOD_NAME.fullmatch(plan["callable"]) or
            not isinstance(plan["source_sha256"], str) or
            not re.fullmatch(r"[0-9a-f]{64}", plan["source_sha256"]) or
            type(plan["seed"]) is not int or not 0 <= plan["seed"] <= 0xffffffff or
            type(plan["max_cases"]) is not int or not 8 <= plan["max_cases"] <= MAX_CASES or
            plan["mode"] not in ("fuzz", "replay") or
            (plan["mode"] == "replay" and
             (type(plan["case_index"]) is not int or not 0 <= plan["case_index"] < plan["max_cases"])) or
            (plan["mode"] == "fuzz" and plan["case_index"] is not None)):
        _deny("unapproved local harness configuration")
    pieces = plan["module"].split("/")
    if (not pieces or len(pieces) > 5 or any(
            part in (".", "..", "") or not GOOD_COMPONENT.fullmatch(part)
            for part in pieces)):
        _deny("invalid repository-relative target path")
    return plan


def _read_pinned_source(path: str, digest: str) -> bytes:
    """Walk with no-follow descriptors underneath the sandbox-only /repo."""
    parts = path.split("/")
    rootfd = os.open("/repo", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        current = rootfd
        for part in parts[:-1]:
            nextfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=current)
            if current != rootfd:
                os.close(current)
            current = nextfd
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=current)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SOURCE_BYTES:
                    _deny("target source must be a bounded ordinary file")
                raw = os.read(fd, MAX_SOURCE_BYTES + 1)
                if len(raw) > MAX_SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != digest:
                    _deny("target source changed from approved fingerprint")
                return raw
            finally:
                os.close(fd)
        finally:
            if current != rootfd:
                os.close(current)
    finally:
        os.close(rootfd)


def cases(seed: int, count: int) -> list[tuple[object, object]]:
    """Fixed synthetic principals/resources; never arbitrary model-supplied payloads."""
    rng = random.Random(seed)
    pairs: list[tuple[object, object]] = [
        ("tenant-a", "tenant-a"), ("tenant-a", "tenant-b"),
        ("Tenant-A", "tenant-a"), ("", ""), (None, None),
        (None, "tenant-a"), ("tenant-a", None), (0, "0"),
        (0, 0), (True, 1), ("../../other-tenant", "tenant-a"),
        ("tenant-a\x00tail", "tenant-a"), ("a/b", "a//b"),
        ("a\u00e9", "ae"), ("TENANT-A", "tenant-a"),
        ("tenant-a ", "tenant-a")]
    alphabet = "abcde0123456789-_"
    while len(pairs) < count:
        a = "acct-" + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 24)))
        if rng.randrange(5) == 0:
            b = a
        elif rng.randrange(5) == 0:
            b = a.upper()
        else:
            b = "acct-" + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 24)))
        pairs.append((a, b))
    return pairs[:count]


def expected(actor, owner) -> bool:
    return (actor is not None and owner is not None and
            type(actor) is type(owner) and actor == owner)


def _call(fn, actor, owner):
    # An untrusted function can print. Capture Python-level streams; raw FD
    # writes remain capped by the trusted parent's bounded pipe watchdog.
    former_stdout, former_stderr = sys.stdout, sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        result = fn(actor, owner)
        if type(result) is bool:
            return result, "boolean"
        return None, "invalid_return_type"
    except BaseException:
        return None, "raised_exception"
    finally:
        sys.stdout, sys.stderr = former_stdout, former_stderr


def _observe_contract(fn, contract, fixture):
    """Isolated target output is a bounded synthetic observation, never its text.

    Recreate state and inputs on every attempt so stateful interleavings can
    be replayed independently. Raw FD output is bounded by the supervisor.
    """
    former_stdout, former_stderr = sys.stdout, sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        if contract == "json_resource_access_v1":
            value = fn(json.loads(canonical(fixture)))
        elif contract == "versioned_cas_v1":
            state = dict(fixture["initial"])
            decisions = []
            for operation in fixture["steps"]:
                decision = fn(state, operation["version"], operation["delta"])
                if type(decision) is not bool:
                    return None
                decisions.append(decision)
            value = {"decisions": decisions, "state": state}
        else:
            return None
        return value if safe_observation(contract, value) else None
    except BaseException:
        return None
    finally:
        sys.stdout, sys.stderr = former_stdout, former_stderr


def _execute_fixed_contract(plan, fn):
    contract = plan["contract"]
    schedule = fixtures(contract, plan["seed"], plan["max_cases"])
    indexes = ([plan["case_index"]] if plan["mode"] == "replay"
               else list(range(len(schedule))))
    trials = plan.get("trials", 3)
    mismatch_count = 0
    errors = 0
    unstable = 0
    candidates = []
    for index in indexes:
        fixture = schedule[index]
        baseline = oracle(contract, fixture)
        results = [_observe_contract(fn, contract, fixture) for _ in range(trials)]
        if any(result is None for result in results):
            errors += 1
            continue
        observed = results[0]
        repeat_matches = all(result == observed for result in results[1:])
        if not repeat_matches:
            unstable += 1
        if observed != baseline or not repeat_matches:
            mismatch_count += 1
            if len(candidates) < MAX_CANDIDATES:
                candidates.append({
                    "case_index": index, "synthetic_input": fixture,
                    "expected": baseline, "observed": observed,
                    "repeated_same_result": repeat_matches,
                    "classification": ("local_contract_mismatch_needs_validation" if repeat_matches else
                                       "local_nondeterministic_case_needs_validation"),
                })
    return {
        "status": "BOUNDED_OFFLINE_AUTHORIZATION_REPRODUCTION_ONLY",
        "contract": contract, "source_sha256": plan["source_sha256"],
        "mode": plan["mode"], "seed": plan["seed"],
        "case_digest": case_digest(schedule), "trials_per_case": trials,
        "cases_requested": len(indexes), "cases_executed": len(indexes),
        "mismatches": mismatch_count, "non_boolean_or_exception": errors,
        "unstable_repetitions": unstable, "candidates": candidates,
        "summary": {"synthetic_cases": len(indexes),
                    "repeated_mismatches": sum(c["repeated_same_result"] for c in candidates),
                    "deployment_impact": "NOT_ESTABLISHED", "finding_status": "needs_validation"},
    }


def execute(plan):
    validate_plan(plan)
    source = _read_pinned_source(plan["module"], plan["source_sha256"])
    ns = {"__name__": "__aegis_isolated_test_target__",
          "__file__": "/repo/" + plan["module"]}
    # Arbitrary target-code execution is restricted by the Linux worker jail,
    # not by Python builtins. It is deliberately not executed in the parent.
    exec(compile(source, ns["__file__"], "exec"), ns, ns)
    fn = ns.get(plan["callable"])
    if not callable(fn):
        _deny("selected callable missing from approved source")
    if plan["contract"] != "strict_tenant_owner_v1":
        return _execute_fixed_contract(plan, fn)
    schedule = cases(plan["seed"], plan["max_cases"])
    indexes = ([plan["case_index"]] if plan["mode"] == "replay"
               else list(range(len(schedule))))
    candidates = []
    errors = 0
    mismatch_count = 0
    repeat_failures = 0
    for index in indexes:
        actor, owner = schedule[index]
        should_allow = expected(actor, owner)
        got, kind = _call(fn, actor, owner)
        if kind != "boolean":
            errors += 1
            continue
        if got != should_allow:
            mismatch_count += 1
            again, second_kind = _call(fn, actor, owner)
            reproduced = second_kind == "boolean" and again == got
            if not reproduced:
                repeat_failures += 1
            if len(candidates) < MAX_CANDIDATES:
                candidates.append({
                    "case_index": index, "synthetic_actor": actor,
                    "synthetic_owner": owner, "expected_authorized": should_allow,
                    "observed_authorized": got,
                    "repeated_same_result": reproduced,
                    "classification": "local_oracle_mismatch_needs_validation",
                })
    return {
        "status": "BOUNDED_OFFLINE_AUTHORIZATION_REPRODUCTION_ONLY",
        "contract": plan["contract"], "source_sha256": plan["source_sha256"],
        "mode": plan["mode"], "seed": plan["seed"],
        "cases_requested": len(indexes), "cases_executed": len(indexes),
        "mismatches": mismatch_count, "non_boolean_or_exception": errors,
        "unstable_repetitions": repeat_failures, "candidates": candidates,
        "summary": {"synthetic_cases": len(indexes), "repeated_mismatches": sum(
            c["repeated_same_result"] for c in candidates),
            "deployment_impact": "NOT_ESTABLISHED", "finding_status": "needs_validation"},
    }


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_PLAN_BYTES + 1)
        if len(raw) > MAX_PLAN_BYTES:
            _deny("local harness plan exceeds bound")
        plan = json.loads(raw)
        result = execute(plan)
        output = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
        if len(output) > 16384:
            _deny("local harness evidence exceeds bound")
        print(output)
        return 0
    except (HarnessDenied, OSError, ValueError, TypeError, SyntaxError, MemoryError,
            UnicodeError, RecursionError, json.JSONDecodeError):
        sys.stderr.write("FUZZ_WORKER_DENIED\n")
        return 76


if __name__ == "__main__":
    raise SystemExit(main())
