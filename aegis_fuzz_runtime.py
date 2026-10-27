#!/usr/bin/env python3
"""v1.7 operator-only bounded, offline synthetic authorization tester.

No agent-facing arbitrary-code execution API exists. Exact module SHA/callable,
synthetic oracle, case limits and repository are operator-pinned; target Python
executes ONLY inside the existing rootless, network-denied source sandbox.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time

from aegis_bounded_fuzz_worker import validate_plan, cases, expected, HarnessDenied
from aegis_local_contracts import fixtures, oracle, safe_observation, case_digest, canonical, CONTRACTS
from aegis_http_broker import bounded_exchange, TransportError
from aegis_supervisor import (
    AegisSupervisor, ExecutionDenied, deny, open_directory_nofollow,
    private_directory, preexec_limits, MAX_RESULT_BYTES,
)

MAX_POLICY = 16384
MAX_TARGETS = 16
CONTRACT = "strict_tenant_owner_v1"


def load_operator_policy(path: Path, repo: Path, state: Path) -> dict:
    """No-follow operator-owned policy; never allow a target-controlled path."""
    path = Path(path)
    if not path.is_absolute() or path.name in ("", ".", ".."):
        deny("operator fuzz policy must be an absolute trusted file")
    with open_directory_nofollow(path.parent) as parent:
        st_dir = os.fstat(parent)
        if (st_dir.st_uid not in (0, os.geteuid()) or
                st_dir.st_mode & 0o022):
            deny("operator fuzz policy parent must not be writable by outsiders")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.geteuid()) or
                    st.st_mode & 0o077 or st.st_size > MAX_POLICY or st.st_nlink != 1):
                deny("untrusted operator fuzz policy owner, mode or size")
            raw = os.read(fd, MAX_POLICY + 1)
            if len(raw) > MAX_POLICY:
                deny("oversized operator fuzz policy")
        finally:
            os.close(fd)
    if (repo == path or repo in path.parents or
            state == path or state in path.parents or
            Path("/usr") == path or Path("/usr") in path.parents):
        deny("operator fuzz policy overlaps worker-visible or mutable files")

    def unique(pairs):
        data = {}
        for k, v in pairs:
            if k in data:
                deny("duplicate operator fuzz policy field")
            data[k] = v
        return data
    try:
        obj = json.loads(raw, object_pairs_hook=unique,
                         parse_constant=lambda _: deny("non-finite policy number"))
    except (UnicodeError, ValueError, RecursionError, json.JSONDecodeError) as exc:
        raise ExecutionDenied("invalid operator fuzz policy encoding") from exc
    if (not isinstance(obj, dict) or
            set(obj) != {"schema_version", "configured", "authorized_repository", "targets"} or
            obj["schema_version"] != 1 or obj["configured"] is not True or
            obj["authorized_repository"] != str(repo) or
            not isinstance(obj["targets"], dict) or not 1 <= len(obj["targets"]) <= MAX_TARGETS):
        deny("operator fuzz policy is not enabled for this exact repository")
    for path_name, item in obj["targets"].items():
        if (not isinstance(item, dict) or
                set(item) not in ({"sha256", "callable", "contract", "max_cases"},
                                  {"sha256", "callable", "contract", "max_cases", "max_trials"})):
            deny("operator fuzz target entry missing fields")
        if ("max_trials" in item and
                (type(item["max_trials"]) is not int or not 2 <= item["max_trials"] <= 5)):
            deny("operator local trial bound invalid")
        try:
            validate_plan({"module": path_name, "callable": item["callable"],
                           "source_sha256": item["sha256"], "contract": item["contract"],
                           "seed": 0, "max_cases": item["max_cases"],
                           "mode": "fuzz", "case_index": None})
        except HarnessDenied as exc:
            raise ExecutionDenied("invalid fixed operator fuzz target") from exc
    return obj


class AegisFuzzSupervisor(AegisSupervisor):
    def __init__(self, manifest, signature, trust_policy, state_root, fuzz_policy):
        super().__init__(manifest, signature, trust_policy, state_root)
        self.fuzz_policy = Path(fuzz_policy)

    def _check_result(self, result, plan):
        """All child output is untrusted; allow only bounded fixed-form evidence."""
        if plan["contract"] != CONTRACT:
            return self._check_extended_result(result, plan)
        keys = {"status", "contract", "source_sha256", "mode", "seed",
                "cases_requested", "cases_executed", "mismatches",
                "non_boolean_or_exception", "unstable_repetitions", "candidates", "summary"}
        requested = 1 if plan["mode"] == "replay" else plan["max_cases"]
        if (not isinstance(result, dict) or set(result) != keys or
                result["status"] != "BOUNDED_OFFLINE_AUTHORIZATION_REPRODUCTION_ONLY" or
                result["contract"] != plan["contract"] or
                result["source_sha256"] != plan["source_sha256"] or
                result["mode"] != plan["mode"] or result["seed"] != plan["seed"] or
                any(type(result[k]) is not int or not 0 <= result[k] <= requested for k in
                    ("cases_requested", "cases_executed", "mismatches", "non_boolean_or_exception", "unstable_repetitions")) or
                result["cases_requested"] != requested or
                result["cases_executed"] != requested or
                not isinstance(result["candidates"], list) or len(result["candidates"]) > 5 or
                not isinstance(result["summary"], dict) or
                set(result["summary"]) != {"synthetic_cases", "repeated_mismatches", "deployment_impact", "finding_status"} or
                result["summary"]["synthetic_cases"] != requested or
                result["summary"]["deployment_impact"] != "NOT_ESTABLISHED" or
                result["summary"]["finding_status"] != "needs_validation" or
                type(result["summary"]["repeated_mismatches"]) is not int or
                not 0 <= result["summary"]["repeated_mismatches"] <= len(result["candidates"])):
            deny("invalid or untrusted bounded fuzz worker evidence")
        schedule = cases(plan["seed"], plan["max_cases"])
        seen = set()
        for item in result["candidates"]:
            if not isinstance(item, dict) or set(item) != {
                "case_index", "synthetic_actor", "synthetic_owner", "expected_authorized",
                "observed_authorized", "repeated_same_result", "classification"}:
                deny("invalid synthetic authorization candidate fields")
            i = item["case_index"]
            if (type(i) is not int or i in seen or not 0 <= i < plan["max_cases"] or
                (plan["mode"] == "replay" and i != plan["case_index"])):
                deny("invalid synthetic case index")
            seen.add(i)
            a, b = schedule[i]
            if (type(item["synthetic_actor"]) is not type(a) or
                    type(item["synthetic_owner"]) is not type(b) or
                    item["synthetic_actor"] != a or item["synthetic_owner"] != b or
                    type(item["expected_authorized"]) is not bool or
                    item["expected_authorized"] != expected(a, b) or
                    type(item["observed_authorized"]) is not bool or
                    item["observed_authorized"] == expected(a, b) or
                    type(item["repeated_same_result"]) is not bool or
                    item["classification"] != "local_oracle_mismatch_needs_validation"):
                deny("synthetic candidate does not match trusted local oracle")
        if result["mismatches"] < len(result["candidates"]) or (
                result["mismatches"] + result["non_boolean_or_exception"] > requested):
            deny("inconsistent synthetic test accounting")
        return result

    def _check_extended_result(self, result, plan):
        """Independently check every synthetic datum and local oracle in worker output."""
        required = {"status", "contract", "source_sha256", "mode", "seed", "case_digest",
                    "trials_per_case", "cases_requested", "cases_executed", "mismatches",
                    "non_boolean_or_exception", "unstable_repetitions", "candidates", "summary"}
        wanted = 1 if plan["mode"] == "replay" else plan["max_cases"]
        schedule = fixtures(plan["contract"], plan["seed"], plan["max_cases"])
        if (not isinstance(result, dict) or set(result) != required or
                result["status"] != "BOUNDED_OFFLINE_AUTHORIZATION_REPRODUCTION_ONLY" or
                result["contract"] != plan["contract"] or
                result["source_sha256"] != plan["source_sha256"] or
                result["mode"] != plan["mode"] or result["seed"] != plan["seed"] or
                result["case_digest"] != case_digest(schedule) or
                type(result["trials_per_case"]) is not int or
                result["trials_per_case"] != plan.get("trials", 3) or
                any(type(result.get(k)) is not int or not 0 <= result[k] <= wanted
                    for k in ("cases_requested", "cases_executed", "mismatches",
                              "non_boolean_or_exception", "unstable_repetitions")) or
                result["cases_requested"] != wanted or result["cases_executed"] != wanted or
                result["mismatches"] + result["non_boolean_or_exception"] > wanted or
                result["unstable_repetitions"] > result["mismatches"] or
                not isinstance(result["candidates"], list) or len(result["candidates"]) > 5 or
                not isinstance(result["summary"], dict) or
                set(result["summary"]) != {"synthetic_cases", "repeated_mismatches",
                                           "deployment_impact", "finding_status"} or
                result["summary"]["synthetic_cases"] != wanted or
                result["summary"]["deployment_impact"] != "NOT_ESTABLISHED" or
                result["summary"]["finding_status"] != "needs_validation" or
                type(result["summary"]["repeated_mismatches"]) is not int):
            deny("invalid offline contract result envelope")
        seen = set()
        for item in result["candidates"]:
            if (not isinstance(item, dict) or set(item) != {"case_index", "synthetic_input",
                    "expected", "observed", "repeated_same_result", "classification"} or
                    type(item["case_index"]) is not int or
                    not 0 <= item["case_index"] < plan["max_cases"] or
                    item["case_index"] in seen or
                    (plan["mode"] == "replay" and item["case_index"] != plan["case_index"])):
                deny("invalid local contract case identity")
            idx = item["case_index"]
            seen.add(idx)
            reference = schedule[idx]
            expected_value = oracle(plan["contract"], reference)
            if (canonical(item["synthetic_input"]) != canonical(reference) or
                    canonical(item["expected"]) != canonical(expected_value) or
                    not safe_observation(plan["contract"], item["observed"]) or
                    type(item["repeated_same_result"]) is not bool or
                    item["classification"] not in
                       ("local_contract_mismatch_needs_validation",
                        "local_nondeterministic_case_needs_validation")):
                deny("untrusted local contract candidate")
            matches_oracle = canonical(item["observed"]) == canonical(expected_value)
            if (item["repeated_same_result"] and (matches_oracle or
                    item["classification"] != "local_contract_mismatch_needs_validation")):
                deny("untrusted stable contract candidate")
            if (not item["repeated_same_result"] and
                    item["classification"] != "local_nondeterministic_case_needs_validation"):
                deny("untrusted unstable contract candidate")
        if (result["mismatches"] < len(result["candidates"]) or
                result["summary"]["repeated_mismatches"] != sum(
                    item["repeated_same_result"] for item in result["candidates"])):
            deny("inconsistent local contract candidate accounting")
        return result

    def execute(self, repository: Path, module: str, *, seed: int, max_cases: int,
                seconds: int = 15, mode: str = "fuzz", case_index: int | None = None) -> dict:
        if sys.platform != "linux" or os.geteuid() == 0:
            deny("bounded runtime validation requires non-root Linux")
        info, manifest = self._guard()
        if "bounded_fuzzing" not in info["approved_methods"]:
            deny("signed scope and operator must approve bounded_fuzzing")
        repo = Path(repository)
        if not repo.is_absolute() or str(repo.resolve()) not in info["authorized_repositories"]:
            deny("runtime target is outside signed repository scope")
        policy = load_operator_policy(self.fuzz_policy, repo, self.state_root)
        if module not in policy["targets"]:
            deny("unregistered local test target")
        item = policy["targets"][module]
        if type(max_cases) is not int or not 8 <= max_cases <= item["max_cases"]:
            deny("case count exceeds operator-authorized bound")
        if type(seconds) is not int or not 2 <= seconds <= 30:
            deny("local test duration exceeds fixed worker ceiling")
        plan = {"contract": item["contract"], "module": module,
                "callable": item["callable"], "source_sha256": item["sha256"],
                "seed": seed, "max_cases": max_cases, "mode": mode,
                "case_index": case_index}
        try:
            validate_plan(plan)
        except HarnessDenied as exc:
            raise ExecutionDenied("invalid bounded test plan") from exc
        # Do not read any repository-controlled source in the privileged parent.
        with open_directory_nofollow(repo) as repo_fd:
            info, manifest, run_id = self.reserve(seconds, "bounded_fuzzing")
            eid = info["engagement_id"]
            worker = None
            jail = None
            try:
                self._guard()
                load_operator_policy(self.fuzz_policy, repo, self.state_root)
                jail = Path(tempfile.mkdtemp(prefix="fuzz-jail-", dir=self.state_root))
                command = self._worker_command(repo_fd, jail, "fuzz")
                worker = subprocess.Popen(command, stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/",
                    start_new_session=True, pass_fds=(repo_fd,),
                    env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1",
                         "PYTHONDONTWRITEBYTECODE": "1"},
                    preexec_fn=lambda: preexec_limits(seconds))
                def guard():
                    self._guard()
                    # Operator cannot widen/replace target permission mid-run.
                    current = load_operator_policy(self.fuzz_policy, repo, self.state_root)
                    if current != policy:
                        deny("operator fuzz target policy changed during local test")
                try:
                    result = bounded_exchange(worker, plan, seconds, guard,
                                              output_limit=MAX_RESULT_BYTES)
                except (TransportError, OSError, ValueError, subprocess.SubprocessError) as exc:
                    raise ExecutionDenied("isolated bounded test failed or was denied") from exc
                self._check_result(result, plan)
                guard()
                raw = json.dumps(result, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True).encode("ascii")
                if len(raw) > MAX_RESULT_BYTES:
                    deny("offline test evidence exceeds persistent reservation")
                report = self._write_report(info, run_id, raw, "bounded-fuzz.json")
                self._finish(eid, run_id, "completed")
                return {"status": "COMPLETED_BOUNDED_LOCAL_VALIDATION_ONLY",
                        "engagement_id": eid, "run_id": run_id, "report": report,
                        "summary": result["summary"], "mismatches": result["mismatches"],
                        "source_sha256": item["sha256"], "seed": seed,
                        "isolation": "OFFLINE_NETWORK_DENIED_READONLY_SECCOMP",
                        "warning": "Local synthetic oracle mismatches are not established deployment exploits."}
            except BaseException as exc:
                if worker is not None and worker.poll() is None:
                    self._kill_worker(worker)
                self._finish(eid, run_id, "aborted", type(exc).__name__)
                raise
            finally:
                if worker is not None:
                    if worker.poll() is None:
                        self._kill_worker(worker)
                    worker.wait()
                    for stream in (worker.stdin, worker.stdout, worker.stderr):
                        if stream is not None and not stream.closed:
                            stream.close()
                if jail is not None:
                    try:
                        jail.rmdir()
                    except OSError:
                        pass


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Operator-only bounded local authorization testing")
    for key in ("manifest", "signature", "trust", "state-root", "fuzz-policy", "repo", "module"):
        ap.add_argument("--" + key, required=True)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--cases", type=int, default=24)
    ap.add_argument("--seconds", type=int, default=15)
    ap.add_argument("--replay-case", type=int)
    a = ap.parse_args(argv)
    try:
        sup = AegisFuzzSupervisor(a.manifest, a.signature, a.trust, a.state_root, a.fuzz_policy)
        output = sup.execute(Path(a.repo), a.module, seed=a.seed, max_cases=a.cases,
                             seconds=a.seconds, mode="replay" if a.replay_case is not None else "fuzz",
                             case_index=a.replay_case)
        print(json.dumps(output, sort_keys=True, separators=(",", ":")))
        return 0
    except (ExecutionDenied, TransportError, OSError, ValueError, TypeError):
        print("BOUNDED_LOCAL_TEST_DENIED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
