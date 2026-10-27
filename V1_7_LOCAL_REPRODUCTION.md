# AEGIS v1.7 — bounded runtime reproduction (expanded local-contract implementation)

**Stacked development PR, not a released assessment capability.** Based on the open
v1.6 branch, which itself depends on v1.5. `main`, release tags, and production
credential tooling are not modified by this change.

## Implemented operator-only workflow

This increment introduces **one fixed security invariant**:
`strict_tenant_owner_v1`. The operator identifies a repository Python module and
callable of the form `fn(actor_id, resource_owner_id) -> bool`. For this *specific
operator-selected contract*, a request is allowed only if both identifiers are
present, have the same Python type, and compare exactly equal. The operator must
confirm that this is the target application's intended authorization rule;
AEGIS does not infer business policy from an arbitrary Python file.

1. The signed engagement and independently protected trust policy must both allow
   `bounded_fuzzing` for the exact authorized repository. No permission is inferred
   from `source_review`, `dependency_analysis`, or HTTP testing.
2. The operator maintains an independently protected, mode-0600
   `fuzz-policy.json` outside every assessed repository, supervisor state,
   and `/usr`. It positively binds a repository path, module path, callable,
   SHA-256 of the exact source file, fixed contract, and maximum case count.
   The example policy is **disabled** and its fingerprint is a placeholder.
3. The trusted parent validates inputs **before** reserving the normal persistent
   runtime/evidence budgets. The fixed trusted launcher binds the authorized
   repository read-only/noexec into a rootless user/mount/network/PID namespace,
   closes inherited host file descriptors, drops capabilities, and applies
   default-deny seccomp. No external sockets, child processes, host filesystem
   writes, package installation, or target-controlled command arguments are enabled.
4. Inside the isolated namespace, the fixed worker reads the pinned module with
   no-follow directory handles, verifies the file fingerprint, executes only the
   configured callable, and runs at most 64 deterministic synthetic tenant pairs
   using an operator-chosen seed. It never accesses real identities or customer
   records. A repeat of a mismatched result is recorded; failures and non-boolean
   results are counted separately.
5. The parent drains both child output pipes with strict byte caps and a wall-time
   deadline, revalidates revocation, emergency stop, and the operator policy during
   the run, verifies output against its own synthetic oracle, and writes a private
   bounded `bounded-fuzz.json` artifact. The seeded input pair, expected/observed
   boolean, pinned hash, and case index permit a **separate replay run**.

Each call is charged to the persistent signed `bounded_fuzzing` budget, including
failed or interrupted runs. An audit event accompanies reservation and completion.

## Operator command example

First pin a *real* file SHA-256 and callable from your authorized isolated test
repository in a private policy file. Do not copy and enable the sample unchanged.

```sh
# Test synthetic cases within the read-only Linux jail.
python aegis_fuzz_runtime.py \
  --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis \
  --fuzz-policy /etc/aegis/fuzz-policy.json \
  --repo /srv/aegis/authorized-repo \
  --module auth/tenant_check.py \
  --seed 42 --cases 24 --seconds 10

# Recheck a recorded case with the same seed, count, source and signed scope.
python aegis_fuzz_runtime.py \
  --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis \
  --fuzz-policy /etc/aegis/fuzz-policy.json \
  --repo /srv/aegis/authorized-repo \
  --module auth/tenant_check.py \
  --seed 42 --cases 24 --seconds 10 --replay-case 2
```

Only an operator-controlled, non-root Linux service should invoke this command.
It is **not** an agent tool, authenticated operator-service API operation, or a
license to execute arbitrary uploaded scripts. Review the target fixture, keep
synthetic data only, and never point it at live shared services.

## Evidence and interpretation

- The report is a bounded **local hypothesis / reproduction record**. Even a
  repeated mismatch does **not** establish deployed exploitability, actual
  cross-tenant data access, or severity. A separate verifier must examine the
  real call path and any preventing security controls.
- Only one intentionally narrow authorization contract is supported. There are
  **no** arbitrary model-chosen payloads, live HTTP mutation, fuzzed native
  binaries, user-supplied shell commands, code-coverage guidance, or unrestricted
  exploit chains. Other application-specific contracts require separately
  reviewed fixed adapters and explicit operator approval.
- Target-controlled Python executes within the kernel sandbox and can access
  read-only code within the authorized repository. A compromised kernel,
  privileged host, operator authority, or another unrestricted agent shell
  remains outside this boundary. The policy and reported results cannot replace
  deployment-host security review.
- The project does not claim a clean target after zero mismatches. The supplied
  oracle represents **only** the selected narrow invariant and tested inputs.

## Release gate

Run the new v1.7 tests and full inherited security suite with **no skipped tests**
on supported Ubuntu 22.04 and 24.04 non-root execution environments. Tests must
include genuine namespaces/seccomp, out-of-repository symlinks, malicious target
socket/file/write attempts, source fingerprint drift, runaway output, replay,
audit/budget accounting, and emergency stop. Independently review the confined
Python execution surface before broadening to native tools or live targets.

## Expanded v1.7 contract catalog and resource controls

The fixed offline worker supports exactly three operator-selected contracts:

| Contract | Expected callable | Reproduction model |
|---|---|---|
| `strict_tenant_owner_v1` | `fn(actor_id, owner_id) -> bool` | Exact synthetic owner/type equality, existing deterministic repeats |
| `json_resource_access_v1` | `fn(request_object) -> bool` | Strict `actor`, `owner`, `operation=read` JSON object; rejects unknown keys, mismatched identities and invalid primitive types |
| `versioned_cas_v1` | `fn(state_object, expected_version, delta) -> bool` | Synthetic versioned-state transitions with fresh state for each trial; detects stale-read acceptance and divergent states |

The latter two contracts run 2–5 repeats per synthetic case and a maximum of 192 total calls per assessment. `max_trials` in the operator-owned policy further reduces that ceiling. The versioned-state harness enumerates **serialized interleavings**, not simultaneous threads or a demonstrated physical race condition.

The trusted parent validates every reported synthetic case, its exact canonical fixture digest, expected oracle answer, observed value type, repeated-result classification and case-accounting bounds. Candidate records remain `needs_validation`. Target exceptions, printed output, imported modules, authorization policy files and unapproved artifacts do not become evidence.

## Independent fresh-sandbox reproduction

A completed run with candidates includes a parent-selected `minimal_reproducer` recipe: source SHA-256, contract, seed, case count and case index. The operator may run:

```sh
python aegis_fuzz_runtime.py \
  --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json --state-root /var/lib/aegis \
  --fuzz-policy /etc/aegis/fuzz-policy.json \
  --repo /srv/aegis/authorized-repo --module api/json_authorize.py \
  --verify-run <completed-run-uuid> --seconds 10
```

The supervisor loads the completed, private evidence file with no-follow checks and verifies the recorded candidate against a fresh, independently reconstructed oracle and the current operator policy. It then reserves **another** persistent runtime/evidence budget and executes only the smallest case in a newly constructed kernel namespace, with the original source file pinned by hash. The returned comparison is either `LOCAL_REPRODUCED_NEEDS_DEPLOYMENT_VALIDATION` or `LOCAL_NOT_INDEPENDENTLY_REPRODUCED`, with an audit event recording both run IDs.

Replayed mismatches are **not proven exploitation**. No deployment host, external network, customer account or real credential is contacted by this local capability. Explicit service/target authorization, true concurrent race testing, native-language fuzzing, general fault injection and independently confirmed deployed impact remain future work and are not silently substituted by this harness.

## Acceptance tests

Run `python -m unittest discover -s tests -v` on a supported non-root Linux service host with functional namespace/seccomp restrictions; skipped kernel tests block acceptance. The test suite includes the original `test_v17_fuzz.py` and the independent-replay and policy-negative checks in `test_v17_extended.py`.

Before merge, ensure the GitHub Ubuntu 22.04 and 24.04 acceptance workflow passes at the **actual PR head**, check tracked SHA-256 sums, and review the inherited v1.5/v1.6 stacked change gates. No release tag or `main` changes are made by this branch.
