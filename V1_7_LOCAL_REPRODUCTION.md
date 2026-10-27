# AEGIS v1.7 development — bounded runtime reproduction (first increment)

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
