# AEGIS v1.7 — bounded local security-invariant testing

**Implementation complete for the three named local Python contracts; stacked development PR, not a tagged release.** v1.7 builds on the unmerged v1.6 and v1.5 feature branches. It does not expand AEGIS's signed authorization, grant any agent an arbitrary shell, or enable live exploitation. Operators must complete the inherited reviews and deployment-host acceptance before release.

## Trust and execution boundary

Every test requires `bounded_fuzzing` in both the Ed25519-signed engagement and independent operator trust. A protected, disabled-by-default `fuzz-policy.json` must explicitly name the authorized repository, a relative Python source path, callable, expected source SHA-256, contract, maximum case count and optionally a stricter maximum-trials ceiling. The parent does not execute target-controlled repository code.

The worker executes **only** the named, SHA-256-pinned Python callable within the existing rootless Linux user, mount, network and PID namespaces, a read-only/noexec repository bind mount and default-deny seccomp. The sandbox blocks new sockets, process spawning, host filesystem writes and access to operator policy/keys/ledger. Arbitrary model-selected executable paths, dependencies, shell commands, networking, external targets and customer records are not supported. Kernel/user-namespace support is mandatory; no unconfined fallback exists.

The supervisor reserves the signed persistent runtime and evidence budgets before execution, drains bounded stdin/stdout/stderr, enforces an independent deadline and continuously checks emergency stop, engagement revocation and operator policy. Aborted and failed runs retain their reservations and audit history. The worker can emit only validated, bounded, synthetic result records; its exception strings, raw prints and untrusted source text are never copied into evidence.

## Fixed operator-selected contracts

| Contract | Callable interface | Precisely defined synthetic invariant |
|---|---|---|
| `strict_tenant_owner_v1` | `fn(actor_id, owner_id) -> bool` | Both IDs exist, have exactly the same type and compare equal |
| `json_resource_access_v1` | `fn(request_object) -> bool` | Exactly the fields `actor`, `owner`, `operation`; the operation is `read`; both IDs are nonempty, identical strings |
| `versioned_cas_v1` | `fn(state, expected_version, delta) -> bool` | Mutate by exactly one only when the expected version is a matching integer and the delta is integer 1; preserve state otherwise |

The operator, not the agent, determines whether a contract actually models the assessed application's business and authorization semantics. A mismatch is a **local hypothesis requiring validation**, not automatically a vulnerability.

Synthetic inputs are seeded and bounded. Each run uses 8–64 cases and a maximum of five recorded candidates. The JSON and CAS contracts support two to five independent repetitions per case with a maximum of 192 tested invocations per run; the operator policy may reduce either limit. The original tenant-ownership contract retains its fixed deterministic repeat semantics. Failure, wrong return type and instability are accounted for separately. **Versioned CAS exercises synthetic serialized interleavings—not real parallel threads or an established race condition.**

## Evidence and replay

The supervisor checks the worker output against its own trusted oracle, exact input cases, case digest, status fields, bounded counts and expected output types before writing `bounded-fuzz.json` to the private engagement report directory. Unverified or unstable results remain `needs_validation` and receive no asserted deployed impact or severity.

When a run has candidates, the trusted parent selects a smallest **candidate among the recorded bounded candidate set**, not a globally minimized exploit. Its replay recipe binds the case index, seed, case count, selected contract, **exact source module and callable**, source SHA-256 and the requirement for a fresh sandbox. This prevents attributing an earlier result to another approved path with identical source bytes.

An operator can independently verify completed local evidence:

```sh
python aegis_fuzz_runtime.py \
  --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis \
  --fuzz-policy /etc/aegis/fuzz-policy.json \
  --repo /srv/aegis/authorized-repo \
  --module auth/tenant_check.py \
  --verify-run <completed-run-uuid> --seconds 10
```

The verifier loads only protected, completed evidence, rejects modifications or an incompatible current scope/policy/module/callable, rechecks the synthetic oracle, reserves a **second** runtime/evidence budget and launches a different sandbox for one replay case. It compares the exact observed local result. Outcomes are `LOCAL_REPRODUCED_NEEDS_DEPLOYMENT_VALIDATION` or `LOCAL_NOT_INDEPENDENTLY_REPRODUCED`; a separate audit event links the run IDs. Unstable cases are never promoted to reproduced. This is an independent **execution**, not the separate researcher/verifier agent roles planned for v2.1.

## Operator command and examples

Only a protected, non-root operator-service identity may invoke the v1.7 CLI. The existing v1.5 signed Unix operator API **does not** automatically expose these operations to AI agents.

```sh
python aegis_fuzz_runtime.py \
  --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis \
  --fuzz-policy /etc/aegis/fuzz-policy.json \
  --repo /srv/aegis/authorized-repo \
  --module auth/tenant_check.py \
  --seed 42 --cases 24 --seconds 10
```

The sample `fuzz-policy.example.json` is intentionally disabled, uses placeholder hashes and lists all three fixed contract shapes. Do not enable it unchanged.

## Verification and release gate

The kernel acceptance suite includes `tests/test_v17_fuzz.py` and `tests/test_v17_extended.py`. It covers valid/mismatching synthetic functions, repeatability and unstable runs, serialized CAS schedules, concurrent supervisor budget reservations, real no-network/no-write namespaces and seccomp, symlink denial, source fingerprint changes, bounded pipe output, stop/revocation, altered evidence, cross-scope replay, and exact module/callable attribution.

**Before declaring a release:** pass the complete inherited suite with zero failures and zero skipped security tests on Ubuntu 22.04 and 24.04 at the actual PR commit; verify tracked-source checksums, kernel sandbox probes, budgets, negative cases and audit integrity; review the installed deployment host and the stacked v1.5/v1.6 dependencies. CI proves only the tested host/runtime and fixed contracts. Do not tag or merge directly into `main` while prerequisite PRs remain unmerged.

### Deliberately outside v1.7

No live exploitation, real customer accounts, arbitrary native binaries, general-purpose fuzzing, production HTTP request mutation, true simultaneous thread race testing, automatic business-policy inference, or deployed-impact confirmation is enabled. Do not treat absence of mismatches as a claim that a program is secure. Broader end-to-end runtime validation belongs in the later authorized platform milestones; Cloudflare multi-agent coverage/review methodology is explicitly scheduled for **v2.1**, not silently pulled into this executor.
