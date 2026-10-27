# AEGIS v1.7 — bounded local reproduction acceptance

Status: **implementation-complete for its stated bounded, local Python contract scope**. This is a stacked development pull request, not a tagged v1.7 release or a production penetration-testing capability.

## Supported, independently reviewable functionality

- The operator must authorize the exact local repository, relative Python file, function name, SHA-256 and one of the three fixed security invariants.
- **strict_tenant_owner_v1:** deterministic, synthetic identity/owner comparison.
- **json_resource_access_v1:** exact JSON fields, type/identity validation and unauthorized access denial.
- **versioned_cas_v1:** synthetic sequential interleavings for versioned compare-and-swap operations; no claim of simultaneous race execution.
- A non-root, read-only Linux user/mount/network/PID namespace executes target code under the existing default-deny seccomp profile with no outgoing sockets, process creation or host writes.
- Each new-contract case has 2–5 bounded attempts; `max_cases * trials <= 192`. Evidence is checked against a separate trusted oracle with no arbitrary worker-supplied narrative.
- The operator may independently verify a prior local mismatch in a second **fresh** sandbox. It checks recorded private evidence, exact source fingerprint and policy, selects the minimal candidate and reserves an additional persistent runtime/evidence budget.
- Both actions respond to live scope revocation, emergency stop, changed operator policy, bounded output and wall-clock deadlines. Reported outcomes remain `needs_validation` until actual authorized deployment impact is established.
- Cloudflare's multi-agent audit methodology remains scheduled for v2.1, not silently imported into v1.7.

## Evidence and test matrix

Committed expansion includes `aegis_local_contracts.py`, extended `aegis_bounded_fuzz_worker.py`, the `aegis_fuzz_runtime.py` replay verifier, sandbox fixed-file mount, `tests/test_v17_extended.py`, the disabled example policy and operator documentation.

- Non-root Linux local check on the exact GitHub source revision: **30 focused tests passed**, zero failures/skips. This is not a claim that the inherited full suite completed locally.
- GitHub Actions on Ubuntu 22.04 and system Python 3.10: **296 tests passed**, no failures or skips.
- GitHub Actions on Ubuntu 24.04 and system Python 3.12: **296 tests passed**, no failures or skips.
- Both CI kernels exercised the inherited source/network syscall denial diagnostics and authenticated-worker regressions. GitHub source-export artifacts allow independent checkout and checksum verification.
- Acceptance evidence: https://github.com/xRedLeader/AEGIS/actions/runs/40579625681

## Explicit exclusions

There is no arbitrary agent-supplied code execution, live target exploitation, external HTTP probing from the fuzz worker, production credentials, native-language fuzz harness, true simultaneous thread-race engine, or guaranteed security assessment. A local mismatch is not by itself a confirmed exploitable vulnerability.

Merge/release gates remain distinct: PR #3 (v1.5) and PR #4 (v1.6) are parents of this stacked PR. Review those and the deployment host before treating the integrated stack as a deployable release. Do not merge PR #5 directly into main while parents are drafts. v1.4.1 and main are not modified.
