# AEGIS roadmap — incremental acceptance toward v2.0

Each version is a **separately testable increment**, not a promised timeline. Working code and negative integration tests are required at every step. Build the next milestone only after the previous one meets its acceptance conditions. Failed tests block release.

| Version | Deliverable | Acceptance gate |
|---|---|---|
| **v1.2 — DONE (limited)** | Scoped local source-review execution, persistent runtime/evidence reservations, stop, audit | Valid signature runs only the known static worker; disallowed repo denied; symlink escapes denied; stop interrupts; budget persists and atomically handles concurrency; offline demo succeeds |
| **v1.3** | OS-isolated, unprivileged worker deployment with restrictive mounts, cgroups, seccomp, no general networking, and read-only assessed code | Demonstrate arbitrary child process cannot open external sockets, escape read-only file mounts, read private policy/key/credential state, or exceed CPU/memory/process limits; include adversarial tests |
| **v1.4** | Dedicated controlled HTTP(S) gateway for approved staging targets | Verify full URL-origin and method binding, DNS answer/routing restrictions, private IP policy, port and TLS identity, redirect/proxy denial, per-origin request/minute rates, concurrency and body/bytes caps; prove bypasses fail from inside sandbox |
| **v1.5** | Credential broker, authenticated exception approvals, revocation updater and replay protection | Secrets never enter model context; tokens bound to precise target; operator approval is independently authenticated/short-lived; updates and session locks enforced across restarts |
| **v1.6** | Safe adapters for static analyzers, dependency databases, permitted scanners and versioned research | Tools run under isolated supervisor, outputs sanitized; findings mapped to exact versions and source references; current advisory lookup records retrieval time and failure modes |
| **v1.7** | Controlled exploit validation, parser fuzzing, bounded concurrency/stochastic testing in isolated replicas | A verified reproducible proof demonstrates impact without live sensitive records; fuzz trials/resource ceilings hold; artifacts/minimization preserved |
| **v1.8** | Canonical report database, findings/evidence store, derived Markdown/PDF, operator notifications, retest workflow | Schema-validated findings and reports agree; no speculative finding claimed confirmed; monitored alert delivery test and transport-failure tests pass |
| **v1.9** | Autonomous hypothesis planner, deduplication, chain tracking and resumable assessments | Model can request only strongly typed permitted actions; uncertainty and verified boundaries stay separate; no path to modifying policy; recover/replay tests pass |
| **v2.0** | Integrated, provider-neutral authorized adversarial assessment platform | Full signed staging assessment: discovery -> safe validation -> chain evidence -> remediation report -> retest; all deny-path, fail-closed, rollback, security and chaos acceptance tests pass under target deployment configuration |

## Definition of v2.0 done

1. A user connects a software repository or explicitly authorized staging app via a trusted operator configuration.
2. The agent may discover and investigate high-impact flaws **without unrestricted shell, unrestricted network egress, or direct access to credentials**.
3. The supervisor enforces approval boundaries, target allowlists, request/byte/concurrency/time limits, revocation, and kill switch **at execution time** across restarts.
4. Findings provide minimal reproduction, independently verified impact, attacker starting state and reached privileges; no false claims of compromise.
5. Operator receives useful reproducible findings and a remediation/regression-test report, including clean assessments and residual uncertainty.
6. A deployment security review and practical penetration test of the supervisor itself are completed.

## v1.2 next actions

The *next* engineering milestone is v1.3: provision a locked-down worker image, test network namespace/no-egress under the actual target host, and enforce filesystem and CPU/memory constraints at the kernel/container level. No Python validation code or LLM prompt can replace those restrictions.
