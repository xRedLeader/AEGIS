# AEGIS milestones toward v2.1

Each milestone is a separately tested increment, not a promised timeline. Unimplemented capabilities are future work. Failed or unexecuted acceptance gates block release.

| Version | Milestone | Status and acceptance gate |
|---|---|---|
| v1.2 | Executable local supervisor, persistent budgets, emergency stop, audit trail | Implemented for fixed source review; signed scopes, persistent accounting, concurrency, stop and audit tests required. |
| v1.3 | Isolated worker environment with operating-system-enforced restrictions | Implemented for the fixed source worker; real namespace/seccomp tests and fresh interpreter execution required. No arbitrary-tool guarantee. |
| v1.3.1 | Default-deny seccomp and signed audit checkpoints | Implemented; external checkpoint retention remains operator-owned. |
| v1.4 | Controlled HTTP/HTTPS testing gateway with strict destination enforcement | Implemented application-level origin/IP/port/route/TLS controls and persistent request budgets. Original v1.4 tag does not contain independent HTTP kernel confinement. |
| v1.4.1 | Independent kernel-enforced network containment | Implemented and verified: connected TCP capability, offline namespaces, seccomp and external lifetime control. Ubuntu 22.04 and 24.04 each passed 120 tests with no skips. Pull-request review and deployment-host validation remain; no release tag yet. See VERIFICATION.md. |
| v1.5 | Credential broker, operator approvals, revocation and session controls | In development: signed Unix operator API, classified expiring profiles, sealed snapshots, kernel-confined HTTPS; final CI/deployment review pending. Secrets must stay out of model context, bind to exact assets, expire/revoke, and survive restart/replay tests. Independently authenticate approvals. |
| v1.6 | Security-tool integrations and current vulnerability intelligence | **Development, first increment**: offline sandboxed pinned dependency inventory, signed/fresh operator OSV snapshots, exact enumerated-version leads, range uncertainty, and fixed schema-only scanner imports. Automated feed retrieval, broader scanners and full ecosystem range coverage not yet implemented. See V1_6_SECURITY_INTELLIGENCE.md. |
| v1.7 | Bounded runtime testing and reproducible local security-invariant validation | **Implemented, stacked development:** operator-pinned strict-tenant, structured-JSON, and versioned-state Python contracts. Two-to-five bounded trials, synthetic serial interleavings, independent fresh-sandbox replay, signed-scope budget accounting, source SHA-256, no network and emergency stop. Final accepted CI + deployment-host validation required before merge/tag. Does not include true thread races, arbitrary native fuzzing, or confirmed deployed exploits. |
| v1.8 | Automated findings, evidence, remediation reports, and notifications | Planned. Canonical schema-validated findings, consistent reports, verified delivery and explicit transport failure handling. |
| v1.9 | Autonomous investigation planning, attack-chain reasoning, and retesting | Planned. Typed permitted actions, verified vs uncertain claims, resumable state and replay/recovery tests without policy-write authority. |
| v2.0 | Fully integrated, tested autonomous assessment system for authorized environments | Planned. End-to-end signed staging assessment, discovery through verified impact/remediation/retest, plus security review and failure/rollback tests. |
| **v2.1** | **Cloudflare security-audit-skill integration** | **Planned, NOT included in v1.7/v2.0:** deterministic coverage ledgers, independent hunters/verifiers, repeated-run source revalidation, strict verdict schemas, reviewed validators, and attribution. Must preserve AEGIS's operator authorization and kernel execution boundary. |

## Before beginning v1.5

Review and merge v1.4.1 only after its kernel and regression gates pass. Validate the actual deployment kernel/runtime and protect the operator-facing API and installation. Design credential handling around the remaining trust boundary: a compromised worker can misuse its granted TCP stream. Never pass credentials directly into an arbitrary worker merely because its destination is confined.

Authenticated approvals, revocation updating, session identity and replay prevention must be designed together. Retain independently signed audit checkpoints off-host.

## Definition of v2.0 done

1. An operator connects explicitly authorized software through protected configuration.
2. The agent can investigate impact without unrestricted shell/network access or direct credential possession.
3. Execution-time approval, scope, resource, revocation and stop controls hold across restarts.
4. Confirmed findings include reproducible impact, attacker starting state and demonstrated privileges, with uncertainty clearly separated.
5. Reports and monitored notifications cover findings, retests, clean assessments and residual uncertainty.
6. Independent deployment security review and practical testing of the supervisor itself are complete.
