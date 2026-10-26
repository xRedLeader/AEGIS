# AEGIS runtime supervisor — implementation contract

**Status: PARTIALLY IMPLEMENTED in v1.2 (local-only).** `aegis_supervisor.py` handles one known read-only local source reviewer, scoped authorization checks, conservatively persistent runtime/evidence reservations, an emergency-stop marker, per-run report files and a chained local audit. **It is NOT an OS sandbox and does not confine the agent or arbitrary workers.** The live network boundary, protected credential broker, authenticated approvals, revocation updater, per-request accounting, alert delivery and externally anchored audit remain unimplemented. Deploying an agent with unrestricted tools bypasses these controls.

## Trust and separation

```
Operator (private signing key) ----sign----> Scope manifest + detached signature
                |                                    |
Operator-controlled approval registry / trust policy |   (agent cannot modify)
                +---------------------+--------------+
                                      v
                              preflight (verify)
                                      v
                   trusted local supervisor (PARTIAL v1.2)
                       |         |          |
                  restricted   action     audit / budget
                   worker      gateway       ledger
                       |
             assessment tools / test credentials
```

**Target architecture:** the supervisor must own the network namespace, OS credentials, tool execution permissions, trusted clock, approval store, and audited budget ledger. v1.2 **does not yet own these OS capabilities**; it mediates only its narrow static review call. The agent must ultimately receive only scoped tool interfaces. No agent instruction or YAML content is itself a sandbox.

## Required additional controls before live assessments

1. **Bootstrapping**: load the trust policy from an operator-controlled immutable or protected location, verify the signer public key, invoke preflight, bind the resulting engagement ID and manifest hash to the process, and fail closed on missing or invalid inputs. Never let the agent supply the trust-policy path or signing key.
2. **Process and filesystem isolation**: run tests with unprivileged worker identities, an isolated workspace, read-only scope and policy mounts, no access to operator keys, and restricted access to evidence/report sinks. Treat symlinks, mount changes, and environment variables as untrusted. Reauthorize sensitive filesystem operations at use time.
3. **Network egress**: deny unknown sockets, protocols, ports, proxies, and name resolutions at the OS/network layer. Permit an explicit origin only after hostname, resolved address, destination port, connection, TLS identity and request route meet policy. Recheck DNS rebinding and redirects; never infer permission from a reachable neighbor. Ensure subprocesses cannot evade these checks.
4. **Credential broker**: hold test secrets outside the worker and release short-lived, task-scoped identity to approved destinations only. Block credential reuse on unapproved SSO hosts, even if it authenticates. Do not write credentials into command lines, logs, or evidence.
5. **Budget ledger**: persist per-engagement cumulative wall-clock/run duration, HTTP requests, responses/evidence bytes, fuzz trials, and other enforceable resource counters across crashes and restarts. Reserve budget atomically before action and account for the actual cost afterward. Honor the smaller of manifest and operator-policy ceilings; deny if reservation fails.
6. **Revocation and clock**: a *trusted updater*, independent of the agent, refreshes the revocation snapshot and `last_checked_utc` in the protected policy. The preflight rejects snapshots older than `max_staleness_seconds` (or future-dated). The supervisor must recheck revocations and time limits during execution, at least as frequently as the policy's freshness ceiling, and fail closed if updates stop. A verified signature is replayable within its valid window unless the supervisor binds each invocation to a protected run/session ledger.
7. **Action approvals**: enforce `excluded_*` and high-impact approval gates before method allowances. Approvals must be operator-authenticated, scoped to a specific target and action, short-lived, revocable, and recorded. An approval does not add new asset scope; changes to targets need a newly approved and signed scope/policy.
8. **Harm prevention and stop**: bound CPU, memory, storage, request concurrency and run time at the OS layer. Use isolated test environments for potentially destructive experiments. Expose an externally controlled kill switch that terminates in-flight tests and revokes credentials.
9. **Reports and notifications**: write findings to the pinned engagement directory, optionally with per-run subdirectories (`runs/<run_id>/`); append security alerts to the pinned engagement-level NDJSON sink. Independently forward critical alerts to a monitored delivery service and exercise a harmless test alert before activation. A writable file alone is *not* evidence of successful notification.
10. **Auditing and recovery**: retain tamper-evident records of verified scope hash, operator approvals, tool decisions, budget reservations, revocation checks, requests, stop events, notifications and failures. Ensure interrupted or crashed runs cannot recover unused privileges by manipulating local files.

## Tool-call contract (illustrative)

Each requested active operation should cross the supervisor boundary with an engagement ID, run ID, method, exact target, declared impact class, estimated resource cost, and requested credential scope. The supervisor verifies the immutable authorization context, approval status and real resource limits before executing. It returns a decision and sanitized evidence reference. A model-produced `allowed: true` field is never authoritative.

## Acceptance tests for a real implementation

The supervisor cannot be considered ready until integration tests demonstrate **blocked execution**, not merely a preflight denial, for:

- Unlisted domains, IPs, ports, protocols and proxy destinations.
- Redirects off an approved origin, DNS rebinding, alternate IP representation, and host/SNI mismatches.
- Unlisted repository roots and symlink/mount changes after preflight.
- An out-of-scope SSO token request using an approved test identity.
- Rate, request-count, byte and concurrency overages across worker restarts.
- Expired, revoked, replayed or stale-revocation engagements, including clock rollback and concurrent sessions.
- A high-impact action without separately authenticated approval.
- An agent attempt to change the trust policy, its public key or the signing private key.
- Emergency stop in the middle of a long fuzz/test batch.
- Critical-alert transport outage with visible failure, no false delivery claim.

## Definition of done

**v1.2 is accepted only for bounded local source review**. It has executable scope checks, a SQLite ledger, local stop polling, and a trusted scanner, but those do not constitute an OS security boundary. Active network assessments may be enabled only after independently reviewed OS/network enforcement and passing integration tests of the deployed supervisor. This document is a contract for future versions, not a security guarantee.
