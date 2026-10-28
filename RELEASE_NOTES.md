## v1.9 investigation planner — development candidate

Operator-side deterministic bounded plans derived only from completed private v1.8 packages; immutable evidence and policy pinning; explicit local replay allowlists; verified shared-asset hypotheses remain unverified; persistent fenced leases and audit results; operator-only manual review/retest checkpoints. See `V1_9_INVESTIGATION.md`. No release tag or production deployment claim.

## v1.8 development — first reporting and local-notification increment (not tagged)

- Explicit v2 canonical findings schema; no severity for unverified/rejected cases. Legacy v1 schema preserved.
- Safe source-review, OSV and bounded local-test evidence projections, deterministic Markdown and digest manifest.
- Operator-owned private report files, atomic Linux no-replace promotion, guarded idempotence and durable SQLite notice enqueue.
- Restricted local Unix-socket notification delivery with peer UID validation, signed-scope revalidation, challenge-bound ack, retry and failure accounting.
- No external notification transport, production authorization or automatic promotion of leads into confirmed findings. See V1_8_REPORTING.md for release gates.

# AEGIS v1.4.1 — independent kernel endpoint containment

Feature branch implementation; publication is through a reviewed pull request, with no release tag created yet.

- Added a non-root trusted DNS/connection broker and lifetime guardian. It opens only the authorized numeric TCP endpoint and passes the established socket into an offline namespace.
- Confined the HTTP/TLS parser with the existing rootless user/mount/network/PID namespaces, capability removal, no-new-privileges and default-deny seccomp. New sockets, reconnects, UDP, Unix sockets, netlink and namespace escape are denied by the kernel.
- Preserved signature/trust/revocation, DNS pinning, TLS, routes, request/concurrency/body budgets, emergency stop, ledger and signed checkpoint behavior.
- Preserved the supplied dup/dup2/dup3 portability hotfix and protected trust-policy reader.
- Closed pre-chroot directory handles; added descriptor/capability checks, bounded worker output, deadlines, interrupted setup/restart tests and supervisor-crash cleanup tests.
- Updated the v1.2–v2.0 roadmap and documented authority, migration, supported Linux prerequisites and compromised-worker limits.

Local verification: **120 tests passed, zero failures, zero skips**, plus the independent source sandbox probe and both signed demos. Actual environment and GitHub matrix results are recorded in VERIFICATION.md. A kernel endpoint boundary does not independently enforce HTTP routes, byte quotas or result authenticity after worker compromise.

Existing v1.4 scope/policy/ledger formats remain compatible. Install the broker, launcher and gateway together in a protected location, stop active operations and rerun deployment-host tests. No host-specific path or account is required; Windows/macOS must host a supported Linux execution environment.

## Historical v1.4 release

### Executable controlled HTTP(S) gateway

## Added

- `aegis_http_policy.py`: strict URL-origin parsing and signed-CIDR pinning; rejects mixed DNS answers and unsafe IP classes.
- `aegis_http_gateway.py`: fixed trusted subprocess for time-bounded DNS lookup and direct, pinned-IP HTTP/HTTPS GET/HEAD; TLS system roots, hostname verification, optional SHA-pinned operator CA; no redirects/proxies/secrets/caller headers; body hashes only.
- `aegis_http_runtime.py`: persistent per-engagement HTTP request, active slot, per-origin minute rate and cumulative worst-case body reservations in same protected SQLite audit/state; enforced watchdog/revocation/stop; private JSON metadata report.
- Supervisor CLI `http` and `http-usage`; `aegis_http_demo.py` runs a signed, scope-controlled **loopback-only** HTTP demo.
- Independent operator route-prefix policy (`allowed_http_path_prefixes`) that defaults to deny and can be updated mid-run.
- Separate `HTTP_GATEWAY_SECURITY.md` detailing implemented controls and limitations.
- Live loopback integration tests including TLS trust/hostname mismatch, DNS/IP confusion, redirects, path ambiguity, rate/byte/concurrency controls, revocation, emergency stop and proxy environment rejection.

## Authorization compatibility

The signed scope **requires a new** `limits.max_total_response_bytes`, with a corresponding positive ceiling in the independent trust policy. Existing signed v1.3.1 scopes are **not** silently upgraded. Create and re-sign a v1.4 scope; keep the original engagement history separate if the scope hash changes. The example trust policy adds `allowed_http_path_prefixes: {}` (deny all) and `tls_custom_ca: null`.

All v1.3.1 local source-review, signed checkpoint and default-deny Linux worker isolation behavior is retained. HTTP helpers are **not** run inside the source scanner namespace because its network syscalls remain denied.

## Scope and non-goals

This release enforces policy in a trusted HTTP helper, but does not install an independent OS egress firewall or confine an LLM with host network/shell access. It does not certify target staging systems, provide arbitrary methods/headers or authenticated attacks, follow redirects, execute payloads, or deliver alerts externally. Deploy behind an authenticated operator service, not as a public network proxy.


## Post-v1.4 portability patch (unreleased tag)

See `PATCH_NOTES.md` for CPython startup syscall compatibility, live
fresh-exec integration testing, and consistent protected trust-policy reads.


## v1.7 expanded bounded local reproduction (draft, not tagged)

Added operator-pinned `json_resource_access_v1` and `versioned_cas_v1` alongside tenant-isolation checks, 2–5 bounded repeated trials, trusted oracle output validation, minimal-case recording, and independent fresh-sandbox replay with a second budget reservation. CI: 296/296 tests passed on Ubuntu 22.04 and 24.04. This is a local offline security-invariant harness, not proof of a real-world exploit, generalized fuzzing or a production release. See `V1_7_ACCEPTANCE.md`.

## v1.8 development (unreleased)

Added evidence-bound canonical findings v2, operator-reviewed dual-signed staging finding promotion with retained proof bytes and immutable reviewed revisions, deterministic remediation reports, complete package integrity validation before local notification delivery, fenced/backoff SQLite outbox with bounded drain, and a separate durable Unix receiver using SO_PEERCRED, idempotency and commit-before-ack. This implementation does not offer production email/webhook delivery or automatic exploit confirmation. See `V1_8_REPORTING.md` for scope and release gates.


## v1.9 extended investigation evidence (development, not tagged)

Adds `aegis_investigation_evidence.py`: up to eight completed, source-pinned
assessment attachments per investigation; deterministic and explicitly
unverified cross-run asset correlation; separately authorized, lease-fenced
synthetic remediation observations using v1.7's existing offline worker and
persistent budgets. Neither zero leads nor a successful local replay resolves
a production finding or operator review checkpoint. A genuinely fixed deployed
system remains a separate independent human/security-review determination.
See `V1_9_INVESTIGATION.md` and `tests/test_v19_evidence.py`.

## v2.0 development: integrated operator assessment

Introduces a bounded, signed-scope, operator-owned orchestration ledger for fixed source review, OSV intelligence, pinned local contract checks, metadata HTTP, reports, investigation and acknowledged local notifications. Real namespace tests, replay-safe completion and fail-closed interrupted-operation recovery are required before release. This is **not** a v2.0 release or a new unrestricted autonomous execution API. Cloudflare audit-methodology orchestration remains planned for v2.1.
