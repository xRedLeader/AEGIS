# HTTP gateway implementation and security boundary (v1.4)

## Actual data path

```text
Model / operator --typed request--> trusted operator service (not included)
    | HTTP GET/HEAD URL (agent never chooses trust policy or filesystem)
    v
AegisHttpSupervisor (trusted Linux non-root service)
    |- Verify signed scope, independent trust, fresh revocation, emergency stop
    |- Bind exact signed origin + independently approved path-prefix
    |- Atomically reserve SQLite request/rate/concurrency/runtime/bytes
    |- Spawn killable fixed DNS helper for approved hostname
    |- Reject every address if any is outside signed+trusted CIDRs / unsafe
    |- Select one numeric IP; recheck authorization and policy
    |- Spawn killable fixed transport helper with pinned IP + signed host
    |    |- TCP direct to numeric IP, no name re-resolution or proxy
    |    |- HTTPS: system/approved operator CA + hostname/SNI validation
    |    |- GET/HEAD fixed headers only; do not follow redirects
    |    '- Discard response body after bounded hashing
    |- Watchdog checks stop, scope, route grant, revocation, CA changes, time
    '- Write private, sanitized response metadata; complete SQLite audit
```

The source scanner remains **separate**: it runs in a default-deny seccomp namespace without network syscalls or access to the HTTP helper, keys, state or trust policy.

## Hard restrictions

- Exact origin (including scheme and port) must appear in both independently approved origins and signed targets. A listed origin without explicit signed+trusted network CIDRs cannot connect.
- A signed DNS name is **not** sufficient permission to connect to arbitrary DNS answers. DNS returns at most 16 distinct addresses; all answers must pass CIDR/exclusion/category checks before any target TCP connection. Literal-address origins must resolve to that same literal.
- No unsafe unspecified, link-local, or multicast destination; excluded CIDRs override network grants. Operator route-prefix rules further limit GET/HEAD paths, defaulting to no routes. Encoded or ambiguous paths are rejected rather than normalized or guessed.
- No redirects, automatic proxies, cookies, authorization, caller-controlled headers, request bodies, or caller-supplied TLS CA options. TLS certificates are verified with the selected approved hostname, not with the numeric pinned IP unless the hostname is an IP literal.
- Each request consumes a durable total-request reservation, a minute-rate slot, a concurrent slot, a wall-time allowance, a private evidence reservation and the full allowed response-body allowance. Reservation is consumed even on error. Only metadata/digests are persisted.
- A fixed subprocess runs with bounded CPU, memory, file output, fd count, clean environment and supervisor-enforced wall time; revocation/stop/policy removal terminates it.

## Explicit non-guarantees

1. **No independent OS-level network confinement of the HTTP helper.** A compromised helper or an agent with another network tool can bypass this user-space gateway. Host firewall/VM boundary plus protected code/policy installation remain deployment requirements. This package does not implement a transparent proxy, TCP-level firewall, network namespace gateway or a private network interface.
2. **GET is not intrinsically harmless.** Some endpoints cause side effects. Restrict paths to staged, intentionally read-only functionality. `/` in the operator route policy authorizes all GET/HEAD paths and should only be used on disposable or exhaustively approved targets.
3. No precise wire-byte quota; response-body reservations are conservative and exclude response headers, DNS, TCP and TLS overhead. No generic traffic decryption or WAF bypass.
4. HTTPS verifies origin identity if root trust is correct. Plain HTTP has no cryptographic authenticity. Trusted public roots or an explicitly protected/fingerprinted operator CA are required.
5. No external notification delivery, independent off-host ledger anchoring, live update channel for revocations, or permission to access real sensitive data. An operator must maintain fresh trust revocation data and signed audit checkpoints.
6. No cgroup enforcement, arbitrary tool isolation, OS-wide agent egress limitations or credentials yet. Run only under a tightly controlled operator process and review before real-world deployment.

## Acceptance tests in this package

`tests/test_http_gateway.py` validates real loopback HTTP and HTTPS requests (including a locally generated private CA), strict hostname checks, untrusted CA denial, redirects not followed, absence of cookies/authorization/body in evidence, path policy, DNS-answer substitution and mixed records, denied link-local/multicast, capped bodies, cumulative request/response budgets, rate and concurrency ceilings, active stop and revocation, changed operator route grants, environment proxy rejection and CLI execution.

`tests/test_isolation.py` and `aegis_sandbox_check.py` continue proving that the original source scanner itself cannot open sockets, fork, escape mounts, gain capabilities or access host files on the current kernel.

**These are tested local boundary checks, not a replacement for an independent penetration test of the supervisor or an OS egress policy.**
