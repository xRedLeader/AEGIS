# AEGIS v1.5 — credential approval prototype (draft / not deployable)

Branch: feat/v1.5-credential-approvals (based on merged v1.4.1 main).
This is **not** a v1.5 release. Do not merge or provision live credentials.

## Committed candidate code

- aegis_credentials.py: operator-side Ed25519 approval validation, replay protection, short-lived origin/route-bound session handles, persistent SQLite use limits and revocation, audit events, and metadata-only HTTPS orchestration.
- aegis_approval_admin.py: offline operator-signed single-use grants.
- aegis_auth_helper.py: HTTPS GET/HEAD bearer-token metadata transport confined by the same namespaces, dropped capabilities and default-deny seccomp as v1.4.1. The trusted broker connects the approved endpoint and supplies a token snapshot over a bounded pipe; the helper receives no vault descriptor or host networking authority.
- tests/test_credentials.py, tests/test_auth_http.py and tests/test_auth_egress.py: approval, replay, scope, concurrency, revocation, permission, synthetic TLS, redaction, raw syscall and hostile-helper lifecycle tests.
- Inherited v1.4.1 kernel containment, DNS pinning, budget ledger, emergency stop and regression tests are preserved, not overwritten by older v1.4 source.

A v1.4.1 compatibility failure was fixed: authenticated evidence uses the existing supervisor-approved http-result.json artifact name.

## Confinement fix and verification

- The authenticated path no longer parses TLS/HTTP with trusted host networking. It uses the existing preconnected-socket broker and an `auth-http` sandbox profile with no additional networking syscalls.
- Both layers drain capped output while enforcing deadlines. The supervisor checks live session, scope, route and CA authorization. Cancellation cleanup handles already-closed pipes and discards hostile output.
- Vault/policy/key locations beneath the worker-visible `/usr` runtime are rejected. Returned HTTP status/counts are range-checked; headers, bodies, body hashes and extra metadata are not accepted.
- Local full regression: **217 passed, 0 failed, 0 skipped** on Ubuntu 24.04.1 / Python 3.12.3 under an unprivileged WSL Linux account. The disposable outer mount namespace described in `VERIFICATION.md` is test setup only. The count includes existing repeated unittest collection through fixture inheritance/imports.
- The authenticated kernel probe passed all **25 checks**, including real TLS exchange, raw connect/socket denials, cleared capabilities, descriptor hygiene and hidden vault files.
- Hostile-helper tests verified fail-closed setup, mismatched peer rejection, stdout/stderr flooding, malformed secret-bearing results, deadline enforcement and TCP closure after session revocation/expiry, emergency stop, route/CA changes and supervisor death.
- The existing CI workflow discovers the new tests and requires zero skipped tests on Ubuntu 22.04 and 24.04. Prior branch CI results do not validate this fix; inspect the current PR head's checks.
- PR #3 remains draft. main and the v1.4.1 tag are unchanged.

## Security limitations blocking release

1. The operator-only API has no independently authenticated external service boundary. Never give the model direct access to the Python authority object, vault or broker.
2. The confined helper holds the granted token. A compromised helper can misuse it on its one permitted stream, forge valid metadata or encode information in metadata/timing. The kernel constrains the endpoint, not HTTP routes, methods or secret disclosure. An authorized endpoint can receive a credential before revocation takes effect.
3. Operator signing-key, credential vault and protected-policy lifecycles need a deployment security review. The trusted host, kernel, supervisor and connection broker remain outside the compromised-worker boundary.
4. Remove unittest class inheritance duplication before release; other deployment host configurations are unverified.

## Release gate

Keep PR #3 in draft. Do not tag v1.5 or use production credentials. The missing kernel egress boundary and hostile-helper cancellation coverage are addressed by this fix. Release still requires authenticated service APIs, independent review of credential exposure, current full Linux CI and deployment-host acceptance.


## Operator-service and credential-lifecycle hardening (draft)

The feature branch now includes a signed local Unix-domain operator interface (`aegis_operator_service.py`, `aegis_operator_client.py`), typed operations, SO_PEERCRED checks, and SQLite replay protection across restarts. Each credential reference requires a classified synthetic/disposable profile, explicit allowed origins, an expiry, an exposure acknowledgement, and a token fingerprint bound to the session. Broker credential handoff now requires an immutable sealed memfd, not a writable vault inode.

Tests cover wrong signature, peer identity, expiration, replay and races, path traversal, real Unix-socket exchange, profile expiration, secret replacement/rotation and sealed snapshot immutability. The in-repository test matrix discovers these together with existing kernel egress and hostile-worker tests.

**Still not a v1.5 release:** do not merge or use production credentials until CI passes on the final commit, deployer verifies operating-system identity separation and protected key provisioning, and an independent review accepts the residual risk of the credential in the kernel-confined worker memory. No general agent-facing API delegation exists.
