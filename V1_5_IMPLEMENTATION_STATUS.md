# AEGIS v1.5 — credential approval prototype (draft / not deployable)

Branch: feat/v1.5-credential-approvals (based on merged v1.4.1 main).
This is **not** a v1.5 release. Do not merge or provision live credentials.

## Committed candidate code

- aegis_credentials.py: operator-side Ed25519 approval validation, replay protection, short-lived origin/route-bound session handles, persistent SQLite use limits and revocation, audit events, and metadata-only HTTPS orchestration.
- aegis_approval_admin.py: offline operator-signed single-use grants.
- aegis_auth_helper.py: fixed HTTPS GET/HEAD bearer-token metadata helper, without returning headers, secrets or response bodies.
- tests/test_credentials.py and tests/test_auth_http.py: approval, replay, scope, concurrency, revocation, permission, synthetic TLS and redaction tests.
- Inherited v1.4.1 kernel containment, DNS pinning, budget ledger, emergency stop and regression tests are preserved, not overwritten by older v1.4 source.

A v1.4.1 compatibility failure was fixed: authenticated evidence uses the existing supervisor-approved http-result.json artifact name.

## Verification

- Local focused credential and HTTPS tests passed: 86/86 under an unprivileged Linux account. This number includes tests re-collected through an inherited unittest class.
- GitHub Ubuntu 22.04 and 24.04 matrices passed against the integrated branch after the compatibility fix.
- A one-day GitHub Actions tracked-source snapshot was exported so the exact branch revision could be independently tested.
- PR #3 remains draft. main and the v1.4.1 tag are unchanged.

## Security limitations blocking release

1. **Authenticated helper lacks v1.4.1 kernel egress containment.** It has trusted host networking and obtains a Bearer secret through a protected file descriptor. The older uncredentialed worker's containment must not be attributed to the credential helper.
2. The operator-only API has no independently authenticated external service boundary. Never give the model direct access to the Python authority object, vault or broker.
3. Mid-flight revocation and cancellation require adversarial testing against an uncooperative or compromised helper. An authorized endpoint can receive a credential before revocation takes effect.
4. Operator signing-key, credential vault and protected-policy lifecycles need a deployment security review.
5. Remove unittest class inheritance duplication before release; other deployment host configurations are unverified.

## Release gate

Keep PR #3 in draft. Do not tag v1.5 or use production credentials. Require independently confined authenticated transport, authenticated service APIs, fail-closed cancellation, secret non-disclosure checks, full Linux CI and deployment-host acceptance.
