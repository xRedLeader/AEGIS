# v1.5 Operator Service and Credential Security

**Development branch. Do not deploy with production/customer credentials or merge solely because tests are green.**

## Trust boundary

AEGIS does not expose its credential authority to an AI agent. The operator runs a distinct protected, non-root Linux service identity with no agent shell access. The signed operator Unix-domain control interface is **operator-only**, not an agent delegation API. Its socket lives in a service-owned mode-0700 directory with mode-0600 socket permissions. Linux SO_PEERCRED UID allowlisting is enforced independently of Ed25519 command signatures.

A separate offline operator API signing key signs canonical JSON requests under the domain separator `AEGIS-operator-command-v1\x00`. The operator-service process holds only the corresponding protected **public** verification key, not the private signing key. Each request binds the principal, engagement ID, a random request ID, a validity window of no more than 60 seconds, one named operation and exactly shaped arguments. The protected SQLite ledger atomically and durably consumes request IDs **before** running the operation, including failed operations. It verifies the audit hash chain before recording acceptance. Service restarts and concurrent requests cannot replay a consumed request.

Operations are strictly: `session.create` (protected named approval file, with a separately signed grant), `session.revoke`, and `session.fetch` (approved GET/HEAD only). Arbitrary commands, filenames/paths, methods, code and URLs outside signed scope are rejected. The service never returns token material, vault paths or response bodies. Session handles are privileged operator capabilities and must not be passed to the AI agent.

**Filesystem permissions must be enforced by the actual OS and separate accounts.** A mode-0700 socket directory admits its owner and root; an operator with a distinct unprivileged UID needs a separately designed privileged handoff rather than a permissive chmod workaround. A trusted root operator can connect and sign without giving the service possession of the API private key. No model-facing delegation adapter is implemented.

## Credential lifecycle

The independently protected credential policy must include an explicit profile for every vault reference:

- `classification`: only `synthetic` or operator-acknowledged `disposable_staging` (never permanent/production/unclassified).
- `allowed_origins`: exact authorized HTTPS origins.
- `issued_at_utc` and `expires_at_utc`: strict UTC timestamps, with at most 24 hours from issuance for disposable staging or seven days for synthetic credentials.
- `fingerprint_sha256`: expected SHA-256 of the token bytes.
- `exposure_acknowledged: true`: operator acceptance that a compromised helper may disclose the short-lived token to the approved endpoint.

Protected token files must be regular, unlinked from worker-visible runtime trees, owned by the operator/service with mode 0600, and match the fingerprint. The fingerprint is also **bound at session creation**, so changing a token and its profile cannot silently upgrade a prior session.

The trusted authority creates a one-request, sealed anonymous `memfd` snapshot with `F_SEAL_WRITE`, `F_SEAL_GROW`, `F_SEAL_SHRINK` and `F_SEAL_SEAL`. The connection broker refuses unsealed descriptors and closes the snapshot before sandbox execution. Only a bounded token string and one preconnected TCP socket reach the isolated helper; no vault path or file descriptor reaches the assessment worker.

The helper still temporarily holds a bearer token in memory. A compromised worker may send it or unauthorized bytes over its **one** kernel-authorized TCP stream, forge bounded metadata or leak information through timing. Kernel egress prevents other destinations, but **does not prove HTTP method/route semantics, prevent all disclosure to the allowed peer, or undo a token already transmitted before revocation**. Use synthetic or disposable credentials only.

Rotate and revoke test tokens at engagement end or on suspected exposure. Keep the API signing key, approval signing key, and scope signing key independently protected. Retain signed audit checkpoints off-host. A compromised host, trusted broker, kernel or operator authority is outside the worker containment threat model.

## Operator workflow (illustrative)

The JSON examples are deliberately disabled; they cannot authorize anything until an operator explicitly configures them.

```bash
# Run service as dedicated non-root service UID with protected state and /run directory
python3 aegis_operator_service.py \
  --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis/private-state \
  --credential-policy /etc/aegis/credential-policy.json \
  --api-policy /etc/aegis/operator-api-policy.json

# Only the separate authorized operator has access to its private signing key
python3 aegis_operator_client.py \
  --socket /run/aegis/operator/operator.sock \
  --operator-key /private/operator/api-signing-key.pem \
  --principal example-operator \
  --engagement-id example-engagement-001 \
  --operation session.create \
  --args-json '{"approval_name":"grant.json"}'
```

Do not store private keys in public Git repositories, the agent context, CI artifacts, or the assessment-worker runtime.

## Test and release gates

`tests/test_operator_service.py` covers signature tampering, wrong OS peer identity, concurrent/restarted replay, traversal, expiry, protected-policy manipulation, real Unix-socket exchange, token fingerprint rotation, disallowed classes, sealed snapshot immutability and mutable-FD rejection. Existing authenticated kernel probes and revocation/hostile-worker tests must remain green on **both** supported Ubuntu versions.

**Do not merge or supply live credentials until** the full Linux CI matrix succeeds at the exact PR head, an actual deployment service/UID separation test succeeds, and an independent security review accepts the remaining token-in-worker exposure model. The tests are not proof of a hardened production deployment.
