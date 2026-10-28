# AEGIS integration — provider-independent

For the current v2.0 candidate, start with
[the integrated workflow](V2_0_INTEGRATED_ASSESSMENT.md) and
[signed agent delegation](V2_0_RELEASE_ACCEPTANCE.md). The delegated model
interface accepts only `snapshot` and proposals for the exact next configured
step. The direct component interfaces below remain operator-controlled; they
are not additional delegated-agent capabilities. See
[the review handoff](V2_0_REVIEW_HANDOFF.md) for release evidence and remaining
deployment inputs.

## v1.4.1 direct operator integration

The operator owns installed code, service identity, signed scope, trust policy, revocation snapshots, protected state, report paths and private signing keys. The operator supplies only a target URL already authorized by scope, GET/HEAD selection and bounded time request.

## Named operations

- `source_review(repo_id, seconds)`: fixed, read-only source review. Map IDs to trusted absolute paths in the operator service.
- `http_get_metadata(url, seconds)` and `http_head_metadata(url, seconds)`: invoke the supervisor's `http` command with operator-pinned configuration.
- `http_usage()`: persistent request, active-slot and reserved response-body counters.
- Operator only: stop, signing, policy/route changes, revocation refresh and audit checkpoint export.

These direct component CLIs are not the v2.0 delegated-agent interface. Never expose the raw broker, launcher, gateway, probe, filesystem options, socket descriptors, executable paths or generic shell to an agent.

## Deployment and migration

Install the complete candidate code set, including `aegis_http_broker.py`, in a protected location. Run as a **non-root Linux service user**. Both scanner and HTTP require working user/mount/network/PID namespaces and libseccomp; HTTP does not work on a host where source isolation is unavailable.

No host firewall, veth, sudo broker or CAP_NET_ADMIN grant is required. The launcher briefly holds capabilities only inside its private user namespace, then drops them. DNS and the initial TCP connect belong to the trusted broker. The parser gets one preconnected peer capability and no ability to create or replace connections.

On AppArmor-enabled Ubuntu 24.04, permit user namespace creation for the operator service. `deployment/apparmor/aegis-supervisor` is a named opt-in profile using AppArmor 4's `userns` permission. An administrator loads it and selects it for the service, such as with systemd's `AppArmorProfile=` setting. It grants a prerequisite to an otherwise unconfined trusted service; it is not a full MAC policy and is not required on hosts without this restriction. Keep the service non-root and the global AppArmor policy enabled. Run the acceptance tests under the same selected service profile.

Existing valid v1.4 manifests, operator route grants, TLS CA policy and SQLite ledgers retain their format. No automatic scope expansion, credential access or engagement reset occurs. Replace trusted code as one unit, stop in-flight operations before upgrading, verify checksums, and run `VERIFICATION.md` on the deployment host.

For scoped staging requests:

```bash
export AEGIS_TRUST_POLICY=/etc/aegis/trust-policy.json
export AEGIS_STATE_ROOT=/var/lib/aegis/protected-state
python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig http \
  --url 'https://staging.example.org/health' --method HEAD --seconds 15
```

Maintain fresh revocation snapshots and retain signed audit checkpoints independently. Only public CA material enters this uncredentialed HTTP worker. The separate v1.5 operator service below controls approved staging credentials; direct HTTP metadata commands do not gain that authority.

Run `python aegis_http_demo.py` for an ephemeral signed loopback demonstration. See `HTTP_GATEWAY_SECURITY.md` before deployment: endpoint confinement does not independently enforce HTTP semantics if the worker is compromised.


## v1.5 operator-only credential control (draft)

Run `aegis_operator_service.py` under a dedicated non-root service identity. It exposes only a filesystem-private Unix-domain socket and checks both SO_PEERCRED and Ed25519-signed, short-lived replay-protected commands. `aegis_operator_client.py` uses a separate offline operator signing key. Allowed operations are `session.create`, `session.revoke` and `session.fetch`; no arbitrary tools or operator policy mutation. Signed grant files live in a protected approval directory. The agent must not have access to this socket, the signing key, the vault, or the privileged Python class.

The sample JSON policies are disabled and require independent operator provisioning. Consult `OPERATOR_SERVICE_SECURITY.md` for credential classes, sealed snapshots and trust boundaries. Separate Linux UIDs and filesystem permissions matter; a mode-0700 directory does not allow unrelated unprivileged users to connect.

## v1.7 bounded local reproduction (development only)

The operator-only fixed `aegis_fuzz_runtime.py` has two actions: `execute(repo, module, seed, max_cases, trials, seconds)` runs a pinned source hash and callable with a fixed synthetic contract; `verify_evidence(repo, module, prior_run_uuid, seconds)` independently replays the smallest verified candidate in a second kernel-denied network namespace with a new budget reservation. Contracts are `strict_tenant_owner_v1`, `json_resource_access_v1`, and `versioned_cas_v1`. For JSON and CAS checks, 2–5 trials and at most 192 total invocations are permitted; operator `max_trials` ceilings can narrow this further.

Both named actions require `bounded_fuzzing` in the signed scope and independently trusted policy. The installed fixed worker and oracle library, but not the untrusted repository, live in the namespace's read-only `/app`. No agent-facing arbitrary shell, network, credential or user-supplied exploit/payload API is present. The v1.5 operator Unix service does **not** implicitly expose these new actions. Results are local `needs_validation` evidence only. Versioned CAS explores serial interleavings, not true simultaneous threads; see `V1_7_LOCAL_REPRODUCTION.md`.

## v1.8 evidence-bound report generation and local notification (development only)

Run only from the trusted operator service identity. `aegis_reporting.py` reads one completed private AEGIS source-review, bounded-fuzz or signed OSV artifact and generates the v2 canonical `findings.json` with derived Markdown and integrity records. It never asserts severity for unverified leads. One durable SQLite outbox entry is queued per canonical report. `aegis_notifications.py` can deliver only to a protected, configured local Unix socket whose OS peer UID is explicitly allowed. It requires a digest- and challenge-bound acknowledgement; delivery failure is explicit and retryable until the configured cap. No internet, SMTP or webhooks are enabled. Do not give an AI agent either operator CLI, private report root or socket. [V1_8_REPORTING.md](V1_8_REPORTING.md) specifies the contracts.

## v1.8 immutable reports and local notification receiver

Operator-only commands: `aegis_reporting.py` generates a canonical per-run report from completed source evidence; `aegis_finding_promotion.py` accepts a dual-signed, proof-hash-bound staging review to produce a new immutable report revision; `aegis_notifications.py` runs a bounded one-shot `--drain 20` or manually delivers a named notice; and `aegis_notification_receiver.py` receives deduplicated metadata under an independent non-root OS identity. The v1.5 operator socket does not automatically offer these functions to agents. See `V1_8_REPORTING.md` for exact arguments, separate reviewer/operator keys, group-only socket access, and failure semantics.


## v1.9 operator-only investigation planning (development)

Use only `aegis_investigation.py plan --source-run UUID`, `snapshot --plan-id UUID` or `advance --plan-id UUID` under a protected non-root operator identity. It derives the typed step queue from verified v1.8 reports; the AI cannot define an executable path, target, request, credential, HTTP method, payload, or scope. The only assessment action is explicitly allowlisted v1.7 bounded local evidence replay, independently reserved and audited. An unresolved finding always needs v1.8 dual-signed independent review; a confirmed staging finding needs a newly authorized, independently reviewed retest. The v1.5 operator Unix service does **not** grant this interface to any agent automatically. See `V1_9_INVESTIGATION.md`.

## v1.9 multi-report investigation extension (operator only)

`aegis_investigation_evidence.py` has three strictly typed commands: `attach`
(admit one completed report with `context` or explicitly bound
`remediation_retest` purpose), `snapshot` (verify immutable report attachments
and show only unverified correlations), and `retest` (optionally replay one
confirmed finding against an explicitly approved new bounded-fuzz assessment).
It uses the original investigation plan ID and protected operator policy. All
new retest executions pass through the same v1.7 fresh Linux sandbox and
independent signed runtime/evidence budgets. Neither `aegis_investigation.py
run` nor the v1.5 operator socket can invoke this extension implicitly. No
model-facing retest delegate, policy write, credential broker, arbitrary
shell/network command or deployed-exploit confirmation is added.
See `V1_9_INVESTIGATION.md` for exact command examples and threat boundaries.

## v2.0 end-to-end operator workflow (feature branch)

The fixed `aegis_integrated_assessment.py` CLI provides `create`, `snapshot`, `advance`, and bounded `run` operations under a private, positively configured operator-owned `assessment-policy.json`. It composes *only* existing signed-scope supervisors and does not expose them to arbitrary model calls. A source step's UUID can be passed into reporting only by an explicit typed step dependency; reporting and investigation must originate from earlier admitted steps. Retesting and report promotion continue to require their existing independent controls.

Use `V2_0_INTEGRATED_ASSESSMENT.md` for the exact policy schema, limits, recovery procedures and supported deployment. A stale or interrupted operation is operator-attention state, not a safe automatic retry.

## v2.0 typed agent delegation and staging sign-off

Only an operator-controlled Unix gateway may translate the model adapter's strict JSON `snapshot` or `propose` into the next preauthorized assessment action. A domain-separated operator-signed grant binds the assessment, policy digests, peer UID, agent public key and expiry; every client request is independently signed and persistently replay-protected. The gateway contains no signing private key and never offers arbitrary shell, network, policy or vault actions. See `V2_0_RELEASE_ACCEPTANCE.md`. Reviewed report admission and remediation retesting are named operator-pinned steps, not agent-directed exploit validation.
