# AEGIS v2.0 — Integrated authorized assessment (development)

See [V2_0_RELEASE_ACCEPTANCE.md](V2_0_RELEASE_ACCEPTANCE.md) for the bounded, signed agent delegation gateway, synthetic staging review/retest, audited recovery and independent release gates. Provider-independent one-shot model proposals do not expand operator-approved execution authority. This is not a production release.

# AEGIS v2.0 development — operator-owned integrated assessment

This feature branch introduces a bounded, audit-pinned workflow that composes the already-authorized source reviewer, OSV intelligence, synthetic contract testing, canonical reporting, v1.9 investigation and durable local notification. **The initial controller did not add model-selected commands; the v2.0 expansion adds only a signed, fixed-action agent delegation boundary, not arbitrary execution, credential access or unconfined networking.** Its completed status means only the selected local steps finished—not that a vulnerability is confirmed, remediated or that the system is production-approved. See [V2_0_INTEGRATED_ASSESSMENT.md](V2_0_INTEGRATED_ASSESSMENT.md). v2.1 remains the separately planned Cloudflare audit-methodology integration.

# AEGIS v1.9 — Bounded Investigation Orchestration (development)

This branch implements a protected, operator-driven investigation planner for completed v1.8 reports. Plans use only typed actions, immutable evidence, conservative unverified attack-path hypotheses, and independently authorized fresh v1.7 replay. The v1.9 extension also admits up to eight distinct completed assessment reports per plan, identifies unverified cross-run asset overlaps, and records bounded operator-gated remediation observations against dual-signed confirmed findings without claiming a production fix. Both planner steps and retest attempts have durable, lease-fenced recovery. It does **not** add an agent-facing arbitrary shell, network, credentials, live testing, or automatic finding confirmation. See [V1_9_INVESTIGATION.md](V1_9_INVESTIGATION.md); v2.1 Cloudflare methodology remains separately planned.

# AEGIS v1.8 — evidence-bound findings and durable local notifications (draft PR)

The v1.8 development branch adds canonical, immutable version-2 security reports; dual-signed human-reviewed finding promotion bound to retained staging evidence; remediation views; a durable local Unix notification receiver; and lease-fenced, backed-off, idempotent notification dispatch. Only the existing privileged operator service controls these APIs: no model gains unrestricted code execution, network access, or credential control. See [V1_8_REPORTING.md](V1_8_REPORTING.md). The local receiver is not an external email, webhook or human inbox, and signing an assessment does not objectively prove real-world exploitability.

# AEGIS v1.8 — evidence-bound reporting and local notifications (draft)

The v1.8 feature branch adds a versioned canonical findings schema, safe projections of completed assessment evidence into *unverified* leads, generated Markdown and integrity manifests, a durable notification outbox and an acknowledgement-verified local Unix-socket sender. **A queued event is not a delivered notification, and a lead is not a confirmed exploit.** No external notifications or new offensive tools are enabled. See [V1_8_REPORTING.md](V1_8_REPORTING.md). This is not a tagged release.

# AEGIS v1.7 — bounded local reproduction (development, stacked PR)

This stacked branch now supports three fixed, operator-pinned, network-denied Python contracts: exact tenant ownership, strict JSON resource authorization, and versioned compare-and-swap state transitions. The parent validates synthetic evidence, runs bounded repeats and can independently replay a minimal mismatch in a new kernel-isolated process with a new budget reservation. This is local security-invariant validation, not a general-purpose pentest engine or proof of deployed exploitation. See [V1_7_LOCAL_REPRODUCTION.md](V1_7_LOCAL_REPRODUCTION.md). The Cloudflare methodology integration remains reserved for **v2.1**, as planned in [V2_1_CLOUDFLARE_AUDIT_PLAN.md](V2_1_CLOUDFLARE_AUDIT_PLAN.md). Neither is a tagged release.

# AEGIS v1.4.1 — Kernel-Enforced Network Containment

This stacked **v1.6 development branch** adds fixed offline dependency inventory, operator-attested OSV exact-version correlation and non-executing security scanner report parsers. Read [V1_6_SECURITY_INTELLIGENCE.md](V1_6_SECURITY_INTELLIGENCE.md). The previously released version remains v1.4.1; this is not a v1.6 release or an autonomous scanner.

AEGIS is a provider-independent, authorization-scoped assessment runner. The released v1.4.1 provides a fixed read-only source reviewer and uncredentialed HTTP/HTTPS GET/HEAD metadata testing. It is not yet the autonomous v2.0 system in the roadmap.

This v1.5 development branch also contains an operator-approved credential-session prototype with kernel-confined HTTPS transport. See [V1_5_IMPLEMENTATION_STATUS.md](V1_5_IMPLEMENTATION_STATUS.md) for its tests and remaining release gates. It remains draft; do not provision production credentials.

The HTTP worker now runs inside private Linux user, mount, network and PID namespaces with default-deny seccomp. A trusted broker gives it **one already-connected TCP socket** to the verified numeric IP and port. The kernel denies new sockets, reconnects, UDP, Unix sockets, netlink and namespace changes. The worker cannot broaden its endpoint permission by modifying Python code or policy files.

See [HTTP_GATEWAY_SECURITY.md](HTTP_GATEWAY_SECURITY.md) for the architecture diagram, privilege model, lifetime controls and precise limits. The trusted supervisor/DNS/connection broker and host kernel remain outside the compromised-worker threat model. Endpoint confinement does not independently enforce HTTP semantics: a compromised worker can misuse the one granted stream until killed.

## Implemented capabilities

- **Signed authorization:** Ed25519-signed scopes, pinned public keys, independent operator trust, fresh revocation snapshots, time windows and exact method/asset restrictions.
- **Source review:** fixed heuristic worker; authorized repository mounted read-only/noexec; no network; no repository code execution.
- **HTTP/HTTPS:** exact approved origin and route; validate every DNS address against signed/trusted networks and exclusions; pin one numeric IP and TCP port. No DNS re-resolution by the worker.
- **TLS:** verified certificates, hostname/SNI and system roots, optionally extended by a protected operator CA whose SHA-256 is checked. Only public CA material enters the worker.
- **Persistent limits:** SQLite request/rate/concurrency/runtime/evidence and worst-case response-body reservations. Failures remain charged. Bodies are bounded, hashed and discarded.
- **Stop and lifecycle:** repeated scope/route/CA/revocation checks, emergency stop, an independent worker deadline and kernel parent-death cleanup. Worker output is bounded before it reaches the supervisor.
- **Audit:** local hash chain and separately signed operator checkpoints; independent off-host retention is still required.

Only GET and HEAD are supported. No proxies, redirects, cookies, credentials, caller-provided headers, request bodies or arbitrary tool execution are enabled.

## Requirements and verification

Use a **non-root Linux service identity**, system `/usr/bin/python3`, `/usr/bin/unshare`, `libseccomp.so.2`, functional user/mount/network/PID namespaces and read-only runtime bind mounts. Supported CI targets are Ubuntu 22.04/system Python 3.10 and Ubuntu 24.04/system Python 3.12.

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python aegis_sandbox_check.py
python aegis_demo.py
python aegis_http_demo.py
```

The tests and demos contact only local synthetic services. They generate temporary signing keys and certificates. The shipped example trust policy is disabled by default. Missing kernel prerequisites deny requests; there is no unconfined fallback.

Read [VERIFICATION.md](VERIFICATION.md) for actual results, CI gates and deployment checks. WSL installations with locked child mounts under `/usr` can fail the runtime bind; do not weaken confinement to bypass that failure.

The code has no workstation-specific paths or user accounts. Installation location and operator state/policy paths are configurable. Windows and macOS hosts need a suitable Linux VM or execution environment; native Windows/macOS kernels cannot provide this Linux security boundary. Other Linux distributions must pass the same prerequisites and acceptance tests before use. Repository text uses LF line endings consistently across platforms.

Ubuntu 24.04's AppArmor policy may deny unprivileged user namespaces by default. An operator must explicitly permit them for the trusted service. The named example profile in `deployment/apparmor/aegis-supervisor` grants that prerequisite; it is not a complete AppArmor confinement policy. Load it administratively and attach it to the service (for example, systemd `AppArmorProfile=aegis-supervisor`). The service still runs non-root. Do not disable AppArmor globally or bypass failed namespace checks. CI tests this opt-in configuration explicitly.

## Operator setup

1. Install all code in a protected location outside agent-writable repositories. Pin `AEGIS_TRUST_POLICY` and `AEGIS_STATE_ROOT`; use a service-owned mode-0700 state directory. Keep private signing keys outside runtime workers.
2. Independently approve the engagement, exact origins, destination CIDRs and `controlled_http_testing` method. Configure `allowed_http_path_prefixes`, such as `{"https://staging.example.org":["/health"]}`. Routes default to deny.
3. Issue a matching signed manifest with network, request, response-body, evidence, concurrency and runtime ceilings. Include `max_total_response_bytes`. Changed scope hashes require a new engagement.
4. For a private staging CA, configure `tls_custom_ca` only in protected operator policy with an absolute `path` and SHA-256. The file must be regular, non-symlinked, protected against other-user writes, and outside tested repositories.
5. Maintain fresh revocation snapshots and independently retain signed audit checkpoints.
6. Expose only named source-review or HTTP metadata operations through your authenticated operator service. This package supplies a CLI, not that API service.

```bash
export AEGIS_TRUST_POLICY=/etc/aegis/trust-policy.json
export AEGIS_STATE_ROOT=/var/lib/aegis/protected-state

python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig http \
  --url 'https://staging.example.org/health' --method HEAD --seconds 15

python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig http-usage

# Operator-only irreversible emergency stop:
python aegis_supervisor.py stop --engagement-id ENGAGEMENT_ID
```

## Migration and limits

v1.4 signed scopes, operator policies and persistent ledger formats remain compatible. Install the new broker and launcher/gateway changes together, stop active operations before upgrading and rerun deployment-host tests. No host firewall rules, privileged broker or CAP_NET_ADMIN grant is needed.

A compromised assessment worker cannot choose another endpoint, but may send arbitrary bytes on its granted stream, violate application body limits or forge metadata until its deadline. Use narrow, authorized staging endpoints; GET is not intrinsically harmless. Exact wire-byte quotas, cgroups, authenticated testing, credentials, arbitrary tools, autonomous planning and external notifications remain future milestones.

No guarantee covers a compromised trusted host, kernel, supervisor/broker, policy or signing key. Remove independent shell/network tools from the agent.

Further reading: [Security model](SECURITY_MODEL.md), [integration](INTEGRATION.md), [supervisor contract](SUPERVISOR_SPEC.md), [milestones](MILESTONES.md), [release notes](RELEASE_NOTES.md), [audit checkpoints](AUDIT_CHECKPOINTS.md).


## v1.5 operator-only prototype (NOT RELEASED)

The v1.5 branch adds `aegis_operator_service.py` and `aegis_operator_client.py`: a local Unix-domain operator interface with Linux peer-UID checks, Ed25519-signed short-lived commands, persistent replay accounting, and only `session.create`, `session.revoke`, and `session.fetch`. The agent must never receive the operator socket, signing key, vault references or session handle. There is **no model-facing delegation adapter**.

The credential authority now requires `credential_profiles` for every vault reference. Only synthetic or explicitly acknowledged, short-lived disposable staging tokens are allowed; production, permanent and unclassified credentials are rejected. Each profile binds exact approved HTTPS origins, a UTC expiration and an expected SHA-256 token fingerprint. Fingerprint rotation invalidates pre-existing sessions. The trusted connection broker requires a sealed anonymous snapshot instead of a mutable vault FD. The worker still temporarily sees its token and can misuse it over its single allowed connection.

Review [Operator Service Security](OPERATOR_SERVICE_SECURITY.md) before deployment. The disabled sample policies are `operator-api-policy.example.json` and `credential-policy.example.json`.

```bash
# Under an unprivileged Linux service identity
PYTHONPATH=tests python3 -m unittest test_operator_service test_credentials -v
PYTHONPATH=tests python3 -m unittest discover -s tests -v
python aegis_sandbox_check.py
```

**Do not merge or use real credentials** until the exact PR head passes Ubuntu CI and deployment-host operator identity separation, key provisioning and residual credential disclosure have been independently reviewed.
