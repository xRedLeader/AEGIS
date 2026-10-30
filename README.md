# AEGIS v2.1 — bounded authorized assessment and source research

AEGIS is a provider-independent assessment runner for explicitly authorized
source repositories and staging services. An operator signs the scope and pins
the allowed workflow. A delegated agent can inspect its state or propose its
exact next approved step. Assessment workers run inside Linux namespaces with
default-deny seccomp; the model receives no general shell, vault or signing key.

**Status: v2.0 merged in [PR #8](https://github.com/xRedLeader/AEGIS/pull/8);
v2.1 source research merged in [PR #9](https://github.com/xRedLeader/AEGIS/pull/9).
Production approval is pending.** Current candidate evidence belongs in the
[exact-commit release bundle](RELEASE_EVIDENCE.md); the
[v2.0 handoff](V2_0_REVIEW_HANDOFF.md) preserves historical evidence.
[Release acceptance](V2_0_RELEASE_ACCEPTANCE.md) defines the existing merge,
release and deployment gates; [host acceptance](V2_0_HOST_ACCEPTANCE.md) provides
the commands and sign-off record. Passing CI does not fill the independent
reviewer or actual deployment-host fields.

## Implemented capabilities

| Capability | Supported boundary |
|---|---|
| Signed authorization | Ed25519 scope, pinned verification keys, independent trust/revocation policy, expiry, stop and persistent budgets |
| Source review | Fixed heuristic worker; authorized repository mounted read-only/noexec; no network or repository code execution |
| v2.1 source research | Pinned Cloudflare guides, deterministic coverage, signed independent research roles, source-line checks and repeated-run revalidation; external adapters supply agents |
| Dependency intelligence | Offline inventory and operator-attested OSV snapshots; exact-version leads with range uncertainty retained |
| Local contract testing | Pinned Python tenant, JSON authorization and versioned-state contracts; bounded trials and fresh isolated replay |
| HTTP/HTTPS metadata | Approved GET/HEAD origin and route, checked DNS addresses, pinned numeric endpoint, verified TLS and one brokered connection |
| Staging credentials | Separate operator-only session API; only classified, expiring synthetic or disposable staging tokens; sealed snapshots and revocation |
| Evidence and findings | Immutable canonical reports; separate verifier/operator signatures for staging finding promotion; retained review proof |
| Investigation and retesting | Typed report-bound plans, bounded cross-run observations and separately authorized local retests; no automatic production-fix verdict |
| Notifications | Durable local Unix receiver, peer-UID validation, commit-before-ack and bounded retry; external human receipt requires separate evidence |
| v2.0 workflow and delegation | At most 12 operator-pinned steps; short-lived signed grants, separately signed requests, OS peer identity, persistent replay prevention and exact-step binding |
| Recovery and audit | Lease-fenced durable state, explicit operator abandonment, local hash chain and independently signed checkpoints |

The [detector roadmap](https://github.com/xRedLeader/AEGIS/issues/10) adds measured
[rule coverage](DETECTOR_COVERAGE.md), broader [dependency inventory](DEPENDENCY_COVERAGE.md),
[scanner evidence admission](SCANNER_ADMISSION.md), a protected
[provider runner](PROVIDER_RUNNER.md), [Ubuntu deployment packaging](deployment/README.md) and release-evidence
reconciliation. Consult each guide for its exact supported formats and remaining
validation. Optional live Claude testing and accountable pilot sign-off remain
separate from offline regression tests.

[Governed offline execution](SCANNER_EXECUTION.md) supports pinned Semgrep-core,
Gitleaks and selected-advisory Trivy SBOM profiles. The separate signed
[Nuclei staging profile](STAGING_DAST_BOUNDARY.md) permits bounded anonymous
HTTP GET/HEAD requests through the trusted request broker. Each guide lists
its restricted configuration, unsupported features and required native checks.
Execution and import results remain unverified leads.

The workflow's completed status means its configured local operations finished.
Finding confirmation, deployed impact and remediation retain their independent
review requirements. [The v2.1 source-audit guide](V2_1_SOURCE_AUDIT.md) explains
configuration, role replies, incremental audits, limits and integration. Research
agents cannot promote a finding to confirmed without the existing staging proof.

## Requirements and verification

Supported CI targets are Ubuntu 22.04 with system Python 3.10 and Ubuntu 24.04
with system Python 3.12. Runtime services must use non-root Linux identities,
`/usr/bin/unshare`, `libseccomp.so.2`, functional user/mount/network/PID namespaces
and read-only runtime bind mounts. Windows and macOS need a suitable Linux VM;
other Linux environments must pass the same acceptance checks.

From the exact candidate checkout, verify the tracked source before installing
dependencies in an isolated environment:

```sh
/usr/bin/python3 aegis_source_integrity.py
/usr/bin/python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python aegis_sandbox_check.py
.venv/bin/python aegis_demo.py
.venv/bin/python aegis_http_demo.py
```

Run acceptance as the intended non-root service identity. Every security test
must execute; skipped tests do not satisfy acceptance. The GitHub Ubuntu matrix
explicitly fails if any test is skipped. Tests and demos use synthetic services,
temporary keys and temporary certificates, and do not authorize a real target.

Ubuntu 24.04 may require an administrator to load the named opt-in AppArmor
profile in `deployment/apparmor/aegis-supervisor` and select it for the service.
It grants the user-namespace prerequisite and is not a complete MAC policy.
Keep AppArmor enabled and run the tests under the actual selected profile.
Missing kernel prerequisites deny execution; there is no unconfined fallback.

## Operator setup

1. Install the complete code set under protected directory chains outside
   agent-writable repositories. Pin the reviewed Git commit and verify
   `SHA256SUMS.txt`; checksums establish consistency, not independent provenance.
2. Provision distinct non-root assessment/gateway, agent-adapter and receiver
   identities. Restrict group access to the required delegation/receiver sockets.
   Keep the privileged credential operator socket private.
3. Protect signed scope, trust/revocation files, verification keys and workflow
   policies with independently read-only mounts or separately reviewed MAC
   controls. A service-owned mode-0600 file alone is still service-writable.
   Keep private operator signing keys offline and outside worker mounts.
4. Authorize the exact staging assets, methods, time window and resource limits.
   Provision protected state, report and policy locations. All shipped example
   policies are disabled; they are not deployment authorization.
5. Create the fixed workflow using `aegis_integrated_assessment.py`. If delegation
   is needed, start `aegis_agent_gateway.py` and separately issue a short-lived
   grant through the offline operator client. The adapter accepts only strict
   `snapshot` or exact-next-step `propose` decisions.
6. Complete the [actual-host runbook](V2_0_HOST_ACCEPTANCE.md), independent staging
   review, recovery drills and off-host checkpoint retention before release.

Use [the integrated assessment guide](V2_0_INTEGRATED_ASSESSMENT.md) for workflow
commands and recovery, [release acceptance](V2_0_RELEASE_ACCEPTANCE.md) for
delegation setup, and [integration](INTEGRATION.md) for the component interfaces.
An interrupted action requires reconciliation; do not repeat it merely because
the client did not receive a response.

## Security limits and upgrades

The trusted host, kernel, interpreter/dependencies, supervisor, connection broker,
policies and signing keys remain part of the trusted boundary. Endpoint
confinement does not constrain all bytes a compromised HTTP helper can send on
its already-approved connection. A credential helper temporarily sees its
staging token and may misuse that approved stream. Review those residual risks
with the accountable operator.

General shell execution, model-selected tools/targets, live HTTP mutation,
automatic exploit confirmation, autonomous remediation and external notification
transport are outside this release. Remove unrelated shell/network capabilities
from the delegated agent. A local zero-lead retest does not certify a deployed
fix; a local acknowledgment does not prove delivery to a human off-host.

Stop active operations before replacing trusted code, install the complete
candidate together, preserve existing ledgers and signed engagement history,
and rerun acceptance on the intended host. Changed scope or policy fingerprints
require the existing reauthorization flow; upgrades do not expand authority.

## Documentation

- [Current release evidence and role onboarding](RELEASE_EVIDENCE.md)
- [Historical v2.0 review handoff](V2_0_REVIEW_HANDOFF.md)
- [Release acceptance](V2_0_RELEASE_ACCEPTANCE.md) and [actual-host runbook](V2_0_HOST_ACCEPTANCE.md)
- [Security review and reproduced fixes](V2_0_SECURITY_REVIEW.md)
- [Security model](SECURITY_MODEL.md), [HTTP boundary](HTTP_GATEWAY_SECURITY.md) and [operator API](OPERATOR_SERVICE_SECURITY.md)
- [Integrated workflow](V2_0_INTEGRATED_ASSESSMENT.md), [investigations](V1_9_INVESTIGATION.md) and [reporting](V1_8_REPORTING.md)
- [Audit checkpoints](AUDIT_CHECKPOINTS.md), [release notes](RELEASE_NOTES.md) and [milestones](MILESTONES.md)
