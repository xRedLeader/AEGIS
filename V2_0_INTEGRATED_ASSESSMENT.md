# AEGIS v2.0 — integrated, authorized assessment workflow

**Implemented bounded workflow; independent release and deployment acceptance remain pending.** v1.9 was merged into `main` before this feature branch. The operator controls every executable action; the workflow never grants an AI agent direct access to privileged Python classes, a shell, a vault, the network broker, a policy file or signing keys. Existing v1.4.1–v1.9 authorization, namespace, audit, credential isolation and evidence controls remain the actual security boundaries. [The review handoff](V2_0_REVIEW_HANDOFF.md) records the candidate and outstanding evidence.

## What works now

A trusted operator can submit a protected, canonical, **disabled-by-default** v2 assessment policy. The controller creates a durable, bounded, typed workflow in the existing trusted SQLite ledger. It can connect the *existing fixed operations*, without giving itself an alternative execution path:

| Action | Existing implementation | Required independent control |
|---|---|---|
| `source_review` | `AegisSupervisor.scan` | Signed `source_review`; rootless offline source worker |
| `dependency_intelligence` | `AegisIntelligenceSupervisor.assess_dependencies` | Signed `dependency_analysis`; pinned, operator-attested OSV snapshot |
| `local_contract` | `AegisFuzzSupervisor.execute` | Signed `bounded_fuzzing`; private, source-hash/callable-pinned fuzz policy |
| `http_metadata` | `AegisHttpSupervisor.request` | Signed `controlled_http_testing`; operator-approved origin/route, numeric-IP pinning, brokered socket, no extra egress |
| `report` | `ReportingSupervisor.generate` | Only a preceding completed source-review, dependency or local-contract run; immutable report package and outbox |
| `admit_report` | Exact completed v1.8 reviewed report admission | Operator-pinned run and report SHA-256; retained independent review and investigation policy |
| `investigate` | `EvidenceInvestigationSupervisor.create` | Previously reported run; private pinned v1.9 investigation policy |
| `remediation_retest` | `EvidenceInvestigationSupervisor` attachment and observation | Earlier investigation, confirmed finding and separately authorized completed retest; conservative outcome requiring independent review |
| `progress_investigation` | `EvidenceInvestigationSupervisor.run_allowed` | Previously created plan; strict action count; stops at manual checkpoints |
| `notify` | `NotificationSupervisor.deliver` | A preceding report, private notification policy, verified receiver UID and challenge-bound durable acknowledgment |

Policy steps have **exact field sets** and a **maximum of 12 entries**. Each is assigned an operator-defined stable ID. `report`, `investigate`, `progress_investigation` and `notify` may reference only the correct *earlier* step ID. Unrecognized actions, embedded commands, free-form targets, cycles, changes to signed scope or widening of per-action budgets are rejected. No model-generated text determines the action list.

The controller stores only bounded structural metadata: source-run IDs, evidence kinds, report hashes, investigation IDs and notification receipt IDs. It **does not** retain target code, response bodies, credentials, local secrets, vulnerability narratives or full endpoint URLs in the workflow result ledger. Recovered results are validated against per-action schemas **and the existing hash-chained audit log**, not merely a mutable row checksum. Operator-signed audit checkpoints must still be independently retained off-host; a compromised trusted host can rewrite an unanchored local ledger.

## Runtime and state machine

- Create: validate fresh Ed25519 scope/revocation, approve the exact configured policy, pin the manifest and byte-for-byte policy digest and persist the plan atomically. An optional operator-generated UUID makes a repeated create request idempotent, but does **not** authorize anything.
- Claim: under a SQLite `BEGIN IMMEDIATE` transaction, select the first unfinished step, atomically lease it to exactly one worker for 60–300 seconds and record an audit event. A second worker is denied.
- Execute: call only that step's fixed supervisor, which independently revalidates scope and consumes its existing resource budget. Pre-existing evidence, report, investigation and delivery records retain their own ownership rules.
- Complete: revalidate signed scope/stop/revocation and exact operator policy; persist the *validated* bounded result under the same lease token, and append its result digest to the audit chain in the same transaction.
- Recover: completed steps survive process restarts and are not executed twice. An interrupted, expired, failed or ambiguous side-effecting step becomes **`attention`**. It is never silently retried: an operator must inspect the underlying budget, run, report and delivery ledgers, then start a separately approved assessment if further work is necessary.
- Finish: `WORKFLOW_COMPLETED_PENDING_INDEPENDENT_VALIDATION` means the configured *local actions* completed. It is **not** a claim of full security coverage, verified exploitability, successful remediation, a clean scan or production readiness.

Example workflow for an operator-owned staging repository:

```sh
# 1. Provision an isolated, private operator policy (mode 0600) outside /usr,
#    the AEGIS state/report root and the assessed repository.
#    Use an independently read-only mount and protected parent paths;
#    mode 0600 alone does not prevent the owning service from rewriting it.
#    Enable only after confirming signed scope, pinned source, other policies,
#    service identity, local receiver and testing budgets.

python aegis_integrated_assessment.py \
  --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis \
  --assessment-policy /etc/aegis/assessment-policy.json \
  create

# Use the returned assessment UUID for controlled progression/recovery:
python aegis_integrated_assessment.py \
  --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json --state-root /var/lib/aegis \
  --assessment-policy /etc/aegis/assessment-policy.json \
  run --assessment-id <assessment-uuid> --max-actions 4

# Read a snapshot instead of retrying interrupted actions:
python aegis_integrated_assessment.py \
  --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json --state-root /var/lib/aegis \
  --assessment-policy /etc/aegis/assessment-policy.json \
  snapshot --assessment-id <assessment-uuid>
```

The included `assessment-policy.example.json` is **not configured** and cannot be enabled without a deliberately protected, independently reviewed operator policy. Other referenced settings (investigation/fuzz/notification policies, OSV signatures and any local TLS trust) remain separate and must be provisioned independently. No generic model tool, credentialed request or private signing-key access is added here.

## Acceptance and limits

Run `python -m unittest discover -s tests -v` as a non-root Linux service identity on supported Ubuntu 22.04 and Ubuntu 24.04 hosts with real namespaces, default-deny seccomp and the configured AppArmor profile. **All tests must pass, including zero skipped kernel-security tests.** The v2.0 suite checks real rootless source and dependency/fuzz execution, signed snapshot intake, multi-report investigation, local receiver acknowledgment, file/policy tampering, SQL result/audit substitution, stop/revocation, scope boundaries, lease concurrency and interrupted-run fail-closed recovery.

Before a production tag: independently review privileged operator code, all existing v1.5–v1.9 trust boundaries, deployment UID/socket/key permissions, control-plane and staging isolation, immutable evidence custody, off-host checkpoints, rate/timeout settings and a fully synthetic operator-provisioned staging assessment. Incident/rollback and crash-recovery drills on the **actual host** remain required.

**First-increment limits (superseded in part by the final expansion below):** the first build lacked an authenticated model-facing delegation API and complete signed staging/retest integration. The expanded version addresses those *bounded* interfaces. Broad native scanners, automated advisory fetching, live HTTP mutation, objective deployed exploit verification and autonomous remediation remain outside the implemented synthetic-staging contract. The production release gate requires independent source/host review and an operator-authorized real staging exercise. Cloudflare's multi-agent coverage/hunting methodology remains planned for **v2.1**; no agent instructions grant signed AEGIS authority.

## Final v2.0 bounded integration expansion

The follow-up implementation adds a separately authenticated, operator-owned
Unix-domain agent gateway, offline Ed25519 delegations, a narrow model-output
adapter, durable request replay prevention and a distinct-UID socket test. The
model can only request a bounded structural snapshot or explicitly propose
the **next** operator-policy-pinned step. The operator retains all original
execution authority and can reject or revoke the grant. No model-generated
URL, payload, shell, credential handle, policy change or arbitrary method is
admitted. See [V2_0_RELEASE_ACCEPTANCE.md](V2_0_RELEASE_ACCEPTANCE.md).

Integrated workflows can now import a completed reviewed v1.8 report by its
exact SHA-256 and, from an approved v1.9 investigation, record a separately
authorized synthetic remediation retest. Every referenced operator policy
and admitted signed-snapshot byte digest is pinned at workflow creation and
checked again before the next action. The retest remains a local observation
requiring an independent operator determination of deployment remediation.

An operator may immutably abandon a failed/expired workflow with an enumerated
reason; this stops further execution, without claiming rollback of already
completed effects. All new capabilities have negative/adversarial and full
Ubuntu kernel regression acceptance tests. v2.0 release status remains blocked
on independent host, reviewer, key and deployment acceptance described in the
release checklist.
