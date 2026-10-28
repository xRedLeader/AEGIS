# AEGIS v2.0 — integrated, authorized assessment workflow (development)

**First end-to-end integration increment, not the finished autonomous v2.0 security platform or a released tag.** v1.9 was merged into `main` before this feature branch. The operator controls every executable action; the workflow never grants an AI agent direct access to privileged Python classes, a shell, a vault, the network broker, a policy file or signing keys. Existing v1.4.1–v1.9 authorization, namespace, audit, credential isolation and evidence controls remain the actual security boundaries.

## What works now

A trusted operator can submit a protected, canonical, **disabled-by-default** v2 assessment policy. The controller creates a durable, bounded, typed workflow in the existing trusted SQLite ledger. It can connect the *existing fixed operations*, without giving itself an alternative execution path:

| Action | Existing implementation | Required independent control |
|---|---|---|
| `source_review` | `AegisSupervisor.scan` | Signed `source_review`; rootless offline source worker |
| `dependency_intelligence` | `AegisIntelligenceSupervisor.assess_dependencies` | Signed `dependency_analysis`; pinned, operator-attested OSV snapshot |
| `local_contract` | `AegisFuzzSupervisor.execute` | Signed `bounded_fuzzing`; private, source-hash/callable-pinned fuzz policy |
| `http_metadata` | `AegisHttpSupervisor.request` | Signed `controlled_http_testing`; operator-approved origin/route, numeric-IP pinning, brokered socket, no extra egress |
| `report` | `ReportingSupervisor.generate` | Only a preceding completed source-review, dependency or local-contract run; immutable report package and outbox |
| `investigate` | `EvidenceInvestigationSupervisor.create` | Previously reported run; private pinned v1.9 investigation policy |
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

**Not yet complete for v2.0:** model-driven investigation selection under an independently authenticated *agent-facing* delegation API, broad reviewed scanner execution, current automated advisory ingestion, direct proof of a reachable deployed exploit, real HTTP mutation or autonomous remediation. Those are not simulated by synthetic replay. The overall v2.0 definition of done includes a complete independently reviewed authorized staging scenario with each remaining decision gate documented. Cloudflare's independent multi-agent coverage/hunting methodology is deliberately scheduled for **v2.1**, and does not grant authority to expand a signed scope.
