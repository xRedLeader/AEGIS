# AEGIS v1.9 — bounded investigation orchestration (development)

**Feature branch, not a v1.9 release or an agent-facing execution API.** This is
an operator-owned, deterministic investigation planner for already completed,
cryptographically and ledger-bound AEGIS v1.8 findings reports. It does not
infer authorization from AI instructions, a finding description, tool output or
an assessed repository. Cloudflare multi-agent audit integration remains at
**v2.1**; this milestone does not instantiate independent AI hunting agents.

## Trust contract

- The signed engagement scope and independent trust/revocation state must pass
  AEGIS's existing `_guard` on every operation. The source run must be
  **completed** and have a v1.8 canonical report recorded in the protected
  SQLite ledger. AEGIS revalidates the latest independently reviewed revision,
  all private package files, proof digests, the canonical schema/renderings,
  original evidence bytes, report SHA-256 and audit hash chain. No finding
  severity, exploitability, authority or deployment reachability is invented.
- A private, external operator-owned `investigation-policy.json` must be
  positively configured for the engagement. It specifies the maximum number
  of steps, two or three bounded attempts, lease lifetime and an explicit
  per-source-run allowlist for offline replay. The file may not live beneath
  AEGIS state, reports, an assessed repository or the worker-visible `/usr`
  tree. The policy's **exact bytes are hashed and pinned** in each plan. Policy
  rotation invalidates the plan rather than silently expanding capability.
- The planner supports only named, typed actions. It has **no shell, model
  tool dispatcher, arbitrary executable, network connection, vault access,
  credential handle, policy mutation or live HTTP mutation**. The established
  v1.5 operator-service socket does not automatically expose this planner.
- The planner cannot mark a finding confirmed/rejected. v1.8's independent
  dual-signed review is still the only promotion path. Likewise, a confirmed
  staging finding is not automatically declared remediated. Its retest requires
  a new, separately authorized and reviewed assessment. Changing an admitted
  report revision invalidates the old plan and requires a new one.

## Deterministic typed plan

Each created plan is a content-addressed snapshot of the engagement, manifest
SHA, operator-policy SHA, completed source run, latest admitted report SHA,
source evidence SHA, and a **maximum 40-step** investigation. It contains:

1. `verify_report_integrity` — always first; rechecks the immutable report and
   original protected evidence. No target code is executed.
2. `replay_bounded_local` — only for a source report with unresolved
   `bounded_fuzz` leads **and** an explicit matching operator replay allowlist.
   It uses `AegisFuzzSupervisor.verify_evidence` with the existing independent
   signed `bounded_fuzzing` authorization, pinned repository/module/function,
   an eight-second budget and a new rootless, offline namespace. The prior
   source run and replay run are linked in the underlying audit ledger; the
   planner retains only a bounded, hash-verified result. A reproduced mismatch
   remains **local / needs deployment validation**.
3. `await_independent_review` — operator checkpoint for each unresolved lead;
   no automatic action, no delegated authority and no fake completion.
4. `await_remediation_retest` — operator checkpoint for an independently
   attested confirmed staging finding. No live target test or automatically
   asserted fix is performed.

For findings sharing an exact affected asset, the report includes a bounded
list of `UNVERIFIED_SHARED_ASSET_ONLY` correlation hypotheses. These have
`observed_transition=false`. **Two confirmed weaknesses do not establish that
one leads to the other**; v1.9 never emits a verified multi-hop exploit chain
without separately reviewed actual transitions. Empty findings and zero
hypotheses do not imply adequate coverage or target security.

## Durable state and recoverability

Plans, typed steps, retries, lease tokens, explicit outcomes and bounded
canonical result JSON are stored under AEGIS's protected SQLite database and
append-only hash-chain audit events. A step has a random lease token and a
60–300-second lifetime. Expired leases are claimable again; a prior worker
cannot finalize a later lease. Retries and interrupted executions consume
attempts; an exhausted step becomes `failed`. A successful locally reproduced
candidate is **not** upgraded to a confirmed finding by that outcome.

This is **at-least-once execution** for operator-approved local replay, not
exactly once: the trusted v1.7 fuzz supervisor independently charges runtime
and evidence budgets each time it executes. If a process crashes after
execution but before finalizing the investigation step, the next attempt
may rerun the synthetic case; the prior v1.7 audit/run remains preserved.
Database integrity is anchored to the existing signed external audit
checkpoint design; a compromised trusted host or operator is outside the
worker threat model.

## Operator commands

The shipped `investigation-policy.example.json` is disabled; provision a
private policy with the exact current engagement ID and (optionally) a
reviewed source-run-specific offline replay target. Write the active JSON
in canonical sorted compact form with mode `0600` under a `0700` operator
configuration directory, outside every assessed repository and AEGIS state.

```sh
python aegis_investigation.py \
  --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json --state-root /var/lib/aegis \
  --investigation-policy /etc/aegis/investigation-policy.json \
  plan --source-run <completed-source-run-uuid>

python aegis_investigation.py \
  --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json --state-root /var/lib/aegis \
  --investigation-policy /etc/aegis/investigation-policy.json \
  advance --plan-id <plan-uuid>

python aegis_investigation.py \
  --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json --state-root /var/lib/aegis \
  --investigation-policy /etc/aegis/investigation-policy.json \
  snapshot --plan-id <plan-uuid>
```

An optional `run --plan-id <uuid> --max-steps 10` performs a bounded one-shot
progression through **only** existing approved automatic steps. It halts on
operator-review checkpoints, busy/failure states or its upper bound. No daemon,
recurring scheduler, agent-generated action payload or background workflow is
installed; the operator chooses when to run or resume a plan. Human-review checkpoints remain visibly unresolved until
external v1.8 signed review/retest evidence produces a **new report version**.

## Acceptance and residual risks

Run the full inherited unit and genuine namespace/seccomp kernel matrix on
Ubuntu 22.04 and 24.04 with zero skips. The v1.9 suite includes concurrent
idempotent planning, immutable report checks, policy tampering, emergency stop,
source/report revision drift, replay allowlist denial, lease recovery, exhausted
attempts, stale token fencing, audit/result corruption, and **one actual v1.7
sandboxed local replay**. Recheck `SHA256SUMS.txt` on the exact PR revision.

This release scope is a *deterministic bounded planner*, not unrestricted
self-directed exploitation, full automatic chain validation, model-selected
payload synthesis, native fuzzing, autonomous production remediation or an
agent that can sign its own authorization. Deployment-host and operator/agent
identity separation must still be independently reviewed before tagging.
