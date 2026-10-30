# Current release review and evidence

V2.0 was merged through [PR #8](https://github.com/xRedLeader/AEGIS/pull/8).
V2.1 source research was merged through [PR #9](https://github.com/xRedLeader/AEGIS/pull/9),
at main commit `aaa0c34a936d886392de75016f1cbac38a787736`.
The detector/provider/deployment work is tracked in
[roadmap #10](https://github.com/xRedLeader/AEGIS/issues/10). Merged code is not a
production approval. The original release/host acceptance requirements continue
to apply; older PR tables and test counts are historical evidence for their
named commits, not evidence for a later candidate.

## Collect one exact candidate

`aegis_release_evidence.py` reads an existing private evidence directory and a
separately selected private trust directory. It compares every regular tracked
source file directly with the pinned Git commit's blobs and verifies
`SHA256SUMS.txt`. Git is used only to read objects: no checkout, filters, hooks,
builds or repository code execute. Source exports without the independently
available Git objects cannot satisfy this particular checker.

```sh
python aegis_release_evidence.py --candidate FULL_40_CHARACTER_COMMIT \
  --source /protected/candidate-checkout --bundle /private/release-evidence \
  --trust /private/release-trust/trust.json > /private/review-summary.json
```

The collector does not initialize/repair a runtime, create ledger entries,
generate keys, run checks, fetch CI results, contact staging or send messages.
It reads the evidence already collected by the responsible operators. Exit 0
means the supplied machine records are structurally complete and consistent;
exit 1 means missing/invalid/stale evidence; exit 2 means the bundle itself is
unusable. **Every result remains `NOT_PRODUCTION_APPROVED`.** The redacted JSON
contains commit, fixed check labels, role status and no source/log contents,
host paths, actor names or key bytes. Publish that summary only after review;
keep original evidence private.

`tests/test_release_evidence.py` is a synthetic executable example of the full
version-1 bundle. It is not actual deployment or CI evidence.

## Version 1 bundle contract

`bundle.json` has exactly these fields:

- `schema_version: 1`, `candidate_sha`, `created_at_utc` (UTC seconds),
  `max_age_seconds` (1–2678400), `source_manifest_sha256`.
- `observations`: at most thirteen private artifact references. Each reference is
  `{ "path": "relative/file", "sha256": "64 lowercase hex characters" }`.
- `checkpoint`: `{ "record": reference, "ledger": reference }`, or `null`
  while missing. The ledger is a read-only export `{ "ledger_id": UUID,
  "rows": [[sequence, event_json, previous_hash, digest], ...] }`. The signed
  checkpoint must anchor this entire supplied snapshot; no unanchored suffix
  passes. Preserve earlier snapshots/checkpoints separately for custody review.
- `signoffs`: zero to four references to signed decisions.

References are bounded regular single-link files opened through no-follow
directory handles. Each JSON artifact is at most 512 KiB, with bounded nesting
and collections. Missing, changed, oversized or stale artifacts fail closed.
GitHub job logs may prefix lines with an ISO UTC timestamp. The collector removes
that presentation prefix only in memory after verifying each artifact hash; the
retained bytes stay unchanged and test-count, failure and no-skip checks still apply.
Do not put credentials/private keys in any evidence bundle. The checker does
not certify that an operator-supplied log is truthful or fully redacted.

Each observation contains exactly `schema_version: 1`, `candidate_sha`, `kind`,
`observed_at_utc`, `result: "PASS"`, `details`, and `artifacts` (1–32 references
to the actual retained outputs). Required kinds and details are:

| Kind | Required details |
|---|---|
| `ci_ubuntu_22_04`, `ci_ubuntu_24_04` | Exact `job_url`, `head_sha`, `conclusion: "success"`, positive integer `tests`, integer `skipped: 0`; retain the complete job log. |
| `ci_agent_delegation`, `ci_notification_receiver`, `ci_source_integrity` | Exact job URL, head SHA, success conclusion and original output. |
| `ci_native_scanners_22_04`, `ci_native_scanners_24_04` | Exact governed-execution job URL, head SHA, success conclusion, pinned preparation receipts and original offline/staging acceptance and recovery outputs. |
| `ci_packaged_services_22_04`, `ci_packaged_services_24_04` | Exact installed-services job URL, head SHA, success conclusion and retained package/service evidence. These CI fixtures do not replace `installed_host`. |
| `installed_host` | `installed_commit`, `host_identity_sha256`, `configuration_sha256`, `dependency_inventory_sha256`, `kernel_acceptance: "PASS"`, `packaged_services: "PASS"`; retain actual service identity, policy/AppArmor, diagnostic and kernel outputs. |
| `staging_proof` | `engagement_scope_sha256`; `proof_admission`, `forged_proof_rejected`, `remediation_retest` all `"PASS"`; retain independently reviewed proof and separately authorized retest. |
| `recovery_drills` | Scope hash; `crash`, `expired_lease`, `stop`, `revocation`, `no_silent_rerun`, `audited_abandonment` all `"PASS"`. |
| `delivery_drills` | Scope hash; `successful_ack`, `failed_delivery`, `receiver_restart` all `"PASS"`. |

Supplied CI/host records are evidence references, not authenticated API queries
or remote host attestations. The reviewer must compare them with the actual job
and host. Missing gates stay missing; do not construct a PASS record merely to
satisfy the schema. The schema identifies evidence required for reconciliation,
not a substitute for performing it.

`trust.json` has `schema_version: 1`, `checkpoint_key` (a public-key reference
relative to its private trust directory), and `role_keys` (role to separately
pinned public-key reference). Do not accept key pins from the evidence producer
without independent custody verification.

Each signoff is `{ "payload": ..., "signature_hex": ... }`. Payload fields are
`schema_version: 1`, `candidate_sha`, `role`, `accountable_identity`,
`observed_at_utc`, `decision: "accepted"`, and `evidence_sha256`. The last hashes
canonical JSON of `{ "observations": {kind: record_sha256, ...}, "checkpoint":
bundle.checkpoint, "source_manifest_sha256": bundle.source_manifest_sha256,
"created_at_utc": bundle.created_at_utc, "max_age_seconds": bundle.max_age_seconds }`.
Changing the bundle creation time or freshness window requires new signatures;
an unsigned edit cannot renew expired decisions. Older signatures that omitted
these fields must be replaced. Schema versions must be integer `1`, never boolean.
Sign canonical payload bytes after domain `AEGIS-RELEASE-SIGNOFF-v1\0` with the
separately controlled Ed25519 key. A valid signature establishes only that the
pinned key signed those bytes. It does not prove independence, truthful staging
impact or actual off-host storage, even when all four roles have signed.

## Responsible people and remaining decisions

| Role | Onboarding and evidence needed |
|---|---|
| Deployment operator | Pin candidate and dependencies, provision distinct non-root identities, protect policies, run the packaged-host acceptance and actual diagnostics, collect outputs and configuration digests. |
| Signing-key custodian (`signing_key_custodian`) | Keep scope/review/delegation/checkpoint private keys outside workers; independently verify public pins, ownership, rotation and recovery; sign custody decision. |
| Independent reviewer (`independent_reviewer`) | Review the exact candidate and trusted boundary, observe staging/remediation and failure cases, verify job/source/host evidence, record findings and independence; sign disposition. |
| Off-host custodian (`off_host_custodian`) | Retain current and prior signed checkpoints on independently controlled storage, verify chain/signatures and restoration, record custody evidence; sign decision. |
| Release owner (`release_owner`) | Name support/recovery owners, accept documented residual risks and supported scope, reconcile unresolved findings and all prior decisions; record the actual deployment/release decision. |

Do not infer role acceptance from a suggested name or assign human attestations
to the implementation agent. Real provider validation on another device is a
separate observation, as are the actual application pilot and any future live
DAST authorization. CI fixtures cannot close operational ticket #23.
