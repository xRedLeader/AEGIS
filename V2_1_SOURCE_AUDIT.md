# v2.1 source-audit workflow

This adds the pinned Cloudflare research methodology to AEGIS's signed assessment
workflow. It coordinates externally supplied agents; it does not embed a model
provider, launch an unrestricted coding agent, or execute target code.

The six phases are reconnaissance, scoped hunting, coverage criticism,
independent verification, final record review, and canonical reporting. The
operator owns the policy and transcript. Each agent sees its assigned context
and returns a signed JSON record; only the coordinator changes the coverage
ledger and final records. Agent prose never becomes a shell command or authority.

## Configuration

Start from `source-audit-policy.example.json`, which is deliberately disabled.
Set the exact signed engagement and canonical repository path, a sorted list of
approved UTF-8 source files, coverage seeds, the profile, and invocation budget.
Configure `agents` as `{ "id": "hunter-a", "role": "hunter", "public_key": "..." }`
records. Public keys are base64-encoded raw Ed25519 keys. Use a distinct private
key for every identity; the coordinator rejects shared keys across identities.
IDs contain 3–64 lowercase letters, digits, underscores or hyphens and begin with a letter.
Private keys belong to the external adapters, never the model prompt.

Roles are `recon`, `hunter`, `critic`, `verifier`, and `record_reviewer`.
Standard/deep workflows need two critic identities for independent final coverage
review, and another hunter identity when a unit is reassigned. Missing independent
capacity produces explicit incomplete/deferred work. Four separate reconnaissance
assignments examine architecture, entrypoints, boundaries and the coverage plan.

Store canonical JSON policy/transcript files outside the target repository,
report directory, state directory and runtime tree, in protected operator-owned
directories. Files must be private, regular, single-link files. Configuration and
transcript bytes are pinned by the integrated assessment policy.

| Profile | Coverage and review behavior |
|---|---|
| quick | Coarsens subsystem/lifecycle dimensions, one hunter wave, one critic; a fresh verifier also performs record review. |
| standard | Up to two hunter waves, post-wave critics and independent final critic, distinct verifier and final record reviewer. |
| deep | Up to three waves, explicit subsystem/lifecycle seeds, and a different hunter when revisiting previously covered work. |

Bounds are explicit: 128 source files, 1 MiB/file, 8 MiB total source, 32 coverage
units, eight findings, 128 agent invocations and eight selected prior runs.
An audit transcript is at most 128 KiB; the retained evidence envelope is at most
256 KiB. Assignments are at most 128 KiB and each agent reply at most 16 KiB.
Exceeding a bound fails closed. Narrow or split an operator-approved
audit rather than silently truncating evidence.

## Run the six phases

Use the existing protected `AEGIS_STATE_ROOT` and `AEGIS_TRUST_POLICY` environment.
The scope must allow `source_review`. Run as the non-root AEGIS operator identity:

```sh
python aegis_source_audit.py plan --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig --policy /etc/aegis/research/policy.json
```

The first response contains a new `bundle` and `next_assignment`. Preserve that
bundle's audit ID and source/policy hashes. Give only `next_assignment` to its
registered agent, with read-only access to the approved source snapshot and
the pinned guides under `third_party/cloudflare-security-audit/security-audit/`.
Use fresh agent contexts/private scratch for each assignment; the adapter is
responsible for those external agent processes. The coordinator assigns separate
scratch namespaces but never reads or promotes arbitrary scratch files.

The agent returns structured data. The external adapter signs it without exposing
its private key to the model:

```sh
python aegis_source_audit_agent.py --assignment /private/assignment.json \
  --key /private/hunter-key.pem < /private/response.json
```

Append the signed envelope to the operator-owned bundle's `records` array and
write canonical JSON. Repeat `plan` with `--bundle /etc/aegis/research/bundle.json`.
The same prefix always yields the same next assignment. Editing a response,
changing source bytes or policy, reusing a reply, changing its assigned identity,
or adding replies after completion fails verification.

Each planning call reserves its bounded AEGIS processing time and logs the plan.
External model-provider spending is controlled by the adapter/operator; this
module neither holds provider credentials nor makes billable model calls. The
transcript invocation limit reserves critic and verifier work before assigning
hunters. Unfunded or unfinished work is never reported as covered.

When `next_assignment` is null, retain the checked transcript:

```sh
python aegis_source_audit.py accept --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig --policy /etc/aegis/research/policy.json \
  --bundle /etc/aegis/research/bundle.json
```

This records `runs/<run-id>/source-audit.json`, including the policy, signed
transcript, source hashes, coverage and reviewed claims, and binds its exact bytes
to the chained audit. `incomplete` is a valid recorded outcome, never an approval.
An audit ID can be accepted only once per engagement; the durable receipt rejects
replays across restarts and concurrent submissions.

An integrated assessment can accept and report that same transcript with:

```json
[
  {"id":"research","action":"source_audit","seconds":10,
   "audit_policy":"/etc/aegis/research/policy.json",
   "audit_bundle":"/etc/aegis/research/bundle.json"},
  {"id":"report","action":"report","source":"research"}
]
```

The existing delegated model adapter can propose this exact preapproved step.
It cannot change the research policy, source files, bundle, role keys, or scope.

## Reply contract and evidence

Every source reference contains `path`, one-based `start_line` and `end_line`,
the complete file `sha256`, and `excerpt_sha256`. The excerpt hash is SHA-256 of
the UTF-8 lines joined with LF, without a trailing newline. References cover at
most 80 lines and must match the current source bytes. No links, special files,
absolute paths, parent traversal or unsafe Windows device paths are admitted.

Every check has `source_refs`, `invariant`, and `result`. These are statements
about source, not claims that a runtime test executed.

| Role | Required response fields |
|---|---|
| recon | `summary`, `checks`, `new_units` using the policy seed shape |
| hunter | `status` (`covered`, `candidate`, `blocked`), `checks`, `candidates`, `unresolved` |
| critic | `reviewed_coverage_ids` accounting for every unit, `checks`, `new_units`, `revisit` (`coverage_id`, `reason`), `clean` |
| verifier | `fingerprint`, `verdict`, `source_refs`, `rationale`, plus verdict-specific fields |
| record_reviewer | `record_sha256`, `decision` (`accept`, `needs_validation`), `reason`, `source_refs` |

Candidates have `title`, `entrypoint`, `sink`, `root_cause`, `attack_condition`,
`description`, `source_refs`, and `validation_plan`. A deterministic fingerprint
binds the boundary, paths and root-cause identity while permitting source lines
to move between revisions. Each hunter may propose at most two candidates.
Unknown fields are rejected. Tests provide executable examples for every role.

Verifier verdicts are `needs_validation` (requires `blocker`, `validation_plan`)
or `rejected` (requires `rejection_reason`). Neither may include severity.
`confirmed` remains available through AEGIS's existing independently signed
verifier/operator staging-proof promotion. Source-agent assertions cannot create
a confirmation, even when several agents agree. The final reviewer checks the
exact verification record and current source paths and may retain uncertainty.

Canonical v2 findings and Markdown views are generated by the existing reporter.
Rejected records retain signed review proofs. Pending verification remains an
explicit pending queue, not a fabricated reviewed finding. Reports show deferred,
blocked and excluded coverage; zero findings never means complete security.

## Repeated audits and review

List the relevant completed run IDs in `prior_run_ids`. Prior artifacts must
belong to this engagement/repository and match the exact hash recorded in the
audit chain. The new run compares file hashes, reports changed paths, restores
prior coverage and gives hunters prior finding records. Removed/out-of-scope
units remain explicit limitations. Previously covered, blocked and deferred
units are examined again; old conclusions are never silently inherited. Deep
mode requires another hunter for previously assigned units. Prior-run selection
is explicit and bounded; the coordinator does not claim to discover historical
audits outside the operator-provided set.

The upstream commit, MIT license and original checksums are retained alongside
the guides. The Python contract is a bounded adaptation of the coverage rules;
shared adversarial fixtures exercise both it and the pinned upstream validator.
Upstream finding-validator tests are retained as reference checks. AEGIS's
canonical finding schema and staging-proof tests define the application contract.
Node is a development/parity dependency only, never a supervisor runtime dependency.

No live endpoint assessment, arbitrary native execution, new credential access,
production promotion, or independent human sign-off is performed by this layer.
Those activities retain the existing signed scope and acceptance requirements.
