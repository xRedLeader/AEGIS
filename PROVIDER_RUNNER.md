# Protected source research provider runner

`aegis_provider_runner.py` drives the existing v2.1 coordinator through fresh
reconnaissance, coverage, hunting, criticism, verification and record-review
assignments. Each reply is signed with its registered research-role key, replayed
through the coordinator, retained by `SourceAuditSupervisor`, and projected into
the existing report package. Results remain `needs_validation` or `rejected`.
Completing this runner never approves deployment or supplies independent staging
proof. Its role separation is procedural and cryptographic; one provider/model
is not a substitute for an independent human reviewer.

The deterministic fake exercises the full workflow using only
`tests/fixtures/provider/synthetic.py`. It does not assess other source. The
Claude adapter is implemented and tested with synthetic protocol responses; a
real Claude call must be performed separately by the operator. No live provider
call or real application export is part of the automated tests.

## Operator configuration

Use a non-root Linux operator identity with access to the protected AEGIS ledger,
signed scope, reports and source-audit policy. The untrusted delegated-agent UID
must not own the runner or its configuration. The deployment package provides a
disabled provider service template; enable it only after configuring this guide.

1. Sign an explicit `source_review` scope for the selected local repository using
   the existing offline operator process. Configure `source-audit-policy.example.json`
   with registered **distinct research-only** Ed25519 keys and the desired profile.
   Keep scope, delegation and human proof private signing keys off this runtime.
   The runner reads only the exact role-key mapping and rejects a scope signer
   reused as a research role.
2. Copy `provider-runner-policy.example.json` to an operator-controlled path.
   Set `audit_policy`, its SHA-256, the private `run_directory`, and the exact
   research-role private-key paths. Policy, credential and key files must be
   regular, single-link private files owned by root or the operator; all protected
   parent directories must exclude group/other writes. Use `0600` files and a
   `0700` run directory outside source, report and AEGIS ledger directories.
3. Review the exact source slice for export. `source_export.paths` must exactly
   match `source_paths` in the research policy. Its digest is
   `digest({path: snapshot[path]["sha256"] for path in snapshot})` using
   `aegis_audit_contract.source_snapshot` and `digest`. Explicitly set `approved`
   and `configured` to true only after approval. The runner rechecks those bytes
   before exporting and admitting each reply. Common credential/private-key
   patterns and the actual configured API credential are blocked; this is not
   a complete secret detector and does not replace export review.
4. Write the finished JSON policies with `aegis_audit_contract.canonical`.
   Pretty-printed examples are intentionally disabled and cannot run directly.
   Store the exact policy hashes with the approval record.

For Claude, set `kind` to `claude`, choose an explicit supported model ID, and pin
the private API-key file's exact SHA-256. The API key goes through private stdin
to the HTTPS transport and into its authentication header, never into model
messages, command arguments, retained reports or diagnostic output. Research
private keys remain in the trusted parent process. No prior conversation is sent;
each assignment gets one new Messages request and an empty private working
directory. Only the approved source slice, coordinator assignment, reference
catalog, reply contract and phase-specific pinned methodology guides are sent.

The transport sends `POST /v1/messages` only to `https://api.anthropic.com:443`,
uses certificate verification, `anthropic-version: 2023-06-01`, and has no tools,
streaming, redirects, proxy inheritance, remote target selection or arbitrary
request headers. Provider/model selection never comes from a model response.
The implementation follows the [official Messages API](https://platform.claude.com/docs/en/api/messages)
and [API error contract](https://platform.claude.com/docs/en/api/errors).

## Budgets and restart

Before every attempt, the runner durably reserves one call, the configured
`input_token_reservation + max_output_tokens`, the corresponding price ceiling,
and the full call timeout. It also reserves that timeout against the signed
AEGIS engagement runtime. Coordinator plan/accept operations reserve additional
two-second slices against that runtime. Set the signed runtime accordingly.

For real calls, `input_token_reservation` must cover the chosen model's maximum
possible billable input for the request, not an estimated tokenizer count.
Before charging or starting the transport, the runner enforces a conservative
floor of **one token for every UTF-8 byte of the exact serialized Messages
request, plus 16,384 framing tokens**. JSON escaping is included. A small declared
reservation cannot send a large prompt and wait for returned usage to discover
the overspend. This text-only byte bound excludes tools, images, cached prompts
and other billing modes; those modes are not enabled by this adapter.
Pin conservative **integer micro-US dollars per token** (one dollar is 1,000,000
micro-US dollars), rounding up and including applicable pricing tiers. Verify
current model limits and [provider pricing](https://platform.claude.com/docs/en/about-claude/pricing)
on the calling device before approval. The runner does not discover prices or
represent these reservations as an invoice. An incorrect operator-supplied model
ceiling or price cannot guarantee an external provider bill. Provider-account
spending controls should bound other clients sharing that account.

Nothing is refunded on timeout, malformed output, rate limiting, uncertainty or
restart. Actual reported usage is retained as bounded metadata; it never grants
extra budget. One guarded process holds the job lock. Accepted replies and the
bundle update commit in one transaction. An interrupted in-flight attempt stays
charged and becomes uncertain; a retry gets a fresh context and another full
reservation. Retries are bounded per assignment. HTTP 429 respects a bounded
`Retry-After`; the command returns instead of silently waiting or retrying.

Policies cannot change under an existing `runner_id`, and deleting/recreating a
working bundle cannot reset ledger reservations. The ledger is authoritative.
Use the same signed scope, policy, ID and protected state after interruption.
An expired absolute job deadline remains expired. A newly authorized job needs
a new explicit ID and approval; limits are per job, not a provider-account cap.
Never edit accounting tables or erase the ledger to recover a job.

The runner periodically rechecks stop/revocation, scope expiry, policy pins and
deadlines while the request is pending. It kills the transport when a guard
fails. A request may already have reached the provider, so its cost stays reserved.
After a crash between canonical evidence acceptance and report generation, it
reuses the existing exact receipt and completes reporting without accepting a
duplicate audit. Raw provider error bodies, prompts and malformed replies are
not retained. Only admitted research records and bounded accounting/provenance
metadata enter durable state.

## Synthetic Claude smoke test on another device

Copy the exact shipped synthetic fixture into an otherwise empty, explicitly
authorized repository as `app.py`. Do **not** run this fixture. Configure the
signed scope and policies above for that repository, with
`source_export.classification` set to `synthetic`. Fake and smoke modes verify
the fixture's exact bytes. Select a real Claude model and credential only on the
device authorized to make the paid call; set prices, token ceilings and a small
approved call/spend limit first. The example's zero-dollar budget must be changed
explicitly for Claude and will otherwise prevent a paid call.

```sh
export AEGIS_STATE_ROOT=/var/lib/aegis
export AEGIS_TRUST_POLICY=/etc/aegis/operator-trust.json
python aegis_provider_runner.py smoke \
  --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.yaml.sig \
  --runner-policy /etc/aegis/provider-runner-policy.json
python aegis_provider_runner.py status \
  --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.yaml.sig \
  --runner-policy /etc/aegis/provider-runner-policy.json
```

`smoke` admits at most **one** synthetic assignment. `PROVIDER_PROGRESS` means
that one response passed the role contract and signature replay; it does not mean
a full audit is complete. Use `run` with the same arguments and still-valid budget
to complete the workflow, or keep the one-call smoke as connectivity evidence.
Exit 0 means completed/progress/status, 3 means retry required/wait, and 2 means
configuration/scope/protocol/budget denial. Inspect the sanitized status and
protected accounting records; do not paste provider credentials or raw source
into an issue when reporting a failed smoke.

Keep the exact AEGIS commit, OS/Python versions, reviewed policy hashes, source
digest, pinned model, sanitized command result, reserved/observed usage, audit
checkpoint and final report hash (if completed). Have the operator review this
record. Neither a one-call smoke nor a complete synthetic audit satisfies the
actual-host pilot, independent reviewer or deployment-release gates.

Offline regression command (Linux, non-root, repository and `tests` on Python's
module path): `python -m unittest test_provider_runner -v`.
