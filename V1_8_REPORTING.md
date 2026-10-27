# AEGIS v1.8 — evidence-bound findings, immutable reports, and durable local notifications

**Feature branch; complete for its explicitly constrained operator-only workflow, NOT an authorization to run production tests.** Assessment workers receive no additional shell, network, credential or filesystem capabilities. The existing v1 source findings format remains supported; v1.8 introduces an explicit canonical schema v2. Cloudflare multi-agent methodology remains reserved for v2.1.

## Canonical source report and evidence constraints

`aegis_reporting.py` reads only a completed and authorized source-review, offline-fuzz or operator-attested OSV assessment from the protected engagement report root. It verifies the ledger/audit chain and private source bytes before producing **unverified** `needs_validation` leads. Static matches, dependency advisories and isolated synthetic mismatches are not declared exploitable findings; zero leads never constitutes a clean assessment.

The canonical v2 `findings.json` is the sole source for `REPORT.md`, `NEEDS-VALIDATION.md` and `FINDINGS-DETAIL.md`. `integrity.json` binds every artifact to its exact bytes. Each private package is atomically installed as an immutable directory with no-follow/hard-link and bounded-content checks, and repeated generation is byte-identical or denied. `aegis_report_validate.py` checks v1 or v2 structure; only the reporting/notification supervisor checks the package and protected run ledger. Missing, added, altered, hard-linked, or symlinked report files fail delivery **before** consuming a delivery attempt.

```
python aegis_reporting.py --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json --state-root /var/lib/aegis \
  --run-id <completed-run-uuid> --evidence source-review.json
```

## Dual-signed finding review and promotion

`aegis_finding_promotion.py` implements a narrowly scoped **manual review acceptance** step. It cannot silently turn model or scanner claims into confirmed findings. An independent verifier and a distinct operator signing key must sign the *same canonical review bytes* under separate Ed25519 domain separators. The operator-configured verification policy is disabled by default and protects the pinned public keys, allowed engagement IDs, review directory and review expiry.

The review identifies the completed source run, original evidence SHA-256, current report SHA-256, one **existing unresolved finding ID**, verifier/operator identities, a bounded verification proof digest and either a confirmed or rejected verdict. A `confirmed` review must include an independently attested, operator-authorized staging validation fixture describing starting access, tested conditions, observed behavior, affected principal and source reference. A local synthetic fixture **cannot** confirm deployed impact. The operator must separately inspect its factual accuracy, exploitability and severity before countersigning: signatures show who approved the record, not whether its contents are true.

Each accepted review creates a **new immutable report revision** under `assessments/<run-id>/revisions/<report-sha256>/`, preserving earlier versions. The proof bytes are retained inside the revision as SHA-256-named private files, included in `integrity.json`; previous reviewed proofs are copied forward. Reviewed results render factual, attributed severity/impact/remediation only for confirmed findings, no severity for rejected/unresolved findings. The protected ledger atomically records the revision, accepted decision and a separate queued notice. Stale parent versions, changed source evidence, reused findings and malformed signatures fail closed. This is an operator-only interface; it is **not** an AI agent delegation capability.

```
python aegis_finding_promotion.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis --run-id <completed-run-uuid> \
  --review-policy /etc/aegis/review-policy.json --review-name review-001.json
```

Prepare an independently reviewed canonical `review-001.json`, detached raw Ed25519 signatures `review-001.json.verifier.sig` and `.operator.sig`, and a bounded `review-001.json.proof` fixture in the service-protected review directory. The corresponding private keys must remain outside the supervisor and AI tools. Sample `review-policy.example.json` is disabled and must never be enabled unchanged.

## Durable receipt and notification dispatch

`aegis_notifications.py` stores an at-least-once delivery outbox in the existing protected SQLite ledger. A notification includes only metadata: engagement and source run, report SHA-256, lead count, assessment status, notice ID and random challenge. No source text, proof, secret, HTTP response or raw finding is sent. The sender verifies **all five canonical report files and any retained proof artifacts**, their byte digests, schema, and deterministic Markdown views before claiming a delivery attempt. It requires a matching challenge- and digest-bound acknowledgement from a positively configured Unix socket peer whose OS UID is explicitly permitted.

Every attempt owns a random, persisted **lease token**, attempt number and lease deadline. A previous sender cannot finalize a recovered lease; expired final attempts become permanent failures. Failed attempts are recorded, backed off exponentially for automatic draining, and retained for explicit operator triage. The dispatcher supports a bounded `--drain 20` one-shot pass suitable for an operator-owned systemd timer (no unrestricted background agent or external network). A manual `--notice-id` can be retried before the configured maximum attempts. `--drain` does not create new assessments or automatically issue privileges.

```
python aegis_notifications.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis \
  --notification-policy /etc/aegis/notification-policy.json --drain 20
```

`aegis_notification_receiver.py` is a **separate durable local receiver**, with a private SQLite ledger under its own non-root OS identity. It parses an exact bounded canonical protocol, checks Linux `SO_PEERCRED` sender UID and allowed engagement IDs, rejects altered/conflicting replays, commits metadata with SQLite `synchronous=FULL`, and **only then acknowledges**. Retries of an identical notice/digest survive service restart without duplicate rows. This is a local durable receipt, not proof of delivery to an off-host human inbox.

```
python aegis_notification_receiver.py --policy /etc/aegis/receiver-policy.json
```

For a real separate-UID installation, provision a receiver-owned socket directory with mode `0710` and a specific group shared with the sender; the receiver creates a mode-`0660` socket. The sender verifies the allowed receiver UID and socket inode; the receiver verifies the allowed sender UID. State and verification policy remain mode `0700`/`0600` and inaccessible to the sender or assessment worker. Same-UID `0700`/`0600` is useful for local tests but is **not** an acceptable production separation. Sample `receiver-policy.example.json` is disabled.

## Acceptance, limitations and release gates

The source and kernel test matrix includes signature/role/review tampering, proof retention, new report revision, current-source pinning, full report integrity, cross-UID sender/receiver (separate CI job), revoked operator policies, concurrent delivery lease fencing, crash-before-ack recovery, restarts, missing sockets and permanent failed-attempt triage. Acceptance requires **zero skipped tests** on supported Ubuntu 22.04 and 24.04, passing AppArmor/namespace/seccomp probes, and independent review of the final commit and deployment credentials/UIDs. The production host must supply its own protected review keys, staging fixtures and notification policy; successful test fixtures do not constitute production approval.

**Out of scope:** externally authenticated SMTP/Teams/Slack/webhooks, inbox delivery receipts, automatic exploit confirmation, internet connectivity for assessment workers, general remote exploitation and v1.9 autonomous planning. Human/external notification transports can be a later increment; this milestone's accepted delivery boundary is the durable, identity-verified local receiver. A confirmed review remains an **operator-attested staging verification**, not an objective proof of impact on production systems.
