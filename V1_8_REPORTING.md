# AEGIS v1.8 — evidence-bound reporting and durable notifications

**Feature branch, first working increment. Not a production release.** It does not grant an AI agent any additional tools, secrets, shell commands, or target-network access. The trusted operator invokes the fixed producer and dispatcher. Cloudflare audit orchestration remains scheduled for v2.1.

## Canonical reporting

`aegis_reporting.py` admits only existing **completed** source-review, bounded-local-contract or operator-attested OSV-correlation artifacts from the signed engagement's private report root. It verifies the run in SQLite, the local audit chain, filesystem ownership, file type, link count, size, source bytes and live signed authorization. Operator/target-controlled prose is not copied into findings.

The version-2 schema `findings-v2.schema.json` distinguishes `confirmed`, `needs_validation` and `rejected`. Only a confirmed record may contain severity, demonstrated impact or remediation. The v1.8 producer **never emits confirmed findings** from static heuristics, local synthetic mismatches or version correlation. Every resulting lead is `needs_validation`, with a specific missing fact and validation plan. An empty source report is **not** a clean security assessment. The older `findings.schema.json` remains available for legacy v1 results; it is not silently changed by this milestone.

One validated `findings.json` is authoritative. `REPORT.md`, `NEEDS-VALIDATION.md`, and `FINDINGS-DETAIL.md` are deterministic projections, written with an `integrity.json` digest manifest. All five outputs are stored in the operator-owned `assessments/<source-run-id>/` directory, using descriptor-relative no-follow opens, exclusive private files, and Linux atomic no-replace promotion. The report generator is idempotent only when existing files are byte-identical; tampering fails closed. An interrupted after-promotion/pre-commit attempt may be recovered by retrying the same report if its exact bytes are present.

```bash
python aegis_reporting.py \
  --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis \
  --run-id <completed-uuid> \
  --evidence bounded-fuzz.json
```

Permitted evidence names: `source-review.json`, `bounded-fuzz.json`, `advisory-candidates.json`. Findings are derived from the source artifact; a model cannot submit a free-form critical finding to this producer.

## Notification delivery

Generating the canonical report atomically adds one idempotency-keyed record to the existing protected SQLite `notification_outbox` and audit chain. **Queueing is not delivery.** The payload contains only the engagement ID, source run ID, canonical report SHA-256, lead count, limited assessment status, notification ID and a fresh delivery challenge. No credentials, endpoint response bodies, request headers, source snippets or issue descriptions enter the transport.

`aegis_notifications.py` connects to **one exact operator-configured private Unix-domain socket**, checks the socket inode and `SO_PEERCRED` UID allowlist, and requires a matching challenge-bound acknowledgement before reporting `DELIVERY_ACKNOWLEDGED`. Before delivery it validates the report's digest again. Failed connections, wrong peers, truncated/mismatching acks and timeouts report `DELIVERY_FAILED_PENDING` and retain the item for retry, or `DELIVERY_FAILED_PERMANENT` after the configured maximum attempts. Leases prevent concurrent senders from delivering the same row during the lease; an expired lease can be recovered after a crash. Delivery is **at least once**, not exactly once: receiver implementations MUST deduplicate by notification ID and report hash and persist the event before acking.

```bash
python aegis_notifications.py \
  --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis \
  --notification-policy /etc/aegis/notification-policy.json \
  --notice-id <64-char-notice-id>
```

The sample `notification-policy.example.json` is disabled and cannot send anything. The configured receiver is a **separate operator service** and must durably store or forward the notice before acknowledging. The v1.8 package implements a bounded local sender, not SMTP, Internet webhooks, a managed inbox, or a remote receiver. No notification of a failed or unexecuted assessment is asserted unless a canonical completed source report was generated. Revocation can prevent reporting and sending; a recipient that acknowledged a notice before cancellation may already retain it.

## Security and acceptance

- The new code executes solely in the **trusted operator control plane** and does not open host TCP/IP sockets or change AEGIS's kernel/seccomp confinement for assessment workers.
- The operator must protect signing keys, trust/revocation policy, report root, SQLite ledger, notification policy, socket directory and recipient UID. Untrusted assessment code and model tools must not have direct access to these files or processes.
- Test on both Ubuntu 22.04/Python 3.10 and Ubuntu 24.04/Python 3.12: full inherited test suite, 14-point source sandbox probe, authenticated egress probes, new negative reports and real Unix-socket acknowledgement/retry tests. No skipped security tests count as passes.
- Re-run on the actual deployment host with its AppArmor, Unix UID, directory permissions and notification recipient. **A green CI matrix does not establish production approval.**
- The next v1.8 increment should add an operator-installed durable notification receiver or vetted email/webhook adapter, independent delivery confirmation, and a reviewed promotion path for independently confirmed findings. Until then this is a bounded local reporting/notification capability, not a complete organization-wide alerting system.
