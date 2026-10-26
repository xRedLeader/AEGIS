# AEGIS v1.2 release notes

## First executable increment

- Added `aegis_supervisor.py`: local action authorizer for **only** `source_review`; rechecks v1.1 preflight, signature hash, freshness, emergency stop before/during/after known-worker execution.
- Added operator-protected SQLite reservation ledger for cumulative runtime seconds and evidence bytes, with atomic reservations and scope-hash pinning across restarts. Reservations are conservatively never refunded after aborted work.
- Added POSIX read-only `aegis_worker.py`: no target code execution; no symlink following within allowed repository; safe static scan for a few security-review leads. Output is **not** a validated vulnerability report.
- Added per-run sanitized evidence file creation with private directories and audit-chain verification. No raw source snippets are exported.
- Added `aegis_demo.py` for offline, ephemeral-key end-to-end demonstration and `tests/test_runtime.py` with runtime positive/negative scenarios.
- Added `MILESTONES.md` and updated integration/README/supervisor architecture.

## Compatibility

**Signing format, schema and trust-policy format are unchanged from v1.1.** Existing valid v1.1 manifests do not require migration, but the new source-review action requires a repository root and `source_review` permission. To use source-only scanning, remove network targets and corresponding accounts/budgets in a newly signed scope.

## Not delivered

No OS-enforced sandbox around arbitrary tools, live network gateway, credentials, human-approval server, continuous external revocation updater, real exploit testing, or automated alert delivery. An agent granted separate shell/network tools can bypass this in-process supervisor; v1.3 will tackle operating-system isolation.
