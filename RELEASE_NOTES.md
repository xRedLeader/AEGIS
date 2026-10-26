# AEGIS v1.1 release notes

## Provider-neutral release

AEGIS is an agent specification, not a specific vendor's model feature. You can use the operating prompt with any tool-using model and orchestration platform that can integrate with an independently constrained executor. No model provider or elevated program access grants permission to test a target.

## Security changes

- **Domain-separated signatures**: Ed25519 signs `b"AEGIS-scope-v1\x00" + raw_manifest_bytes`, instead of the bare YAML bytes. Preflight verifies the same input *before* parsing YAML. A v1.0 signature will NOT verify with v1.1; re-sign approved manifests using the updated operator utility.
- **Nonblind signing**: `aegis_admin.py sign` requires `--trust-policy` and runs the shared schema/authorization policy validation before signing. It also verifies that the supplied private key matches the independently pinned public signing key.
- **Revocation freshness**: `trust-policy.example.json` includes `revocation.last_checked_utc` and `max_staleness_seconds` (example ceiling: 300 seconds). Preflight rejects old, missing, or future-dated snapshots. This is a *trusted updater assertion*; the updater and continuous runtime polling remain external requirements.
- **Bounded input**: preflight limits signed manifest bytes before YAML parsing.
- **Expanded regression tests**: malformed scope, legacy/wrong-context signatures, wrong operator key, unsafe signing, stale/future snapshot and oversize manifest.
- **Supervisor specification**: new `SUPERVISOR_SPEC.md` states concrete enforcement requirements and integration acceptance tests.

## Migration from v1.0

1. Replace the v1.0 tools and instructions with v1.1.
2. Add the `revocation` object to the operator-controlled trust policy; a trusted updater must maintain its timestamp and approved/revoked lists. Preflight fails closed if absent/stale.
3. Confirm independent asset/identity approvals and the current manifest's UTC window.
4. Re-sign the approved scope using v1.1 `aegis_admin.py sign --trust-policy ...`; *do not* try to retain v1.0 signatures.
5. Verify with the v1.1 preflight, run the tests, and separately test the runtime supervisor before any active assessment.

## Still not implemented

No executable attack runner, packet-level enforcement, credential broker, persistent revocation updater, cumulative-budget service, independent human approval service, kill switch, or notification delivery transport is included. AEGIS v1.1 is a stronger **preflight and operating specification**, not a ready-to-deploy autonomous penetration-testing platform. Signatures remain replayable within their allowed window absent a supervisor-maintained invocation/session ledger.
