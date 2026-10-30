# AEGIS v2.1 — Cloudflare security-audit-skill integration

**Implementation candidate.** The bounded source-only adaptation is implemented
in `aegis_audit_coordinator.py` and `aegis_source_audit.py`, with the existing
reporter, signed assessment steps and independent staging-proof boundary retained.
[V2_1_SOURCE_AUDIT.md](V2_1_SOURCE_AUDIT.md) is the operational guide and describes
the external-agent adapter contract, resource bounds and explicit prior-run selection.

Upstream: https://github.com/cloudflare/security-audit-skill/tree/main/skills/security-audit

Reviewed upstream `main` at commit
`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` (October 2026).
The upstream is **MIT licensed**; retain required attribution and license if
copying/adapting substantial portions. Original files, license and checksums are
retained under `third_party/cloudflare-security-audit/`. The application ports
bounded invariants; upstream scripts run only in development/parity tests.

## Implemented v2.1 additions and their boundaries

1. **Deterministic coverage ledger:** canonical coverage units for entry surface,
   trust boundary, subsystem, attack class, and applicable lifecycle mode;
   explicitly represent covered, candidate, blocked, deferred, and out-of-scope.
   Never infer complete coverage from absence of findings.
2. **Multi-agent audit coordinator:** independent reconnaissance, constrained
   hunter assignments, coverage critics, and separate verifier/record-review
   agents. Preserve isolation across each researcher's scratch and evidence.
3. **Evidence and verdict semantics:** confirmed, needs_validation, and rejected
   with severity only for independently proven impact. Map to AEGIS's canonical
   findings/report schema through a versioned migration, not parallel divergent
   records.
4. **Repeated-run revalidation:** compare precise source refs and relevant
   changed paths, carry forward only evidence still applicable, and revisit
   unverified/deferred cases on later runs.
5. **Reviewed validator integration:** pin reviewed code and dependencies,
   run the Cloudflare ledger/findings validators as untrusted tools in a
   constrained process or port equivalent invariants with parity tests.
6. **Domain hunting guides:** adapt AI/LLM, native binary, local IPC, supply-chain,
   web/auth and cloud guidance to AEGIS's approved target types. Treat their
   prose as research guidance, never privileged operator instructions.

## Architectural boundaries to preserve

Cloudflare's source-first audit workflow is intentionally local-only. AEGIS may
perform separately authorized bounded runtime tests, but **no Cloudflare agent
prompt, copied script, or checklist can expand a signed AEGIS scope**. Tool
execution remains under the AEGIS supervisor/OS restrictions. Never copy the
Cloudflare validators into the trusted broker without independent review.

## Acceptance

- Repeatable coverage IDs; all deferred work retained; no false completeness.
- Two distinct agents independently check each confirmed claim; provenance and
  source-line verification are enforced on every final finding.
- Full schema/ledger validity under normal and adversarial inputs, including
  false confirmations, unverifiable references and altered evidence artifacts.
- Existing AEGIS kernel isolation, operator approvals and budget/revocation
  tests continue passing across supported deployment environments.

## Verification entry points

`tests/test_v21_source_audit.py` covers signed role separation, source and excerpt
hashes, budget reservations, incremental review, final-critic gaps, whole-audit
replay across concurrency/restart, altered evidence, stop controls, inert report
rendering and the integrated action. The full existing suite remains required.

`tests/fixtures/source-audit-coverage.json` contains shared valid/adversarial
ledger cases. Python tests and `node tests/source_audit_parity.cjs` check the
same cases; the pinned upstream's own 65 tests run separately in CI. The original
vendor checksum manifest and repository-wide `SHA256SUMS.txt` must both match.

This implementation review does not substitute for independent human review,
configured external-agent context isolation, or deployment-host acceptance.
