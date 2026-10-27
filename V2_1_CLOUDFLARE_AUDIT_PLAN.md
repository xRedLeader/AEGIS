# AEGIS v2.1 — Cloudflare security-audit-skill integration (planned)

**Roadmap only; NOT implemented by v1.7.** The v2.0 milestone remains the
integrated AEGIS assessment platform. v2.1 will add Cloudflare's research
orchestration methodology without replacing the kernel- and operator-enforced
execution boundary.

Upstream: https://github.com/cloudflare/security-audit-skill/tree/main/skills/security-audit

Reviewed upstream `main` at commit
`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` (October 2026).
The upstream is **MIT licensed**; retain required attribution and license if
copying/adapting substantial portions. Recheck its current content and supply
chain when implementation begins; do not automatically execute upstream scripts.

## Intended v2.1 additions

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
