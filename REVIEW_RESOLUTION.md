# Review resolutions — prompt and manifest

| Reviewer concern | Resolution |
| --- | --- |
| Undefined vendor-specific capability terminology | Replaced with model-neutral rule: capability does not constitute target authorization |
| Two competing budget authorities | Signed manifest supplies explicit budgets; operator-protected trust policy supplies non-overridable upper bounds; calendar window and cumulative/per-run budgets are distinct |
| Three-failure rule inhibits race findings | Distinct deterministic and nondeterministic processes; statistical trial plans, outcome frequency and manifest cap for timing/race research |
| Trusted manifest's authenticity | Detached Ed25519 signature over exact file bytes, verified against an out-of-band pinned public key; signer principal and engagement ID checked against independent trust registry |
| Defender controls only requested at reporting time | Controls inventoried during reconnaissance and evidence captured during each blocked test, with verified vs inferred effect |
| No severity rubric | Five-level rubric tied to demonstrated impact; high/critical findings receive additional fields when applicable |
| Placeholder detection based on strings | Positive JSON Schema validation plus exact trusted allowlist, UTC-window verification, signature, output checks, preapproved identity and engagement ID; template ships unconfigured |
| Redundant report sources | `findings.json` declared canonical; Markdown report, attack-paths, and coverage derived from structured records |
| Test-account secret refs can work elsewhere | Each ref bound to exact approved origins and forbidden from use outside them; runtime broker must enforce |
| Auth windows unbounded | Timestamps mandatory UTC; trust policy caps engagement authorization period; expiry checked against current UTC |
| Exclusions vague | Explicit exact origins and CIDR networks; omitted/empty means none, not discovery permission; supervisor denies unlisted egress |
| Methods conflict with approvals | Exclusions, effects, and approval gates override method permissions; baseline gates cannot be deleted |
| No resource ceilings or destination clarity | Total requests, per-origin request rates, concurrency, body and evidence limits, fuzz time, stochastic trials; absolute report/alert paths outside assessed repositories |
| Incident discovery/harm | Active incident, unexpected personal data and destructive paths require stopping the affected test and notifying approved sink |
| Report delivery undefined | Invoking-session summary plus engagement-scoped file alert path. Executor must implement and test end-to-end notification |

## What this package deliberately does not pretend to solve

- Preflight verification is not a runtime security boundary. A sandboxed executor must enforce network and tool actions.
- Signatures prove origin and integrity, not legal permission by themselves. An independent human-approved target registry remains essential.
- A writable trust policy or compromised signing key invalidates the threat model.
- No live scans, vulnerability reports, secret manager hookup, notification sending, or autonomous background schedule are included.

## Latest hardening round (v1.1)

| Issue | Change |
| --- | --- |
| Provider-specific authorization language | All runtime prompts and integration instructions are provider neutral |
| Preflight isn't runtime enforcement | Explicit, testable `SUPERVISOR_SPEC.md`; runtime layer is **not** claimed implemented |
| Ed25519 bare-message signing | Versioned protocol context `AEGIS-scope-v1\x00` included in signature and verification |
| Revocation freshness not bounded | Protected revocation snapshot and fail-closed age check in preflight; updater/runtime rechecks still required |
| Operator tool signed arbitrary bytes | Operator `sign` command now applies the same schema, signer, asset, limits, window, and output checks used by preflight |
| TOCTOU/file changes | Runtime reauthorization and filesystem isolation required; not solved in preflight |
| One fixed report dir/alert | Engagement directory remains fixed; supervisor can make controlled per-run subdirectories |
| Cross-run replay | Documented remaining risk; supervisor session binding and ledger required |

## v1.4 release review

Implemented a fixed HTTP(S) testing gateway without weakening the v1.3.1 static reviewer sandbox. Signed origin and operator CIDR are both required; all DNS answers checked and one IP pinned; no proxy/redirect/cookies/credentials; TLS hostname and CA checked with optional operator-locked custom CA; independent route allowlist; durable atomic request/time/response-body budgets; watchdog stops mid-request. Tests include local HTTP/TLS and denial cases. **Not implemented:** independent network namespace or OS firewall confinement of the helper, arbitrary HTTP methods or exploit tools, credential broker or alert delivery. Those remain non-deployable generic pentest capabilities.
