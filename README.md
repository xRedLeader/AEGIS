# AEGIS agent starter

A **starter specification and authorization preflight** for authorized adversarial testing of your own software. It is **not** a ready-made, fully sandboxed penetration-testing executor, and it does not itself run scans or attacks.

## Included

| File | Purpose |
| --- | --- |
| `AGENT_DESCRIPTION.md` | Short description for an agent configuration UI |
| `AEGIS_AGENT.md` | Operating instructions for the research agent |
| `security-scope.example.yaml` | Strict, deliberately **unauthorized** sample engagement scope |
| `security-scope.schema.json` | Exact schema (rejects unknown and missing fields) |
| `trust-policy.example.json` | Independent operator policy; ships with `configured:false` and no approved assets |
| `aegis_preflight.py` | Ed25519 signature, schema, identity, target, credential, window, budget, and output preflight checks |
| `aegis_admin.py` | **Operator-side** key generation and manifest signing utility |
| `tests/test_preflight.py` | Positive and negative verification tests |
| `findings.schema.json` and `findings.example.json` | Canonical, tiered findings format and empty-assessment example |
| `aegis_report_validate.py` | Check the format of a generated findings report |
| `requirements.txt` | Required Python libraries |

## Key separation

1. **Operator signing key:** Keep the Ed25519 private key *outside* repositories, agent workspaces, and the agent runtime. Do not let an agent invoke the signing utility with it.
2. **Independent trust policy:** The supervisor pins a protected policy containing the public key, operator identity, approved engagement IDs, explicit target allowlists, tool-method permissions, budgets, and reporting roots. This policy may never be supplied or edited by the agent.
3. **Signed scope:** A scope manifest is signed over its exact bytes by the operator. A valid signature alone never authorizes a target not present in the independent trust-policy allowlist.
4. **Executor:** An OS/container/CI supervisor enforces the effective scope while tests execute. A command-line preflight script or an LLM prompt is *not* an enforcement boundary.

## Operator setup (example on a Linux security runner)

Install dependencies from a trusted environment:

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python aegis_report_validate.py findings.example.json
```

Generate signing keys on an operator-controlled computer (paths should be accessible only to trusted operator services):

```bash
python aegis_admin.py keygen \
  --private /secure/operator-ed25519.key.pem \
  --public /secure/operator-ed25519.pub.pem
```

Distribute **only the public key** to the runner's protected key directory. Keep the private key on the operator system. Edit a copy of `trust-policy.example.json` **outside the agent-writable workspace** and set `configured:true` only after an independent operator has explicitly registered an engagement and its authorized resources. Populate the trust policy's `approved_engagement_ids`, `allowed_origins`, `allowed_repository_roots`, `approved_methods`, report/alert roots, operator identity, and budgets. File permissions must prevent an agent from changing the policy or public key. This example does not implement identity-provider checks or file-permission lockdown for your chosen OS.

Edit a copy of `security-scope.example.yaml`, providing actual approved assets, identity, UTC timestamps, credential refs, limits, and output paths. Set the output directory to an engagement-specific absolute path **outside assessed repositories**, and create its parent directory and the alerts directory with service-account permissions.

Sign the final, reviewed manifest on the **operator host**:

```bash
python aegis_admin.py sign \
  --private /secure/operator-ed25519.key.pem \
  --manifest /secure/security-scope.yaml \
  --signature /secure/security-scope.yaml.sig
```

Place the signed manifest and signature in a location supplied to the executor; neither the agent nor a target under test should be allowed to modify them. The supervisor—not the agent—sets `AEGIS_TRUST_POLICY` to an absolute protected path and invokes:

```bash
export AEGIS_TRUST_POLICY=/etc/aegis/trust-policy.json
python aegis_preflight.py \
  --manifest /secure/security-scope.yaml \
  --signature /secure/security-scope.yaml.sig
```

A successful response has status `PREFLIGHT_VERIFIED_NOT_RUNTIME_ENFORCEMENT`. This means the input passed verification; it **does not** mean outbound operations have been securely constrained. Re-run before any new target, privilege escalation, or elevated-risk test, and during long batches.

## Runtime supervisor requirements (NOT implemented here)

- Restrict sockets/HTTP egress to authorized origins, allowed resolved IP ranges and approved ports; independently handle DNS changes, redirects, proxies, SNI, and secondary protocols. Unknown destinations are denied. Empty allowlists mean none.
- Protect the signing key, trust policy, scope input, cumulative usage ledger, kill switch, and approval records from the agent and tested code.
- Inject test credentials with per-origin policies; prevent their use on production SSO or other out-of-scope resources.
- Enforce per-engagement **cumulative** runtime/request/data budgets across restarts and per-run limits; verify time window/revocations continuously.
- Treat exclusions, disallowed effects, and pending approvals as stricter than method allowances. Approvals must be independently verified, target-specific, short-lived, and recorded. This starter deliberately provides no bypass or automatic approval path.
- Isolate destructive experiments; block customer-data exposure, persistence, evasion, third-party side effects, and disruption without explicit additional approval.
- Wire the alert sink to a monitored notification transport. Preflight checks only that a file-based sink directory exists and is writable; **it does not prove an alert will reach a person**. The executor should test end-to-end delivery before an engagement.
- Restrict report output to an external directory, redact sensitive materials, and retain auditable logs.

## Budget and testing semantics

The signed manifest is authoritative **within ceilings imposed by the trust policy**. There are no automatic permissive defaults. Distinguish (1) the calendar authorization period, (2) total cumulative effort over all agent runs, (3) a single-run cap, and (4) per-hypothesis limits. `nondeterministic_max_trials` caps stochastic/concurrent testing; a lack of success after a few trials is **not** proof that a race condition does not exist.

## Reports

`findings.json` is canonical and can be checked using `aegis_report_validate.py`. `report.md`, `attack-paths.md`, and `coverage.md` are human-readable views from those records; place redacted proofs in `evidence/`. The agent returns a summary in the invoking session and records critical findings in the explicitly configured sink.

## Known limitations

This preflight uses a detached Ed25519 signature of the **exact UTF-8 YAML bytes**. Changing whitespace or comments requires re-signing. It rejects duplicate YAML map keys, unrecognized fields, out-of-window/revoked engagements, overbroad targets and limits, test-account origin expansion, and mismatched signer identity.

The implementation assumes the surrounding supervisor truly pins a read-only policy and handles revocation updates. If the agent can choose a different trust file, replace the public key, modify the supervisor, or control the machine clock, the cryptographic checks are not a security boundary. If a trusted signer has not independently confirmed legal/operational authorization, a valid signature alone does not fix that problem. Cross-platform file ownership and custody, actual credential broker integration, active network containment, live notification delivery, and cumulative-budget accounting are implementation tasks for the runtime supervisor.
