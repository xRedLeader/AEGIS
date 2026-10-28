# AEGIS v2.0 — bounded authorized assessment release acceptance

**Implementation acceptance is separate from deployment authorization.** This milestone integrates the existing v1.4.1–v1.9 kernel-isolated capabilities, signed staging review, bounded remediation observation, audited recovery and a constrained agent-delegation endpoint. It is not a general-purpose unrestricted penetration-testing platform, a production exploit engine, or a guarantee of security. The operator must review and approve all scoped testing.

## v2.0 supported integration boundary

1. An operator provisions a signed engagement manifest, private trust/revocation files and the disabled-by-default `assessment-policy.json`. The policy's fixed action graph names only approved operations; each operation independently enforces its existing signed scope and budget.
2. The operator creates an assessment ID with `aegis_integrated_assessment.py create`. The operator can run it directly or independently delegate only `snapshot` and `propose` of the *exact next* configured action through `aegis_agent_gateway.py`.
3. The agent gateway verifies OS `SO_PEERCRED`, a short-lived domain-separated **operator-signed delegation**, and a separately signed per-request proof of possession. It binds the engagement, current signed manifest SHA, assessment policy and referenced policy/snapshot digest, exact assessment UUID, peer UID and permitted operations. Every request ID is durably consumed **before** execution. An uncertain response requires a new `snapshot` request; replaying a request is denied.
4. The operator-only `aegis_model_adapter.py` receives at most 768 bytes of untrusted JSON model output: either `{ "operation": "snapshot" }` or `{ "operation": "propose", "step_id": "...", "expected_action": "..." }`. It cannot generate a new grant, sign an operator approval, select a URL, mutate policy, provide executable code, access the vault, or bypass the preapproved next step. The delegated client signing key belongs in a protected adapter process, never a model context.
5. The existing offline source/dependency/contract and brokered HTTP workers remain confined by their original Linux namespace/seccomp and authorization boundaries. Existing v1.8 reports and v1.9 investigations remain immutable, evidence-bound and require independent human review before finding promotion.
6. A separate operator policy can admit an **already completed and independently reviewed** report by exact digest, create its investigation, and bind a new completed, separately authorized synthetic retest to one confirmed finding. Only `RETEST_*_NEEDS_REVIEW` or `RETEST_NO_LOCAL_LEADS_NOT_VERIFIED_FIXED` is allowed; no result automatically says a production vulnerability is fixed.
7. A crashed or expired action never silently repeats its side effects. The operator can run `abandon --reason-code interrupted_unknown_outcome` to record an immutable terminal reconciliation event; a new assessment ID and separate authorization are required for any further work. Abandonment is not rollback of previously accepted evidence or delivered notifications.

## Local agent-gateway deployment

The gateway is a **distinct, non-root, operator-owned service**. Provision a private root-owned or service-owned directory for its canonical JSON policy (0600) and signer **public** key (0600); private Ed25519 operator grant signing material stays offline. Store assessment state, vault, report root and other operator policies in separate mode-0700 directories. The assessment runner's existing v1.5 operator socket is never exposed to agents.

For same-UID local fixture testing, the gateway socket directory is mode 0700 and the socket mode 0600. For a real agent with a different UID, set `shared_gid` to a dedicated tightly controlled group, set the gateway-owned socket directory to exactly 0710 with that GID, and allow the gateway to create a 0660 group-owned socket. The agent and gateway must use different non-root UIDs. The gateway additionally checks `SO_PEERCRED` against the explicit UID allowlist in its signed operator configuration. The agent adapter pins the gateway's expected OS UID. Do not use a world-accessible group, share the private operator signer, or expose the gateway behind an unauthenticated network proxy.

- Start the gateway with `python aegis_agent_gateway.py --manifest ... --signature ... --trust ... --state-root ... --assessment-policy ... --delegation-policy ...` under the dedicated trusted service identity.
- Separately use `aegis_agent_client.py issue-grant` from a protected offline operator environment with a private signing key, the agent adapter's **public** key, exact engagement/assessment IDs and current manifest/policy digests, authorized client UID and short expiry.
- Supply only the signed grant, detached signature, and a separate **delegated** client key to the protected adapter process. The model receives neither signing key. `aegis_model_adapter.py` reads one strict JSON decision on stdin and sends a signed one-shot request to the Unix socket.
- An agent has no `create`, `abandon`, reviewer-sign, credential, remediation, policy-update, shell, external network, or arbitrary parameter authority. Repeated, stale, wrong-UID and wrong-step requests are rejected.

The provided `delegation-policy.example.json` and `assessment-policy.example.json` are deliberately disabled. Enabling an example unchanged is not safe or sufficient deployment configuration.

## Reproducible synthetic staging acceptance

The CI acceptance case in `tests/test_v20_staging_acceptance.py` performs these real operations under a non-root Linux identity:

1. Operator-pinned vulnerable Python tenant-authorization fixture inside the kernel-isolated read-only worker; synthetic mismatch recorded without an exploitability claim.
2. Immutable v1.8 findings report initially containing only `needs_validation`.
3. An **independent verifier key plus distinct operator key** sign a bounded staging proof; the existing v1.8 promotion accepts it as an attested staging confirmation and retains its proof bytes.
4. A separately authorized second kernel-isolated run tests the source-modified fixture; its own immutable report records no local leads.
5. A new operator-pinned v2.0 assessment admits the exact reviewed report revision, creates its v1.9 investigation, links the separately authorized fixed-case run, and records a bounded retest outcome that explicitly **does not** assert an independently verified production fix.
6. Failure cases reject wrong review revision, mismatched source/policy SHA, unauthorized action, wrong OS peer and replay, forged source, and out-of-order or concurrent side-effecting execution.

This test demonstrates software integration and local staging review **with synthetic fixtures**; it does not establish independently observed real deployment impact, remediation or absence of vulnerabilities. A production staging environment and real external reviewer must be supplied by the operator.

## Acceptance commands

Run as the **non-root installed service identity** under the exact deployment AppArmor/seccomp configuration:

```sh
python -m unittest discover -s tests -v
python aegis_sandbox_check.py
python aegis_demo.py
python aegis_http_demo.py
```

Every kernel isolation test must execute; skipped security tests block acceptance. The Ubuntu 24.04 CI uses the named AppArmor opt-in profile, not global disablement. The CI-only `tests/cross_uid_agent_acceptance.py` runs from a privileged **fixture launcher** solely to provision two distinct non-root UIDs and verifies the actual Unix socket peer and replay behavior. Neither runtime service executes as root.

## Sign-off gates before merging, releasing or deploying

- [ ] Independent code/security review of the v1.5–v2.0 trusted host, operator APIs, signing keys, policy file ownership, embedded agent adapter, privilege and OS isolation.
- [ ] Ubuntu 22.04 and 24.04 full regression suites pass on the **exact final commit**, no skipped kernel tests, and the cross-UID receiver/delegation jobs pass.
- [ ] Verified tracked-file SHA-256 manifest and exact GitHub source snapshot; confirmed no private keys, production credentials, or user-specific host paths committed.
- [ ] Actual deployment host, non-root UIDs, socket ACL/group, AppArmor profile, vault locations, policy trust, parent-death and emergency-stop validated independently.
- [ ] Real, separately authorized staging engagement uses dummy/practice identities, independently reviews confirmed impact and remediation, verifies both successful and unsuccessful notification deliveries, and records signed off-host audit checkpoints.
- [ ] Conduct repeated crash/expired-lease/stop/revocation drills and demonstrate no silently retried side effects; test explicit audited abandonment and renewed assessment authorization.
- [ ] Release owner decides and records residual risks: authenticated helper sees its short-lived bearer token and can misuse an allowed stream; isolated local replay does not prove network exploitability; local notification receipt does not prove off-host human receipt.

Do **not** mark the last host- or human-dependent gates as complete from CI alone. Do not merge or tag a production `v2.0` release without their sign-off.

The Cloudflare multi-agent research methodology remains scheduled for **v2.1**. It does not change AEGIS's signing, scope or isolation rules.
