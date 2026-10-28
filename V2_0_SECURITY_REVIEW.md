# AEGIS v2.0 — independent-checkable security review record

**Review status: source and automated controls assessed; NOT an independent production approval.** This review was performed during PR #8 hardening. An author-assisted review and a test matrix are not a substitute for an independent operator/security organization accepting the deployment. The code branch remains a *bounded, operator-approved synthetic/staging* assessment platform, not an unrestricted autonomous pentesting service.

## Source scope and trust boundaries

Review base: PR #8 at `b40fabec7c74a36a6665befa459c2c4f73d1d8e9`. Security-relevant code inspected: `aegis_integrated_assessment.py`, `aegis_agent_gateway.py`, `aegis_agent_client.py`, `aegis_model_adapter.py`, `aegis_supervisor.py`, `aegis_sandbox.py`, `aegis_auth_helper.py`, `aegis_http_broker.py`, `aegis_reporting.py`, `aegis_finding_promotion.py`, `aegis_notifications.py`, `aegis_notification_receiver.py`, audit checkpoint code, the signed-scope preflight, and negative tests. This is a targeted manual source review, **not** comprehensive assurance of every dependency, Linux kernel path, or deployment configuration.

- The **operator** controls signed engagement scope, independent trust/revocations, fixed workflow policy, report/review files, signing keys and the real deployment.
- The **agent** can only submit short, signed, replay-protected `snapshot` or `propose` requests for an exact next operator-configured step via a separate Unix socket; the model is never an authorization root. This software boundary depends on preventing untrusted code from gaining a trusted operator process or shell.
- Untrusted **assessment code** executes within fixed rootless Linux namespaces with default-deny seccomp and no new socket authority. A credentialed helper temporarily holds a bounded token in memory and can misuse the **one already connected, approved stream** if compromised; endpoint confinement does not prove safe HTTP semantics or absolute token confidentiality.
- The **local notification receiver** durably stores bounded metadata and acknowledges after commit. A local acknowledgement is not an independently verified delivery to an off-host human mailbox.
- Local SQLite audit chaining detects non-recomputed edits. Independently retained **signed** off-host checkpoints are necessary to detect wholesale ledger rewriting; the feature does not automatically retain them off-host.

## Reproduced findings and patches

### SR-20-01 — action claim can race operator abandonment (fixed in PR #8 hardening)

Before the patch, `_claim` checked abandonment in a transaction, read step state via `_rows`, then claimed a step in a **different** transaction without checking abandonment again. `abandon` independently checked live steps before entering its final transaction. Interleaving the two paths could allow an action to be claimed **after** an operator's terminal abandonment, or let abandonment be recorded **during** a newly claimed live lease. That violates the operator terminal-action invariant.

The new `tests/test_v20_release_races.py` reproduces both interleavings: **both tests fail on the original `b40fabec` source and pass on the patched source**. The claim and abandonment paths now recheck their opposing state and audit provenance under `BEGIN IMMEDIATE`; expiry handling also checks terminal abandonment before modifying the step. A completed workflow cannot be abandoned through a stale read. The patch does **not** claim to roll back side effects that already occurred.

### SR-20-02 — delegation signing-key file TOCTOU (hardened in PR #8)

`aegis_agent_client._private_file` originally called `lstat(path)` and subsequently followed the same path with a regular `open(path)`, permitting a check/use gap if the directory was unexpectedly mutable. The replacement uses no-follow directory-relative opens, checks UID/mode/type/link count and bounded size on the **opened descriptor**, then checks identity/size again after reading. Negative tests reject symlink, hard-link, world-readable, relative and oversized key files. Key directory access and remote/offline signing-key custody remain deployment obligations.

### SR-20-03 — host acceptance could falsely accept replaceable trusted code (fixed)

The prior read-only host diagnostic checked just five Python modules for writable
file modes. A runtime service could replace a mode-0444 module by renaming it
within a writable parent directory; other imported first-party modules were not
checked. The old check also verified read-only policy leaf mounts without ensuring
that all ancestors were protected from service-owned path replacement.

The acceptance diagnostic now checks the whole first-party `aegis_*.py` source
set, its ancestor directory chain, file owner/mode/hardlink safety, effective
service write access and independent read-only mount status for service-owned
code. The same ancestor-chain rule applies to sensitive scope/policy paths.
It also records the configured delegation socket's real inode owner, mode and
sharing group without connecting. That is socket-presence evidence, **not**
proof a process is listening; live PID/UID/unit verification remains an external
gate. Adversarial tests cover read-only leaf files in replaceable directories,
wrong socket permissions/groups and symlinked socket paths.

### SR-20-04 — read-only host evidence initialized a missing audit ledger (fixed)

The diagnostic called `AegisSupervisor.verify_audit_chain()`, which opens the
runtime database initializer. On a valid signed fixture without a ledger, that
path created the database, audit schema and ledger identity, then reported the
new empty chain as valid. A diagnostic must not manufacture the evidence it is
supposed to inspect.

The operator check now requires an existing, private, regular, non-linked ledger
and invokes `aegis_audit.read_ledger()` using SQLite read-only mode. The new
missing-ledger regression fails against `8eb48c6` and passes with this change.
Another regression verifies an existing ledger's bytes, modification timestamp
and directory entries remain unchanged. This fixes the evidence collector; it
does not establish off-host custody or an independent deployment approval.

### SR-20-05 — referenced key custody and receiver socket group omitted (fixed)

The host collector checked top-level trust/delegation policy immutability but
did not check the public-key paths those policies reference. It now applies the
same protected-parent and read-only mount checks to both the scope signer and
delegation signer public keys. A protected policy pointing to a mutable key no
longer leaves that key's custody unmeasured.

The receiver diagnostic also omitted the configured shared GID on the socket
inode. It now shares the descriptor-relative socket type/UID/mode/GID validator
with delegation. Its evidence label explicitly names the private state directory
instead of implying that receipt records were inspected. Tests exercise mutable
referenced keys and a socket GID mismatch. These changes improve acceptance
evidence and do not broaden runtime authorization.

### Delegation lifetime boundary correction

The client backdated `not_before_utc` by two seconds while setting expiration to
the requested duration after the current time. A requested 900-second grant
therefore had a 902-second signed interval; a 30-second request had 32 seconds.
The gateway correctly rejected these overlong intervals. The client now signs
exactly the requested duration and rejects non-integer duration arguments.
Frozen-clock tests exercise actual gateway acceptance at one-second, configured
and hard limits. This was a client availability/correctness issue, not a gateway
authorization bypass.

The final closeout's focused host, delegation, release-race and source-integrity
tests passed **29/29 as a non-root identity, with no skips**. The full supported
Ubuntu acceptance for the exact committed candidate is recorded in
[PR #8](https://github.com/xRedLeader/AEGIS/pull/8); those CI results must be
checked separately from this local focused run. This remains author-assisted
review and does not populate the independent human sign-off.

## Security-sensitive deployment constraints not proven by CI

1. **Read-only operator inputs.** The runtime permits some service-owned mode-0600 policy/trust files. Service ownership alone permits that UID to rewrite them; enforce independently mounted read-only policy/trust paths or an equivalent independently reviewed OS mandatory access control rule. `aegis_host_acceptance.py` requires observed read-only mounts as its concrete supported check. Filesystem mode `0600` without independent write restriction is not a sufficient release sign-off.
2. **Strong OS identity separation.** The agent, trusted controller/gateway and durable notification receiver must use distinct non-root UIDs, protected socket directories and exact permitted peer UIDs. The PR's cross-UID CI fixtures demonstrate the behavior in ephemeral runners, **not** the real installation's systemd profiles/groups/file access.
3. **Protected deployment code.** Trusted Python modules and helpers must not be writable by the runtime service or the untrusted agent, and key material must not be reachable inside any worker bind mount. The script checks trusted source write access, but all package/import paths and upgrades need external review.
4. **External audit custody.** A signed current audit checkpoint must verify against the ledger, and a **separate** operator must verify it is retained off-host with an independently pinned public key. Local signature verification cannot prove off-host retention or reviewer independence.
5. **Real staging impact and remediation.** Existing tests use synthetic identities, stand-in review signers and local fixtures; actual approved staging impact, defensive controls, remediation observation and negative cases require independent operator attestation. Do not claim production exploitability or that a vulnerability is fixed from a zero-lead local test.
6. **No external notification channel yet.** Durable local acknowledged receipt is the bounded v2.0 contract. SMTP/Teams/Slack/webhooks and human inbox receipt remain outside this release and must not be implied by notification success.
7. **Availability, kernel and toolchain changes.** Confirm namespace/seccomp/AppArmor behavior on the intended host and after updates. The gateway processes one bounded socket request at a time; an authorized client can exhaust its service capacity by opening slow requests. Rate/worker-budget and service-supervisor limits need host operations review.

## Independent release checklist

Treat a release as **NOT APPROVED** until all of the following are observed and signed by the accountable owner on the actual deployment host: code review including the patches above; all Ubuntu supported CI at the *exact* final SHA; source and dependency provenance; distinct live UIDs/socket permissions; rootless kernel/no-egress tests; read-only mounted scope/trust/operator policies; independently pinned current signed audit checkpoint **off-host**; verified staging positive/negative/failed-delivery runs; crash, lease expiry, emergency stop, revocation and restart drills; residual bearer-token disclosure risk acceptance.

The read-only `aegis_host_acceptance.py` tool produces machine-readable **evidence** under operator and receiver identities. Its status is intentionally `NOT_PRODUCTION_APPROVED` even when all local checks pass, because a program cannot establish reviewer independence, actual application impact or off-host custody merely by declaring success. See `V2_0_HOST_ACCEPTANCE.md` for commands and the human sign-off record.

Cloudflare's multi-agent audit/review methodology remains scheduled for **v2.1**; it must not be silently treated as a v2.0 audit certification.
