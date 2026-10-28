# AEGIS v2.0 — actual-host deployment and independent sign-off

**There is no production sign-off from CI alone.** Run these checks using the exact installed source and the actual service identities on your intended Ubuntu/Linux host. The sample files shipped in this repository are **disabled**; do not turn them on or supply real credentials merely to satisfy a checklist.

## Install and isolate

The authorized operator selects the signed engagement, independently protected scope/trust/revocation policy, isolated assessment repository, staging-only evidence, credential classification and time limits. Record the exact Git commit SHA, installed file digests, kernel version, Python version, AppArmor profile, and the owner/permissions of all signing keys and policy files. Keep operator private Ed25519 signing keys offline; the gateway needs only the protected verification public key. AEGIS does **not** create a dedicated production Linux host or provision real credentials.

At minimum, provision **three distinct unprivileged Unix identities**: the trusted assessment/gateway service, the agent adapter, and the durable receiver. Provide explicit group access to only the required socket paths, never to trusted state/ledger, policy, signing keys or the older operator approval socket. Do not give untrusted agent subprocesses a general shell or a network capability outside the existing AEGIS gateway. Run services under a service manager with resource, privilege and restart boundaries appropriate to the deployment.

For protected service-readable configuration, a `0600` mode check **does not by itself make the file immutable to its owning service**. Use an independently provisioned read-only bind mount or an equivalent audited mandatory-access-control rule, then verify the *effective* mount under the actual service identity. The supplied script currently verifies read-only mounts; equivalent MAC protection requires separate manual evidence and sign-off. The signed scope, trust, assessment and delegation policies cannot be safely service-writable in a production admission boundary.

## Read-only host evidence commands

Run under the actual trusted **non-root assessment service identity** (not root and not the agent UID):

```sh
python aegis_host_acceptance.py operator \
  --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig \
  --trust /etc/aegis/trust.json \
  --state-root /var/lib/aegis/protected-state \
  --assessment-policy /etc/aegis/assessment-policy.json \
  --delegation-policy /etc/aegis/delegation-policy.json \
  --expected-agent-uid 2001 \
  --expected-receiver-uid 2002 \
  --audit-checkpoint /secure/operator/checkpoints/current.anchor.json \
  --audit-public-key /secure/operator/audit-public.pem
```

`2001`/`2002` are **placeholders**, not suggested actual account IDs; replace them with confirmed distinct non-root system UIDs. The diagnostic reads protected configuration and the ledger, verifies one current signed checkpoint if provided, and runs the benign offline Linux namespace/seccomp probe. It performs no external target requests and does not sign anything. Omit the checkpoint arguments only if you intentionally want a reported missing-evidence condition. `--skip-kernel` records an **unverified** kernel gate; it is not an acceptance shortcut.

Run a separate instance as the **non-root receiver identity** while its real socket service is running:

```sh
python aegis_host_acceptance.py receiver \
  --receiver-policy /etc/aegis/receiver-policy.json \
  --expected-operator-uid 2000
```

`2000` is likewise a placeholder. Receiver policy and ledger are inspected under the receiver's own UID. The tool checks live socket identity and permissions, but does not send a notification or forge an acknowledgment.

The installation check now examines **all first-party `aegis_*.py` modules**,
not just the main controller, and rejects writable ancestor directories even
when a module itself is mode-0444. The policy check likewise rejects a
service-replaceable parent, even if the policy leaf was independently bind-mounted
read-only. Deploy code under root-protected, non-service-writable directory
chains (for example `/opt/aegis`) or independently read-only filesystem mounts;
all ancestor mounts are part of the protection boundary. Third-party interpreter,
`.pth`/`PYTHONPATH` and installed-dependency custody still require separate
operator review.

The operator diagnostic also observes the delegation Unix-socket inode, owner,
mode and shared group. Start the *real* delegation gateway before running it.
Presence of a Unix socket path does **not** prove that a live gateway is
listening; separately verify the active service-manager unit, PID, effective UID
and group membership, and preserve those observations in the sign-off record.

Every machine result is labeled `NOT_PRODUCTION_APPROVED` and lists `PASS`, `FAIL` and `REQUIRES_EXTERNAL_EVIDENCE` observations. A missing source/configuration file or unsafe mode is a **failed admission check**; a passing check verifies only the fact measured on that host. The CLI returns nonzero even if every automatable check passes, to prevent CI or scripts from mistaking collected evidence for human approval. Store the output in an operator-owned location with restricted access and independently attach it to the release review.

## Required independent actions

- Have a reviewer **other than the implementer** read the security change set and check the terminal-action race fix, agent authorization, policy mounts, key/UID/socket isolation and allowed-stream credential risk.
- Execute the full `python -m unittest discover -s tests -v`, `python aegis_sandbox_check.py`, `python aegis_demo.py`, and `python aegis_http_demo.py` as the installed operator identity under the intended AppArmor profile. No skipped kernel tests count as accepted.
- Conduct the **real** authorized staging assessment with practice identities. Record positive and negative scope examples, reviewed control boundaries, independent verifier proof, remediation and re-test results. Never infer remote exploitability or remediation from an isolated Python contract result alone.
- Verify two separate Linux service UIDs via live process credentials, receiver restart and distinct-UID signed agent delegation; test wrong-peer and expired/replayed requests, mismatched report proofs, undeliverable notification, and durable retry after crash.
- Issue a current audit checkpoint with an independent operator Ed25519 key, transfer the signed result **off-host**, verify its anchor with a separately pinned key and retain earlier checkpoints. Confirm off-host copy under a second identity; a local database hash chain alone is insufficient.
- Inject a safe test-process crash during a leased assessment step, confirm that the step is **not** automatically retried, run operator-only audited `abandon` when appropriate, and require a new signed assessment for continued work. Exercise emergency stop and revocation between action selection and execution.
- Document approved residual risks, platform scope, support owner, emergency recovery path and the decision whether the system may be exposed to real credentials. A compromised credential helper may misuse its approved stream; no test suite eliminates that possibility.

## Human sign-off record (fill with observed evidence)

| Gate | Observed evidence / exact host or artifact | Reviewer identity and date | Decision |
|---|---|---|---|
| Independent v2 code review | | | NOT VERIFIED |
| Final PR commit + CI + checksums | | | NOT VERIFIED |
| Installed kernel/AppArmor/service identities | | | NOT VERIFIED |
| Operator policy/key read-only custody | | | NOT VERIFIED |
| Current signed off-host audit checkpoint | | | NOT VERIFIED |
| Authorized real staging impact and remediation | | | NOT VERIFIED |
| Crash, expiry, stop, revocation, retry drills | | | NOT VERIFIED |
| Residual risk/production use approval | | | NOT VERIFIED |

**No automated run or source review in this conversation can populate the real-host and independent-human columns without the deployment evidence.** Do not merge/tag v2.0 as a deployable production release on the basis of an unfilled record.
