# AEGIS v1.3.1 — containment and audit hardening

This release is an incremental security hardening of v1.3, not the network-enabled v1.4 milestone.

## Implemented

- **Default-deny seccomp:** `aegis_sandbox.py` now returns `EPERM` for unspecified syscalls and positively allows only the needs of the fixed read-only Python worker and its loading/runtime. The sole `ioctl` exception is Linux `FIOCLEX` (argument-specific), instead of allowing `ioctl` generally. On the test host the actual kernel diagnostic verifies 13 behaviors, including rejection of `getppid` and non-`FIOCLEX` `ioctl`.
- **Local audit checks:** hash verification now checks sequence continuity and runs before budget reservation; the supervisor reports `LOCAL_AUDIT_CHAIN_VALID_UNANCHORED` for a local chain check rather than implying independent tamper resistance.
- **Independent audit checkpoints:** `aegis_audit.py` can sign a verified ledger head using a distinct operator Ed25519 key and verify that its signed prefix is still present. The signature uses `AEGIS-audit-checkpoint-v1` domain separation and the payload binds a random ledger identity, sequence number and digest. An independent operator must store checkpoints **off-box** and pin the audit public key outside the agent's control.
- **Adversarial tests:** reproduce the full-DB rewrite+rehash bypass of a local hash chain, demonstrate signed-checkpoint detection, and cover truncation, mismatched keys, tampering, sequence gaps, and later legitimate events.

## Unchanged limitations

- The assessment action is only a fixed, read-only source scanner (simple rules, not a mature static analyzer).
- The supervisor cannot constrain an independent agent shell; the operator must broker actions exclusively through a trusted restricted service.
- No network gateway, credentials, remote notification delivery, cgroup-v2 policy, arbitrary analyzer execution, or automated off-box checkpoint delivery is implemented.
- Before namespace setup completes, the trusted launcher has user-namespace mount capabilities. Protect its files and keep the host kernel patched. The allowlist is specific to the tested Python/Linux ABI: on different hosts tests may fail closed until deliberately ported and verified.
- Audit checkpoint verification detects modification of an **already anchored prefix**. It cannot detect changes to events created after the most recent checkpoint or loss of a newer checkpoint. Schedule frequent independent retention/verification.

## Compatibility

- v1.3 signed scope and policy formats are unchanged. Existing v1.3 audit tables are upgraded in place with a ledger identity on first use; **take an offline backup and immediately establish the first independent checkpoint**.
- The `scan` response now names `LINUX_ROOTLESS_NAMESPACES_READONLY_ROOT_SECCOMP_DEFAULT_DENY`.
- The local `audit` command status is renamed to `LOCAL_AUDIT_CHAIN_VALID_UNANCHORED`. For independent assurance, use `aegis_audit.py verify` with an operator-pinned public key and checkpoint.
