# AEGIS v1.3 release notes

## New working code

- `aegis_sandbox.py`: fixed-worker rootless Linux user/mount/network/PID namespace launcher, protected tmpfs filesystem, ro bind mounts, pinned source inode verification, capability drop, `no_new_privs`, libseccomp system-call deny rules.
- `aegis_isolation_probe.py` and `aegis_sandbox_check.py`: harmless operator-only runtime diagnostics for kernel-enforced read/write/network/privilege denials.
- `aegis_supervisor.py`: replaces bare subprocess execution with a fail-closed namespace command, inherited pinned source FD, temporary per-run jail, and an explicit isolation indicator in results. Signed authorization, stop, revocation and the v1.2 budget/audit semantics remain in effect.
- `tests/test_isolation.py`: actual kernel-denial tests, direct-launcher failure, missing/broken sandbox command denial, no fallback, and result/audit assertions.

## Compatibility

- Scope signing format, trusted policy and report schema are unchanged from v1.2. Previously valid v1.1/v1.2 signed scopes remain compatible when their active authorization, revocation and host requirements still hold.
- Linux non-root + user namespace support and libseccomp are **new mandatory runtime requirements**. A missing security feature is an execution denial, not a downgrade to v1.2 behavior.
- `scan` result now includes `isolation: LINUX_ROOTLESS_NAMESPACES_READONLY_ROOT_SECCOMP`.

## Explicit non-features

- No generic command tool, arbitrary code execution, unconfined fallback, outbound HTTP client, credentials, production exploitation, alerts-to-operator transport, external revocation updater, or cgroup-v2 quotas.
- Although a real kernel-isolated worker now exists, broader model/agent confinement and network-enabled tool security have not been implemented.
