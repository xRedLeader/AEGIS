# v1.3.1 runtime security model

## Assets and boundaries

**Trusted:** operator; protected signed engagement scope and independent trust policy; pinned signer public key; supervisor implementation; trusted `aegis_worker.py`; sandbox launcher and operator-supplied system binaries; host kernel and correctly configured namespace support.

**Untrusted:** source files and symlinks in assessed repositories, scanner leads, LLM-produced plans, user-controlled application data, tool outputs and repository content. Repository code is never imported or executed.

**Out of scope:** adversarial native binaries as worker payloads; local kernel exploitation; agent with arbitrary host shell; a compromised host operator account; compromise of trust-policy/key installation. Treat kernel capabilities as defense in depth, not a proof against unknown kernel vulnerabilities.

## Linux confinement steps (ordered)

1. Host service validates manifest and trust policy and checks exact authorized repository. It opens each directory component without following symlinks.
2. Supervisor atomically reserves cumulative budget, opens a private temporary jail directory, and launches `unshare` with new user+mount+network+PID namespaces, inheriting only the authorized repo descriptor plus standard streams.
3. Inside namespaces, trusted launcher positively verifies all four namespace identities changed and UID 0 maps to the original non-root service UID. It makes mount propagation private, mounts a small tmpfs, ro-binds system Python runtime, assessed repository and fixed reviewer code, and verifies the repo mount's device/inode equals the inherited descriptor.
4. Launcher switches root into the new filesystem, removes write permission on the temporary root, sets `no_new_privs`, locks securebits, clears permitted/effective/inheritable and bounding capabilities, and installs a default-deny seccomp allowlist before execing the trusted worker.
5. Worker sees only `/repo`, `/app/worker.py`, `/usr` (read-only), `/lib` and `/lib64` symlinks. It cannot access host `/etc`, `/proc`, sibling repositories, protected state or operator keys. No network interface or external route is exposed; seccomp additionally blocks socket syscalls.
6. Supervisor polls scope and stop conditions, enforces wall time and process resource limits, and accepts only a bounded, expected JSON result. All evidence is written outside the jailed process by the supervisor into private report directories; failures have no unsandboxed fallback.

## Guarantees tested directly

`aegis_sandbox_check.py` launches a hard-coded probe in exactly this namespace layout to test positive authorized repository reads and negative repository writes, jail-root writes, host files, procfs, socket syscall, spawning child processes, application-code writes, capabilities, seccomp mode and `no_new_privs`.

These are **observed controls on the host running the test**. They do not guarantee every other Linux environment behaves identically. Run the probe again whenever the host kernel, container runtime, user namespaces or installed libraries change.

## Known gaps and residual risks

- The sandbox is a *worker* boundary only. A model with any other shell, host tool, network client, or file access can bypass this supervisor completely. The model must be restricted to a small operator-owned API.
- Code/policy/trust/ledger installation integrity depends on operator-controlled host permissions; an agent must never write them. No measured boot or hardware attestation exists.
- No cgroup-v2 accounting or quota enforcement. The scan worker uses RLIMIT_CPU, RLIMIT_AS, RLIMIT_FSIZE, RLIMIT_NOFILE, an 8 MiB tmpfs, and a no-process-creation seccomp profile. These limits are appropriate for the fixed reviewer but not sufficient for arbitrary future tools.
- The local audit hash chain alone is not externally anchored. v1.3.1 adds operator-side signed checkpoints; they detect tampering of a signed prefix **only if** an independent operator protects the signing key, retains the checkpoint off-box, and verifies it. No automatic off-box retention exists.
- The namespace setup process temporarily has mount capabilities **inside its new user namespace** before dropping all capabilities; security relies on trusted launcher code and a patched host kernel.
- A repository inode is pinned while scanned; content within the same filesystem can still change during review. The scanner does not provide snapshot consistency or file-integrity guarantees.
- A process may inherit standard I/O pipes, but no credentials, extra host file handles, proxies, or broadly writable mounts. Normal deployment must ensure supervisor paths and OS installation are not controlled by an untrusted agent.
- An uncontrolled scan worker's stderr/stdout could exhaust supervisor memory in a generalized execution system; v1.3.1 runs only the fixed bounded reviewer. Future tool adapters need streaming limits.
- No runtime HTTP gateway, request/byte accounting, credential broker, approval service, external revocation updater or alert delivery exists yet.

**Security policy:** any failed containment step denies operation. Never downgrade to a bare subprocess, relax the seccomp policy, or allow arbitrary executables to preserve availability.

## v1.3.1 incremental mitigations

The fixed worker now loads a **positive libseccomp syscall allowlist**, with `EPERM` for unspecified calls. It still permits `execve` for the trusted launch transition and `prctl` for the diagnostic; these are acknowledged residual permissions. Kernel checks verify arbitrary `ioctl` is not permitted. The allowlist has been tested on the build environment only; do not extrapolate to all architectures or future analyzers.

The auditor can now sign and verify checkpoints of a self-consistent ledger head with a **separate operator key**, but the checkpointer/verification workflow remains operator-side. This package does not transmit or store the checkpoints on an independent host automatically. Protect the signing key, pinned public key and checkpoint retention independently. A rollback of the unanchored suffix remains detectable only after the next successful external checkpoint.
