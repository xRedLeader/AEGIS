# AEGIS v1.3 — kernel-isolated local review worker

**Provider-neutral security research platform, built incrementally.** v1.3 retains the signed, operator-scoped supervisor and persistent budget/audit system from v1.2, and now runs its fixed read-only static scanner under **actual Linux kernel confinement**. It is not yet a general autonomous pentesting platform. Live target probing, user-provided commands, credential use, exploit execution and network access are intentionally unavailable.

## What ships in v1.3

- **Signed authorization:** Ed25519 manifest checked against a separate operator-pinned trust policy; engagement, targets, methods, report paths, expiry, and revocation freshness are revalidated before and during the operation.
- **Kernel-enforced worker isolation:** a new user, mount, network, and PID namespace via `unshare`, an 8 MiB temporary root filesystem, read-only mounts of `/usr`, the one trusted scanner, and the authorized repo, plus a process with no visible host `/etc`, `/proc`, supervisor state, signing keys, or other repositories.
- **System-call filtering:** `libseccomp` denies socket creation/communication, process spawning, namespace/mount changes, ptrace, keyring calls, and relevant bypass syscalls; Linux capabilities are cleared and `no_new_privs` is set. CPU, address-space, open-file and output-file limits apply.
- **Pinned source root:** supervisor passes an already-open directory descriptor; the launcher verifies it is still the same device+inode after bind-mounting and before the trusted worker runs.
- **Control continuity:** accumulated runtime/evidence budgets are reserved in SQLite, emergency stop and revocations terminate work, and result artifacts/audit records remain outside repositories. Scanner matches remain unverified leads, **never confirmed vulnerabilities**.
- **Operator-only kernel diagnostic:** `aegis_sandbox_check.py` executes a fixed probe that verifies 11 real allow/deny behaviors; it cannot launch arbitrary user commands.

## System requirements

Linux with unprivileged user/mount/net/PID namespace support, `/usr/bin/unshare` (util-linux), `/usr/bin/python3` plus its standard library and dynamic dependencies, `libseccomp.so.2`, and a **non-root service user**. The assessment user must not be given direct shell/network bypass around the trusted supervisor. The operator must install program code and trust policy outside writable agent and target locations. Operator private signing keys must never live in the worker environment.

Docker/containers, hardened distributions, and some managed Linux hosts restrict user namespaces: **the supervisor fails closed on such hosts**. It never runs an unconfined worker as fallback. Native Windows and macOS are not supported; Windows operators need a Linux VM or appropriately configured WSL2 with these kernel capabilities.

Dependencies for the **trusted supervisor**, not the jailed Python worker:

```bash
python -m pip install -r requirements.txt
```

Run these commands **as a non-root Linux user** from the unpacked AEGIS directory:

```bash
python aegis_sandbox_check.py
python -m unittest discover -s tests -v
python aegis_demo.py
```

The diagnostic must report `KERNEL_ISOLATION_VERIFIED_IN_THIS_ENVIRONMENT` and every check `true`. The demo creates an ephemeral signing key, sample repo and policy, runs one real sandboxed static assessment, checks its evidence and audit, and removes temporary data. It contacts **no external hosts**.

## Real scoped local assessment (operator-owned service)

1. Install the trusted supervisor and launcher under a protected path outside the target source tree; configure a non-root service identity and its private state directory (`0700`).
2. Configure an independent trust policy and fresh revocation snapshot; ensure it explicitly approves the engagement and authorized repo roots. The sample policy is **disabled** by default.
3. Prepare a signed `security-scope.yaml` (template supplied). For local source-only review use `methods.allowed=[source_review]`, no network origins/accounts, and zero network budgets.
4. Sign the scope on a different, operator-controlled system with `aegis_admin.py`. Transfer only the signed manifest, detached signature and approved public key to the runner.
5. Expose only a named `source_review` action through the operator's API. Do **not** give an AI agent direct shell access to the supervisor host.

Example operator invocation, with the trusted environment variables configured by the service **not by the agent**:

```bash
export AEGIS_TRUST_POLICY=/etc/aegis/trust-policy.json
export AEGIS_STATE_ROOT=/var/lib/aegis/protected-state

python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig \
  scan --repo /srv/authorized-repository --seconds 20

python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig usage
```

Operator emergency stop (one-way until separately serviced):

```bash
python aegis_supervisor.py stop --engagement-id ENGAGEMENT_ID
```

`stop` is operator-only: enforce access restrictions around this CLI/API; an agent must not be able to modify its protected state.

## Limitations and threat model

**This is OS isolation for ONE known, trusted source-review worker, not confinement of arbitrary adversarial binaries or the AI orchestrator.** The supervisor only protects calls it mediates. It does not configure cgroups, external egress filters for future network tools, an authenticated approvals server, remote revocation updates, external audit anchoring, a credential broker, alert delivery, or any active test capability. The root filesystem is immutable to the jailed worker, but the operator-controlled host and an agent with independent shell access remain outside this boundary. Each deployment must pass the actual sandbox diagnostic and receive independent security review before handling hostile binaries. More in [`SECURITY_MODEL.md`](SECURITY_MODEL.md).

The syscall policy is intentionally restrictive, including denying forks/clones. Some future scanner tools will require separate security profiles—not an unreviewed relaxation of this profile. Runtime reservations are charged in full even if a scan fails. Some protective checks are limited by source, kernel, package, and host configuration. **Do not expose live network scanning or arbitrary exploit execution as v1.3 actions.**

For the next milestone, see [`MILESTONES.md`](MILESTONES.md). v1.4 will add a separate, narrowly scoped HTTP testing gateway while keeping the sandbox's default network-deny policy intact.
