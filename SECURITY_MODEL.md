# AEGIS v1.4.1 security model

This document describes the released baseline. On the v1.5 development branch, the credential-bearing HTTPS helper also uses the same kernel boundary; the trusted broker passes a bounded token snapshot and one preconnected TCP descriptor. The vault descriptor is closed before sandbox launch. See the v1.5 section in `HTTP_GATEWAY_SECURITY.md` and the remaining gates in `V1_5_IMPLEMENTATION_STATUS.md`. A compromised credential helper may misuse its granted token on the approved stream or through metadata/timing channels; kernel endpoint confinement does not guarantee credential secrecy.

## Trust boundaries

Trusted components are the operator's authority, independently protected scope/trust/revocation files and public keys, installed supervisor and DNS/connection broker, sandbox launcher, system Python/runtime, and host kernel. Private signing keys remain operator-only.

Assessment data, target responses, repository source, model plans and tool output are untrusted. Repository code is never executed. The worker cannot rewrite trusted configuration, state or audit records.

The assessment boundary does not protect against a compromised host/kernel, trusted broker/supervisor, operator authority, or an agent holding independent host shell/network access. Expose only the named operations in `INTEGRATION.md`.

## Common worker containment

1. The trusted supervisor validates signed authorization and independent policy, checks revocation/stop, and reserves persistent budget.
2. A non-root service creates fresh user, mount, network and PID namespaces. The launcher positively checks all namespace identities and the single-UID mapping.
3. The launcher makes mount propagation private, creates a bounded tmpfs root, and mounts only the system runtime and fixed worker code read-only. The source-review worker additionally receives the pinned authorized repository mounted read-only/noexec.
4. Before chroot/exec, it closes all extra descriptors, including the original repository directory handle. Keeping a pre-chroot directory fd would allow traversal outside the intended filesystem.
5. It sets no-new-privileges, locks root capability semantics, clears effective/permitted/inheritable/bounding capabilities and installs default-deny seccomp. Namespace UID 0 has no host-root or CAP_NET_ADMIN authority.
6. The assessment worker cannot create processes, change namespaces/mounts or access host policy, keys, state or procfs. Missing capabilities, unsupported mounts or setup errors deny execution.

## Source review

The fixed heuristic source scanner receives no sockets. Socket creation and networking syscalls remain denied. The preserved `dup`, `dup2`, `dup3` portability fix permits fresh Python startup without permitting process creation or networking. Tests exercise a fresh system interpreter after filtering.

The authorized directory inode is pinned and checked after binding. Contents can still change concurrently; this is not a filesystem snapshot. Scanner leads are not confirmed vulnerabilities.

## HTTP transport

The trusted broker resolves the approved hostname and opens only the verified numeric IP and exact TCP port. The worker receives that connected descriptor inside an otherwise offline namespace. It can exchange bytes only with that kernel-established peer; seccomp denies new sockets and every connect call, including reconnect/disconnect on the granted fd. Socket I/O and its nonblocking ioctl are restricted to that fd.

Three standard streams must be pipes. No extra host descriptor, Unix socket, DNS client, proxy channel or writable configuration is exposed. The broker supplies only public CA material; TLS and HTTP parsing occur inside the confined worker. Kernel parent-death signals and namespace teardown close the capability on crashes; a trusted guardian enforces the deadline and output caps.

The trusted DNS/connection broker intentionally has host networking. It is part of the control plane, not an assessment process. An agent cannot invoke it directly. See `HTTP_GATEWAY_SECURITY.md` for the architecture, authority table and race/lifecycle analysis.

## Compromised-worker limits

A compromised gateway cannot open a connection to another IP or port, use UDP/IPv6/Unix/netlink as alternate paths, change firewall/routing configuration, escape namespaces, inherit other sessions' sockets or read host signing keys. It can misuse the already-granted TCP stream until its deadline or cancellation. The kernel does not parse HTTP routes, count response-body bytes or authenticate result metadata. Keep approved endpoints narrow and staged; do not expose credentials or arbitrary tools.

## Remaining risks and operational requirements

- Protect code, OS runtime, policy, keys and ledger with operator-controlled permissions. No measured boot or hardware attestation is provided.
- Deploy on a tested Linux host with user/mount/network/PID namespaces, libseccomp and supported read-only runtime bind mounts. A runtime subtree containing locked nested mounts can deny setup; never replace the failed boundary with an unconfined process.
- Resource limits cover the fixed workers, not general third-party tools. There is no cgroup accounting or exact wire-byte quota.
- Local audit hash chains require separately signed checkpoints retained and verified off-box. An unanchored suffix can be rewritten; no automatic off-host delivery exists.
- Runtime enforcement requires fresh operator revocation snapshots and a reliable host clock. No credential broker, authenticated approvals, session protocol, updater or external alert delivery is implemented.
- Namespace resources and socket grants disappear with processes. A hard crash may leave empty protected temporary directories; they do not retain network authority.
- This is test evidence for a specific configuration, not a certification or a substitute for independent security review.

Run `aegis_sandbox_check.py`, kernel egress tests and the complete suite on the deployment host after kernel/runtime or configuration changes.
