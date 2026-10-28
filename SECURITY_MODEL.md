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


## v1.5 operator API and credential containment

A dedicated non-root operator service owns a mode-0600 Unix socket in a private directory, protected ledger and credential profiles. Every command requires an independently pinned API signature over canonical JSON plus Linux SO_PEERCRED UID authorization. Commands expire within one minute; their unique IDs are consumed transactionally before executing any side effect. Only session creation, revocation and a scoped GET/HEAD request are supported. No model-facing delegation adapter exists.

Private operator API, grant, and scope signing keys stay outside the untrusted worker and public repository. The operator-service process keeps only relevant protected public verification keys. Credential profiles explicitly reject production/permanent tokens and bind token fingerprints into sessions. The trusted broker accepts only sealed anonymous credential snapshots; vault files/descriptors are not passed into the sandbox.

**Limit:** A compromised credential-bearing worker still holds the short-lived token temporarily and may send it or arbitrary bytes over the approved TCP stream. Kernel endpoint containment does not independently prove HTTP semantics or perfect secrecy; revocation cannot undo an already sent token. Operate using disposable staging accounts with strict routes and follow [Operator Service Security](OPERATOR_SERVICE_SECURITY.md).

## v1.7 synthetic local contract boundary (stacked development)

The operator pins the exact authorized repo, module, callable, SHA-256 and contract independently of the signed engagement's `bounded_fuzzing` authorization. Target Python executes only in the rootless user/mount/network/PID namespaces with a read-only/noexec repository mount and default-deny seccomp; sockets, child processes and host writes are denied. The trusted `aegis_local_contracts.py` oracle is mounted read-only from the installed AEGIS code, never supplied by the assessed target.

The parent checks every synthetic fixture, oracle value, safe observed type, trial count, case digest, expected status and output size. It records only bounded synthetic `needs_validation` leads. A verified private record yields a pinned minimal-case recipe; independent reproduction requires a fresh kernel jail and another budget reservation. This does not prove a live exploit. JSON/type and serialized CAS stale-version checks are deterministic local simulations, not generalized fuzzing or simultaneous race reproduction. Neither the worker nor model receives credentials, network, unrestricted shell, or unreviewed tool execution.

## v1.8 reporting and notification boundary (draft)

The operator-side report generator reads only completed private source artifacts and verifies the protected ledger and signed scope. It derives unverified leads, never independently confirmed severity or impact. Report paths are protected by no-follow and no-replace semantics. The notification queue shares the protected SQLite audit state; delivery is separate from enqueueing. The operator-only local Unix sender uses a configured private socket, SO_PEERCRED checks, strict bounded messages and a nonce-bound acknowledgement. Receiver persistence and honest forwarding must be established independently: a receiver's ack is a local transport assertion, not proof of a remote email or user notification. A privileged host compromise or a malicious receiver with an allowed UID is outside this boundary. See V1_8_REPORTING.md.

## v1.8 operator-side reporting/notification boundaries

The review and notification components are trusted operator-installed control-plane code only. Original static and synthetic assessment outputs can generate *unverified* findings, never confirmed severity. Confirmations require a bounded external staging proof countersigned by distinct operator and verifier Ed25519 keys, with the proof bytes retained inside an immutable SHA-256-addressed report revision. Canonical JSON, deterministic Markdown and every retained proof are verified before delivery. Sender leases have random attempt-specific fencing tokens, expiry and bounded retry, with a receiver under a separate approved Linux UID and a durable idempotent SQLite store. The metadata acknowledgment denotes local receipt, not off-host message delivery. Unreviewed models, scanners, source repositories and sandbox workers cannot sign reviews, mutate reports, or configure a recipient. Protected key custody, deployment OS/group setup and independent security assessment remain deployment responsibilities.


## v1.9 investigation orchestration

The deterministic planner is trusted operator code, not an agent-owned executor. A canonical private operator policy, signed engagement scope and latest protected v1.8 report/ledger constrain its actions. Every local retest calls the existing kernel-confined `AegisFuzzSupervisor` under separate signed budgets, never a model-provided command. Durable random lease tokens fence stale/crashed workers; current policy, source revision and emergency stop are checked again before accepting step results. Correlated findings never become verified exploit chains and no autonomous confirmation/remediation authority is introduced. The trusted host/DB remains outside the compromised-worker boundary.
