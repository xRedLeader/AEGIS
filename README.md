# AEGIS v1.4 — controlled HTTP(S) gateway

**A provider-neutral, incremental, authorization-scoped security assessment platform.** Version 1.4 retains the v1.3.1 signed scope, kernel-contained read-only reviewer, persistent SQLite budget/audit controls, emergency stop, and independently signed audit checkpoints. It adds a **fixed, uncredentialed HTTP/HTTPS GET/HEAD gateway** through the trusted supervisor.

**This is not yet a general-purpose penetration-testing platform or a network-isolated arbitrary tool runner.** The HTTP gateway runs as a separate trusted non-root subprocess with OS network access. It is constrained in software to authorized routes and pinned IPs, but **an agent with independent host shell/network access can bypass these controls**. Do not expose that access.

## What is implemented

- **Destination binding:** URL must match an exact signed and independently approved origin, including port; DNS answers must *all* fall into an explicitly signed CIDR independently approved by the operator. Empty network lists authorize **no packets**, even if an origin is listed. Unsafe link-local, multicast and unspecified addresses are categorically denied.
- **Route binding:** Operator-maintained `allowed_http_path_prefixes` has default-deny behavior. Only approved paths are tested; ambiguous paths (encoded path bytes, dot segments, repeated slashes, semicolon path parameters) are denied. Prefix `/` authorizes all paths of that origin and is appropriate **only** for explicitly disposable staging where such breadth is approved.
- **Pinned transport:** DNS runs in a killable subprocess. After all answers pass policy, the gateway connects only to a numeric IP; it does **not** re-resolve on connect. It retains the authorized hostname for HTTP `Host` and HTTPS SNI/hostname verification. HTTP proxy settings, caller-supplied headers, cookies, credentials, request bodies, and automatic redirect handling are all disabled. **Only GET and HEAD.**
- **Verified TLS:** Default system CA roots and hostname validation. For staging CAs, a separate operator trust policy can pin a protected PEM CA file by SHA-256; neither the agent nor URL can select its TLS trust anchor. An untrusted CA or hostname mismatch rejects the request.
- **Persistence and limits:** SQLite atomically reserves total requests, per-origin requests per minute, active requests, cumulative time, evidence bytes, and cumulative *worst-case response body allowances*. Full reservations are charged even on failure. Actual fetched response bodies are SHA-256 hashed then discarded, never included in evidence. Response body cap is at most 1 MiB.
- **Stop/revocation:** Supervisor re-verifies signed authorization, fresh revocation policy, operator route grants, custom CA policy, and kill switch while the DNS/HTTP subprocess runs. It terminates the subprocess if those checks fail or the wall-time budget expires.
- **Reports:** `runs/<id>/http-result.json` contains response status, body length/digest, selected nonsensitive headers, destination IP and target path hash (not URL query or response body). Scanner results remain separate `source-review.json` heuristic leads, not confirmed findings.

## Requirements

Linux, a **non-root** service identity, `/usr/bin/python3`, `/usr/bin/unshare`, `libseccomp.so.2`, Linux user/mount/net/PID namespaces for the *source scanner*, and Python dependencies in `requirements.txt` for the supervisor.

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python aegis_sandbox_check.py
python aegis_demo.py             # existing source-only, offline demo
python aegis_http_demo.py        # signed loopback-only HTTP gateway demo
```

The sample trust policy is **disabled by default**. All integration demos generate temporary signing keys, scopes, and local services. No external hosts are contacted in the demos.

## Operator configuration

1. Install all executable code in a trusted, non-agent-writable location. Pin `AEGIS_TRUST_POLICY` to an independently operator-controlled JSON file and `AEGIS_STATE_ROOT` to a service-owned mode-`0700` directory. Install the public signing key outside target repositories.
2. Add an engagement ID, exact origins and allowed destination CIDRs to the independent trust policy. Set `approved_methods` to include `controlled_http_testing`. Define `allowed_http_path_prefixes`, e.g. `{"https://staging.example.org":["/health", "/api/status"]}`.
3. Create an engagement manifest matching that policy. Set `targets.origins` (exact scheme, hostname, port spelling), `targets.networks` (specific CIDRs, preferably `/32` or `/128`), method `controlled_http_testing`, and all network/body budgets, including **new required `max_total_response_bytes`**. Sign with `aegis_admin.py` on the operator-controlled system. Public services with changing DNS require deliberate IP/CIDR policy maintenance; AEGIS fails closed on drift.
4. For a private staging CA only, optionally set `tls_custom_ca` in the protected JSON policy to `{"path":"/etc/aegis/staging-ca.pem","sha256":"<64 hex SHA-256>"}`. The file must be regular, not a symlink, not group/other writable, and owned by root or the service identity. Never put this certificate path under an assessed repository or a model-writable location.
5. Expose only *named operations* (`source_review`, `http_get_metadata`, `http_head_metadata`) via your separate authenticated operator service. This release provides a CLI, **not** an authenticated API server, model tool adapter, agent authorization system, or external firewall.

Example operator invocation after valid scope/key/trust configuration:

```bash
export AEGIS_TRUST_POLICY=/etc/aegis/trust-policy.json
export AEGIS_STATE_ROOT=/var/lib/aegis/protected-state

python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig http \
  --url 'https://staging.example.org/health' --method HEAD --seconds 15

python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig http-usage
```

Operator-only irreversible emergency stop: `python aegis_supervisor.py stop --engagement-id ENGAGEMENT_ID` (with `AEGIS_STATE_ROOT` configured). Existing source-review CLI remains available unchanged.

## Why v1.4 is intentionally narrow

- A GET can still change server state in badly designed applications. The route policy **cannot prove** an endpoint is read-only; operators must explicitly select staging routes and validate semantics. No POST/PUT/PATCH/DELETE, authentication, custom headers, parameter generation, or exploitation tools in this milestone.
- The scanner's **no-network Linux sandbox remains unchanged**. The HTTP helper is a separately trusted process, not isolated by a kernel network allowlist/firewall or a cgroup. A defect in its transport logic, a compromised helper, or an independently network-capable agent could bypass the *software* target policy. Deploy only on operator-controlled staging, preferably with an independent host egress firewall. Do not claim kernel-enforced egress for the gateway.
- HTTPS verifies the configured hostname and CA trust; plain HTTP has no cryptographic server identity. Signed IP/CIDR pinning mitigates DNS-redirection scope changes but does not authenticate an HTTP server.
- The cumulative response-body budget charges each request's full potential response allowance, even when fewer bytes arrive; headers and TLS handshake bytes are not part of that counter. It is conservative, not precise bandwidth metering. An expired active reservation may be reaped after its deadline; a stalled host clock or suspended supervisor remains a residual concurrency-accounting risk.
- Local hash-chain audit integrity is **not** independent authenticity. Operator-side signed checkpoints must be retained and checked off-box (see `AUDIT_CHECKPOINTS.md`). There is no automated off-host delivery or alerting in v1.4.
- No credential broker, authenticated approvals, revocation updater, generic vulnerability analyzer, sandboxed arbitrary offensive tools, or autonomous model orchestration yet. Those remain future milestones. Never give the model a raw shell or the helper executable.

More: `HTTP_GATEWAY_SECURITY.md`, `SECURITY_MODEL.md`, `SUPERVISOR_SPEC.md`, `MILESTONES.md`, `RELEASE_NOTES.md`, `INTEGRATION.md`.
