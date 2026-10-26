# AEGIS v1.4 — executable controlled HTTP(S) gateway

## Added

- `aegis_http_policy.py`: strict URL-origin parsing and signed-CIDR pinning; rejects mixed DNS answers and unsafe IP classes.
- `aegis_http_gateway.py`: fixed trusted subprocess for time-bounded DNS lookup and direct, pinned-IP HTTP/HTTPS GET/HEAD; TLS system roots, hostname verification, optional SHA-pinned operator CA; no redirects/proxies/secrets/caller headers; body hashes only.
- `aegis_http_runtime.py`: persistent per-engagement HTTP request, active slot, per-origin minute rate and cumulative worst-case body reservations in same protected SQLite audit/state; enforced watchdog/revocation/stop; private JSON metadata report.
- Supervisor CLI `http` and `http-usage`; `aegis_http_demo.py` runs a signed, scope-controlled **loopback-only** HTTP demo.
- Independent operator route-prefix policy (`allowed_http_path_prefixes`) that defaults to deny and can be updated mid-run.
- Separate `HTTP_GATEWAY_SECURITY.md` detailing implemented controls and limitations.
- Live loopback integration tests including TLS trust/hostname mismatch, DNS/IP confusion, redirects, path ambiguity, rate/byte/concurrency controls, revocation, emergency stop and proxy environment rejection.

## Authorization compatibility

The signed scope **requires a new** `limits.max_total_response_bytes`, with a corresponding positive ceiling in the independent trust policy. Existing signed v1.3.1 scopes are **not** silently upgraded. Create and re-sign a v1.4 scope; keep the original engagement history separate if the scope hash changes. The example trust policy adds `allowed_http_path_prefixes: {}` (deny all) and `tls_custom_ca: null`.

All v1.3.1 local source-review, signed checkpoint and default-deny Linux worker isolation behavior is retained. HTTP helpers are **not** run inside the source scanner namespace because its network syscalls remain denied.

## Scope and non-goals

This release enforces policy in a trusted HTTP helper, but does not install an independent OS egress firewall or confine an LLM with host network/shell access. It does not certify target staging systems, provide arbitrary methods/headers or authenticated attacks, follow redirects, execute payloads, or deliver alerts externally. Deploy behind an authenticated operator service, not as a public network proxy.
