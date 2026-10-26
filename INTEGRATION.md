# AEGIS v1.4 integration — model/provider-independent

The operator owns trusted code, system identity, trust policy, signature/manifest, protected state, paths and private signing keys. Agent-provided tool arguments are only a target URL (from already authorized origins), GET/HEAD choice, and a bounded time request. The model never receives a direct shell, custom request headers, credentials, or a generic network/HTTP client.

## Named capability surface

- `source_review(repo_id, seconds)`: existing bounded, kernel-contained local heuristic code review. Repo IDs must be mapped to trusted absolute directories by the operator service.
- `http_get_metadata(url, seconds)`: invokes `aegis_supervisor.py ... http --url URL --method GET --seconds N` with operator-set trust environment.
- `http_head_metadata(url, seconds)`: same as above with HEAD.
- `http_usage()`: returns persistent HTTP request count, in-flight slots, and reserved body allowances.
- Operator-exclusive: stop, manifest issuance/signing, trust-policy and route edits, revocation refresh, audit signing/checkpoint export. The agent must never invoke these independently.

This package includes these supervisor **CLI** actions but does not supply an authenticated HTTP API server or a provider-specific tool adapter. Build the operator service so the agent cannot override file paths, trust env vars, networking or exec the gateway helper directly. Restrict its host privileges with independent OS policy and run the tests on the real host.

For an ephemeral local example, execute `python aegis_http_demo.py`. For signed real staging usage, follow `README.md` and `HTTP_GATEWAY_SECURITY.md`. Configure exact origin, **pinned signed network CIDR**, operator-allowlisted path prefix, and all budget ceilings first. Use custom operator CA bundle only through independent trust policy `tls_custom_ca`, never from a tool argument.
