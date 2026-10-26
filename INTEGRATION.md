# AEGIS v1.4.1 integration — provider-independent

The operator owns installed code, service identity, signed scope, trust policy, revocation snapshots, protected state, report paths and private signing keys. The agent supplies only a target URL already authorized by scope, GET/HEAD selection and bounded time request.

## Named operations

- `source_review(repo_id, seconds)`: fixed, read-only source review. Map IDs to trusted absolute paths in the operator service.
- `http_get_metadata(url, seconds)` and `http_head_metadata(url, seconds)`: invoke the supervisor's `http` command with operator-pinned configuration.
- `http_usage()`: persistent request, active-slot and reserved response-body counters.
- Operator only: stop, signing, policy/route changes, revocation refresh and audit checkpoint export.

This package provides a CLI, not an authenticated API server or model tool adapter. Never expose the raw broker, launcher, gateway, probe, filesystem options, socket descriptors, executable paths or generic shell to an agent.

## Deployment and migration

Install the entire v1.4.1 code set, including `aegis_http_broker.py`, in a protected location. Run as a **non-root Linux service user**. Both scanner and HTTP now require working user/mount/network/PID namespaces and libseccomp; HTTP no longer works on a host where source isolation is unavailable.

No host firewall, veth, sudo broker or CAP_NET_ADMIN grant is required. The launcher briefly holds capabilities only inside its private user namespace, then drops them. DNS and the initial TCP connect belong to the trusted broker. The parser gets one preconnected peer capability and no ability to create or replace connections.

Existing valid v1.4 manifests, operator route grants, TLS CA policy and SQLite ledgers retain their format. No automatic scope expansion, credential access or engagement reset occurs. Replace trusted code as one unit, stop in-flight operations before upgrading, verify checksums, and run `VERIFICATION.md` on the deployment host.

For scoped staging requests:

```bash
export AEGIS_TRUST_POLICY=/etc/aegis/trust-policy.json
export AEGIS_STATE_ROOT=/var/lib/aegis/protected-state
python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig http \
  --url 'https://staging.example.org/health' --method HEAD --seconds 15
```

Maintain fresh revocation snapshots and retain signed audit checkpoints independently. Only public CA material enters the HTTP worker. Credentials, arbitrary methods/headers, body capture and authenticated assessment are not enabled.

Run `python aegis_http_demo.py` for an ephemeral signed loopback demonstration. See `HTTP_GATEWAY_SECURITY.md` before deployment: endpoint confinement does not independently enforce HTTP semantics if the worker is compromised.
