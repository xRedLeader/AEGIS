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

On AppArmor-enabled Ubuntu 24.04, permit user namespace creation for the operator service. `deployment/apparmor/aegis-supervisor` is a named opt-in profile using AppArmor 4's `userns` permission. An administrator loads it and selects it for the service, such as with systemd's `AppArmorProfile=` setting. It grants a prerequisite to an otherwise unconfined trusted service; it is not a full MAC policy and is not required on hosts without this restriction. Keep the service non-root and the global AppArmor policy enabled. Run the acceptance tests under the same selected service profile.

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


## v1.5 operator-only credential control (draft)

Run `aegis_operator_service.py` under a dedicated non-root service identity. It exposes only a filesystem-private Unix-domain socket and checks both SO_PEERCRED and Ed25519-signed, short-lived replay-protected commands. `aegis_operator_client.py` uses a separate offline operator signing key. Allowed operations are `session.create`, `session.revoke` and `session.fetch`; no arbitrary tools or operator policy mutation. Signed grant files live in a protected approval directory. The agent must not have access to this socket, the signing key, the vault, or the privileged Python class.

The sample JSON policies are disabled and require independent operator provisioning. Consult `OPERATOR_SERVICE_SECURITY.md` for credential classes, sealed snapshots and trust boundaries. Separate Linux UIDs and filesystem permissions matter; a mode-0700 directory does not allow unrelated unprivileged users to connect.
