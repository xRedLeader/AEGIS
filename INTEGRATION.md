# Provider-neutral agent integration — v1.3.1

The operating model is independent of any specific AI provider or model. An agent must never receive the host's unrestricted shell or credentials.

1. A trusted operator service pins the approved trust policy, revocation snapshot, signed scope and protected state root. Agent messages cannot select these files.
2. The agent may request the single typed action `source_review` and an authorized repository identifier. The operator service authenticates the requester and maps it to the fixed `scan` command. This repo does not yet supply an HTTP API adapter.
3. The Linux worker is launched only via the new namespace sandbox. It receives a read-only mount of the precise source repo and a built-in reviewer. If namespace/mount/seccomp installation fails, the action fails—there is no in-process fallback.
4. The service returns sanitized `source-review.json` results to the agent as unverified static leads. The model can propose further authorized tests, but v1.3.1 has no active-test action to carry them out.
5. Before deploying on a new host, execute `aegis_sandbox_check.py` as the non-root service user. A clean result is necessary but not a full host or kernel security certification.

For the API gateway, limited active HTTP tools and credential routing, see v1.4–v1.5 in [`MILESTONES.md`](MILESTONES.md).

Independent audit checkpoint creation and verification are operator-only; do not expose the signing private key or checkpoint creation to the agent. See `AUDIT_CHECKPOINTS.md`.
