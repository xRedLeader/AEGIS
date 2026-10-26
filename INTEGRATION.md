# Provider-neutral agent integration

AEGIS has no dependence on a model family, provider, API, proprietary agent framework, or hosted IDE.

## General integration steps

1. Supply `AGENT_DESCRIPTION.md` as the agent description and `AEGIS_AGENT.md` as its operating instructions.
2. Connect the agent to **supervisor-mediated tools**, not unrestricted shell/network access. Suggested categories: read source, inspect dependency advisories, request controlled local tests, record findings, and finish assessment.
3. Have the privileged supervisor read the protected trust policy and invoke `aegis_preflight.py` on the signed manifest before permitting any active action. The supervisor must enforce the resulting effective scope on every actual operation.
4. Store `findings.json` conforming to `findings.schema.json` and generate human-readable reports from it.
5. Route critical findings via an independently tested monitored channel, and retain all sanitized evidence inside the authorized reporting root.

## Deployment boundary

You can use the text-only instructions without a supervisor for passive review of operator-provided local source code. Do **not** grant real network attack tools or production credentials solely on the strength of the prompt or a successful preflight. Build/test the controls in `SUPERVISOR_SPEC.md` first.
