# Provider-neutral agent integration — v1.2

AEGIS can use any model and agent orchestrator. **There is no direct model-to-shell integration in v1.2.** The only executable action is a trusted local source reviewer run by `aegis_supervisor.py` under a distinct, operator-controlled service identity.

1. Supply `AGENT_DESCRIPTION.md` and `AEGIS_AGENT.md` to the agent.
2. Present the agent with an application/tool API that only accepts a named action (`source_review`) and an approved repository identifier; do not expose unrestricted command execution. The operator service translates the approved request into `aegis_supervisor.py scan`.
3. The service pins `AEGIS_TRUST_POLICY`, `AEGIS_STATE_ROOT`, scope and signature. Do **not** let the model pick these paths.
4. The service reports the `source-review.json` artifact as **unverified static leads** and may use them to draft follow-up hypotheses, not confirmed findings.
5. Keep full source, secrets, policy, signing keys and state outside the model's access. v1.2 writes files locally; a model/agent interface adapter has not yet been implemented.

Read `README.md` to run the offline demo. `MILESTONES.md` defines acceptance gates before adding web probing, credential access, fuzzing, or other active security tools.
