# AEGIS v1.2 — first executable, limited supervisor

**Provider-neutral. No special model access required.** AEGIS is an incremental project toward an authorized autonomous security-assessment platform. **v1.2 is a real local execution milestone, not a deployable penetration-testing sandbox.** It only executes a known, read-only source reviewer. It does **not** permit live network attacks, arbitrary commands, credentials, or exploitation.

## What works in v1.2

- Ed25519-signed engagement manifest verification against an independent operator-pinned trust policy (inherited from v1.1).
- Manifest and revocation verification immediately before execution, continuously while a worker runs, and again before accepting results.
- SQLite `BEGIN IMMEDIATE` reservation of **cumulative runtime seconds and evidence bytes**, surviving supervisor restarts; the full reservation is charged even after an interrupted run. This accounts for the local review action only, not network traffic or fuzzing.
- An emergency stop marker that denies new operations and kills a running worker via its process group when polled.
- A trusted, no-shell, no-network, **read-only source-review worker** with resource limits and POSIX no-follow file opening. It never imports/runs target code.
- Evidence written outside target repositories into private, per-run subdirectories, with a chained SQLite audit history. Chain validation is not a tamper-proof external log.
- Test coverage for allowed execution as well as denials, restarts, symlink traversal, scope drift, budget contention, and live emergency stop.

Source-review regex matches are **unverified leads**; they do **not** become entries in the canonical `findings.json` until appropriately validated.

## Verify it offline (non-root Linux / POSIX)

Install required libraries and run the existing v1.1 tests plus new v1.2 integration tests:

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python aegis_demo.py
```

The demo generates an ephemeral signing key, an authorized **temporary demo repository**, a temporary policy, and a synthetic `shell=True` review candidate. It sends **zero network requests** and deletes all demo materials at exit. The demo is not an example of an acceptable production key-custody design.

Native Windows is not supported in this milestone. On Windows, use a properly configured Linux/WSL2 environment and a non-root service identity. Later milestones will provide a reproducible isolated container deployment.

## Operator-owned local execution

AEGIS v1.2 must be launched by a **trusted operator service**, never as an unrestricted command available to the assessment agent. Pre-provision the service installation and trust material outside the agent's writable folders, protected by OS permissions. Run under an unprivileged account. Keep the private signing key on a different operator machine.

1. Register authorized engagement ID, repository roots, methods, report root and ceilings in an independent trust policy (`trust-policy.example.json` is **disabled** by default).
2. Maintain `revocation.last_checked_utc` via a trusted updater; v1.2 checks freshness but **does not supply the updater**.
3. Populate a signed scope per `security-scope.example.yaml` for your **actual local repo**, with method `source_review`. Set `targets.origins=[]`, `targets.networks=[]`, `accounts=[]`, and network request ceilings to zero when running repository-only assessments.
4. Sign the scope **from an operator-controlled host** using `aegis_admin.py sign --trust-policy ...`, following the v1.1 instructions. Copy only the signed manifest and detached signature to the trusted runner.
5. Pre-create the supervisor's protected state root, owned by the service identity with permissions `0700`. Run the supervisor via your trusted service (not through unrestricted agent shell access).

```bash
export AEGIS_TRUST_POLICY=/etc/aegis/trust-policy.json
export AEGIS_STATE_ROOT=/var/lib/aegis/private-supervisor-state

python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig \
  scan --repo /srv/authorized-repository --seconds 20

python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig usage

python aegis_supervisor.py --manifest /etc/aegis/scope.yaml \
  --signature /etc/aegis/scope.yaml.sig audit
```

Operator-only, permanent stop for the engagement until operator manual intervention in the protected state store:

```bash
python aegis_supervisor.py stop --engagement-id actual-engagement-id
```

Because a stop marker is state-backed rather than remotely authenticated, only the operator service should control this CLI. The process user must not be root; the `state_root` must be service-owned with mode `0700`. In practice, put the operator-side stop action behind independently authenticated administration.

## Important security boundary

The supervisor mediates **only calls made through its API**. It does not prevent an AI agent or compromised tool with independent shell or network access from bypassing it. Restrict the agent and target worker with operating-system-level isolation before attaching broad tool access. The trusted supervisor source files, scope, policy, audit state, and code installation must not be writable by the model or the target repository. v1.2 does not implement a kernel-enforced deny-all network namespace, credential broker, production-grade logging, automatic revocation feed, independent approval service, or active testing tools.

For the remaining engineering work, see [`SUPERVISOR_SPEC.md`](SUPERVISOR_SPEC.md) and [`MILESTONES.md`](MILESTONES.md). **Do not expose active network scanning or arbitrary code execution until v1.3+ controls are verified.**

## Files

- `AEGIS_AGENT.md` — model-independent agent operating instructions
- `AGENT_DESCRIPTION.md` — short profile
- `aegis_supervisor.py` — new trusted local action runner, budgets, stop, audit
- `aegis_worker.py` — new deliberately narrow static source reviewer
- `aegis_demo.py` — new offline end-to-end demonstration
- `aegis_preflight.py`, `aegis_admin.py` — inherited signed-scope and signing tools
- `security-scope.schema.json`, `security-scope.example.yaml`, `trust-policy.example.json` — authorization format
- `findings.schema.json`, `findings.example.json`, `aegis_report_validate.py` — validated report format
- `tests/` — preflight, schema, and runtime tests
- `MILESTONES.md` — incremental route to v2.0
- `SUPERVISOR_SPEC.md` — additional containment requirements
- `RELEASE_NOTES.md`, `REVIEW_RESOLUTION.md`, `INTEGRATION.md` — release and integration guidance

## Known limitations

This release requires POSIX directory-relative `O_NOFOLLOW` support. Resource limits use `resource` and process groups; Linux is the intended target. External dependencies may change with time; dependency pins should be reviewed and locked before deployment. The static worker uses heuristic pattern matching and limits each file to 128 KiB; results may be partial or false positives. The one-run reservation is not refunded after failures. Control polling is roughly every 250 ms, not instantaneous. SQLite chaining can detect accidental/tampered row modification but does not prevent whole-database replacement without an external anchor. Directory permissions and trust material custody are deployment responsibilities.
