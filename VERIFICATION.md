# v1.4 verification protocol

Run as an **unprivileged Linux user** on the deployment host:

```bash
python -m unittest discover -s tests -q
python aegis_sandbox_check.py
python aegis_demo.py
python aegis_http_demo.py
```

- Kernel isolation tests must pass on the actual host; no fallback to an unconfined scanner is permitted.
- HTTP integration tests use a local, dynamically allocated loopback port. HTTPS tests generate an ephemeral CA and server certificate, validate trusted-CA success and reject untrusted roots and hostname mismatch. Neither tests nor demos need internet access.
- Negative cases exercise out-of-scope ports/CIDRs, conflicting DNS answers, stale authorization, method/path controls, max body bytes, persistent request limits, concurrency, emergency stop, policy route withdrawal, proxy variables and redirect non-following.
- Test suite success does not mean there is an OS-wide outbound packet firewall. The trusted HTTP transport runs with host network access and relies on software policies, operator process isolation and protected installation.
- Verify packaged ZIP checksums and rerun tests from the **extracted archive** before distributing or deploying.
