# v1.4.1 verification and release gate

Run as a non-root Linux service user on the intended deployment host:

```bash
python -m unittest discover -s tests -v
python aegis_sandbox_check.py
python aegis_demo.py
python aegis_http_demo.py
```

All active tests use temporary signed fixtures and synthetic local HTTP/HTTPS servers. No external assessment targets are contacted.

## Real kernel evidence

`tests/test_egress.py` executes the fixed adversarial probe with the same namespace and seccomp profile used by the HTTP worker. It checks authorized TCP exchange, positive IPv6 operation, denied IPv4/IPv6/UDP/Unix/raw/netlink socket creation, unauthorized IP/port reconnects and direct libc connect calls. EPERM, not a mocked socket result or absent listener, is the denial criterion.

It also checks namespace/firewall escape attempts, capabilities, extra inherited handles, concurrent workers, interrupted setup/restart, each mount failure, capability/seccomp setup failures, missing prerequisites, output flooding, a worker ignoring timeouts, and supervisor death without process-group cleanup.

Existing HTTP tests exercise signed authorization, DNS pinning and mixed answers, TLS trust/hostname failures, redirects, routes, proxy configuration, persistent budgets, concurrency, stop and revocation. Existing source tests execute a fresh system Python after seccomp and verify source review still works. The dup/dup2/dup3 fix is preserved.

## Execution record

The local acceptance environment is Ubuntu 24.04.1, system Python 3.12.3, kernel 6.18.54.1-microsoft-standard-WSL2, with workers running as UID 1000.

Unmodified WSL layout initially failed closed while binding `/usr`, because WSL adds locked child mounts there. Testing uses a disposable **outer private mount namespace**, created by root only for test setup, with those WSL-specific child mounts removed inside it. Tests and every AEGIS operation then run as the normal non-root user from the native Linux filesystem. The host mount configuration and production sandbox policy are unchanged. This environment is not claimed to be a stock Ubuntu kernel.

Final local run: **120 tests passed, 0 failed, 0 skipped** in 35.596 seconds. The independent source sandbox probe passed all 14 checks. The signed source-review demo and local HTTP demo both passed. The egress probe passed all 23 checks, including actual EPERM denials and successful authorized TCP exchange. GitHub Ubuntu 22.04/24.04 results are pending; no result is inferred from the local run.

## CI and deployment acceptance

The GitHub workflow targets Ubuntu 22.04 and 24.04 using their system interpreters. It separates policy/schema unit tests from real kernel/regression tests. Kernel prerequisites are checked before acceptance. An unavailable prerequisite is reported as **NOT EXECUTED**, fails the required job and blocks release. Skipped tests must not be represented as passing.

Do not declare multi-distribution compatibility until both matrix jobs actually pass. At least one supported Linux environment must execute the real acceptance tests successfully before v1.4.1 is considered complete. Repeat on the actual deployment host after kernel/runtime changes.

The workflow exercises fresh interpreter startup, real namespaces, raw socket denials, source review, HTTP/TLS, stop and revocation. Demos supplement the automated tests. No test success implies OS-wide confinement of unrelated agent tools or protection against trusted-host/broker compromise.

## Before publication

- Review the diff and scan tracked content for credentials, private signing material and generated runtime artifacts.
- Verify `SHA256SUMS.txt`; exclude test logs, caches, virtual environments, temporary policies and databases from commits.
- Preserve historical commits and tags, including the October 25, 2026 v1.0 date.
- Review the feature pull request; do not tag an unverified release.
