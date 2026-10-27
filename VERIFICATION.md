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

Final local run: **120 tests passed, 0 failed, 0 skipped** in 35.596 seconds. The independent source sandbox probe passed all 14 checks. The signed source-review demo and local HTTP demo both passed. The egress probe passed all 23 checks, including actual EPERM denials and successful authorized TCP exchange. The final focused egress run passed all 16 tests after strengthening the interrupted-setup and uncooperative-worker assertions.

GitHub [acceptance run 40390198086](https://github.com/xRedLeader/AEGIS/actions/runs/40390198086) verified implementation revision `6b1f08fdd6333321246172a85db19f9a537ee03a` on October 26, 2026:

| Environment | Full suite | Additional verification |
|---|---|---|
| Ubuntu 22.04, system Python 3.10.12 | 120 passed, 0 failed, 0 skipped (36.532s) | Policy job, source kernel probe and both signed demos passed. |
| Ubuntu 24.04, system Python 3.12.3, named AppArmor userns opt-in | 120 passed, 0 failed, 0 skipped (36.378s) | Policy job, source kernel probe and both signed demos passed. |

These are observed results on independent CI hosts, not claims that every Linux distribution, container policy or Windows/macOS environment works. The four matrix jobs passed; the parallel push-triggered run also passed. No v1.4.1 release tag was created as part of this verification.

## CI and deployment acceptance

The GitHub workflow targets Ubuntu 22.04 and 24.04 using their system interpreters. It separates policy/schema unit tests from real kernel/regression tests. Ubuntu 24.04 explicitly loads the named AppArmor user-namespace opt-in profile and runs the suite non-root under that service profile; it does not disable AppArmor globally. Initial Ubuntu 24.04 jobs without that prerequisite reported **NOT EXECUTED** on a denied UID mapping. Kernel prerequisites are checked before acceptance. Unavailable prerequisites or skipped tests fail the required job and block release.

Do not declare multi-distribution compatibility until both matrix jobs actually pass. At least one supported Linux environment must execute the real acceptance tests successfully before v1.4.1 is considered complete. Repeat on the actual deployment host after kernel/runtime changes.

The workflow exercises fresh interpreter startup, real namespaces, raw socket denials, source review, HTTP/TLS, stop and revocation. Demos supplement the automated tests. No test success implies OS-wide confinement of unrelated agent tools or protection against trusted-host/broker compromise.

## Before publication

- Review the diff and scan tracked content for credentials, private signing material and generated runtime artifacts.
- Verify `SHA256SUMS.txt`; exclude test logs, caches, virtual environments, temporary policies and databases from commits.
- Preserve historical commits and tags, including the October 25, 2026 v1.0 date.
- Review the feature pull request; do not tag an unverified release.


## v1.7 bounded local reproduction acceptance (draft stacked PR)

The first v1.7 increment was expanded to three operator-pinned Python contracts, a repeated-trial bound and independent fresh-sandbox verification of a minimal mismatch. The exact GitHub feature branch passes **296/296 tests on Ubuntu 22.04 and 296/296 on Ubuntu 24.04**, with no skipped tests, in [run 40579625681](https://github.com/xRedLeader/AEGIS/actions/runs/40579625681). Non-root local source-specific tests: 30/30 passed; the inherited full local suite was incomplete on the development host and is not counted as a local success. Final PR-head CI and deployment-host operator authorization checks still apply. See `V1_7_ACCEPTANCE.md` for exact limitations.
