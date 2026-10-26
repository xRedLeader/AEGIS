# v1.4 portability and trust-file hardening patch

This patch updates the v1.4 source without changing the published `v1.4`
release snapshot. It addresses an independent Ubuntu 22.04 / CPython 3.10
compatibility finding: the default-deny seccomp profile omitted `dup`,
`dup2` and `dup3`, preventing fresh Python interpreter startup from creating
standard I/O streams. This could return exit status 0 with no JSON result.

## Changes

- Allow `dup`, `dup2` and `dup3` inside the **fixed read-only scanner**
  seccomp profile. This does not authorize network or child processes.
- Add a real namespace integration test that `execv`s a fresh
  `/usr/bin/python3` under the installed seccomp profile and requires
  nonempty, parseable JSON stdout.
- Use one bounded, `O_NOFOLLOW` protected trust-policy reader in both
  preflight and the HTTP gateway's repeated operator-policy checks. Reject
  nonregular, group/other writable, unapproved-owner, oversized, and
  symlinked trust files.
- Add a Linux CI matrix for Ubuntu 22.04 and Ubuntu 24.04, exercising the
  **system Python interpreter** inside the namespace plus the full suite.

## Verification and limitations

Local validation was performed on Debian GNU/Linux 13 with Python 3.13.
Passing tests on this host do **not** establish that Ubuntu runner jobs have
passed; inspect the GitHub Actions result on each target baseline before
claiming multi-distribution compatibility.

All active testing remains limited to signed, approved scopes. This patch
neither adds exploitation tools nor provides kernel-enforced egress for the
HTTP gateway. That remains an upcoming implementation milestone.

Seccomp is architecture-, kernel- and interpreter-dependent. Any new pinned
runtime combination requires a fresh-exec check on that exact deployment
baseline. The operator must still protect the trust policy's parent
directories and execute the supervisor independently of any untrusted agent.
