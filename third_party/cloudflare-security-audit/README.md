# Pinned Cloudflare audit methodology

These files are copied without modification from
[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill/tree/c1c8a8c1471069fb0e188eeaff69b8e8db6564a8/skills/security-audit)
at commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` under the accompanying
[MIT license](LICENSE). `SHA256SUMS.txt` inventories the original vendored files;
the repository-wide manifest also covers the provenance and adaptation files.

The guides are research references. Their suggested tools, scripts and tests do
not grant AEGIS agents permission to execute repository code, contact endpoints,
obtain credentials, or bypass signed scope and existing sandbox controls.

AEGIS implements its bounded source-only workflow and coverage invariants in
Python. This is an adaptation, not a drop-in implementation of every upstream
JSON field or an unbounded autonomous scanner. Upstream JavaScript validators
and their tests remain review/parity references; the application never loads or
executes them. Shared adversarial coverage fixtures are checked by both ports.
The existing AEGIS canonical finding schema remains authoritative.

Updating the pin requires reviewing the diff, keeping the license, replacing
the original-file checksums, rerunning upstream and parity tests, and updating
the repository source-integrity manifest. No automatic upstream fetching occurs.
