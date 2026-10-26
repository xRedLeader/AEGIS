# AEGIS v1.3 verification record

Verification was performed in the build environment under a **non-root** service identity on Linux (not using production systems or external targets).

- Full unit and integration suite: **59 tests, all passing**.
- Offline signed-scope demo: **PASS**; one synthetic static-review lead; budget ledger and audit chain verified.
- Operator kernel diagnostic: **PASS**. Eleven direct checks including authorized repository read, repository write denial, jail-root write denial, host `/etc` and `/proc` isolation, socket syscall denial, no-new-privileges, active seccomp, cleared capabilities, fork denial, trusted-worker-file write denial.
- No live application targets or outside networks were contacted.

Run these checks on each intended target host before using the release:

```bash
python aegis_sandbox_check.py
python -m unittest discover -s tests -v
python aegis_demo.py
```

Passing these checks establishes the restricted **fixed source-review worker** works on the tested kernel. It is not a penetration test of the supervisor, proof of broad agent confinement, or authorization for active/network tools. Review [`SECURITY_MODEL.md`](SECURITY_MODEL.md) for deployment assumptions.
