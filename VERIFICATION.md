# AEGIS v1.3.1 verification record

Run on each intended Linux host as a **non-root** service identity before deployment:

```bash
python aegis_sandbox_check.py
python -m unittest discover -s tests -v
python aegis_demo.py
```

The sandbox diagnostic must pass **all 13 kernel checks**, including new negative tests for an unspecified `getppid` syscall and an unapproved ioctl request. The automated suite includes active Linux namespace integration and independent audit-checkpoint forgery tests. The demo is local-only; it does not send packets to real targets.

Keep three assurance claims distinct:

- OS containment of **one trusted fixed source-review worker** is implemented and tested under Linux.
- A locally verifiable audit chain and separately signed, manually exported checkpoints are implemented. Automatic off-host retention/continuous runtime verification are not.
- Network-enabled pentesting, general-purpose analyzer sandboxes, credentials and runtime cgroup-v2 limits are **not yet implemented**.
