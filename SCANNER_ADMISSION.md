# Scanner evidence admission

`aegis_scanner_import.py` admits an existing report as **unverified leads**. It
does not run a scanner, build source, install dependencies, pull an image, query
a vulnerability service, validate a credential or contact a target. The existing
independent verifier/operator staging-proof path remains necessary to confirm a
finding. An exact repeat of the full attestation and verified provenance returns
its original run. New observation times, database identities or signing identities
are retained separately even when the report bytes are unchanged. Finding IDs
stay stable, and repeated scanner output is not independent corroboration.

Run as the protected non-root Linux operator identity, with existing
`AEGIS_STATE_ROOT` and `AEGIS_TRUST_POLICY`:

```sh
python aegis_scanner_import.py --manifest /protected/scope.json \
  --signature /protected/scope.sig --policy /protected/scanner-policy.json \
  --report /protected/original-report.json --seconds 5
```

The input report, canonical JSON admission policy and scanner configuration are
private regular files outside authorized repositories, runtime state and report
directories. Protected policy pins the exact report SHA-256, scanner/version/
schema, configuration bytes, allowed rule IDs, observation time, maximum age,
and independently selected source or artifact identity. Empty/default example
policies do not authorize imports. There is no free-form scanner command field.

The shared schema is version `1`. `scanner-admission-policy.example.json` shows
all required fields. JSON rejects duplicate keys, nonfinite values, excessive
depth/counts and oversized input (512 KiB). At most 64 normalized observations
fit the 32 KiB evidence reservation; excessive input fails rather than silently
reporting complete coverage. Imported paths and line ranges must belong to the
independently selected source snapshot. Source is re-read before publication.
An integrated `scanner_import` step additionally binds that repository to its
assessment's repository, and uses protected `scanner_policy` and `scanner_report`
paths. Reporting accepts its `scanner-import.json` artifact only when the exact
bytes match the completed audited receipt.

## Provenance is explicit

| Mode | Evidence required | What it establishes |
|---|---|---|
| `operator_attested_external` | Protected admission policy and exact report/config/input digests | The operator associated these bytes; no independent execution verification. |
| `verified_ci` | Canonical attestation, detached Ed25519 signature and separately pinned public key | The configured signer attested the exact tool/config/input/report/time/database tuple; the signer and CI environment still require trust. |
| `aegis_governed` | Matching completed internal execution run and hash-chain-verified execution event | The separately admitted execution profile recorded those exact inputs and outputs. An external JSON claim alone is rejected. |

CI signs `AEGIS-SCANNER-ATTESTATION-v1\0` followed by canonical JSON from
`aegis_scanner_contract.attestation(policy, input_identity)`. The statement binds
the engagement, detector, configuration SHA, input SHA, report SHA, observation
time, database metadata and producer. Keep signing private keys outside AEGIS.
An import cannot acquire execution authority by changing its provenance label.

Source selection names an exact authorized repository and a map of relative
paths to SHA-256 values (128 UTF-8 files, 1 MiB each, 8 MiB total). Its portable
identity excludes the private host path. Artifact and staging adapters impose
their additional schema, package/image/database, origin and route checks.
Unsupported report releases/schemas fail closed. Legacy
`import_scanner_report()` callers for pip-audit/npm remain compatible; shared
admission pins pip-audit `2.9.0` and npm `10.9.2` explicitly.

## Redaction and interpretation

Adapters return only bounded structural observations: kind, independently
allowed rule ID, source location, package coordinate or exact staging route.
Vendor descriptions, match text, source snippets, commands, request/response
bytes, cookies and authorization values do not enter canonical evidence.
Fingerprinting uses those structural fields, never a secret value. Original
report/config hashes identify artifacts and are not observation identifiers.
Keep the original sensitive report in the operator-controlled location.

Coverage and unresolved records accompany results. A zero-result report is not
a security clearance. Source, dependency, secret and staging observations all
remain `needs_validation`, without severity, impact or an automatic remediation
claim. Stable finding identities bind the engagement, selected input and
structural observation; every separately admitted import retains its provenance.
Report and database freshness are rechecked throughout admission and after acquiring
the database write lock, before evidence is durably accepted.

The adversarial regression suite covers source/report/config tampering, replay,
duplicate observations, stale/unsupported schemas, forged provenance, signed CI
binding, stop, bounded JSON, canonical reporting and sensitive-output canaries.
These synthetic parser checks do not measure a third-party detector's accuracy.
