# Semgrep, CodeQL and Gitleaks import-only evidence

The source adapters accept the exact versions and formats below through
`aegis_scanner_import.py`. They do not run a scanner, compile a project, restore
dependencies, follow code actions or use a detected credential. Every observation
remains an unverified lead. Agreement between scanners is not independent proof.

| Detector | Pinned version | Admission `report_schema` | Actual captured regression coverage |
|---|---|---|---|
| Semgrep | 1.125.0 | `semgrep-json-v1` | C# `Process.Start`; JavaScript/TypeScript `eval`; positive and safe controls |
| CodeQL CLI | 2.23.8 | `sarif-2.1.0` | C# process-launch and JavaScript/TypeScript evaluation queries; positive and safe controls |
| Gitleaks | 8.24.3 | `gitleaks-json-v8` | Synthetic credential rule; raw/redacted current-source, safe control and two-commit history |

These are narrow fixture rules, **not production detector coverage claims**.
Java, Go, infrastructure and arbitrary additional rules have not been validated
for these adapters. Runtime evidence states that limitation. Structural report
admission does not certify a scanner's language coverage, accuracy, complete
extraction or complete target traversal. Semgrep skipped paths/rules and errors,
and CodeQL unsuccessful invocations/warnings/errors, remain unresolved counts.
An empty report never establishes a clean assessment.

## Authentic fixtures and reproduction

`tests/fixtures/source_scanners/capture.json` records exact commands, tool pins,
download digests, source/config/query/dependency-lock hashes and unmodified export
hashes. The files in `reports/` were exported by those actual tools on Ubuntu 24.04
over the adjacent synthetic `source/` and `safe-source/` files. Tests mutate copies
in memory for adversarial cases; those mutations are not presented as vendor
exports. No real credentials or application data appear in the fixtures.
`codeql-config-manifest.json` additionally binds every custom query/lock file and
the exact downloaded library file-tree digests used for these captures.

Semgrep's Python dependencies are recorded in `semgrep-requirements.lock.txt`;
its legacy dependency requires the included setuptools 80.9.0 pin. CodeQL uses
`codeql/javascript-all` 2.6.18 and `codeql/csharp-all` 5.4.3 with the captured
transitive `codeql-pack.lock.yml` files. The custom QL files intentionally identify
simple call sites and make no taint/reachability claim. JavaScript and TypeScript
fixture filenames differ: CodeQL can treat a same-basename JavaScript file next
to TypeScript as generated output, which must not be mistaken for tested coverage.

The CodeQL archive digest was checked against the official release asset digest;
Gitleaks was checked against its official release checksums. Their source releases
are [CodeQL 2.23.8](https://github.com/github/codeql-cli-binaries/releases/tag/v2.23.8),
[Semgrep 1.125.0](https://github.com/semgrep/semgrep/releases/tag/v1.125.0), and
[Gitleaks 8.24.3](https://github.com/gitleaks/gitleaks/releases/tag/v8.24.3).
CodeQL query library pins come from the matching
[JavaScript](https://github.com/github/codeql/blob/codeql-cli/v2.23.8/javascript/ql/lib/qlpack.yml)
and [C#](https://github.com/github/codeql/blob/codeql-cli/v2.23.8/csharp/ql/lib/qlpack.yml)
release definitions.

## Export and admission

Run export commands only under a separately authorized execution profile or in
an independently controlled CI environment. These examples show report formats;
the import command does not authorize their execution. CodeQL extraction may
invoke toolchain helpers even with `--build-mode=none`; real project extraction,
builds and dependency restoration need their own approved execution controls.

```sh
semgrep scan --config /protected/approved-rules.yaml --metrics=off \
  --disable-version-check --no-rewrite-rule-ids --no-git-ignore \
  --json --output /protected/semgrep.json src/approved.ts

codeql database analyze /protected/approved-database /protected/pinned-query-pack \
  --format=sarifv2.1.0 --output=/protected/codeql.sarif

cd /approved/source
gitleaks dir --config /protected/approved-gitleaks.toml --redact=100 \
  --report-format=json --report-path=/protected/gitleaks.json .
```

Use the common `scanner-admission-policy.example.json` and CLI documented in
`SCANNER_ADMISSION.md`. Select the detector triple above, exact allowed rule IDs,
raw report SHA-256, protected configuration SHA-256 and exact source-file hashes.
For CodeQL, pin a configuration manifest covering the query sources, `qlpack.yml`
and dependency lock; a rule ID alone does not bind its implementation. Have the
CI producer sign the existing shared attestation when using `verified_ci` mode.
Otherwise label the evidence `operator_attested_external`; it does not prove
which binary actually ran. Gitleaks JSON has no embedded scanner version, so the
protected operator/CI provenance is essential to its release pin.

```sh
python aegis_scanner_import.py --manifest /protected/scope.yaml \
  --signature /protected/scope.yaml.sig --policy /protected/admission.json \
  --report /protected/scanner-export.json
```

Source locations must name approved relative paths with valid bounded line and
column ranges. Absolute, external, traversing, encoded/ambiguous paths, inconsistent
SARIF indices, unapproved rules and changed source are rejected. SARIF locations
use the selected snapshot as `%SRCROOT%`; diagnostic prose and source-root URLs
never create filesystem or network authority. An export containing over 64
observations or a source range longer than 80 lines is rejected, not
silently truncated. Reports must fit the shared 512-KiB input bound.

## Secret handling and historical scope

Gitleaks admission retains only the selected rule, approved path, source range
and, for history, exact revision. It drops `Secret`, `Match`, snippets,
`Description`, `Fingerprint`, author/email/message fields, tags and arbitrary
nested vendor fields. Canonical finding identity comes from location/rule/scope,
not a hash of the secret. Required source/report integrity digests remain in
provenance; they do not authorize copying raw evidence into ordinary reports.
Unredacted detected values are checked against their exact selected source range
and cannot appear in retained identity fields. `--redact=100` is useful, but the
importer still strips all sensitive vendor fields instead of trusting that flag.

Keep original reports, if retained, in the protected operator evidence area with
restricted access and the original digest in a separate custody record. They
are not copied into canonical report bundles, model-facing evidence, notices or
routine logs. The tests check synthetic canary absence in retained evidence,
generated reports, queued notice artifacts and the failure ledger. There is no
live credential testing, revocation, rotation or assertion that a suspected
secret is usable.

`input.kind: source` requires an empty Gitleaks `Commit`. A Git-history export
requires `input.kind: history` and **explicit** source snapshots for 1–8 exact
40-hex revisions:

```json
{
  "kind": "history",
  "repository": "/approved/repository",
  "revisions": {
    "43de70119caa6487d3648782a3daf9dc6279c79b": {
      "secrets-positive.txt": "REPLACE_WITH_EXACT_APPROVED_BLOB_SHA256"
    }
  }
}
```

Select the exact report commit set in protected policy and bound the export depth;
for example `gitleaks git --log-opts='-n 2 <approved-tip>' ...` on the synthetic
two-commit fixture. The full `Commit` from every finding must be selected.
Admission reads exact Git blobs through the shared bounded history reader, without
checkout, hooks, filters or network access. Current working-tree bytes never stand
in for an old revision. The synthetic Git bundle reproduces the captured commit
identities without access to another repository's history.
