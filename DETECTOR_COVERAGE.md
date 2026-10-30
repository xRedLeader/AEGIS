# Measured deterministic detector coverage

`aegis_worker.py` engine `aegis-regex`, version `2`, runs six fixed, line-oriented
regular expressions. It does not parse an AST, trace data flow, resolve imports,
evaluate configuration, establish reachability, or execute repository code.
The ruleset fingerprint hashes the exact rule IDs, labels, regexes/flags and
extension assignments. Worker execution still requires the existing signed
source-review scope and Linux namespace/seccomp boundary.

## Capability matrix

| Source | Fixed detector rules | Prerequisites and limits |
|---|---|---|
| Python (`.py`) | Four `PY-*` rules below | Readable UTF-8, bounded source and a canonical-report-compatible path; extension matching is case insensitive. |
| JavaScript/TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`) | `JS-TLS-NOVERIFY`, `JS-EVAL` | Same bounds; JSX/TypeScript syntax is not parsed or type checked. |
| C#/.NET (`.cs`) | Unsupported | No C# rules or semantic engine in this worker. |
| Java (`.java`) | Unsupported | No Java rules or semantic engine in this worker. |
| Go (`.go`) | Unsupported | No Go rules or semantic engine in this worker. |
| Infrastructure/configuration (`.yaml`, `.yml`, `.json`, Terraform and other formats) | Unsupported | These are recorded as unsupported; configuration text is not treated as assessed source. |
| C/C++ and other extensions | Unsupported | Previously accepted extensions did not create vulnerability-class coverage. |
| v2.1 source-agent research | A separate, configured analysis mode | Signed assignments, approved source and independent role replies; it has no measured language/rule guarantee from this regex corpus. |

The matrix describes this engine only. Offline importers can admit separately
produced results from their tested tool/schema versions. Importing such a result
does not prove that AEGIS executed the tool or assessed another language itself.

| Rule | Textual condition | Principal limitations |
|---|---|---|
| `PY-SHELL-TRUE` | `shell = True` | Matches unrelated arguments, comments and strings; misses values supplied through variables or other spellings. |
| `PY-PICKLE-LOAD` | `pickle.load(` / `pickle.loads(` | Does not establish input trust; misses imported aliases and indirect calls. |
| `PY-EVAL` | Bare `eval(` | Does not establish untrusted input; misses aliases, attribute-based and indirect invocation. |
| `PY-TLS-NOVERIFY` | `verify = False` | Does not identify the actual library or transport; misses flags passed indirectly. |
| `JS-TLS-NOVERIFY` | `rejectUnauthorized: false` | Does not resolve object use; misses indirect values and quoted/computed property spellings. |
| `JS-EVAL` | Bare `eval(` | Does not establish input trust; misses callable aliases and indirect invocation. |

All matches remain `unverified_static_lead`. Even a syntactically dangerous
pattern may be unreachable, use trusted input, or appear only in documentation.
None of these observations creates a confirmed severity or a remediation verdict.

## Reproducible corpus

`tests/fixtures/detector-corpus.json` contains synthetic source text, expected
rule IDs, expected assessment states and explanations. Tests write each case to
an isolated temporary directory and read it as data; fixture code is never
imported or executed. A “safe control” is safe only relative to the specific
tested signature, not a certificate about the application's security.

Run on Linux with the existing test environment:

```sh
PYTHONPATH=tests python -m unittest test_detector_coverage -v
```

The test prints the observed fixture denominators into the CI log. The checked
baseline is:

| Category | Fixtures | With regex leads | Without regex leads |
|---|---:|---:|---:|
| Synthetic vulnerable spellings | 9 | 9 | 0 |
| Corresponding safe controls | 9 | 0 | 9 |
| Known false positives (comments) | 6 | 6 | 0 |
| Known false negatives (aliases/indirect flags) | 6 | 0 | 6 |
| Unsupported source/configuration languages | 6 | 0 | 6 |

These 36 examples are regression observations, not detection-rate estimates.
All six rules have a positive, control, documented false positive and documented
false negative. The additional positive/control pairs exercise JSX, TypeScript
and TSX explicitly. The suite also checks unstable/unreadable sources, hardlinks,
symlinks, special files, prefix truncation, encoding boundaries, candidate caps,
and the total evidence-byte budget.

New detector integrations must contribute versioned report fixtures and their
source/artifact identities, positive and safe-control cases, malformed and
out-of-scope cases, documented known misses/false positives, and the actual
fixture denominator. Parser tests validate admission, not the detector's accuracy.
Claims about a tool detecting a fixture additionally require recorded output
from that exact tool/ruleset/database/configuration and execution mode. CI must
not require paid provider calls, live targets or committed secrets.

## Coverage evidence contract

The legacy top-level status, `summary` and `candidates` remain compatible. The
new `coverage` object has `schema_version: 1` and contains:

- `engine`: detector name, version and `ruleset_sha256`; `rules`: every rule and
  its applicable extensions/family, independent of the number of matching files.
- `files`: bounded per-path records with one of `assessed`, `unsupported`,
  `excluded`, `unreadable`, or `partial`, plus an explicit reason. Assessed and
  partially read files identify their applicable rule IDs and actual read bytes.
- `content_sha256` with `hash_scope: full_file` or `prefix`. Full-file hashes
  require stable descriptor/path identity and metadata before/after the read.
  Partial prefixes never masquerade as whole-file identity. Unsupported files
  are not opened and have no content hash.
- `source_identity`: a SHA-256 digest of the canonical, recorded observation
  list, labelled `recorded_observation_manifest`, with
  `complete_repository: false`. This is not a Git commit, an atomic repository
  snapshot, or a hash of unread/unrecorded content.
- `counts`, `limits`, `limits_hit`, `unrecorded_entries`, and
  `remaining_entries_unknown`: separately report assessed files, unsupported
  inputs, exclusions, read failures, partial analysis and traversal/output limits.

Every record includes a hash of the original relative path. Display paths longer
than 180 characters are explicitly marked truncated. Paths that cannot be
represented by the existing canonical finding contract are excluded, rather than
emitting a lead that cannot be admitted. Paths in raw evidence are inert data.

The standard worker invocation retains its 1,000 supported-file-open-attempt and
4 MiB read budgets, a 128 KiB/file prefix limit, at most 64 candidates, and a
32 KiB evidence limit. Actual bytes read are charged even if a source changes
before its final integrity check. If evidence space runs out, an omitted record
is counted and the traversal becomes incomplete; findings/coverage are never
silently discarded into a “clean” result.

`assessment_status` distinguishes `unverified_leads`,
`no_leads_in_assessed_files`, `incomplete`, `unsupported_analysis`, and
`no_supported_source_files`. Exclusions, unsupported files mixed with assessed
files, unreadable/unstable inputs, partial prefixes and resource limits make the
overall result incomplete. Ordinary repositories containing excluded directories
or unsupported documentation/configuration therefore often have incomplete
coverage. The detailed records explain that outcome. Zero candidates never
establishes a clean bill of security.

Canonical report views must display the engine/ruleset/source identity, assessed
rule families and these coverage limitations. Historical source artifacts without
the new block remain legacy evidence with unmeasured coverage, not retroactively
upgraded assessments.
