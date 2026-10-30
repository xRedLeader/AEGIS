# Governed offline scanner execution

The operator selects a compiled profile, exact executable/rules/input hashes and
a fresh operation ID. The signed engagement still authorizes the method and
reserves cumulative runtime/evidence before launch. Scanner output becomes
canonical **unverified** evidence; neither execution nor a model conclusion
confirms a vulnerability.

| Profile | Actual supported input | Deliberate boundaries |
| --- | --- | --- |
| `gitleaks-dir-v8.24.3` | Current UTF-8 source files explicitly selected by hash | Explicit bounded TOML rules; no Git-history walk, includes, downloads or repository config discovery |
| `semgrep-core-v1.125.0` | Selected C#, JavaScript, TypeScript, JSX and TSX files | Static core and bounded JSON pattern rules; no Python CLI, subprocesses, registry rules, dynamic validators or build |
| `trivy-sbom-v0.76.1` | Selected CycloneDX 1.5/1.6 or SPDX 2.3 SBOM and explicit advisory IDs | Independently prepared schema-2 vulnerability database; no source extraction, image pull, container daemon, Java DB update or feed download |

These profiles support Linux x86-64 on the tested Ubuntu 22.04/24.04 namespace
backend. Other scanner versions, arbitrary commands/flags, CodeQL extraction,
Grype execution, container execution and target builds are rejected. Existing
versioned external-report imports remain available, including Trivy 0.58.2.
The 0.58.2 source tag remains available, but its official binary release/archive
was unavailable during implementation; the new execution profile independently
pins released 0.76.1 instead.

## Prepare authority and inputs

`scanner-execution-policy.example.json` is disabled. A production ruleset must
be selected independently: the repository's synthetic canary rules demonstrate
the transport and are not a production secrets assessment. Policies/configuration
must be private protected files outside the repository, runtime state and reports.
Serialize the selected policy with the project's canonical JSON function before
use. The bounded adapter validates the configuration itself, not just its hash.
The operator never supplies a command line.

The source input consists of an absolute signed-scope repository and at most 128
explicit relative file/SHA-256 entries. Files are read without following symlinks,
verified, copied into a separate private snapshot, and checked again after the
scan. Only that snapshot enters the scanner. Unselected files, Git metadata,
operator state, signing keys, provider credentials and host sockets stay outside.

For Semgrep, select `semgrep-core-v1.125.0`, executable SHA-256
`313bf3bbb50648fb5c3f43bd1d72dfee28dae436e10a096acb7d9a5839d18f11`, and
the bounded rules supported by `aegis_semgrep_sandbox.validate_rules`. Its static
engine needs a nonempty CA store during startup even offline; the launcher
provides an embedded synthetic public certificate whose private key was discarded.
It does not expose the host trust store or permit networking/process creation.

The canonical JSON configuration contains only `rules`, with 1–64 rules whose
exact fields are `id`, `languages`, `message`, `severity` and `pattern`. Languages
are limited to `javascript`, `typescript` and `csharp`; rule IDs must equal the
policy's `allowed_rule_ids`. The acceptance fixtures' two synthetic patterns
prove the supported language transport, not production detection quality.

For Trivy, select `trivy-sbom-v0.76.1`, executable SHA-256
`d1dfca6ae10a1ad4540bb94e64f0510077c47008920a9b554986b39dca573d83`, and
configuration bytes exactly `{}`. All Trivy flags are compiled into the profile:
vulnerability scanning, memory cache, disabled telemetry/version/VEX/Java/feed
updates, disabled ignore-file discovery, and offline operation. The input has
the existing scanner-admission SBOM fields: `kind`, `artifact_path`,
`artifact_sha256`, `format`, and `image_digest: null`.

Trivy's `allowed_rule_ids` explicitly selects up to 64 CVE/advisory IDs. There is
no wildcard. A newly reported ID outside that selection fails admission and
requires operator review, a revised policy and a fresh operation/budget. This
profile assesses selected advisories; it does not provide comprehensive
unknown-vulnerability discovery or justify a blanket clean verdict.

The additional Trivy `database` selection has `path`, `files`, `built_at_utc`
and `max_age_seconds`. `files` maps exactly `trivy.db` and `metadata.json` to their
SHA-256 values. The directory, its parents and both regular single-link files
must be root-owned and protected against group/other writes. The DB is bounded
to 2 GiB; metadata to 4 KiB. The build time must match schema-2 metadata's UTC
`UpdatedAt`, truncated to seconds, and satisfy the selected freshness window.
Both hashes are checked before and after execution; their canonical map's hash
becomes the admitted database identity. The native scanner receives a read-only
DB mount. No database preparation occurs during execution.

An operator may explicitly prepare/update a DB in a separate environment using
the verified Trivy release's `image --download-db-only` operation, then review
its repository, build timestamp, file identities and protected custody before
selecting it. This preparation needs network access and its own disk/time budget.
Current databases can exceed 1 GiB: retain one reviewed immutable copy and account
for temporary download space before preparing another. The disposable CI helper
`tests/prepare_scanner_execution_ci.py` demonstrates this separation and refuses
to run outside GitHub Actions; it is not a production installer.

## Execute and recover

```sh
python aegis_scanner_execution.py \
  --manifest /etc/aegis/operator/scope.yaml \
  --signature /etc/aegis/operator/scope.sig \
  --trust /etc/aegis/operator/trust.json \
  --state-root /var/lib/aegis-controller \
  --execution-policy /etc/aegis/operator/scanner-execution.json
```

Run as the non-root trusted controller identity inside the intended protected
service environment. The integrated `scanner_execute` action further binds
current-source profiles to the assessment repository and its per-step duration.
The delegated agent can propose only the already approved next step.

The launcher enters new user, mount, network and PID namespaces; copies sealed
executable/rules bytes into a private RAM filesystem; freezes the root; drops all
capabilities; sets no-new-privileges; and loads a separate positive native syscall
profile. No `/usr`, `/proc`, host root, model credentials or container socket is
mounted. Source/artifacts are read-only, scratch is 8 MiB and non-executable.
Trivy's SBOM-only profile needs no writable files, so its scratch is read-only
as well; there is no mutable file whose shared mapping could be upgraded later.
Threads are allowed; new processes and sockets are denied. Trivy additionally
allows only read-only shared file mappings for BoltDB; anonymous/shared writable
mapping alternatives remain denied.

Native limits include bounded CPU, wall time, 64 file descriptors, 64 processes
and threads per real UID (32 for Semgrep), no core dumps, 512 KiB output, 32 KiB diagnostic output,
and 512 MiB writable data. Go/Wasm profiles reserve up to 8 GiB virtual address
space without committing it; memory probes verify that later commits cannot
bypass the writable-data limit. Semgrep has its separately reviewed smaller
virtual-address limit. The supervisor drains output incrementally, checks stop,
revocation and expiry during execution, and kills the process group on failure.
Parent-death signals also terminate native descendants when the supervisor crashes.

The native profiles use up to 256 MiB of separate read-only RAM for executable
and rules, in addition to their writable scratch and data limits.

Large binaries, the supervisor's immutable snapshots and scanner heaps share the
service's cgroup. Set the reviewed deployment configuration's `memory_max_mb`
to **1024** for these native profiles; keep `tasks_max: 96` and
`cpu_quota_percent: 100` unless separately reviewed. Re-render/reinstall stopped
units using that configuration and repeat host acceptance. This is an explicit
operator configuration change; the ordinary package's 512 MiB default is not
silently increased. The native CI job verifies actual `memory.max`, `pids.max`
and `cpu.max` inside a 1024 MiB systemd test unit and retains its memory peak when
the kernel exposes that metric. The native hard limits stay in force as well.

Every operation ID is single use, including failed and uncertain operations.
Reservations, launch, exit/resource metadata, partial-output digest and completion
are durable. A timeout, stop, revocation, output flood or crash must be reconciled;
restarting the process never silently reruns the operation. Inspect the retained
ledger and determine whether the original run completed. A completed execution
whose import was interrupted can be admitted through
`import_governed_report(execution_run_id)`; an incomplete execution cannot.
A genuinely new approved scan needs a new policy/operation ID and a new budget
reservation. Budgets are never silently refunded.

Vendor bytes remain in bounded memory and are discarded. Persisted handoff files
contain only structural observations, coverage, the safe approved rules, exact
input/tool/database identities and the original-output digest. They omit vendor
snippets, matches, secrets, author/email/message fields and model instructions.
An audited `scanner_execution_completed` event binds all three artifacts and the
admission attestation. The importer reads these through a dedicated internal
receipt path; generic protected-file admission rules are unchanged.

## Evidence

`governed-execution.yml` checks the exact PR head on Ubuntu 22.04/24.04, verifies
source integrity, prepares independently pinned tool binaries/DB, and executes
actual positive and safe-control fixtures plus native escape/resource/recovery
probes. The Semgrep bootstrap also has its own hostile probe, covering its
separate root setup, closed descriptors, non-executable scratch and memory limit.
Trivy has its own hostile probe for the separate root and database mounts,
including attempts to turn permitted read-only shared mappings into writable ones.
Staging execution has a separate explicit test step and network profile.
No scanner job targets the user's deployed application. These artifacts establish
engineering behavior for that commit; they do not replace the intended host's
acceptance, authorized application pilot, independent review, off-host retention
or release-owner decision.
