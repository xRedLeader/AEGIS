# Package and staging report imports

These adapters parse existing reports through the protected scanner admission
contract. Import never pulls an image, starts a container, installs a package,
updates a database, invokes a scanner, opens a Docker socket, runs a template,
spiders a site, or makes a target request. Their outputs are unverified leads;
the existing independently signed staging-proof process remains authoritative.

| Detector | Pinned release/exporter | Accepted report schema |
| --- | --- | --- |
| Trivy | `0.58.2` | `trivy-json-v2` |
| Grype | `0.85.0` | `grype-json-v0.85` |
| Nuclei | `3.3.8` | `nuclei-json-export-v3.3.8`, JSON array from `-json-export` |
| ZAP | `reports-0.35.0` report-generation add-on | `traditional-json` |

These are tested compatibility pins, not a claim that they are current releases.
ZAP's pin identifies its report-generation add-on and template, not the ZAP core
scanner. ZAP core build identity is part of the independently admitted producer
configuration; the format's arbitrary core-version field does not establish it.
The upstream ZAP exporter fixture says `Dev Build`, and the upstream Grype
presenter fixture says `[not provided]`. Those omissions stay explicit rather
than being replaced with invented execution evidence.

## Package provenance

Protected admission selects exact source file hashes, a CycloneDX 1.5/1.6 or
SPDX 2.3 SBOM hash, or an OCI/Docker descriptor with an immutable image digest.
The image selector explicitly chooses a `manifest` or `config` digest, and the
descriptor media type must agree. Trivy's `ImageID` is a configuration digest;
it is never silently treated as a registry manifest digest. Manifest imports
require a matching Trivy `RepoDigests` value or Grype `manifestDigest`.

Source findings must refer to selected files. SBOM findings must match typed
package URLs in the separately admitted SBOM, including ecosystem, name and
version. Equal names in unrelated ecosystems do not match. Unsupported or absent
typed identity cannot establish presence. SBOM inventory belongs to its own
generator; accepting a Trivy/Grype match does not make that matcher the inventory
generator or establish image contents.

Native OS packages use `os/...` ecosystem labels, distinct from application
packages. Supported application types cover npm, Python, NuGet, Maven/JAR, and
Go formats exposed by these selected report schemas. Unknown types and unresolved
versions increase the unresolved count. Ignored Grype matches and nonvulnerability
Trivy sections also remain coverage gaps. An empty result does not establish
complete coverage or safety.

Every package import requires an independently selected vulnerability database
SHA-256, build time and maximum age, plus the selected scanner/configuration,
report digest, observation time, and provenance mode. Embedded database/build
metadata must agree when available. Trivy JSON omits scanner/database checksums;
Grype's presenter may omit them. These cases remain explicit operator-attested
provenance, not proof that AEGIS ran the scanner or verified the remote database.

## Staging provenance

Protected admission selects an origin already in the signed engagement, exact
query-free routes, a deployment digest, and the scan start/finish times. The
whole interval must fall within the signed engagement. The finish time equals
the policy observation time. Nuclei event times must fall within that interval;
timezone offsets are normalized. ZAP's traditional timezone-free generation
time cannot independently prove its scan interval, which remains externally
attested. A zoned `created` timestamp, if supplied, must fall within the interval.

Nuclei import supports HTTP matched results from one selected template. Its
protected configuration hash identifies that YAML template; when the export
contains `template-encoded`, the decoded template must match the hash. The
template bytes are never executed or retained in ordinary evidence. DNS,
headless and other result kinds are not admitted by this adapter.

ZAP site authority and each alert instance must match the admitted origin and
routes. Nuclei's matched location must match those routes. Credentials in URL
authorities and ambiguous encoded/traversal paths are rejected. Query data,
request/response bodies, authorization and cookie headers, template content,
extractor results, descriptions, severity claims and shell commands are omitted
from ordinary evidence. Only selected rule/template IDs and safe locations are
normalized. Duplicate records collapse deterministically and do not become
independent corroboration.

## Evidence and limitations

`tests/fixtures/scanner-exports/provenance.json` records exact input hashes and
source commits. Trivy, Grype and ZAP fixtures are genuine upstream exported
golden outputs from their pinned exporter implementations; they are not claimed
as locally executed scanner or deployment acceptance evidence. Nuclei positive
and control reports were captured locally with the checksum-verified 3.3.8
binary, a harmless synthetic marker template, an unprivileged account and a
fresh network namespace exposing only loopback. No real application or public
host was assessed to create these fixtures.

The tests cover the original exports, explicitly derived negative controls,
duplicate observations, unsupported packages, database freshness, changed image
and SBOM identities, wrong targets, altered templates, redaction, bounded JSON,
and complete protected admission into canonical unverified reports.

Import support does not by itself enable live execution. Governed offline
scanner execution and staging DAST execution are separate capabilities with
their own authorization, isolation, resource and recovery acceptance gates.
