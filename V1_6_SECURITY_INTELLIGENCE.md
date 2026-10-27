# AEGIS v1.6 development — security tool adapters and vulnerability intelligence

**Stacked development branch; not a release.** v1.6 is based on the open v1.5 PR, not on the earlier v1.4.1 `main`. v1.5 must be reviewed/merged before v1.6 can be merged independently. No existing secrets, live assessments or external hosts are used in the tests.

## First working increment

1. `dependencies` runs a **fixed, stdlib-only dependency inventory worker inside the same rootless Linux user/mount/network/PID namespace, no-network seccomp profile, and read-only repository mount** used for source review. Supported root files: exact pinned Python `requirements.txt` and npm v2/v3 `package-lock.json`. No package manager is invoked, no target code is imported, and no network socket can be opened. URLs, free-form text, tokens and package-install commands are never included in the inventory. Unpinned/conditional dependencies and unsupported formats are counted as unresolved. Maximum 150 coordinates. Inventory does not prove installation.
2. `intel-assess` verifies operator-signed OSV snapshot bytes **before parsing**, checks source identity and a maximum age of 72 hours, inventories the authorized repository inside the offline sandbox, correlates only advisory `affected[].versions` **exactly**, and writes a second sanitized artifact in the same protected run directory. Range-only matches are counted as *unresolved*, not marked safe or converted into positive findings. Audit records include the signed snapshot SHA-256 and lead count; requests consume existing signed `dependency_analysis` runtime and evidence limits.
3. `aegis_security_tool_adapters.py` provides **non-executing JSON importers** for `pip-audit` and npm audit v2 output. No scanner process is launched, no untrusted descriptions/remediation/URLs are copied, and all imported items remain explicitly **unverified leads**. npm output is not assigned an invented installed version.

## Authorization boundary

The operator must approve `dependency_analysis` in **both** the signed scope and independent trust policy. The repository path must be explicitly authorized. The intelligence snapshot is signed under a distinct Ed25519 context, using the independently pinned operator public key from the protected trust policy, with a separately stored `.sig` and a bounded, fixed-source, fail-closed JSON loader. The signature is an **operator attestation of admitted source bytes**, not cryptographic proof that OSV provided the data or that OSV covers all packages or vulnerabilities.

The operator retrieves and reviews a bounded OSV snapshot **out of band** from `https://api.osv.dev`. AEGIS v1.6 does not yet include automated feed fetching or background updates. The operator populates `retrieved_at_utc` from its verified fetch, builds a JSON object of the form below, then signs it using `aegis_intel_admin.py`. Do not infer `retrieved_at_utc` from an advisory's publication or modified date.

```json
{
  "format": "AEGIS-OSV-v1",
  "source": "OSV",
  "source_url": "https://api.osv.dev",
  "retrieved_at_utc": "2026-10-27T12:00:00Z",
  "records": [
    {"id": "GHSA-EXAMPLE-0001", "affected": [{"package": {"ecosystem": "PyPI", "name": "example-package"}, "versions": ["1.2.3"]}]}
  ]
}
```

The example is **illustrative only**; it is not a real advisory, a claim of a vulnerability, or a current database snapshot. An empty collection is rejected; the maximum raw signed snapshot size is 1 MiB and the maximum advisory count is 250. Unsupported larger feeds or range-only data require another reviewed workflow. Never invent a negative vulnerability assessment based on this subset.

An authorized service operator can run:

```bash
# Offline, requires privately-held operator key; the key is never an agent tool.
python aegis_intel_admin.py sign --bundle /etc/aegis/intel/osv.json --operator-key /etc/aegis/keys/operator.key --signature /etc/aegis/intel/osv.json.sig

# Non-root AEGIS operator service, with signed engagement & trusted policy:
AEGIS_STATE_ROOT=/var/lib/aegis AEGIS_TRUST_POLICY=/etc/aegis/trust.json \
  python aegis_supervisor.py --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.sig \
  intel-assess --repo /work/approved-repository --snapshot /etc/aegis/intel/osv.json \
  --snapshot-signature /etc/aegis/intel/osv.json.sig --seconds 15
```

Do not expose `intel-assess` or the snapshot signer to an AI agent as an unrestricted shell command. They are operator-control-plane operations. The current operator Unix service does **not** grant these new commands to models.

## Known v1.6 gaps and release gate

- No live vendor advisory ingestion, KEV enrichment, semantic-version range interpretation, SBOM reconciliation, or recurring updates. An empty/missing/stale snapshot is a failed assessment input, not proof of security.
- `pip-audit` and npm audit imports are **parsers only**. Reviewed scanner binary execution inside a dedicated, constrained adapter is a later v1.6 increment.
- Source manifests and scanner reports are untrusted; package version declarations are not runtime reachability or verified exploitability.
- Supported OS acceptance still requires kernel-isolation probes and full inherited GitHub CI on Ubuntu 22.04 and 24.04. A local tool test does not constitute a production deployment security review.
- PR remains draft until tool adapters, reproducible freshness verification, complete range coverage policy, full CI, and independent review meet the intended v1.6 definition of done.

References: [OSV schema and version semantics](https://ossf.github.io/osv-schema/); [OSV service](https://osv.dev/).
