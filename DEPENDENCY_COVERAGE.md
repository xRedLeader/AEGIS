# Offline dependency inventory

The native inventory recursively reads the exact repository directory approved by
the signed engagement. An operator can authorize an application subdirectory as
that repository root. Discovery never follows links, manifest includes, local
replacement paths or project instructions. It never runs restoration, builds,
package managers, scripts or network requests.

| Format | Recorded evidence | Explicit limits |
| --- | --- | --- |
| Nested `requirements.txt` | Exact `name==version` declarations | Extras, markers, includes, URLs and ranges remain unresolved. |
| Nested `package-lock.json`, versions 2/3 | Locked `packages` entries | Workspace/project records, links, nonregistry source URLs and unresolved versions remain unresolved. |
| Nested `packages.lock.json`, version 1 | NuGet Direct/Transitive resolved entries, separately for every target framework | Project dependencies and missing resolutions remain unresolved; no restore is performed. |
| Nested `pom.xml`, UTF-8 with no DTD/entities | Literal direct Maven dependency declarations | Properties, ranges, managed versions, profiles, parents and the effective/transitive graph are unresolved. |
| Nested `go.mod` | Unquoted `require` declarations with literal Go versions | Replacements/exclusions are unresolved; no selected build graph is inferred. |
| `go.sum` | Coverage gap only | Checksums do not establish installed or selected dependency inventory. |

Other recognized manifest formats, including Gradle, C# project files, Python
project metadata and additional lockfile formats, produce coverage gaps. Excluded
directories (`.git`, `.hg`, `node_modules`, `vendor`, virtual environments,
`__pycache__`, `bin`, `obj`) also appear as gaps. A repository with no supported
manifest reports that explicitly. Ordinary source files are not dependency
manifests and are not read by this worker.

The contract retains the legacy status, packages and summary fields and adds
`schema_version: 2`, `manifests`, `manifest_set_sha256`, `unresolved`, and `coverage`.
Each resolved or unresolved coordinate retains its ecosystem/name, source path,
manifest SHA-256, declared/locked evidence kind, and a deterministic position in
the manifest. The position distinguishes duplicate frameworks, nested npm package
locations and repeated declarations without copying arbitrary manifest text.
Raw URLs, markers and source expressions are redacted. These records do not claim
installed inventory or an atomic repository snapshot.

Traversal is lexical and deterministic. Limits are depth 8, 1,000 filesystem
entries, 64 supported manifests, 4 MiB total charged manifest bytes, 512 KiB per
text manifest (4 MiB per JSON lock), 150 combined resolved/unresolved coordinates,
and 32 KiB serialized evidence. A larger directory is rejected before choosing an
arbitrary partial subset. Exceeded limits explicitly mark remaining entries as
unknown. Malformed manifests discard their partial coordinates; unreadable or
changing files produce gaps. A linked or special-file supported manifest denies
the worker entirely. All reads use descriptor-relative nofollow opens and check
regular-file identity before and after reading.

Signed OSV snapshot correlation accepts the original inventory and this version.
It validates manifest/digest bindings and preserves every matched origin, including
conflicting versions across applications. Matching remains exact enumerated
versions only; snapshot freshness and unresolved advisory ranges remain enforced
by the existing signed admission path. Zero matches never establish safety.

The synthetic corpus in `tests/fixtures/dependency-corpus.json` has positive pins
and safe controls in all five ecosystems, conflicting Python versions, duplicate
NuGet framework origins, unsupported formats and unresolved declarations. The
dedicated tests exercise bounds, malformed data, XML entities, symlinks, hardlinks,
special files, out-of-scope includes, digest tampering and no-match controls.

Format references: [NuGet PackageReference and lock files](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files),
[Maven POM](https://maven.apache.org/pom.html), and
[Go modules](https://go.dev/ref/mod).
