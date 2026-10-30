# Restricted staging DAST boundary design

Status: implementation boundary reviewed during development; proceed with the
restricted profile below. This is not independent release or host acceptance. The
existing metadata gateway and offline scanner profiles are unchanged by this
design. Restricted implementation and measured synthetic acceptance are recorded
below. Intended-host acceptance and the real application pilot remain separate.

## Supported authority and features

The initial profile is `nuclei-passive-http-v3.3.8`: exactly Nuclei 3.3.8, one
protected template, anonymous HTTP GET or HEAD, and a fixed body-word matcher.
The template may use only `{{BaseURL}}`; operator-selected targets are exact
origin/path pairs. No query strings, mutation, cookies, authentication, redirects,
HTTPS CONNECT tunnels, headless/browser mode, scripts/code, external callbacks,
remote templates, update traffic, arbitrary arguments or subprocesses are
supported. Unsupported features fail closed.

A separate canonical execution profile is signed with the independently pinned
operator key using a distinct staging-profile context. It binds the engagement,
scanner binary SHA-256, template SHA-256, deployment SHA-256, exact HTTP origin,
exact paths, literal approved destination addresses/networks, GET/HEAD methods,
anonymous test identity, explicit no-mutation declaration, start/expiry times,
and request/runtime/response ceilings. These are intersected with the active
signed engagement and independent operator route policy on every operation.
The ordinary report/model input supplies no execution authority.

GET/HEAD alone cannot prove a route is state-free. The operator must select
disposable staging routes whose semantics meet the no-mutation declaration.
Synthetic acceptance uses server-side logs and state checks, never a public or
real application target.

## Processes, descriptors and network boundary

1. The trusted operator service validates scope/profile/binary/template, records
   durable run/resource reservations, and starts a separate native boundary.
   It never passes an Internet socket, credential, source checkout, trust key,
   database file or general executable path to the scanner.
2. A distinct launcher creates private user, mount, PID and network namespaces.
   Its filesystem contains only the pinned static scanner, template, exact
   target list, bounded report output and small temporary storage. The only
   network interface is loopback. There is no default route or external DNS.
3. A fixed trusted loopback HTTP relay runs beside the scanner. It alone owns
   two framed-pipe capabilities to the operator service. The scanner process
   closes those descriptors before execution, drops capabilities, enables
   `no_new_privs`, and receives a default-deny syscall filter permitting required
   Go threads and loopback TCP but denying fork, new namespaces, ptrace and
   unrestricted process creation. The offline launcher is not relaxed.
4. Nuclei is configured to use that relay. CLI options are convenience controls;
   network namespaces and the trusted broker are the independent enforcement.
   Direct scanner networking can reach only its private loopback interface.
5. The relay accepts one bounded HTTP request per connection. It rejects CONNECT,
   request bodies, transfer encoding, credentials and non-GET/HEAD methods. It
   forwards only a structured method and absolute target URL over framed pipes;
   scanner-supplied headers never reach the target.
6. The operator broker revalidates signed scope/profile/time/stop/revocation,
   exact origin/path/method, independent route policy and destination address.
   It charges every attempt through `AegisHttpSupervisor._reserve_request`
   before DNS or connection, using the existing durable rate, request,
   concurrency, runtime and body-byte budgets. Requests are serial.
7. Resolution is performed by the trusted parent helper. Every resolved address
   must pass existing scope exclusions and the staging profile allowlist; the
   connection uses a chosen numeric address, never re-resolves the hostname.
   A fixed trusted fetch helper sends a canonical Host header and fixed harmless
   headers, with no credentials. Redirects and oversized/unsupported responses
   abort rather than following or silently truncating them.
8. Response bodies exist only transiently in bounded helper/pipe/scanner memory.
   Only a small response-header allowlist is relayed. Request/response contents,
   cookies and raw scanner logs are never ordinary evidence. Raw export/log
   identity is represented by hash and size; admitted structural observations
   pass through the existing Nuclei report normalizer as unverified leads.

## Lifetime and durable recovery

The parent watches scope, profile integrity, operator stop/revocation and wall
time while draining bounded pipes. Helper parent-death signals, pipe EOF,
namespace init lifetime, and bounded CPU/process/file/memory limits terminate
the entire scanner/relay tree when the supervisor disappears or cancels.

The run state distinguishes reserved, running, completed, aborted and interrupted
execution. Request reservations are durable before dispatch. Recovery marks
uncertain runs interrupted, retains consumed reservations, and never replays a
request automatically. Completion requires a successful boundary receipt,
bounded scanner exit, report normalization, unchanged protected inputs, and a
durable execution receipt matching the imported evidence. A new process cannot
claim success from an orphaned report file.

## Required acceptance evidence

- Real pinned Nuclei positive/control execution against disposable local
  services, with server logs proving allowed requests and unchanged state.
- Wrong origin, IP, path, method, credentials, redirect/re-resolution escape,
  request/rate exhaustion, unsupported template and direct-network denial.
- Operator stop, expiry and revocation during a request; process termination,
  crash recovery, uncertain-request accounting and no automatic replay.
- Canonical unverified evidence, template/binary/deployment identity, duplicate
  handling and absence of synthetic secret canaries from persisted artifacts.

The implementation review explicitly requires rejecting proxy authorization,
cookies, duplicate/ambiguous headers, bodies and pipelined trailing input, plus
continuous profile/signature checks and complete descendant termination.

## Operator setup and invocation

`examples/staging-execution-profile.json` deliberately contains expired dates,
placeholders and `configured: false`. It supplies no authority. The independently
pinned operator must choose a fresh operation UUID, actual deployment digest,
protected template bytes and exact disposable routes; activate and canonicalize
the completed JSON using `aegis_audit_contract.canonical`; and sign
`b"AEGIS-STAGING-EXECUTION-PROFILE-v1\x00" + canonical_profile_bytes` with the
operator Ed25519 private key. Store the detached 64-byte signature separately.
The application, model and scanner must never receive that private key. Profile,
signature and template must satisfy the existing protected-file custody checks.
The example literal template is in `examples/staging-passive-template.yaml`.

Invoke the existing trusted service identity, with protected module installation:

```sh
python -m aegis_staging_execution \
  --manifest /etc/aegis/scope.yaml --signature /etc/aegis/scope.sig \
  --trust /etc/aegis/trust.json --state-root /var/lib/aegis \
  --profile /etc/aegis/staging-profile.json \
  --profile-signature /etc/aegis/staging-profile.sig
```

The integrated `staging_dast` action also supplies a workflow runtime ceiling;
the signed profile must fit that ceiling before any reservation or launch.
`execute(..., max_seconds=None)` preserves the standalone profile ceiling.
Once durably reserved, each operation ID is single-use even after a failure. Recovery requires explicit
operator reconciliation and a newly signed operation; it never retries a saved
request. A per-state-directory exclusive lock prevents concurrent staging runs.
The shared request ledger separately enforces engagement-wide concurrency/rate.

Only the pinned Linux x86-64 Nuclei 3.3.8 executable is accepted (binary SHA-256
`63f881a5b1df284710daf02e880f3ceaf0eca269e0885dd860d0f31715153a9c`). The official
release archive SHA-256 is
`1526650021ada87e9cfc2a30048c8e59f5db9eed079c7807d53b7e181009bfe4`.
ZAP remains import-only; HTTPS, authenticated scanning and mutating scans are
explicitly unsupported by this first execution profile. Transfer-encoded responses
(including chunked responses/trailers), duplicate length headers and content
encodings are rejected; responses must be plain identity bytes with one length
or connection-close framing. This keeps response framing within explicit bounds.

## Resource bounds and retained evidence

The profile is limited to eight exact routes, 64 reserved attempts, 120 seconds,
and 64 KiB per response, intersected with tighter signed engagement limits.
Runtime callers can further reduce the time ceiling. The private root is a
128 MiB read-only memory mount; writable `/tmp` is a separate 8 MiB no-execute
mount. The scanner has 512 MiB writable data, 8 MiB stack, 8 GiB virtual-address
reservation (needed by Go), 64 descriptors, 96 tasks and bounded CPU time.
Anonymous mappings must be private; shared/growing-stack mapping escapes are
denied. There are no executable writable files or mounted host runtimes.

Relay requests have at most 8 KiB of headers, one request per connection, and
128 accepted connections per run (including empty proxy availability probes).
The relay is serial even if hostile scanner code opens simultaneous connections.
The export is capped at 512 KiB; stdout and stderr are each capped at 32 KiB and
are persisted only as size and hash. The three shared execution artifacts are
capped in aggregate by `MAX_ARTIFACTS`: sanitized structural report, exact
approved template, and receipt. The receipt binds the operator profile and its
signature, binary/template/deployment digests, exact request destinations and
body hashes, original export identity, and resource totals. No response body,
cookies or raw scanner logs are retained as ordinary evidence.

The scanner is not the source of the boundary receipt: the trusted relay sends
it through descriptors closed in the scanner before execution. A successful run
must complete exactly the selected routes and pass report admission. Findings
remain unverified leads; no scanner result substitutes for independent proof.

## Measured synthetic acceptance

`tests/test_staging_execution.py` includes three pure boundary tests. The thirteen
real Linux boundary tests live separately in `tests/staging_execution_acceptance.py`
and run explicitly with `python -m unittest staging_execution_acceptance.StagingKernelTests -v`
and `PYTHONPATH` containing both the protected source root and its `tests` directory.
Ordinary discovery therefore needs no scanner installation and skips no tests.
On Ubuntu 24.04 WSL, all thirteen native tests passed
against an unmodified protected source copy in 19.156 seconds, using the pinned
Nuclei binary and disposable localhost fixtures. The durable test log is
`/opt/aegis-roadmap-tests/staging-meeq_52d/kernel.log`; subsequent checks must bind
their evidence to the final release commit.

Actual Nuclei positive/control runs produced one and zero unverified observations,
respectively. Server-side logs proved exact routes, fixed harmless headers and
no test-state mutations. Synthetic body/cookie canaries were absent from all
persisted artifacts. A separate static hostile fixture deliberately bypasses
binary admission only in the test harness to exercise the kernel boundary: it
proves direct host networking, UDP/Unix sockets, fork, new namespaces, host files,
`/proc`, writable-file execution and privilege/capability escape are denied.

Actual relay traffic tests cover wrong origin/path/method, proxy authorization,
cookies, bodies, duplicate headers and pipelined requests. Other tests prove
numeric-address rejection, no redirect following, serial dispatch for concurrent
connections, request/rate/response ceilings, and denial before preparation when
the workflow ceiling is exceeded. Stop, revocation, expiry, signature corruption,
and even a validly re-signed profile change cancel an active request. Killing the
supervising process terminates all captured scanner/relay/helper descendants;
restart records interruption, retains the reserved request, and performs no replay.

This evidence covers the restricted local fixture profile, not a deployment,
an independently attested production image, authenticated business workflows,
or the authorized application pilot. Host installation, off-host retention,
recovery procedures and independent release approval remain separate gates.
