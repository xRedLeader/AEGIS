# AEGIS v2.0 — review handoff

## Scope and decision

v2.0 implements a fixed, operator-authorized assessment workflow: signed scope,
bounded source and contract testing, evidence-bound reports, independently signed
staging review, conservative retests, durable local notifications, audited
recovery, and signed agent delegation of the exact next authorized step. The
release decision covers this bounded staging scope. General autonomous hunting
remains outside this release. Cloudflare methodology integration is planned for
v2.1.

Complete the existing sign-off record in [V2_0_HOST_ACCEPTANCE.md](V2_0_HOST_ACCEPTANCE.md)
using the inputs below. The code and CI evidence are review inputs; the actual
deployment, independent reviewer, staging exercise and risk decision still need
their accountable owners' evidence. Release requirements remain defined in
[V2_0_RELEASE_ACCEPTANCE.md](V2_0_RELEASE_ACCEPTANCE.md) and
[V2_0_SECURITY_REVIEW.md](V2_0_SECURITY_REVIEW.md).

## Find the current candidate

- [PR #8](https://github.com/xRedLeader/AEGIS/pull/8): current candidate SHA,
  current acceptance evidence and release decision.
- [PR commits](https://github.com/xRedLeader/AEGIS/pull/8/commits): changes since
  the previously accepted source.
- [PR checks](https://github.com/xRedLeader/AEGIS/pull/8/checks): workflow results
  associated with the candidate under review.
- [PR files](https://github.com/xRedLeader/AEGIS/pull/8/files): complete change set
  against `main`.

Record the full candidate SHA before review. Confirm each CI result names that
same SHA; a successful run on an earlier commit does not accept later fixes.

## Historical baseline — verified 2026-10-28

The following observations apply **only** to
[`8eb48c60dff26da12d714d9de86d845d93d9d368`](https://github.com/xRedLeader/AEGIS/tree/8eb48c60dff26da12d714d9de86d845d93d9d368).
They are retained as a verified baseline while further hardening is reviewed.
They do not claim acceptance of the newer candidate containing this handoff.

| Baseline check | Observed result | Evidence |
|---|---|---|
| Ubuntu 22.04 full regression | 405 tests; `OK`; 80.764 seconds | [Job 122859516236](https://github.com/xRedLeader/AEGIS/actions/runs/40700732568/job/122859516236) |
| Ubuntu 24.04 full regression | 405 tests; `OK`; 74.136 seconds | [Job 122859516584](https://github.com/xRedLeader/AEGIS/actions/runs/40700732568/job/122859516584) |
| Source manifest | `TRACKED_SOURCE_DIGESTS_MATCH`; 114 entries verified | [Job 122859516551](https://github.com/xRedLeader/AEGIS/actions/runs/40700732568/job/122859516551) |
| Distinct-UID agent delegation | Passed signed-grant, replay and wrong-peer checks | [Job 122859517313](https://github.com/xRedLeader/AEGIS/actions/runs/40700732568/job/122859517313) |
| Distinct-UID notification receiver | Passed durable ACK, wrong-UID and replay checks | [Job 122859516653](https://github.com/xRedLeader/AEGIS/actions/runs/40700732568/job/122859516653) |
| Complete workflows | PR and branch runs succeeded at this SHA | [PR run 40700732568](https://github.com/xRedLeader/AEGIS/actions/runs/40700732568) / [branch run 40700722117](https://github.com/xRedLeader/AEGIS/actions/runs/40700722117) |

The regression jobs reject any skipped test. The source-export job intentionally
runs on branch pushes rather than PR events. At this baseline, PR #8 remained a
draft with no submitted GitHub reviews, and `main` remained at
`573bd60edb2250ad5e5164f8801c759e819f3350`.

## Pending evidence and responsible roles

Every row below is **PENDING**. Record the evidence reference, exact source SHA,
host or engagement identifier where applicable, responsible identity, date and
decision in the existing host sign-off record. Retain sensitive host evidence in
the operator-controlled review location; do not commit private keys or tokens.

| Existing gate | Who provides it | Concrete evidence needed |
|---|---|---|
| Independent security review | Security reviewer other than the implementer | A signed decision on the exact candidate and v1.5–v2.0 trusted boundary, including the recorded race fixes, delegation, signer custody, policy protection, OS isolation and credential-helper risk; identify unresolved findings. |
| Actual installed host | Deployment operator, independently checked by the reviewer | Host identity, installed commit and file digests, kernel/Python/dependency provenance, AppArmor profile, actual service-manager units/PIDs, and effective UIDs/GIDs for the distinct non-root controller, agent and receiver. Preserve operator and receiver diagnostic output plus kernel, full regression and signed-demo results from that host. |
| Protected code, policies and keys | Deployment operator and signing-key custodian | Observed ownership, modes, protected ancestor paths and effective read-only policy mounts under the service identity; protected interpreter/import paths and signing-key custody; live delegation/receiver socket ownership, permissions and service identities. Use the runbook's actual-host commands with confirmed paths and UIDs. |
| Real authorized staging exercise | Engagement owner/operator and independent verifier | The separately signed staging scope and practice identities, positive and negative scope cases, immutable report revisions and retained verification proofs, independently observed impact, separately authorized remediation retest and its bounded outcome. Synthetic fixture results alone do not fill this row. |
| Signed off-host audit retention | Independent operator signer and a second custody/verifying identity | A current signed checkpoint matching the ledger, verification with the independently pinned public key, and an independently confirmed retained off-host copy with earlier checkpoints. Record the retained artifact reference and digest. |
| Failure and recovery drills | Deployment operator, reviewed by the independent reviewer | Actual-host records for leased-action crash/expiry, no silent action retry, audited abandonment and renewed authorization, emergency stop/revocation, service restart, wrong-peer/expired/replayed delegation, mismatched proof, and successful/failed notification delivery with durable recovery. |
| Residual risk and deployment decision | Accountable release/deployment owner | Signed disposition of remaining findings and risks, supported platform/scope, support owner and emergency recovery path. Address permitted-stream bearer-token misuse, the limits of local replay evidence, local receipt versus off-host human delivery, and whether real credentials are authorized. |

The host collector always reports `NOT_PRODUCTION_APPROVED` and returns nonzero;
inspect its individual observations and external-evidence requirements. A
passing machine observation does not fill a reviewer or custody attestation.

## Final exact-commit checklist

1. Pin the final PR head and preserve its source. Review all changes since the
   historical baseline, including any changes made during acceptance.
2. Confirm Ubuntu 22.04 and 24.04 full suites, kernel isolation, signed demos,
   both distinct-UID jobs and source integrity succeed at that final SHA.
   Record the actual test counts and job URLs; do not reuse the baseline counts.
3. Verify the exact checkout with `python aegis_source_integrity.py`, preserve
   the manifest and source reference, and check that the candidate contains no
   private keys, production credentials or user-specific host paths.
4. Collect the pending evidence above on the intended host and engagement;
   complete each row of the host sign-off record with its real owner and decision.
5. Have the accountable owner reconcile unresolved findings and sign the release
   decision. Recheck that the reviewed SHA is still the PR head before any merge
   or tag. Follow the existing release gates; unresolved required evidence keeps
   the release pending.

No reviewer identity, deployment address or approval is supplied by this handoff.
