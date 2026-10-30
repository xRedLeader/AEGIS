"""Project checked research into AEGIS's existing canonical findings contract."""
import hashlib

from aegis_audit_contract import canonical, decode, digest, require, validate_ledger


def research_projection(raw, eid, run_id, ended):
    artifact = decode(raw)
    research = artifact["result"]
    require(research["version"] == 1 and research["status"] in {"incomplete", "source_review_complete"}
            and research["deployment_approval"] is False, "incompatible research artifact")
    validate_ledger(research["coverage"])
    sha = hashlib.sha256(raw).hexdigest()
    path = "runs/" + run_id + "/source-audit.json"
    items, proofs = [], {}
    require(isinstance(research["findings"], list) and len(research["findings"]) <= 8, "unbounded research findings")
    for index, record in enumerate(research["findings"]):
        claim, verification = record["claim"], record["verification"]
        item = {"id": "A18-" + digest([eid, run_id, sha, index])[:20],
                "verdict": "needs_validation", "title": claim["title"],
                "affected_asset": claim["source_refs"][0]["path"],
                "evidence_sha256": sha, "evidence_ref": path + "#item=" + str(index),
                "description": claim["description"]}
        if verification["verdict"] == "rejected":
            signed = [r for r in artifact["bundle"]["records"] if
                      r["result"].get("fingerprint") == verification["fingerprint"] or
                      r["result"].get("record_sha256") == digest(verification)]
            proof = canonical({"version": 1, "kind": "source_research_rejection",
                               "source_sha256": sha, "policy_sha256": research["policy_sha256"],
                               "signed_reviews": signed})
            proof_sha = hashlib.sha256(proof).hexdigest()
            proofs["proof-" + proof_sha + ".json"] = proof
            item.update(verdict="rejected", rejection_reason=verification["rejection_reason"],
                        verification_evidence_sha256=proof_sha,
                        verifier_id=record["record_reviewer_id"], verified_at_utc=ended)
        else:
            require(verification["verdict"] == "needs_validation", "source research cannot supply staging confirmation")
            item.update(blocker=verification["blocker"], validation_plan=verification["validation_plan"])
        items.append(item)
    statuses = {s: sum(u["status"] == s for u in research["coverage"]) for s in
                ("covered", "candidate", "blocked", "deferred", "out_of_scope")}
    report = {"schema_version": 2, "engagement_id": eid, "source_run_id": run_id,
              "generated_at_utc": ended, "assessment_status": "limited_source_evidence_only",
              "source_evidence": {"relative_path": path, "sha256": sha, "kind": "source_audit"},
              "findings": items, "coverage": {
                  "tested": ["Signed source research: " + ", ".join(str(v) + " " + k for k, v in statuses.items()) + "."],
                  "untested": ["Deployment reachability, runtime controls and attacker impact remain unverified.",
                               str(len(research["pending_fingerprints"])) + " candidate(s) still await independent validation."],
                  "limitations": ["Research status: " + research["status"] + ". No clean bill of security.",
                                   "Source reviews cannot replace signed staging proof or release approval.",
                                   "See the retained coverage ledger for every excluded, blocked and deferred unit."]}}
    return report, proofs
