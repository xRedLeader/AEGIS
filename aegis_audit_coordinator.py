"""Replay a bounded, signed research transcript and assign the next isolated role.

The coordinator never invokes a model, a shell, target code, or a network tool.
Adapters receive one assignment and return data signed by their registered key.
"""
from __future__ import annotations

import base64
import copy
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis_audit_contract import (MAX_FINDINGS, MAX_UNITS, agent_id, canonical,
    canonical_coverage_id, digest, fields, require, seed_unit, source_references,
    text, validate_ledger)

ROLES = {"recon", "hunter", "critic", "verifier", "record_reviewer"}
SIGNING_CONTEXT = b"AEGIS-SOURCE-AUDIT-REPLY-v1\x00"
METHODOLOGY_COMMIT = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8"
RECON = ("architecture", "entrypoints", "trust_boundaries", "coverage_plan")
ATTEMPT_FIELDS = ("wave", "status", "agent_id", "reviewed_paths", "local_checks",
                  "result_fingerprints", "unresolved")


def validate_policy(policy):
    fields(policy, {"version", "configured", "engagement_id", "repository", "profile",
                    "max_invocations", "source_paths", "units", "agents", "prior_run_ids"})
    require(type(policy["version"]) is int and policy["version"] == 1 and policy["configured"] is True, "source audit is not configured")
    text(policy["engagement_id"], 128); text(policy["repository"], 1024)
    require(policy["profile"] in {"quick", "standard", "deep"}, "unknown research profile")
    require(type(policy["max_invocations"]) is int and 0 <= policy["max_invocations"] <= 128,
            "invalid research invocation budget")
    require(isinstance(policy["agents"], list) and 1 <= len(policy["agents"]) <= 32,
            "bounded explicit research identities required")
    ids, keys, roles = set(), set(), set()
    for actor in policy["agents"]:
        fields(actor, {"id", "role", "public_key"})
        aid = agent_id(actor["id"])
        require(len(aid) >= 3 and aid[0].isalpha(), "research identity must fit the canonical verifier identity")
        require(actor["role"] in ROLES and aid not in ids, "invalid or reused research identity")
        try:
            key = base64.b64decode(actor["public_key"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid research public key") from exc
        require(len(key) == 32 and key not in keys, "independent agents require distinct signing keys")
        ids.add(aid); keys.add(key); roles.add(actor["role"])
    expected = ROLES - ({"record_reviewer"} if policy["profile"] == "quick" else set())
    require(expected <= roles, "research role is missing")
    require(isinstance(policy["prior_run_ids"], list) and len(policy["prior_run_ids"]) <= 8
            and len(set(policy["prior_run_ids"])) == len(policy["prior_run_ids"]), "invalid prior audit list")
    for value in policy["prior_run_ids"]:
        require(str(uuid.UUID(value)) == value, "noncanonical prior run ID")
    require(isinstance(policy["units"], list) and 1 <= len(policy["units"]) <= MAX_UNITS,
            "explicit bounded coverage seeds required")


class AuditCoordinator:
    def __init__(self, policy, snapshot, prior=()):
        validate_policy(policy)
        self.policy, self.snapshot = policy, snapshot
        require(sorted(snapshot) == policy["source_paths"], "source snapshot differs from approved scope")
        self.source_files = {p: value["sha256"] for p, value in snapshot.items()}
        self.policy_sha = digest(policy)
        self.source_sha = digest(self.source_files)
        self.agents = {a["id"]: a for a in policy["agents"]}
        self.units, self.candidates, self.findings = {}, {}, []
        self.calls = 0
        self.limit = policy["max_invocations"]
        self.reasons = []
        self.quick = policy["profile"] == "quick"
        self.reviews_per_claim = 1 if self.quick else 2
        self.critic_ids = set()
        self.provenance = []
        self.prior_owners = {}
        self.prior_claims = {}
        self.changed_paths = set()
        for seed in policy["units"]:
            self.add_unit(seed)
        for previous in prior:
            require(previous["version"] == 1 and previous["repository"] == policy["repository"],
                    "incompatible prior source audit")
            self.changed_paths.update(p for p in set(previous["source_files"]) | set(self.source_files)
                                      if previous["source_files"].get(p) != self.source_files.get(p))
            require(len(self.changed_paths) <= 256, "incremental source history exceeds bound")
            for finding in previous["findings"]:
                self.prior_claims.setdefault(finding["coverage_id"], {})[finding["verification"]["fingerprint"]] = finding
            for old in previous["coverage"]:
                uid = old["coverage_id"]
                if uid not in self.units:
                    seed = {"canonical_refs": old["canonical_refs"], "starting_paths": old["starting_paths"],
                            "guides": old["selected_companion_blocks"], "exclusion": None}
                    # Removed/out-of-scope files are explicitly retained as a limitation.
                    if not set(seed["starting_paths"]) <= set(snapshot):
                        self.reasons.append("prior_unit_outside_current_scope:" + digest(uid)[:16])
                        continue
                    self.add_unit(seed)
                unit = self.units[uid]
                if policy["profile"] == "deep" and old["agent_id"]:
                    self.prior_owners.setdefault(uid, set()).add(old["agent_id"])
                same = all(previous["source_files"].get(p) == self.source_files.get(p)
                           for p in old["reviewed_paths"] or old["starting_paths"])
                state = old["status"]
                unit["prior_status"] = ("prior_covered_" + ("same_source" if same else "changed_source")
                    if state == "covered" else {"candidate": "prior_needs_validation",
                        "blocked": "prior_blocked", "deferred": "prior_deferred",
                        "out_of_scope": "prior_out_of_scope"}.get(state, "new"))
        require(len(self.units) <= MAX_UNITS, "combined coverage exceeds bound")

    def add_unit(self, seed):
        seed = copy.deepcopy(seed)
        if self.quick:
            seed["canonical_refs"]["subsystem"] = "profile/quick/all-in-scope-subsystems"
            seed["canonical_refs"].pop("lifecycle", None)
        unit = seed_unit(seed, self.snapshot)
        uid = unit["coverage_id"]
        if uid in self.units:
            old = self.units[uid]
            if self.quick and old["status"] == "planned":
                paths = sorted(set(old["starting_paths"]) | set(unit["starting_paths"]))
                require(len(paths) <= 8 and old["unresolved"] == unit["unresolved"], "quick coverage merge exceeds scope")
                old["starting_paths"] = unit["starting_paths"] = paths
                guides = sorted(set(old["selected_companion_blocks"]) | set(unit["selected_companion_blocks"]))
                old["selected_companion_blocks"] = unit["selected_companion_blocks"] = guides
            require(old["starting_paths"] == unit["starting_paths"] and
                    old["selected_companion_blocks"] == unit["selected_companion_blocks"] and
                    old["unresolved"] == unit["unresolved"], "conflicting duplicate coverage unit")
        else:
            require(len(self.units) < MAX_UNITS, "coverage discovery exceeds bounded scope")
            self.units[uid] = unit

    def actor(self, role, excluded=()):
        return next((a for a in sorted(self.agents) if self.agents[a]["role"] == role and a not in excluded), None)

    def request(self, role, subject, context, *, excluded=()):
        actor = self.actor(role, excluded)
        require(actor is not None and self.calls < self.limit, "independent research reserve unavailable")
        self.calls += 1
        assignment = {"version": 1, "audit_id": self.audit_id, "ordinal": self.calls,
                      "policy_sha256": self.policy_sha, "source_sha256": self.source_sha,
                      "methodology_commit": METHODOLOGY_COMMIT,
                      "agent_id": actor, "role": role, "subject": subject, "context": context,
                      "scratch_namespace": "agents/" + actor + "/assignment-" + str(self.calls),
                      "authority": "source_data_only_no_execution_no_network"}
        assignment["assignment_id"] = digest(assignment)
        require(len(canonical(assignment)) <= 131072, "research assignment exceeds adapter byte limit")
        response = yield assignment
        return response, actor

    def check_response(self, assignment, record):
        fields(record, {"assignment_id", "agent_id", "result", "signature"})
        require(isinstance(record["result"], dict), "research reply must be structured data")
        require(len(canonical(record["result"])) <= 16384, "research reply exceeds adapter byte limit")
        require(record["assignment_id"] == assignment["assignment_id"] and
                record["agent_id"] == assignment["agent_id"], "research reply is replayed or belongs to another assignment")
        body = {k: record[k] for k in ("assignment_id", "agent_id", "result")}
        try:
            key = base64.b64decode(self.agents[record["agent_id"]]["public_key"], validate=True)
            signature = base64.b64decode(record["signature"], validate=True)
            Ed25519PublicKey.from_public_bytes(key).verify(signature, SIGNING_CONTEXT + canonical(body))
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise ValueError("invalid independently signed research reply") from exc
        self.provenance.append(copy.deepcopy(record))
        return record["result"]

    def checks(self, values, actor):
        require(isinstance(values, list) and 1 <= len(values) <= 4, "research needs bounded source checks")
        checks = []
        for value in values:
            fields(value, {"source_refs", "invariant", "result"})
            paths = source_references(value["source_refs"], self.snapshot)
            text(value["invariant"]); text(value["result"])
            checks.append({"agent_id": actor, "reviewed_paths": paths, "invariant": value["invariant"],
                           "method": "source", "result": value["result"], "artifact": None})
        return checks

    def candidate(self, value, actor, unit):
        fields(value, {"title", "entrypoint", "sink", "root_cause", "attack_condition",
                       "description", "source_refs", "validation_plan"})
        for name in ("title", "entrypoint", "sink", "root_cause", "attack_condition", "description", "validation_plan"):
            text(value[name])
        paths = source_references(value["source_refs"], self.snapshot)
        fingerprint = digest({k: value[k] for k in ("entrypoint", "sink", "root_cause", "attack_condition")} |
                             {"boundary": unit["canonical_refs"]["boundary"], "paths": paths})
        if fingerprint in self.candidates:
            require(self.candidates[fingerprint]["claim"] == value, "same root-cause fingerprint has conflicting claims")
        else:
            require(len(self.candidates) < MAX_FINDINGS, "research finding bound exceeded")
            self.candidates[fingerprint] = {"fingerprint": fingerprint, "hunter_id": actor,
                                            "claim": value, "coverage_id": unit["coverage_id"]}
        return fingerprint

    def hunt(self, unit, response, actor):
        fields(response, {"status", "checks", "candidates", "unresolved"})
        require(response["status"] in {"covered", "candidate", "blocked"}, "hunter cannot discard assigned coverage")
        require(isinstance(response["candidates"], list) and len(response["candidates"]) <= 2,
                "hunter exceeded its candidate reservation")
        require(isinstance(response["unresolved"], list) and len(response["unresolved"]) <= 4, "unbounded unresolved work")
        checks = self.checks(response["checks"], actor)
        unit.update(status=response["status"], agent_id=actor, local_checks=checks,
                    reviewed_paths=sorted({p for c in checks for p in c["reviewed_paths"]}),
                    result_fingerprints=sorted(self.candidate(c, actor, unit) for c in response["candidates"]),
                    unresolved=response["unresolved"])
        require(set(unit["starting_paths"]) <= set(unit["reviewed_paths"]), "hunter did not inspect its assigned starting paths")
        require(all(set(source_references(c["source_refs"], self.snapshot)) <= set(unit["reviewed_paths"])
                    for c in response["candidates"]), "candidate source was not reviewed by its hunter")
        validate_ledger(sorted(self.units.values(), key=lambda u: u["coverage_id"]))

    def reopen(self, unit, reason, wave):
        if unit["status"] in {"covered", "candidate", "blocked"}:
            old = {key: copy.deepcopy(unit[key]) for key in ATTEMPT_FIELDS}
            old["reassignment_reason"] = reason
            unit["attempts"].append(old)
        unit.update(wave=wave, status="planned", agent_id=None, reviewed_paths=[], local_checks=[],
                    result_fingerprints=[], unresolved=[])

    def critique(self, response, wave):
        fields(response, {"reviewed_coverage_ids", "checks", "new_units", "revisit", "clean"})
        require(response["reviewed_coverage_ids"] == sorted(self.units), "critic did not account for every coverage unit")
        require(type(response["clean"]) is bool and isinstance(response["new_units"], list)
                and isinstance(response["revisit"], list) and len(response["revisit"]) <= MAX_UNITS,
                "invalid coverage critique")
        for item in response["new_units"]:
            uid = canonical_coverage_id(item["canonical_refs"])
            require(uid not in self.units, "critic rediscovered existing coverage")
            self.add_unit(item)
        seen = set()
        for item in response["revisit"]:
            fields(item, {"coverage_id", "reason"})
            uid = item["coverage_id"]
            require(uid in self.units and uid not in seen and self.units[uid]["status"] != "out_of_scope",
                    "critic tried to reassign absent or excluded coverage")
            seen.add(uid); text(item["reason"])
            self.reopen(self.units[uid], item["reason"], wave + 1)
        require(response["clean"] == (not response["new_units"] and not response["revisit"]),
                "clean coverage critique contradicts recorded gaps")
        return response["clean"]

    def verification(self, result, candidate):
        base = {"fingerprint", "verdict", "source_refs", "rationale"}
        verdict = result.get("verdict") if isinstance(result, dict) else None
        # Source attestations cannot replace the existing dual-signed staging proof.
        extra = {"needs_validation": {"blocker", "validation_plan"}, "rejected": {"rejection_reason"}}
        require(verdict in extra, "invalid research verdict")
        fields(result, base | extra[verdict])
        require(result["fingerprint"] == candidate["fingerprint"], "verification changed finding identity")
        checked_paths = source_references(result["source_refs"], self.snapshot)
        require(set(source_references(candidate["claim"]["source_refs"], self.snapshot)) <= set(checked_paths),
                "verifier did not check the candidate's source paths")
        for name in {"rationale"} | extra[verdict]:
            text(result[name])
        return copy.deepcopy(result)

    def workflow(self):
        critic_reserve = 1 if self.quick else 2
        minimum = 4 + critic_reserve + self.reviews_per_claim
        if self.limit < minimum:
            self.reasons.append("budget_cannot_fund_reconnaissance_and_reserves")
            return self.finish()
        for subject in RECON:
            result, actor = yield from self.request("recon", subject, {"source_files": self.source_files})
            fields(result, {"summary", "checks", "new_units"})
            text(result["summary"])
            self.checks(result["checks"], actor)
            require(isinstance(result["new_units"], list), "invalid reconnaissance coverage")
            for seed in result["new_units"]:
                self.add_unit(seed)
        max_waves = 1 if self.quick else (3 if self.policy["profile"] == "deep" else 2)
        clean = False
        final_checked = False
        for wave in range(1, max_waves + 1):
            final_checked = False
            for unit in sorted(self.units.values(), key=lambda u: u["coverage_id"]):
                if unit["status"] != "planned":
                    continue
                old_owners = {a["agent_id"] for a in unit["attempts"]} | self.prior_owners.get(unit["coverage_id"], set())
                reserve = critic_reserve + self.reviews_per_claim * (len(self.candidates) + 2)
                if (self.calls + 1 + reserve > self.limit or len(self.candidates) + 2 > MAX_FINDINGS
                        or self.actor("hunter", old_owners) is None):
                    unit.update(status="deferred", unresolved=["independent_hunter_or_validation_reserve_unavailable"])
                    continue
                unit["wave"] = wave
                context = copy.deepcopy(unit)
                context["prior_findings"] = list(self.prior_claims.get(unit["coverage_id"], {}).values())
                result, actor = yield from self.request("hunter", unit["coverage_id"], context, excluded=old_owners)
                self.hunt(unit, result, actor)
            if self.calls + critic_reserve + self.reviews_per_claim * len(self.candidates) > self.limit:
                self.reasons.append("coverage_critic_reserve_exhausted")
                break
            result, actor = yield from self.request("critic", "post_wave_" + str(wave),
                                                    {"coverage": copy.deepcopy(list(self.units.values()))})
            self.critic_ids.add(actor)
            self.checks(result.get("checks"), actor)
            clean = self.critique(result, wave)
            if clean and not self.quick and self.actor("critic", self.critic_ids) is not None:
                result, actor = yield from self.request("critic", "final_coverage_review",
                    {"coverage": copy.deepcopy(list(self.units.values()))}, excluded=self.critic_ids)
                self.checks(result.get("checks"), actor)
                clean = self.critique(result, wave)
                final_checked = True
            if clean:
                break
        if not self.quick and not final_checked:
            fresh = self.actor("critic", self.critic_ids)
            if fresh is None or self.calls + 1 + self.reviews_per_claim * len(self.candidates) > self.limit:
                self.reasons.append("independent_final_coverage_review_unavailable")
                clean = False
            else:
                result, actor = yield from self.request("critic", "final_coverage_review",
                    {"coverage": copy.deepcopy(list(self.units.values()))}, excluded=self.critic_ids)
                self.checks(result.get("checks"), actor)
                clean = self.critique(result, max_waves)
        if not clean:
            self.reasons.append("coverage_review_has_unresolved_gaps")
        for fingerprint, candidate in sorted(self.candidates.items()):
            if self.calls + self.reviews_per_claim > self.limit:
                self.reasons.append("validation_budget_exhausted")
                break
            result, verifier = yield from self.request("verifier", fingerprint, candidate,
                                                       excluded={candidate["hunter_id"]})
            finding = self.verification(result, candidate)
            reviewer = verifier
            if not self.quick:
                result, reviewer = yield from self.request("record_reviewer", fingerprint,
                    {"candidate": candidate, "record": finding, "record_sha256": digest(finding)},
                    excluded={candidate["hunter_id"], verifier})
                fields(result, {"record_sha256", "decision", "reason", "source_refs"})
                require(result["record_sha256"] == digest(finding), "final reviewer checked another record")
                source_references(result["source_refs"], self.snapshot); text(result["reason"])
                require({r["path"] for r in candidate["claim"]["source_refs"]} <=
                        {r["path"] for r in result["source_refs"]}, "final reviewer omitted finding source paths")
                require(result["decision"] in {"accept", "needs_validation"}, "invalid final record decision")
                if result["decision"] == "needs_validation":
                    finding = {"fingerprint": fingerprint, "verdict": "needs_validation",
                               "source_refs": result["source_refs"], "rationale": result["reason"],
                               "blocker": result["reason"], "validation_plan": candidate["claim"]["validation_plan"]}
            self.findings.append({"claim": candidate["claim"], "verification": finding,
                                  "coverage_id": candidate["coverage_id"],
                                  "hunter_id": candidate["hunter_id"], "verifier_id": verifier,
                                  "record_reviewer_id": reviewer})
        return self.finish()

    def finish(self):
        for unit in self.units.values():
            if unit["status"] == "planned":
                unit.update(status="deferred", unresolved=["audit_budget_or_wave_limit_reached"])
        ledger = sorted(self.units.values(), key=lambda u: u["coverage_id"])
        validate_ledger(ledger)
        gaps = [u["coverage_id"] for u in ledger if u["status"] in {"blocked", "deferred"}]
        checked = {f["verification"]["fingerprint"] for f in self.findings}
        pending = sorted(set(self.candidates) - checked)
        return {"version": 1, "audit_id": self.audit_id, "repository": self.policy["repository"],
                "profile": self.policy["profile"], "source_files": self.source_files,
                "changed_paths": sorted(self.changed_paths),
                "source_sha256": self.source_sha, "policy_sha256": self.policy_sha,
                "invocations": self.calls, "coverage": ledger, "findings": self.findings,
                "pending_fingerprints": pending, "limitations": sorted(set(self.reasons)),
                "status": "incomplete" if gaps or pending or self.reasons else "source_review_complete",
                "deployment_approval": False}

    def replay(self, bundle):
        fields(bundle, {"version", "audit_id", "policy_sha256", "source_sha256", "records"})
        require(type(bundle["version"]) is int and bundle["version"] == 1 and str(uuid.UUID(bundle["audit_id"])) == bundle["audit_id"],
                "invalid source audit identity")
        require(bundle["policy_sha256"] == self.policy_sha and bundle["source_sha256"] == self.source_sha,
                "research transcript is bound to different policy or source bytes")
        require(isinstance(bundle["records"], list) and len(bundle["records"]) <= self.limit,
                "research transcript exceeds invocation budget")
        self.audit_id = bundle["audit_id"]
        flow = self.workflow()
        try:
            assignment = next(flow)
            for record in bundle["records"]:
                assignment = flow.send(self.check_response(assignment, record))
        except StopIteration as completed:
            require(len(self.provenance) == len(bundle["records"]), "transcript contains replies after audit completion")
            return {"next_assignment": None, "result": completed.value}
        return {"next_assignment": assignment, "result": None}
