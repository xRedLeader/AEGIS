"""Research proofs cannot become execution authority or deployed-impact claims."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_audit_contract import (canonical, canonical_coverage_id, decode, digest,
    relative_path, source_snapshot, validate_ledger)
from aegis_audit_coordinator import AuditCoordinator
from aegis_audit_reporting import research_projection
from aegis_source_audit import SourceAuditSupervisor, retained
from aegis_source_audit_agent import sign_reply
from aegis_reporting import report_package, verified_package
from aegis_supervisor import ExecutionDenied
from test_v18_reporting import ReportFixture

ROOT = Path(__file__).resolve().parents[1]


class ResearchFixture:
    def prepare(self, repository="/approved/repo", engagement="source-audit-test"):
        body = b"def handle(request):\n    return eval(request)\n"
        self.snapshot = {"app.py": {"sha256": hashlib.sha256(body).hexdigest(),
                                    "lines": body.decode().splitlines()}}
        self.ref = {"path": "app.py", "start_line": 1, "end_line": 2,
                    "sha256": self.snapshot["app.py"]["sha256"],
                    "excerpt_sha256": hashlib.sha256(body.rstrip(b"\n")).hexdigest()}
        self.keys, actors = {}, []
        for role in ("recon", "hunter", "hunter", "critic", "critic", "verifier", "record_reviewer"):
            aid = role + str(len(actors))
            key = Ed25519PrivateKey.generate()
            self.keys[aid] = key
            actors.append({"id": aid, "role": role, "public_key": base64.b64encode(
                key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()})
        self.policy = {"version": 1, "configured": True, "engagement_id": engagement,
                       "repository": repository, "profile": "standard", "max_invocations": 24,
                       "source_paths": ["app.py"], "agents": actors, "prior_run_ids": [],
                       "units": [{"canonical_refs": {"surface": "http", "boundary": "caller-to-eval",
                                  "subsystem": "handler", "attack_class": "code-injection"},
                                  "starting_paths": ["app.py"], "guides": ["WEB-PROTOCOL-AND-AUTH.md"],
                                  "exclusion": None}]}
        self.bundle = {"version": 1, "audit_id": str(uuid.uuid4()), "policy_sha256": digest(self.policy),
                       "source_sha256": digest({p: v["sha256"] for p, v in self.snapshot.items()}), "records": []}
        self.mode = "needs_validation"

    def check(self):
        return {"source_refs": [self.ref], "invariant": "Untrusted input cannot select executable code.",
                "result": "The source passes request data to eval."}

    def response(self, assignment):
        role, context = assignment["role"], assignment["context"]
        if role == "recon":
            return {"summary": "One externally reachable handler requires review.",
                    "checks": [self.check()], "new_units": []}
        if role == "hunter":
            if self.mode == "clean":
                return {"status": "covered", "checks": [self.check()], "candidates": [], "unresolved": []}
            claim = {"title": "Request reaches eval", "entrypoint": "handle", "sink": "eval",
                     "root_cause": "request controls evaluated expression", "attack_condition": "untrusted request input",
                     "description": "The handler evaluates its argument without constraining the expression.",
                     "source_refs": [self.ref], "validation_plan": "Verify reachability in the authorized staging fixture."}
            return {"status": "candidate", "checks": [self.check()], "candidates": [claim], "unresolved": []}
        if role == "critic":
            return {"reviewed_coverage_ids": sorted(u["coverage_id"] for u in context["coverage"]),
                    "checks": [self.check()], "new_units": [], "revisit": [], "clean": True}
        if role == "verifier":
            result = {"fingerprint": context["fingerprint"], "verdict": self.mode, "source_refs": [self.ref],
                      "rationale": "The source trace is checked against the current file."}
            if self.mode == "confirmed":
                result.update(severity="high", demonstrated_impact="An arbitrary expression reaches eval in this source path.",
                              remediation="Use a constrained parser.")
            elif self.mode == "needs_validation":
                result.update(blocker="Deployment reachability is unknown.", validation_plan="Check the approved staging route.")
            else:
                result.update(rejection_reason="The claimed trust boundary does not exist in this configuration.")
            return result
        return {"record_sha256": context["record_sha256"], "decision": "accept",
                "reason": "The verdict matches the cited source and its stated limitations.", "source_refs": [self.ref]}

    def replay(self, prior=()):
        return AuditCoordinator(self.policy, self.snapshot, prior).replay(self.bundle)

    def complete(self, prior=(), change=None):
        for _ in range(128):
            outcome = self.replay(prior)
            assignment = outcome["next_assignment"]
            if assignment is None:
                return outcome["result"]
            response = self.response(assignment)
            if change:
                response = change(assignment, response)
            self.bundle["records"].append(sign_reply(assignment, response, self.keys[assignment["agent_id"]]))
        self.fail("research did not terminate within its invocation budget")


class CoordinatorTests(ResearchFixture, unittest.TestCase):
    def setUp(self):
        self.prepare()

    def test_full_independent_workflow_and_source_only_projection(self):
        result = self.complete()
        self.assertEqual(result["status"], "source_review_complete")
        finding = result["findings"][0]
        self.assertEqual(len({finding[k] for k in ("hunter_id", "verifier_id", "record_reviewer_id")}), 3)
        artifact = canonical({"version": 1, "policy": self.policy, "bundle": self.bundle, "result": result})
        report, proofs = research_projection(artifact, "source-audit-test", str(uuid.uuid4()), "2026-10-30T17:00:00Z")
        self.assertEqual(report["findings"][0]["verdict"], "needs_validation")
        self.assertNotIn("severity", report["findings"][0])
        self.assertTrue(report_package(report, proofs))

    def test_rejected_claim_has_retained_signed_proof(self):
        self.mode = "rejected"
        result = self.complete()
        raw = canonical({"version": 1, "policy": self.policy, "bundle": self.bundle, "result": result})
        report, proofs = research_projection(raw, "source-audit-test", str(uuid.uuid4()), "2026-10-30T17:00:00Z")
        self.assertEqual(report["findings"][0]["verdict"], "rejected")
        self.assertEqual(len(proofs), 1)
        self.assertTrue(report_package(report, proofs))

    def test_budget_cannot_silently_skip_required_phases(self):
        self.policy["max_invocations"] = 3
        self.bundle["policy_sha256"] = digest(self.policy)
        result = self.complete()
        self.assertEqual(result["invocations"], 0)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["coverage"][0]["status"], "deferred")
        self.assertIn("budget_cannot_fund_reconnaissance_and_reserves", result["limitations"])

    def test_hunting_reserves_validation_and_critic_calls(self):
        self.policy["max_invocations"] = 8
        self.bundle["policy_sha256"] = digest(self.policy)
        result = self.complete()
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["coverage"][0]["status"], "deferred")
        self.assertLessEqual(result["invocations"], 8)

    def test_signature_replay_tampering_and_role_reuse_fail(self):
        self.complete()
        original = copy.deepcopy(self.bundle)
        for mutate in (lambda b: b["records"][0]["result"].update(summary="Tampered"),
                       lambda b: b["records"].insert(1, copy.deepcopy(b["records"][0])),
                       lambda b: b.update(source_sha256="0"*64),
                       lambda b: b["records"][-1].update(agent_id=b["records"][-2]["agent_id"])):
            self.bundle = copy.deepcopy(original)
            mutate(self.bundle)
            with self.assertRaises((ExecutionDenied, ValueError)):
                self.replay()

    def test_same_key_cannot_impersonate_independence(self):
        self.policy["agents"][-1]["public_key"] = self.policy["agents"][-2]["public_key"]
        with self.assertRaises(ExecutionDenied):
            self.replay()

    def test_boolean_schema_versions_are_not_integers(self):
        self.policy["version"] = True
        with self.assertRaises(ExecutionDenied): self.replay()

    def test_stale_or_invented_source_lines_are_rejected(self):
        for key, value in (("sha256", "f"*64), ("end_line", 30), ("start_line", True),
                           ("excerpt_sha256", "f"*64), ("path", "../secret")):
            with self.subTest(key=key):
                self.prepare()
                self.ref[key] = value
                with self.assertRaises(ExecutionDenied):
                    self.complete()

    def test_unverified_severity_and_incomplete_confirmation_are_rejected(self):
        for mode in ("needs_validation", "confirmed"):
            self.prepare(); self.mode = mode
            def bad(assignment, response):
                if assignment["role"] == "verifier":
                    if mode == "needs_validation": response["severity"] = "high"
                    else: response.pop("demonstrated_impact")
                return response
            with self.assertRaises(ExecutionDenied):
                self.complete(change=bad)

    def test_final_reviewer_can_record_a_further_validation_blocker(self):
        def downgrade(assignment, response):
            if assignment["role"] == "record_reviewer": response["decision"] = "needs_validation"
            return response
        finding = self.complete(change=downgrade)["findings"][0]["verification"]
        self.assertEqual(finding["verdict"], "needs_validation")
        self.assertNotIn("severity", finding)

    def test_source_signatures_cannot_substitute_for_staging_confirmation(self):
        self.mode = "confirmed"
        with self.assertRaises(ExecutionDenied): self.complete()

    def test_agent_prose_cannot_embed_active_markdown_or_html(self):
        from aegis_reporting import markdown
        result = self.complete()
        result["findings"][0]["claim"]["title"] = '<img src="https://invalid.example/x"> ![image](https://invalid.example/y)'
        raw = canonical({"version": 1, "policy": self.policy, "bundle": self.bundle, "result": result})
        report, _ = research_projection(raw, "source-audit-test", str(uuid.uuid4()), "2026-10-30T17:00:00Z")
        for body in markdown(report).values():
            self.assertNotIn("<img", body)
            self.assertNotIn("![image]", body)

    def test_reassignment_preserves_attempt_and_uses_fresh_hunter(self):
        self.mode = "clean"
        def revisit(assignment, response):
            if assignment["subject"] == "post_wave_1":
                response.update(clean=False, revisit=[{"coverage_id": response["reviewed_coverage_ids"][0],
                                                       "reason": "Independently recheck the trust boundary."}])
            return response
        unit = self.complete(change=revisit)["coverage"][0]
        self.assertEqual(len(unit["attempts"]), 1)
        self.assertNotEqual(unit["agent_id"], unit["attempts"][0]["agent_id"])
        self.assertEqual(unit["attempts"][0]["status"], "covered")

    def test_incremental_same_and_changed_source_never_carry_confirmation(self):
        self.mode = "clean"
        prior = self.complete()
        for changed in (False, True):
            self.prepare(); self.mode = "clean"
            if changed:
                self.snapshot["app.py"]["sha256"] = "e"*64
                self.ref["sha256"] = "e"*64
                self.bundle["source_sha256"] = digest({"app.py": "e"*64})
            result = self.complete([prior])
            self.assertEqual(result["coverage"][0]["prior_status"],
                             "prior_covered_" + ("changed_source" if changed else "same_source"))
            self.assertGreaterEqual(result["invocations"], 7)

    def test_canonical_ids_and_hostile_json_and_paths(self):
        refs = {"surface": "a::b", "boundary": "c/d", "subsystem": "Café", "attack_class": "x y"}
        self.assertEqual(canonical_coverage_id(refs), "a%3A%3Ab::c%2Fd::Caf%C3%A9::x%20y")
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'['*40+b'0'+b']'*40):
            with self.assertRaises(ExecutionDenied): decode(raw)
        for path in ("/etc/passwd", "../secret", "x//y", "x\\y", "NUL.txt", "x. ", "x/COM1", "x\u200by"):
            with self.assertRaises(ExecutionDenied): relative_path(path)

    def test_coverage_cannot_claim_unowned_or_reused_evidence(self):
        unit = self.complete()["coverage"][0]
        for mutate in (lambda u: u.update(agent_id=None), lambda u: u.update(reviewed_paths=["other.py"]),
                       lambda u: u.update(result_fingerprints=[]), lambda u: u.update(coverage_id="invented"),
                       lambda u: u.update(selected_companion_blocks="abc")):
            changed = copy.deepcopy(unit); mutate(changed)
            with self.assertRaises(ExecutionDenied): validate_ledger([changed])

    def test_source_reader_rejects_links_and_nonregular_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/"real.py").write_text("safe\n")
            (root/"link.py").symlink_to(root/"real.py")
            os.link(root/"real.py", root/"hard.py")
            os.mkfifo(root/"pipe.py")
            for name in ("link.py", "hard.py", "pipe.py"):
                with self.assertRaises((ExecutionDenied, OSError)): source_snapshot(root, [name])

    def test_quick_coarsens_units_but_keeps_independent_verifier(self):
        self.policy["profile"] = "quick"
        self.bundle["policy_sha256"] = digest(self.policy)
        result = self.complete()
        self.assertEqual(result["coverage"][0]["canonical_refs"]["subsystem"], "profile/quick/all-in-scope-subsystems")
        finding = result["findings"][0]
        self.assertNotEqual(finding["hunter_id"], finding["verifier_id"])
        self.assertEqual(finding["verifier_id"], finding["record_reviewer_id"])

    def test_final_critic_gap_runs_another_wave_when_budget_allows(self):
        self.mode = "clean"
        found = False
        def critic(assignment, response):
            nonlocal found
            if assignment["subject"] == "final_coverage_review" and not found:
                found = True
                response.update(clean=False, revisit=[{"coverage_id": response["reviewed_coverage_ids"][0],
                                                       "reason": "Inspect an overlooked boundary condition."}])
            return response
        result = self.complete(change=critic)
        self.assertEqual(result["status"], "source_review_complete")
        self.assertEqual(len(result["coverage"][0]["attempts"]), 1)

    def test_missing_independent_final_critic_is_explicitly_incomplete(self):
        self.policy["agents"] = [a for a in self.policy["agents"] if a["id"] != "critic4"]
        self.bundle["policy_sha256"] = digest(self.policy)
        result = self.complete()
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("independent_final_coverage_review_unavailable", result["limitations"])

    def test_deep_revisits_previously_covered_unit_with_another_hunter(self):
        self.mode = "clean"
        prior = self.complete()
        old_owner = prior["coverage"][0]["agent_id"]
        self.bundle["records"] = []
        self.bundle["audit_id"] = str(uuid.uuid4())
        self.policy["profile"] = "deep"
        self.bundle["policy_sha256"] = digest(self.policy)
        result = self.complete([prior])
        self.assertNotEqual(old_owner, result["coverage"][0]["agent_id"])

    def test_shared_coverage_contract_fixtures(self):
        cases = json.loads((ROOT/"tests/fixtures/source-audit-coverage.json").read_text())
        for case in cases:
            with self.subTest(case=case["name"]):
                if case["valid"]:
                    validate_ledger(case["ledger"])
                else:
                    with self.assertRaises(ExecutionDenied): validate_ledger(case["ledger"])


class SourceAuditIntegrationTests(ResearchFixture, ReportFixture):
    def setUp(self):
        super().setUp()
        self.prepare(str(self.fx.fx.repo), self.fx.fx.manifest["engagement"]["id"])
        (self.fx.fx.repo/"app.py").write_text("def handle(request):\n    return eval(request)\n")
        self.audit_policy = self.fx.fx.p/"research-policy.json"
        self.audit_bundle = self.fx.fx.p/"research-bundle.json"
        self.engine = SourceAuditSupervisor(self.fx.fx.manifest_path, self.fx.fx.sig_path,
                                            self.fx.fx.trust_path, self.fx.state)

    def save_research(self):
        self.complete()
        for path, value in ((self.audit_policy, self.policy), (self.audit_bundle, self.bundle)):
            path.write_bytes(canonical(value)); path.chmod(0o600)

    def test_actual_supervisor_retains_reports_and_revalidates_tampering(self):
        self.save_research()
        recorded = self.engine.research(self.audit_policy, self.audit_bundle, accept=True, seconds=5)
        self.assertEqual(recorded["status"], "SOURCE_AUDIT_RECORDED")
        run = recorded["run_id"]
        report = self.sup.generate(run, "source-audit.json")
        verified_package(Path(report["report"]).parent, report["sha256"])
        info, _ = self.engine._guard()
        self.assertEqual(retained(self.engine, info, run)["result"]["status"], "source_review_complete")
        target = Path(info["report_directory"])/"runs"/run/"source-audit.json"
        target.write_bytes(target.read_bytes().replace(b"Request reaches eval", b"Request ignores eval"))
        with self.assertRaises(ExecutionDenied): self.sup.generate(run, "source-audit.json")

    def test_scope_revocation_and_incomplete_transcripts_cannot_be_accepted(self):
        self.save_research()
        self.bundle["records"].pop()
        self.audit_bundle.write_bytes(canonical(self.bundle))
        with self.assertRaises(ExecutionDenied): self.engine.research(self.audit_policy, self.audit_bundle, accept=True, seconds=2)
        self.policy["repository"] = "/etc"
        self.audit_policy.write_bytes(canonical(self.policy))
        with self.assertRaises(ExecutionDenied): self.engine.research(self.audit_policy, self.audit_bundle, accept=True, seconds=2)

    def test_stop_and_changed_source_prevent_new_evidence(self):
        from aegis_supervisor import operator_stop
        self.save_research()
        (self.fx.fx.repo/"app.py").write_text("def handle(request):\n    return request\n")
        with self.assertRaises(ExecutionDenied): self.engine.research(self.audit_policy, self.audit_bundle, accept=True, seconds=2)
        operator_stop(self.fx.state, self.policy["engagement_id"])
        with self.assertRaises(ExecutionDenied): self.engine.research(self.audit_policy, self.audit_bundle, accept=True, seconds=2)

    def test_evidence_budget_accounts_for_the_full_retained_transcript(self):
        self.save_research()
        self.engine.research(self.audit_policy, self.audit_bundle, accept=True, seconds=2)
        with self.engine._database() as con:
            total = con.execute("SELECT reserved_evidence_bytes FROM usage WHERE engagement_id=?",
                                (self.policy["engagement_id"],)).fetchone()[0]
        self.assertEqual(total, 262144)

    def test_duplicate_audit_admission_is_rejected_across_restart_and_concurrency(self):
        self.save_research()
        def accept():
            try:
                return self.engine.research(self.audit_policy, self.audit_bundle, accept=True, seconds=2)["status"]
            except ExecutionDenied:
                return "DENIED"
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: accept(), range(2)))
        self.assertEqual(sorted(results), ["DENIED", "SOURCE_AUDIT_RECORDED"])
        restarted = SourceAuditSupervisor(self.fx.fx.manifest_path, self.fx.fx.sig_path,
                                           self.fx.fx.trust_path, self.fx.state)
        with self.assertRaises(ExecutionDenied): restarted.research(self.audit_policy, self.audit_bundle, accept=True, seconds=2)
        with self.engine._database() as con:
            self.assertEqual(con.execute("SELECT count(*) FROM source_audit_receipts").fetchone()[0], 1)
            self.assertEqual(con.execute("SELECT count(*) FROM runs WHERE status='completed'").fetchone()[0], 1)
            con.execute("DELETE FROM source_audit_receipts")
            con.commit()
        with self.assertRaises(ExecutionDenied): restarted.research(self.audit_policy, self.audit_bundle, accept=True, seconds=2)

    def test_integrated_action_pins_inputs_and_routes_to_existing_reporter(self):
        from aegis_integrated_assessment import IntegratedAssessment
        self.save_research()
        path = self.fx.fx.p/"integrated-research.json"
        policy = {"schema_version": 1, "configured": True, "engagement_ids": [self.policy["engagement_id"]],
                  "repository": self.policy["repository"], "lease_seconds": 90,
                  "steps": [{"id": "research", "action": "source_audit", "seconds": 5,
                             "audit_policy": str(self.audit_policy), "audit_bundle": str(self.audit_bundle)},
                            {"id": "report", "action": "report", "source": "research"}]}
        path.write_bytes(canonical(policy)); path.chmod(0o600)
        controller = IntegratedAssessment(self.fx.fx.manifest_path, self.fx.fx.sig_path,
                                          self.fx.fx.trust_path, self.fx.state, path)
        audit = controller.create()["assessment_id"]
        self.assertEqual(controller.run(audit)["completed"], 2)
        self.audit_bundle.write_bytes(canonical(self.bundle) + b" ")
        with self.assertRaises(ExecutionDenied): controller.snapshot(audit)
