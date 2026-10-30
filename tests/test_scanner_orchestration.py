"""Governed scans preserve fixed workflow, repository and recovery boundaries."""
from pathlib import Path
import uuid
from unittest.mock import patch

from aegis_model_adapter import parse_model_decision
from aegis_reporting import canonical
from aegis_supervisor import ExecutionDenied
from test_v20_integrated import IntegratedFixture


class ScannerOrchestrationTests(IntegratedFixture):
    def prepare(self, kind):
        profile = self.fx.fx.p / "scanner-profile.json"
        profile.write_bytes(canonical({"configured": True}))
        profile.chmod(0o600)
        entry = {"id": "scanner", "action": kind, "seconds": 10}
        if kind == "scanner_execute":
            entry["scanner_execution_policy"] = str(profile)
        else:
            signature = self.fx.fx.p / "scanner-profile.sig"
            signature.write_bytes(b"signature-pinned-by-controller")
            signature.chmod(0o600)
            entry.update(staging_profile=str(profile), staging_signature=str(signature))
            self.fx.fx.manifest["methods"]["allowed"].append("controlled_http_testing")
            self.fx.fx.trust["approved_methods"].append("controlled_http_testing")
            self.fx.fx.save()
        self.policy["steps"] = [entry, {"id": "render", "action": "report", "source": "scanner"}]
        self.save()
        return entry, profile

    def test_fixed_dispatch_preserves_input_and_runtime_caps(self):
        for kind, module, supervisor, status in (
                ("scanner_execute", "aegis_scanner_execution", "ScannerExecutionSupervisor", "SCANNER_EXECUTION_COMPLETED_UNVERIFIED"),
                ("staging_dast", "aegis_staging_execution", "StagingExecutionSupervisor", "STAGING_EXECUTION_COMPLETED_UNVERIFIED")):
            with self.subTest(kind=kind):
                entry, profile = self.prepare(kind)
                engine = self.controller()
                plan = engine.create()["assessment_id"]
                execution_id, imported_id = str(uuid.uuid4()), str(uuid.uuid4())
                with patch(module + "." + supervisor + ".execute", return_value={
                        "status": status, "execution_run_id": execution_id,
                        "import": {"status": "SCANNER_IMPORT_RECORDED", "run_id": imported_id}}) as execute:
                    engine.advance(plan)
                    args, kwargs = execute.call_args
                    self.assertEqual(args[0], profile)
                    self.assertEqual(kwargs["max_seconds"], 10)
                    if kind == "scanner_execute":
                        self.assertEqual(kwargs["expected_repository"], self.fx.fx.repo)
                    else:
                        self.assertEqual(args[1], Path(entry["staging_signature"]))
                result = engine.snapshot(plan)["steps"][0]["result"]
                self.assertEqual(result["execution_run_id"], execution_id)
                self.assertEqual(result["run_id"], imported_id)
                self.assertEqual(result["evidence"], "scanner-import.json")

    def test_unadmitted_execution_enters_attention_without_automatic_retry(self):
        self.prepare("scanner_execute")
        engine = self.controller()
        plan = engine.create()["assessment_id"]
        with patch("aegis_scanner_execution.ScannerExecutionSupervisor.execute", return_value={
                "status": "SCANNER_EXECUTION_COMPLETED_UNVERIFIED", "execution_run_id": str(uuid.uuid4())}) as execute:
            with self.assertRaises(ExecutionDenied):
                engine.advance(plan)
            with self.assertRaisesRegex(ExecutionDenied, "reconciliation"):
                engine.advance(plan)
            self.assertEqual(execute.call_count, 1)
        self.assertEqual(engine.snapshot(plan)["status"], "REQUIRES_OPERATOR_RECONCILIATION")

    def test_changed_profile_and_signature_invalidate_existing_plan(self):
        for kind in ("scanner_execute", "staging_dast"):
            entry, profile = self.prepare(kind)
            for selected in ([profile] if kind == "scanner_execute" else [profile, Path(entry["staging_signature"])]):
                engine = self.controller()
                plan = engine.create()["assessment_id"]
                selected.write_bytes(selected.read_bytes() + b" ")
                with self.assertRaises(ExecutionDenied):
                    engine.advance(plan)

    def test_staging_needs_signed_method_and_cannot_take_profile_from_target(self):
        entry, profile = self.prepare("staging_dast")
        self.fx.fx.manifest["methods"]["allowed"].remove("controlled_http_testing")
        self.fx.fx.save()
        with self.assertRaises(ExecutionDenied):
            self.controller().create()
        self.fx.fx.manifest["methods"]["allowed"].append("controlled_http_testing")
        self.fx.fx.save()
        target_profile = self.fx.fx.repo / "profile.json"
        target_profile.write_bytes(profile.read_bytes())
        target_profile.chmod(0o600)
        entry["staging_profile"] = str(target_profile)
        self.save()
        with self.assertRaises(ExecutionDenied):
            self.controller().create()

    def test_model_cannot_supply_runtime_profile_or_scanner_arguments(self):
        for kind in ("scanner_execute", "staging_dast"):
            decision = {"operation": "propose", "step_id": "scanner", "expected_action": kind}
            self.assertEqual(parse_model_decision(canonical(decision)), ("propose", "scanner", kind))
            for field in ("seconds", "profile", "command", "url"):
                with self.assertRaises(ExecutionDenied):
                    parse_model_decision(canonical({**decision, field: "attacker-selected"}))
            for invalid in ([], {}, None):
                with self.assertRaises(ExecutionDenied):
                    parse_model_decision(canonical({**decision, "expected_action": invalid}))
