"""Independent review regressions: no action claim after operator abandonment."""
from unittest.mock import patch
import unittest

from aegis_supervisor import ExecutionDenied
from test_v20_integrated import IntegratedFixture


class OperatorReconciliationRaceTests(IntegratedFixture):
    def test_abandon_between_snapshot_and_lease_claim_is_terminal(self):
        runner = self.controller()
        operator = self.controller()
        workflow = runner.create()["assessment_id"]
        info, policy, digest = runner._admit()
        original_rows = runner._rows
        def raced_rows(*args, **kwargs):
            rows = original_rows(*args, **kwargs)
            self.assertEqual(operator.abandon(workflow, "operator_cancelled")["status"],
                             "ABANDONED_REQUIRES_OPERATOR_REVIEW")
            return rows
        with patch.object(runner, "_rows", side_effect=raced_rows):
            with self.assertRaisesRegex(ExecutionDenied, "abandoned"):
                runner._claim(workflow, info, policy, digest)
        snapshot = operator.snapshot(workflow)
        self.assertEqual(snapshot["steps"][0]["state"], "pending")
        self.assertEqual(snapshot["status"], "ABANDONED_REQUIRES_OPERATOR_REVIEW")
        self.assertTrue(operator.verify_audit_chain())

    def test_abandon_cannot_race_a_newly_claimed_live_lease(self):
        operator = self.controller()
        runner = self.controller()
        workflow = operator.create()["assessment_id"]
        original_rows = operator._rows
        def raced_rows(*args, **kwargs):
            rows = original_rows(*args, **kwargs)
            info, policy, digest = runner._admit()
            self.assertIsNotNone(runner._claim(workflow, info, policy, digest))
            return rows
        with patch.object(operator, "_rows", side_effect=raced_rows):
            with self.assertRaisesRegex(ExecutionDenied, "live worker lease"):
                operator.abandon(workflow, "operator_cancelled")
        snapshot = runner.snapshot(workflow)
        self.assertEqual(snapshot["steps"][0]["state"], "leased")
        self.assertEqual(snapshot["status"], "IN_PROGRESS")
        self.assertTrue(runner.verify_audit_chain())

    def test_successful_reconciliation_blocks_all_later_claims(self):
        operator = self.controller()
        workflow = operator.create()["assessment_id"]
        operator.abandon(workflow, "deployment_recovery_required")
        runner = self.controller()
        info, policy, digest = runner._admit()
        with self.assertRaisesRegex(ExecutionDenied, "abandoned"):
            runner._claim(workflow, info, policy, digest)
        with self.assertRaisesRegex(ExecutionDenied, "abandoned"):
            runner.advance(workflow)
        self.assertTrue(runner.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()

class OfflineDelegationKeyFileTests(unittest.TestCase):
    def test_private_key_loader_denies_symlink_hardlink_and_oversized_file(self):
        import os
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from aegis_agent_client import _private_file
        with TemporaryDirectory() as d:
            root = Path(d)
            key = root / "key.pem"
            key.write_bytes(b"synthetic-key")
            key.chmod(0o600)
            self.assertEqual(_private_file(key), b"synthetic-key")
            alias = root / "alias.pem"
            alias.symlink_to(key)
            with self.assertRaises((ExecutionDenied, OSError)):
                _private_file(alias)
            linked = root / "linked.pem"
            os.link(key, linked)
            with self.assertRaises(ExecutionDenied):
                _private_file(key)
            linked.unlink()
            key.write_bytes(b"x" * 8193)
            with self.assertRaises(ExecutionDenied):
                _private_file(key)

    def test_private_key_loader_denies_world_readable_and_relative_paths(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from aegis_agent_client import _private_file
        with TemporaryDirectory() as d:
            key = Path(d) / "key.pem"
            key.write_bytes(b"synthetic")
            key.chmod(0o644)
            with self.assertRaises(ExecutionDenied):
                _private_file(key)
            with self.assertRaises(ExecutionDenied):
                _private_file(Path("relative.pem"))
