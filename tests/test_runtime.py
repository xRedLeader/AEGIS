from __future__ import annotations

import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from aegis_supervisor import AegisSupervisor, ExecutionDenied, operator_stop


class AegisRuntimeTests(unittest.TestCase):
    def setUp(self):
        from test_preflight import AegisPreflightTests
        self.fx = AegisPreflightTests("test_valid_signed_scope")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.state = self.fx.p / "state"
        self.state.mkdir(mode=0o700)
        self.fx.manifest["targets"]["origins"] = []
        self.fx.manifest["accounts"] = []
        self.fx.manifest["methods"]["allowed"] = ["source_review"]
        self.fx.manifest["limits"]["max_total_requests"] = 0
        self.fx.manifest["limits"]["max_requests_per_minute_per_origin"] = 0
        self.fx.manifest["limits"]["max_concurrent_requests"] = 0
        self.fx.manifest["limits"]["engagement_runtime_minutes"] = 1
        self.fx.manifest["limits"]["max_single_run_minutes"] = 1
        self.fx.manifest["limits"]["deterministic_hypothesis_minutes"] = 1
        self.fx.trust["approved_methods"] = ["source_review"]
        self.fx.save()
        (self.fx.repo / "app.py").write_text('import subprocess\nsubprocess.run("hello", shell=True)\n')

    def supervisor(self):
        return AegisSupervisor(self.fx.manifest_path, self.fx.sig_path, self.fx.trust_path, self.state)

    def test_real_readonly_review_and_canonical_artifact(self):
        s = self.supervisor()
        result = s.scan(self.fx.repo, budget_seconds=5)
        self.assertEqual(result["status"], "COMPLETED_STATIC_REVIEW_ONLY")
        self.assertEqual(result["unverified_leads"], 1)
        out = json.loads(Path(result["report"]).read_text())
        self.assertEqual(out["candidates"][0]["id"], "PY-SHELL-TRUE")
        self.assertEqual(out["candidates"][0]["status"], "unverified_static_lead")
        self.assertTrue(s.verify_audit_chain())
        self.assertEqual(s.usage(result["engagement_id"])["reserved_seconds"], 5)
        self.assertFalse((self.fx.repo / "source-review.json").exists())

    def test_out_of_scope_path_is_blocked_before_reservation(self):
        another = self.fx.p / "other"
        another.mkdir()
        (another / "danger.py").write_text('eval("1+1")')
        with self.assertRaisesRegex(ExecutionDenied, "outside verified"):
            self.supervisor().scan(another, 5)
        self.assertFalse((self.state / "ledger.sqlite3").exists())

    def test_unlisted_method_blocks_execution(self):
        self.fx.manifest["methods"]["allowed"] = ["dependency_analysis"]
        self.fx.trust["approved_methods"] = ["dependency_analysis"]
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "source_review is not authorized"):
            self.supervisor().scan(self.fx.repo, 5)

    def test_symlinks_not_followed_by_worker(self):
        outside = self.fx.p / "unapproved_data.py"
        outside.write_text('eval("UNAUTHORIZED")')
        (self.fx.repo / "escape.py").symlink_to(outside)
        (self.fx.repo / "escape_dir").symlink_to(self.fx.p)
        result = self.supervisor().scan(self.fx.repo, 5)
        data = json.loads(Path(result["report"]).read_text())
        self.assertEqual(len(data["candidates"]), 1)
        self.assertGreaterEqual(data["summary"]["symlinks_skipped"], 2)

    def test_cumulative_budget_survives_new_supervisor_instance(self):
        first = self.supervisor().scan(self.fx.repo, 31)
        self.assertEqual(first["reserved_runtime_seconds"], 31)
        with self.assertRaisesRegex(ExecutionDenied, "cumulative runtime budget"):
            self.supervisor().scan(self.fx.repo, 30)
        self.assertEqual(self.supervisor().usage(first["engagement_id"])["reserved_seconds"], 31)

    def test_emergency_stop_denies_new_execution(self):
        operator_stop(self.state, self.fx.manifest["engagement"]["id"])
        with self.assertRaisesRegex(ExecutionDenied, "emergency stop"):
            self.supervisor().scan(self.fx.repo, 5)

    def test_revocation_denies_operation(self):
        self.fx.trust["revoked_engagement_ids"].append(self.fx.manifest["engagement"]["id"])
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "revoked"):
            self.supervisor().scan(self.fx.repo, 5)

    def test_modified_manifest_signature_denies_operation(self):
        self.fx.manifest_path.write_bytes(self.fx.manifest_path.read_bytes() + b"# changed after sign")
        with self.assertRaisesRegex(ExecutionDenied, "signature"):
            self.supervisor().scan(self.fx.repo, 5)

    def test_stale_revocation_denies_operation(self):
        self.fx.trust["revocation"]["last_checked_utc"] = "2022-01-01T00:00:00Z"
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "revocation snapshot stale"):
            self.supervisor().scan(self.fx.repo, 5)

    def test_report_dir_symlink_disallowed(self):
        evil = self.fx.p / "evil"
        evil.mkdir()
        (self.fx.report_root / self.fx.manifest["engagement"]["id"]).symlink_to(evil)
        with self.assertRaises((OSError, ExecutionDenied)):
            self.supervisor().scan(self.fx.repo, 5)
        self.assertFalse(list(evil.glob("**/*")))

    def test_protected_state_permissions_enforced(self):
        self.state.chmod(0o777)
        with self.assertRaisesRegex(ExecutionDenied, "0700"):
            self.supervisor().scan(self.fx.repo, 5)

    def test_audit_detects_modified_event(self):
        s = self.supervisor()
        s.scan(self.fx.repo, 5)
        with closing(sqlite3.connect(self.state / "ledger.sqlite3")) as con, con:
            con.execute("UPDATE audit SET event='tampered' WHERE seq=1")
        self.assertFalse(s.verify_audit_chain())

    def test_scope_change_requires_new_engagement_even_if_signed(self):
        s = self.supervisor()
        s.scan(self.fx.repo, 5)
        self.fx.manifest["limits"]["engagement_runtime_minutes"] = 2
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied, "scope hash changed"):
            self.supervisor().scan(self.fx.repo, 5)

    def test_parallel_reservations_are_atomic(self):
        results = []
        guard = threading.Lock()
        def do_scan():
            try:
                self.supervisor().scan(self.fx.repo, 35)
                result = "allowed"
            except ExecutionDenied:
                result = "denied"
            with guard:
                results.append(result)
        threads = [threading.Thread(target=do_scan), threading.Thread(target=do_scan)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), ["allowed", "denied"])

    def test_live_stop_interrupts_worker(self):
        s = self.supervisor()
        def slow(_):
            import sys
            return [sys.executable, "-I", "-S", "-c", "import time;time.sleep(8)"]
        with patch.object(s, "_worker_command", side_effect=slow):
            def trigger():
                time.sleep(0.5)
                operator_stop(self.state, self.fx.manifest["engagement"]["id"])
            t = threading.Thread(target=trigger)
            t.start()
            try:
                with self.assertRaisesRegex(ExecutionDenied, "emergency stop"):
                    s.scan(self.fx.repo, budget_seconds=4)
            finally:
                t.join()


    def test_evidence_reservations_are_cumulative(self):
        self.fx.manifest["limits"]["max_total_evidence_bytes"] = 32 * 1024
        self.fx.save()
        self.supervisor().scan(self.fx.repo, 5)
        with self.assertRaisesRegex(ExecutionDenied, "evidence budget"):
            self.supervisor().scan(self.fx.repo, 5)

    def test_worker_timed_out_and_killed(self):
        s = self.supervisor()
        def slow(_):
            import sys
            return [sys.executable, "-I", "-S", "-c", "import time;time.sleep(10)"]
        with patch.object(s, "_worker_command", side_effect=slow):
            started = time.monotonic()
            with self.assertRaisesRegex(ExecutionDenied, "runtime budget"):
                s.scan(self.fx.repo, budget_seconds=1)
            self.assertLess(time.monotonic() - started, 4)
            self.assertTrue(s.verify_audit_chain())

    def test_source_payload_cannot_execute_when_scanned(self):
        token = self.fx.p / "execution-marker"
        (self.fx.repo / "malicious.py").write_text(
            "from pathlib import Path\nPath(" + repr(str(token)) + ").write_text('EXECUTED')\n")
        self.supervisor().scan(self.fx.repo, 5)
        self.assertFalse(token.exists())

    def test_review_repo_with_symlinked_parent_denied(self):
        link = self.fx.p / "alias"
        link.symlink_to(self.fx.repo.parent, target_is_directory=True)
        linked_repo = link / self.fx.repo.name
        with self.assertRaises((ExecutionDenied, OSError)):
            self.supervisor().scan(linked_repo, 5)

    def test_report_directory_requires_private_permissions(self):
        output = self.fx.report_root / self.fx.manifest["engagement"]["id"]
        output.mkdir(mode=0o755)
        with self.assertRaisesRegex(ExecutionDenied, "private report directory"):
            self.supervisor().scan(self.fx.repo, 5)

    def test_midrun_revocation_interrupts_worker(self):
        s = self.supervisor()
        def slow(_):
            import sys
            return [sys.executable, "-I", "-S", "-c", "import time;time.sleep(8)"]
        with patch.object(s, "_worker_command", side_effect=slow):
            def revoke():
                time.sleep(0.5)
                self.fx.trust["revoked_engagement_ids"] = [self.fx.manifest["engagement"]["id"]]
                self.fx.save()
            thread = threading.Thread(target=revoke)
            thread.start()
            try:
                with self.assertRaisesRegex(ExecutionDenied, "revoked"):
                    s.scan(self.fx.repo, budget_seconds=4)
            finally:
                thread.join()

    def test_cli_can_execute_with_operator_pinned_env(self):
        import subprocess
        import sys
        module = Path(__file__).resolve().parents[1] / "aegis_supervisor.py"
        env = {**os.environ, "AEGIS_TRUST_POLICY": str(self.fx.trust_path),
               "AEGIS_STATE_ROOT": str(self.state)}
        result = subprocess.run([sys.executable, str(module), "--manifest", str(self.fx.manifest_path),
                                 "--signature", str(self.fx.sig_path), "scan",
                                 "--repo", str(self.fx.repo), "--seconds", "5"],
                                capture_output=True, text=True, env=env, check=True)
        self.assertEqual(json.loads(result.stdout)["status"], "COMPLETED_STATIC_REVIEW_ONLY")

    def test_cli_without_protected_env_denied(self):
        import subprocess
        import sys
        module = Path(__file__).resolve().parents[1] / "aegis_supervisor.py"
        env = dict(os.environ)
        env.pop("AEGIS_TRUST_POLICY", None)
        env.pop("AEGIS_STATE_ROOT", None)
        result = subprocess.run([sys.executable, str(module), "--manifest", str(self.fx.manifest_path),
                                 "--signature", str(self.fx.sig_path), "scan",
                                 "--repo", str(self.fx.repo)],
                                capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 2)
        self.assertIn("DENIED", result.stderr)


if __name__ == "__main__":
    unittest.main()
