"""Synthetic provider integration and paid-call boundary regressions; no live API calls."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from aegis_audit_contract import canonical, digest, source_snapshot
from aegis_audit_providers import ClaudeProvider, FakeProvider, ProviderFailure, SYNTHETIC_SOURCE
from aegis_provider_runner import ProviderRunner, require_no_secrets
from aegis_claude_transport import main as transport_main
from aegis_reporting import verified_package
from aegis_source_audit import SourceAuditSupervisor
from aegis_supervisor import ExecutionDenied, operator_stop
from test_v18_reporting import ReportFixture
from test_v21_source_audit import ResearchFixture


class ProviderFixture(ResearchFixture, ReportFixture):
    def setUp(self):
        super().setUp()
        self.prepare(str(self.fx.fx.repo), self.fx.fx.manifest["engagement"]["id"])
        (self.fx.fx.repo/"app.py").write_text(SYNTHETIC_SOURCE)
        self.snapshot = source_snapshot(self.fx.fx.repo, ["app.py"])
        self.audit_path = self.fx.fx.p/"source-audit-policy.json"
        self.audit_path.write_bytes(canonical(self.policy)); self.audit_path.chmod(0o600)
        self.role_paths = {}
        for aid, key in self.keys.items():
            path = self.fx.fx.p/(aid+".key.pem")
            path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
            path.chmod(0o600); self.role_paths[aid] = str(path)
        self.runner_path = self.fx.fx.p/"runner.json"
        self.config = {"version": 1, "configured": True, "runner_id": "synthetic-test",
            "audit_policy": str(self.audit_path), "audit_policy_sha256": hashlib.sha256(self.audit_path.read_bytes()).hexdigest(),
            "run_directory": str(self.fx.fx.p/"runner-work"),
            "provider": {"kind": "fake", "model": "synthetic-v1", "api_key_file": None, "api_key_sha256": None,
                "input_token_reservation": 65536, "max_output_tokens": 2048,
                "input_microusd_per_token": 1, "output_microusd_per_token": 1},
            "source_export": {"approved": True, "classification": "synthetic", "paths": ["app.py"],
                "source_sha256": digest({p:v["sha256"] for p,v in self.snapshot.items()})},
            "role_keys": self.role_paths, "limits": {"max_calls": 12, "max_tokens": 1000000,
                "max_spend_microusd": 1000000, "max_wall_seconds": 120, "call_timeout_seconds": 1,
                "max_attempts_per_assignment": 2, "max_prompt_bytes": 131072, "max_response_bytes": 32768}}
        self.save_runner()

    def save_runner(self):
        self.runner_path.write_bytes(canonical(self.config)); self.runner_path.chmod(0o600)

    def runner(self):
        sup = SourceAuditSupervisor(self.fx.fx.manifest_path, self.fx.fx.sig_path, self.fx.fx.trust_path, self.fx.state)
        return ProviderRunner(sup, self.runner_path)


class ProviderRunnerTests(ProviderFixture):
    def test_fake_provider_completes_all_six_phases_without_network(self):
        with patch("subprocess.Popen", side_effect=AssertionError("fake provider must not launch a transport")):
            outcome = self.runner().run()
        self.assertEqual(outcome["status"], "PROVIDER_AUDIT_COMPLETED")
        self.assertEqual(outcome["reserved_calls"], 9)
        self.assertEqual(outcome["reserved_tokens"], 9*(65536+2048))
        self.assertEqual(outcome["reserved_microusd"], outcome["reserved_tokens"])
        again = self.runner().run()
        self.assertEqual(again, outcome)
        report = self.sup.generate(outcome["run_id"], "source-audit.json")
        document = verified_package(Path(report["report"]).parent, report["sha256"])
        self.assertEqual(document["findings"][0]["verdict"], "needs_validation")
        self.assertNotIn("severity", document["findings"][0])
        contexts = list(Path(self.config["run_directory"]).glob("context-*"))
        self.assertEqual(len(contexts), 9)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o700 and not list(p.iterdir()) for p in contexts))

    def test_exact_export_permission_and_policy_are_required_before_calls(self):
        for change in (lambda: self.config["source_export"].update(approved=False),
                       lambda: self.config["source_export"].update(source_sha256="0"*64),
                       lambda: self.config.update(audit_policy_sha256="0"*64)):
            original = json.loads(canonical(self.config))
            change(); self.save_runner()
            with patch.object(FakeProvider, "invoke", side_effect=AssertionError("not authorized")):
                with self.assertRaises(ExecutionDenied): self.runner().advance()
            self.config = original

    def test_stop_and_changed_role_key_block_invocation(self):
        self.config["role_keys"]["recon0"] = self.config["role_keys"]["hunter1"]
        self.save_runner()
        with self.assertRaises(ExecutionDenied): self.runner().advance()
        self.config["role_keys"]["recon0"] = str(self.fx.fx.p/"recon0.key.pem")
        self.save_runner()
        operator_stop(self.fx.state, self.policy["engagement_id"])
        with self.assertRaises(ExecutionDenied): self.runner().advance()

    def test_budget_is_reserved_before_call_and_cannot_reset_on_restart(self):
        self.config["limits"]["max_calls"] = 1; self.save_runner()
        self.assertEqual(self.runner().advance()["status"], "PROVIDER_PROGRESS")
        with self.assertRaises(ExecutionDenied): self.runner().advance()
        self.config["limits"]["max_calls"] = 12; self.save_runner()
        with self.assertRaises(ExecutionDenied): self.runner().advance()

    def test_token_and_spend_limits_prevent_calls(self):
        baseline = json.loads(canonical(self.config))
        for field in ("max_tokens", "max_spend_microusd"):
            with self.subTest(field=field):
                self.config = json.loads(canonical(baseline))
                self.config["runner_id"] = "limit-"+field
                self.config["limits"][field] = 1; self.save_runner()
                with patch.object(FakeProvider, "invoke", side_effect=AssertionError("budget prevents call")):
                    with self.assertRaises(ExecutionDenied): self.runner().advance()

    def test_offline_scope_signer_cannot_be_reused_as_research_identity(self):
        Path(self.role_paths["recon0"]).write_bytes(self.fx.fx.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        self.policy["agents"][0]["public_key"] = base64.b64encode(self.fx.fx.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
        self.audit_path.write_bytes(canonical(self.policy))
        self.config["audit_policy_sha256"] = hashlib.sha256(self.audit_path.read_bytes()).hexdigest()
        self.save_runner()
        with self.assertRaisesRegex(ExecutionDenied, "offline scope"): self.runner().advance()

    def test_single_writer_lock_prevents_concurrent_calls(self):
        with self.runner()._locked(Path(self.config["run_directory"])):
            with patch.object(FakeProvider, "invoke", side_effect=AssertionError("concurrent call")):
                with self.assertRaises(ExecutionDenied): self.runner().advance()

    def test_status_does_not_initialize_missing_ledger(self):
        self.assertEqual(self.runner().status()["status"], "PROVIDER_NOT_STARTED")
        self.assertFalse((self.fx.state/"ledger.sqlite3").exists())
        self.runner().advance()
        before = (self.fx.state/"ledger.sqlite3").read_bytes()
        self.assertEqual(self.runner().status()["reserved_calls"], 1)
        self.assertEqual(before, (self.fx.state/"ledger.sqlite3").read_bytes())

    def test_deleted_or_rolled_back_accounting_cannot_reset_charges(self):
        self.runner().advance()
        with self.sup._database() as con: con.execute("UPDATE provider_jobs SET calls=0")
        with self.assertRaises(ExecutionDenied): self.runner().advance()
        with self.sup._database() as con: con.execute("DELETE FROM provider_jobs")
        with self.assertRaises(ExecutionDenied): self.runner().advance()

    def test_crash_after_acceptance_resumes_without_duplicate_evidence(self):
        self.assertEqual(self.runner().run(9)["status"], "PROVIDER_PROGRESS")
        runner = self.runner()
        with patch.object(runner.sup, "generate", side_effect=RuntimeError("synthetic crash after receipt")):
            with self.assertRaises(RuntimeError): runner.advance()
        with self.sup._database() as con:
            before = con.execute("SELECT source_run_id FROM source_audit_receipts").fetchall()
        with patch.object(FakeProvider, "invoke", side_effect=AssertionError("no duplicate calls")):
            recovered = self.runner().run()
        with self.sup._database() as con:
            after = con.execute("SELECT source_run_id FROM source_audit_receipts").fetchall()
        self.assertEqual(before, after)
        self.assertEqual(after, [(recovered["run_id"],)])

    def test_uncertain_call_remains_charged_and_restart_uses_fresh_context(self):
        with patch.object(FakeProvider, "invoke", side_effect=ProviderFailure("TRANSPORT_UNCERTAIN", 0)):
            failed = self.runner().advance()
        self.assertEqual(failed["status"], "PROVIDER_RETRY_REQUIRED")
        with self.sup._database() as con:
            con.execute("UPDATE provider_attempts SET status='INFLIGHT'")
        outcome = self.runner().run()
        self.assertEqual(outcome["status"], "PROVIDER_AUDIT_COMPLETED")
        self.assertEqual(outcome["reserved_calls"], 10)
        self.assertEqual(outcome["reserved_tokens"], 10*(65536+2048))
        with self.sup._database() as con:
            counts = dict(con.execute("SELECT status,count(*) FROM provider_attempts GROUP BY status"))
        self.assertEqual(counts, {"ACCEPTED": 9, "UNCERTAIN": 1})

    def test_rate_limit_wait_and_invalid_response_do_not_admit_records(self):
        with patch.object(FakeProvider, "invoke", side_effect=ProviderFailure("RATE_LIMIT", 300)):
            self.assertEqual(self.runner().advance()["reason"], "RATE_LIMIT")
        self.assertEqual(self.runner().advance()["status"], "PROVIDER_RETRY_WAIT")
        with self.sup._database() as con:
            con.execute("UPDATE provider_attempts SET retry_after=0")
        with patch.object(FakeProvider, "invoke", return_value=({"tools": ["shell"]}, {})):
            outcome = self.runner().advance()
        self.assertEqual(outcome["status"], "PROVIDER_RETRY_REQUIRED")
        with self.sup._database() as con:
            bundle = json.loads(con.execute("SELECT bundle FROM provider_jobs").fetchone()[0])
        self.assertEqual(bundle["records"], [])

    def test_secret_in_response_never_enters_retained_state(self):
        secret = "sk-ant-THIS_IS_A_SYNTHETIC_SECRET_SENTINEL"
        with patch.object(FakeProvider, "invoke", return_value=({"summary": secret}, {})):
            outcome = self.runner().advance()
        self.assertEqual(outcome["status"], "PROVIDER_RETRY_REQUIRED")
        self.assertNotIn(secret.encode(), (self.fx.state/"ledger.sqlite3").read_bytes())
        self.assertNotIn(secret, json.dumps(outcome))

    def test_source_change_and_prompt_limit_prevent_export(self):
        self.config["limits"]["max_prompt_bytes"] = 4096; self.save_runner()
        with patch.object(FakeProvider, "invoke", side_effect=AssertionError("prompt should be denied")):
            with self.assertRaises(ExecutionDenied): self.runner().advance()
        (self.fx.fx.repo/"app.py").write_text("changed\n")
        with self.assertRaises(ExecutionDenied): self.runner().advance()

    def test_source_policy_change_during_call_is_not_signed(self):
        original = FakeProvider.invoke
        def changed(backend, *args, **kwargs):
            result = original(backend, *args, **kwargs)
            self.audit_path.write_bytes(self.audit_path.read_bytes()+b" ")
            return result
        with patch.object(FakeProvider, "invoke", changed):
            self.assertEqual(self.runner().advance()["status"], "PROVIDER_RETRY_REQUIRED")
        with self.sup._database() as con:
            self.assertEqual(json.loads(con.execute("SELECT bundle FROM provider_jobs").fetchone()[0])["records"], [])


class TransportTests(unittest.TestCase):
    def test_nested_credentials_and_secret_markers_are_blocked(self):
        for data in ({"prior": [{"description": "password = 'SYNTHETIC_PASSWORD_123456789'"}]},
                     {"source": ["-----BEGIN PRIVATE KEY-----"]}, {"result": ["a credential with quotes: abc\"def"]}):
            with self.assertRaises(ExecutionDenied): require_no_secrets(data, 'abc"def')

    def test_claude_request_is_stateless_fixed_and_rejects_tools(self):
        response = {"type": "message", "role": "assistant", "model": "claude-test-20261030", "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": '{"summary":"Synthetic response"}'}],
                    "usage": {"input_tokens": 100, "output_tokens": 20}, "id": "msg_synthetic"}
        class Process:
            returncode = 0
            stdin = io.BytesIO(); stdout = io.BytesIO()
            def communicate(self, input=None, timeout=None):
                self.input = input
                return canonical({"status":"OK","response_b64":base64.b64encode(canonical(response)).decode()}), None
            def poll(self): return 0
        process = Process()
        config = {"model": "claude-test-20261030", "max_output_tokens": 256, "input_token_reservation": 65536}
        limits = {"call_timeout_seconds": 1, "max_response_bytes": 32768}
        with patch("aegis_audit_providers.subprocess.Popen", return_value=process) as launch:
            result, usage = ClaudeProvider().invoke({"assignment": "synthetic"}, config, limits, "private-provider-key", lambda: None)
        transport = json.loads(process.input)
        request = json.loads(transport["body"])
        self.assertNotIn("private-provider-key", transport["body"])
        self.assertEqual(len(request["messages"]), 1)
        self.assertNotIn("tools", request)
        self.assertNotIn("HTTP_PROXY", launch.call_args.kwargs["env"])
        self.assertEqual(result, {"summary": "Synthetic response"})
        self.assertEqual(usage["input_tokens"], 100)
        response["content"] = [{"type":"text","text":json.dumps({"items": ["x"*200]*50})}]
        with patch("aegis_audit_providers.subprocess.Popen", return_value=process):
            large, _ = ClaudeProvider().invoke({}, config, limits, "private-provider-key", lambda: None)
        self.assertEqual(len(large["items"]), 50)
        for change in ({"model": "unexpected-model"}, {"stop_reason": "max_tokens"},
                       {"usage": {"input_tokens": 65537, "output_tokens": 20}}):
            original = json.loads(json.dumps(response))
            response.update(change)
            with patch("aegis_audit_providers.subprocess.Popen", return_value=process):
                with self.assertRaises(ExecutionDenied): ClaudeProvider().invoke({}, config, limits, "private-provider-key", lambda: None)
            response.clear(); response.update(original)
        response["content"] = [{"type":"tool_use","name":"shell"}]
        with patch("aegis_audit_providers.subprocess.Popen", return_value=process):
            with self.assertRaises(ExecutionDenied): ClaudeProvider().invoke({}, config, limits, "private-provider-key", lambda: None)

    def test_transport_timeout_kills_the_request(self):
        class Process:
            stdin = io.BytesIO(); stdout = io.BytesIO(); killed = False
            def poll(self): return None
            def kill(self): self.killed = True
            def wait(self): return 0
        process = Process()
        with patch("aegis_audit_providers.subprocess.Popen", return_value=process), \
             patch("aegis_audit_providers.time.monotonic", side_effect=[0, 2]):
            with self.assertRaises(ProviderFailure):
                ClaudeProvider().invoke({}, {"model":"claude-test", "max_output_tokens":256,"input_token_reservation":65536},
                                        {"call_timeout_seconds":1,"max_response_bytes":32768}, "private-key", lambda: None)
        self.assertTrue(process.killed)

    def test_underreserved_large_prompt_never_starts_paid_transport(self):
        with patch("aegis_audit_providers.subprocess.Popen") as launch:
            with self.assertRaisesRegex(ExecutionDenied, "request byte ceiling"):
                ClaudeProvider().invoke({"source": "x"*80000},
                    {"model":"claude-test","max_output_tokens":256,"input_token_reservation":1024},
                    {"call_timeout_seconds":1,"max_response_bytes":32768}, "synthetic-private-key", lambda: None)
        launch.assert_not_called()

    def test_fixed_https_endpoint_and_error_body_redaction(self):
        from unittest.mock import MagicMock
        response = MagicMock(status=429)
        response.getheader.return_value = "8"
        conn = MagicMock(); conn.getresponse.return_value = response
        request = {"body":'{"model":"synthetic-only"}', "api_key":"SYNTHETIC_PRIVATE_CREDENTIAL",
                   "timeout_seconds":1, "response_limit":1024}
        for status, expected in ((429, "RATE_LIMIT"), (302, "PROVIDER_ERROR")):
            response.status = status
            output = io.StringIO()
            with patch("aegis_claude_transport.http.client.HTTPSConnection", return_value=conn) as connect, \
                 patch("aegis_claude_transport.sys.stdin", io.TextIOWrapper(io.BytesIO(canonical(request)))), \
                 patch("aegis_claude_transport.sys.stdout", output):
                transport_main()
            self.assertEqual(connect.call_args.args, ("api.anthropic.com", 443))
            self.assertEqual(conn.request.call_args.args, ("POST", "/v1/messages"))
            self.assertEqual(json.loads(output.getvalue())["status"], expected)
            self.assertNotIn(request["api_key"], output.getvalue())
            response.read.assert_not_called()
