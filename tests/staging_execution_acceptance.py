"""Restricted relay policy and real disposable Nuclei execution acceptance."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

from aegis_audit_contract import canonical
from aegis_staging_execution import CONTEXT, NUCLEI_SHA256, StagingExecutionSupervisor, validate_template
from aegis_staging_protocol import PROFILE, decode_frame, encode_frame
from aegis_staging_sandbox import parse_proxy_request
from aegis_supervisor import ExecutionDenied, operator_stop
import test_preflight

BINARY = Path(os.environ.get("AEGIS_TEST_NUCLEI", "/opt/aegis-scanner-fixtures/nuclei-v3.3.8/nuclei"))
TEMPLATE = Path(__file__).parent/"fixtures"/"scanner-exports"/"nuclei-fixture.yaml"


class StagingKernelTests(unittest.TestCase):
    def setUp(self):
        if not BINARY.is_file():
            self.fail("Pinned Nuclei fixture binary required; set AEGIS_TEST_NUCLEI")
        self.fx = test_preflight.AegisPreflightTests("test_valid_signed_scope")
        self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        self.logs, self.mutations = [], []
        logs, mutations = self.logs, self.mutations
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                record={"method":"GET","path":self.path,"headers":dict(self.headers),"started":time.monotonic()}
                logs.append(record)
                if self.path == "/slow":
                    time.sleep(3)
                if self.path.startswith("/medium"):
                    time.sleep(.3)
                if self.path == "/redirect":
                    self.send_response(302); self.send_header("Location", "http://outside.invalid/private"); self.end_headers(); return
                if self.path == "/chunked":
                    self.send_response(200);self.send_header("Transfer-Encoding","chunked");self.end_headers()
                    try:self.wfile.write(b"0\r\n\r\n")
                    except (BrokenPipeError,ConnectionResetError):pass
                    return
                self.send_response(200); self.send_header("Content-Type", "text/plain"); self.send_header("Set-Cookie", "PRIVATE_COOKIE_CANARY"); self.end_headers()
                try:
                    self.wfile.write(b"x"*32769 if self.path == "/huge" else b"AEGIS_SYNTHETIC_MARKER PRIVATE_BODY_CANARY" if self.path != "/control" else b"safe control")
                except (BrokenPipeError, ConnectionResetError):
                    pass
                record["ended"]=time.monotonic()
            def do_HEAD(self):
                logs.append({"method":"HEAD","path":self.path,"headers":dict(self.headers)})
                self.send_response(200); self.end_headers()
            def do_POST(self):
                mutations.append(self.path); self.send_response(405); self.end_headers()
            def log_message(self, *args):
                pass
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(self.server.server_close); self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.origin = "http://127.0.0.1:"+str(self.server.server_port)
        self.fx.manifest["targets"].update(origins=[self.origin], networks=["127.0.0.1/32"], excluded_networks=[])
        self.fx.manifest["accounts"] = []
        self.fx.manifest["methods"]["allowed"] = ["controlled_http_testing"]
        self.fx.manifest["limits"].update(engagement_runtime_minutes=5, max_single_run_minutes=2,
            deterministic_hypothesis_minutes=1, max_total_requests=10, max_requests_per_minute_per_origin=10,
            max_concurrent_requests=1, max_response_body_bytes=32768, max_total_response_bytes=327680)
        self.fx.trust.update(allowed_origins=[self.origin], allowed_networks=["127.0.0.1/32"], approved_methods=["controlled_http_testing"],
                             allowed_http_path_prefixes={self.origin:["/"]})
        self.fx.save()
        self.state = self.fx.p/"staging-state"; self.state.mkdir(mode=0o700)
        self.template = self.fx.p/"template.yaml"; self.template.write_bytes(TEMPLATE.read_bytes()); self.template.chmod(0o600)
        self.path = self.fx.p/"staging-profile.json"; self.signature = self.fx.p/"staging-profile.sig"
        self.profile = {"schema_version":1,"configured":True,"engagement_id":self.fx.manifest["engagement"]["id"],
            "operation_id":str(uuid.uuid4()),"profile":PROFILE,"executable":{"path":str(BINARY),"sha256":NUCLEI_SHA256},
            "configuration":{"path":str(self.template),"sha256":hashlib.sha256(self.template.read_bytes()).hexdigest()},
            "origin":self.origin,"routes":["/fixture"],"networks":["127.0.0.1/32"],"methods":["GET"],
            "test_identity":"anonymous-disposable-staging","mutation_permitted":False,"deployment_sha256":"d"*64,
            "valid_from_utc":self.fx.manifest["engagement"]["valid_from_utc"],"valid_until_utc":self.fx.manifest["engagement"]["valid_until_utc"],
            "seconds":20,"max_requests":1,"max_requests_per_minute":10,"body_limit":16384,"rule_id":"aegis-fixture-marker"}
        self.save()
        self.supervisor = StagingExecutionSupervisor(self.fx.manifest_path,self.fx.sig_path,self.fx.trust_path,self.state)

    def save(self):
        raw = canonical(self.profile); self.path.write_bytes(raw); self.path.chmod(0o600)
        self.signature.write_bytes(self.fx.key.sign(CONTEXT+raw)); self.signature.chmod(0o600)

    def run_profile(self):
        return self.supervisor.execute(self.path,self.signature)

    def events(self):
        with self.supervisor._database() as con:
            return [json.loads(row[0]) for row in con.execute("SELECT event FROM audit ORDER BY seq")]

    def probe(self, mode, error=None):
        if not hasattr(type(self), "probe_binary"):
            with tempfile.TemporaryDirectory(prefix="aegis-staging-probe-") as directory:
                output=Path(directory)/"probe"
                subprocess.run(["/usr/bin/cc","-static","-O2","-o",str(output),
                    str(Path(__file__).parent/"fixtures"/"staging-native-probe.c")],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                type(self).probe_binary=output.read_bytes()
        self.template.write_bytes(TEMPLATE.read_bytes().replace(b"AEGIS_SYNTHETIC_MARKER",mode.encode()))
        self.profile["configuration"]["sha256"]=hashlib.sha256(self.template.read_bytes()).hexdigest()
        self.save()
        with mock.patch("aegis_staging_execution.binary_bytes",return_value=type(self).probe_binary):
            with self.assertRaisesRegex(ExecutionDenied,error) if error else self.assertRaises((ExecutionDenied,ValueError,OSError)):
                self.run_profile()

    def test_workflow_ceiling_denies_before_any_reservation_or_launch(self):
        with mock.patch.object(self.supervisor,"reserve",side_effect=AssertionError("unexpected reservation")), \
             mock.patch("aegis_staging_execution.binary_bytes",side_effect=AssertionError("unexpected binary preparation")):
            with self.assertRaisesRegex(ExecutionDenied,"workflow ceiling"):
                self.supervisor.execute(self.path,self.signature,max_seconds=1)
            for ceiling in (0,True,121,"20"):
                with self.assertRaises(ExecutionDenied):
                    self.supervisor.execute(self.path,self.signature,max_seconds=ceiling)
        self.assertFalse(self.logs)

    def test_real_positive_and_control_only_reach_selected_route(self):
        result = self.run_profile()
        self.assertEqual(result["observations"],1)
        self.assertEqual(result["requests_completed"],1)
        self.assertEqual([(r["method"],r["path"]) for r in self.logs],[("GET","/fixture")])
        self.assertFalse(self.mutations)
        self.assertEqual(self.logs[0]["headers"]["User-Agent"],"AEGIS-restricted-staging/1")
        for header in ("Authorization","Cookie","Proxy-Authorization"):
            self.assertNotIn(header,self.logs[0]["headers"])
        info,_ = self.supervisor._guard()
        for file in Path(info["report_directory"]).rglob("*"):
            if file.is_file():
                self.assertNotIn(b"PRIVATE_BODY_CANARY",file.read_bytes())
                self.assertNotIn(b"PRIVATE_COOKIE_CANARY",file.read_bytes())
        with self.assertRaises(ExecutionDenied):
            self.run_profile()
        self.assertEqual(len(self.logs),1)
        self.profile.update(operation_id=str(uuid.uuid4()),routes=["/control"]); self.save()
        result = self.run_profile()
        self.assertEqual(result["observations"],0)
        self.assertEqual([r["path"] for r in self.logs],["/fixture","/control"])

    def test_actual_native_probe_denies_direct_network_process_and_filesystem_escape(self):
        self.probe("PROBE_NETWORK")
        expected=("DIRECT_NETWORK_BLOCKED\nUDP_BLOCKED\nUNIX_BLOCKED\nFORK_BLOCKED\nUNSHARE_BLOCKED\n"
                  "HOST_FILES_BLOCKED\nPROC_BLOCKED\nNO_NEW_PRIVS\nCAPABILITIES_DROPPED\nTMP_EXEC_BLOCKED\n").encode()
        aborted=[e for e in self.events() if e["type"]=="staging_execution_aborted"][-1]
        self.assertTrue(aborted["boundary_ready"])
        self.assertEqual(aborted["stdout_sha256"],hashlib.sha256(expected).hexdigest())
        self.assertFalse(self.logs)

    def test_actual_relay_and_broker_reject_wrong_origin_route_method_credentials_and_framing(self):
        for mode in ("PROBE_ORIGIN","PROBE_ROUTE","PROBE_METHOD","PROBE_COOKIE","PROBE_PROXY_AUTH","PROBE_BODY","PROBE_DUPLICATE","PROBE_PIPELINE"):
            with self.subTest(mode=mode):
                self.profile["operation_id"]=str(uuid.uuid4())
                self.probe(mode)
                self.assertFalse(self.logs)
        self.assertFalse(self.mutations)

    def test_request_exhaustion_stops_actual_second_dispatch(self):
        self.probe("PROBE_REPEAT")
        self.assertEqual([r["path"] for r in self.logs],["/fixture"])
        self.assertEqual(self.supervisor.http_usage(self.profile["engagement_id"])["reserved_requests"],1)

    def test_concurrent_scanner_connections_dispatch_serially(self):
        self.profile.update(routes=["/medium1","/medium2"],max_requests=2)
        self.probe("PROBE_CONCURRENT")
        self.assertEqual([r["path"] for r in self.logs],["/medium1","/medium2"])
        self.assertLessEqual(self.logs[0]["ended"],self.logs[1]["started"])
        self.assertFalse(self.mutations)

    def test_oversized_response_aborts_without_partial_success(self):
        for route in ("/huge","/chunked"):
            self.profile.update(operation_id=str(uuid.uuid4()),routes=[route]);self.save()
            with self.assertRaisesRegex(ExecutionDenied,"bounded broker"):
                self.run_profile()
        self.assertEqual([r["path"] for r in self.logs],["/huge","/chunked"])
        self.assertFalse(any(e["type"]=="scanner_execution_completed" for e in self.events()))

    def test_real_head_request_has_no_body_or_mutation(self):
        self.template.write_bytes(TEMPLATE.read_bytes().replace(b"method: GET",b"method: HEAD"))
        self.profile.update(methods=["HEAD"],configuration={"path":str(self.template),"sha256":hashlib.sha256(self.template.read_bytes()).hexdigest()})
        self.save()
        result=self.run_profile()
        self.assertEqual(result["observations"],0)
        self.assertEqual([(r["method"],r["path"]) for r in self.logs],[("HEAD","/fixture")])
        self.assertFalse(self.mutations)

    def test_rate_exhaustion_keeps_completed_attempt_and_never_reports_success(self):
        self.profile.update(routes=["/fixture","/control"],max_requests=2,max_requests_per_minute=1)
        self.save()
        with self.assertRaises(ExecutionDenied):
            self.run_profile()
        self.assertEqual(len(self.logs),1)
        self.assertFalse(any(e["type"]=="scanner_execution_completed" for e in self.events()))

    def test_wrong_resolved_ip_and_redirect_never_escape(self):
        with mock.patch.object(self.supervisor,"_resolve",return_value=["127.0.0.2"]):
            with self.assertRaises((ExecutionDenied,ValueError)):
                self.run_profile()
        self.assertFalse(self.logs)
        self.profile.update(operation_id=str(uuid.uuid4()),routes=["/redirect"]);self.save()
        with self.assertRaises((ExecutionDenied,ValueError)):
            self.run_profile()
        self.assertEqual([r["path"] for r in self.logs],["/redirect"])

    def test_stop_revocation_and_profile_signature_tampering_cancel_an_active_request(self):
        for action in ("stop","revoke","signature","profile"):
            with self.subTest(action=action):
                self.profile.update(operation_id=str(uuid.uuid4()),routes=["/slow"]);self.save()
                previous=len(self.logs)
                def cancel():
                    deadline=time.monotonic()+5
                    while len(self.logs)==previous and time.monotonic()<deadline:
                        time.sleep(.02)
                    if action=="stop":
                        operator_stop(self.state,self.profile["engagement_id"])
                    elif action=="revoke":
                        self.fx.trust["revoked_engagement_ids"]=[self.profile["engagement_id"]];self.fx.save()
                    elif action=="signature":
                        self.signature.write_bytes(b"x"*64)
                    else:
                        self.profile["body_limit"]-=1;self.save()
                thread=threading.Thread(target=cancel);thread.start()
                pattern={"stop":"emergency stop", "revoke":"revoked", "signature":"signature", "profile":"protected staging inputs changed|signature"}[action]
                with self.assertRaisesRegex(ExecutionDenied,pattern):
                    self.run_profile()
                thread.join(timeout=6)
                self.assertEqual(len(self.logs),previous+1)
                # Restore operator controls only inside this synthetic test fixture.
                if action=="stop":
                    (self.state/(self.profile["engagement_id"]+".stop")).unlink()
                elif action=="revoke":
                    self.fx.trust["revoked_engagement_ids"]=[];self.fx.save()
                self.save()
                with self.assertRaises(ExecutionDenied):self.run_profile()
                self.assertEqual(len(self.logs),previous+1)

    def test_expired_profile_denies_and_running_profile_expiry_terminates(self):
        self.profile["valid_until_utc"]=(datetime.now(timezone.utc)-timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ");self.save()
        with self.assertRaises(ExecutionDenied):self.run_profile()
        self.assertFalse(self.logs)
        self.profile.update(routes=["/slow"],valid_until_utc=(datetime.now(timezone.utc)+timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ"));self.save()
        self.probe("PROBE_REPEAT",error="profile is expired")
        self.assertEqual(len(self.logs),1)

    def test_supervisor_crash_terminates_descendants_and_recovery_never_replays(self):
        self.profile.update(routes=["/slow"]);self.save()
        def identity(pid):
            try:
                tail=Path("/proc",str(pid),"stat").read_text().rsplit(") ",1)[1].split()
                return tail[19],tail[0]
            except (FileNotFoundError,ProcessLookupError):
                return None
        def descendants(pid):
            found={}
            try:children=Path("/proc",str(pid),"task",str(pid),"children").read_text().split()
            except (FileNotFoundError,ProcessLookupError):return found
            for value in children:
                child=int(value);found[child]=identity(child);found.update(descendants(child))
            return found
        worker=subprocess.Popen([sys.executable,"-m","aegis_staging_execution","--manifest",str(self.fx.manifest_path),
            "--signature",str(self.fx.sig_path),"--trust",str(self.fx.trust_path),"--state-root",str(self.state),
            "--profile",str(self.path),"--profile-signature",str(self.signature)],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        children={}
        try:
            deadline=time.monotonic()+8
            while not self.logs and worker.poll() is None and time.monotonic()<deadline:time.sleep(.02)
            self.assertEqual(len(self.logs),1,"crash must occur after actual dispatch")
            children=descendants(worker.pid)
            self.assertGreaterEqual(len(children),3,"scanner, relay and fetch helper must be active")
            worker.kill();worker.communicate(timeout=5)
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                alive={pid for pid,old in children.items() if old and (current:=identity(pid)) and current[0]==old[0] and current[1]!="Z"}
                if not alive:break
                time.sleep(.02)
            self.assertFalse(alive,"supervisor death left live descendants")
            with self.assertRaises(ExecutionDenied):self.run_profile()
            interrupted=[e for e in self.events() if e["type"]=="staging_execution_interrupted"]
            self.assertEqual(len(interrupted),1)
            self.assertFalse(interrupted[0]["requests_replayed"])
            self.assertEqual(len(self.logs),1)
            self.assertEqual(self.supervisor.http_usage(self.profile["engagement_id"])["reserved_requests"],1)
        finally:
            if worker.poll() is None:worker.kill()
            for pid,old in children.items():
                current=identity(pid)
                if old and current and current[0]==old[0] and current[1]!="Z":
                    try:os.kill(pid,9)
                    except ProcessLookupError:pass
            worker.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
