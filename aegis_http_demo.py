#!/usr/bin/env python3
"""AEGIS v1.4 self-contained, loopback-only HTTP gateway demonstration.

Starts a tiny local HTTP server and uses a short-lived, self-generated signed
scope, independent trust policy, and explicit /status+/redirect route grants.
It sends no internet or third-party requests and retains no signing keys.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import yaml

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_http_runtime import AegisHttpSupervisor
from aegis_preflight import SIGNING_CONTEXT

HERE = Path(__file__).resolve().parent


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.paths.append(self.path)
        if self.path == "/status":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/blocked")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_error(404)


def main():
    with tempfile.TemporaryDirectory(prefix="aegis-http-demo-") as temp:
        base = Path(temp)
        server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
        server.paths = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            reports, alerts, state = (base / key for key in ("reports", "alerts", "state"))
            for folder in (reports, alerts, state):
                folder.mkdir(mode=0o700)
            scope = yaml.safe_load((HERE / "security-scope.example.yaml").read_text())
            trust = json.loads((HERE / "trust-policy.example.json").read_text())
            now = datetime.now(timezone.utc)
            stamp = lambda time: time.strftime("%Y-%m-%dT%H:%M:%SZ")
            eid = "aegis-http-demo-001"
            scope["engagement"].update(id=eid, authorized_by="demo-operator@example.invalid",
                                        signer_id="demo-operator", valid_from_utc=stamp(now - timedelta(minutes=1)),
                                        valid_until_utc=stamp(now + timedelta(hours=1)))
            scope["targets"].update(repositories=[], origins=[origin],
                                    networks=["127.0.0.1/32"], excluded_origins=[],
                                    excluded_networks=[])
            scope["accounts"] = []
            scope["methods"]["allowed"] = ["controlled_http_testing"]
            scope["limits"].update(engagement_runtime_minutes=1, max_single_run_minutes=1,
                                   deterministic_hypothesis_minutes=1, max_total_requests=2,
                                   max_requests_per_minute_per_origin=2, max_concurrent_requests=1,
                                   max_response_body_bytes=1024, max_total_response_bytes=2048)
            scope["reporting"]["output_dir"] = str(reports / eid)
            scope["reporting"]["critical_alert"]["path"] = str(alerts / (eid + ".ndjson"))
            key = Ed25519PrivateKey.generate()
            public = base / "operator.pub.pem"
            public.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
            trust["configured"] = True
            trust["operator"].update(principal="demo-operator@example.invalid", signer_id="demo-operator",
                                     public_key_pem_path=str(public))
            trust["approved_engagement_ids"] = [eid]
            trust["allowed_repository_roots"] = []
            trust["allowed_origins"] = [origin]
            trust["allowed_networks"] = ["127.0.0.1/32"]
            trust["allowed_http_path_prefixes"] = {origin: ["/status", "/redirect"]}
            trust["approved_methods"] = ["controlled_http_testing"]
            trust["allowed_report_roots"] = [str(reports)]
            trust["allowed_alert_roots"] = [str(alerts)]
            trust["revocation"]["last_checked_utc"] = stamp(now)
            manifest_path, signature_path, trust_path = (base / name for name in ("scope.yaml", "scope.sig", "trust.json"))
            manifest = yaml.safe_dump(scope, sort_keys=False).encode()
            manifest_path.write_bytes(manifest)
            signature_path.write_bytes(key.sign(SIGNING_CONTEXT + manifest))
            trust_path.write_text(json.dumps(trust))
            sup = AegisHttpSupervisor(manifest_path, signature_path, trust_path, state)
            one = sup.request(origin + "/status", "GET", 7)
            two = sup.request(origin + "/redirect", "GET", 7)
            first_report = json.loads(Path(one["report"]).read_text())
            if (first_report["result"]["http_status"] != 200 or one["http_status"] != 200 or
                two["http_status"] != 302 or not two["redirect_not_followed"] or
                not sup.verify_audit_chain() or server.paths != ["/status", "/redirect"]):
                raise RuntimeError("HTTP demo did not meet safety assertions")
            usage = sup.http_usage(eid)
            print(json.dumps({"status": "LOCAL_HTTP_GATEWAY_DEMO_PASS", "http_responses": [200, 302],
                              "redirect_followed": False, "requests_observed": len(server.paths),
                              "reserved_requests": usage["reserved_requests"],
                              "reserved_body_bytes": usage["reserved_body_bytes"],
                              "audit_chain": "VALID_LOCAL_UNANCHORED", "external_network_requests": 0}, indent=2))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    main()
