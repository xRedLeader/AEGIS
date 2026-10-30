"""Signed, anonymous HTTP-only Nuclei execution through a per-request trusted broker."""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import stat
import struct
import subprocess
import tempfile
import time
import uuid

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from aegis_agent_gateway import _protected
from aegis_audit_contract import canonical, digest, fields, require
from aegis_http_broker import parent_death_guard, bounded_exchange
from aegis_http_gateway import TransportError
from aegis_http_policy import inspect_url, pinned_address
from aegis_http_runtime import AegisHttpSupervisor
from aegis_intelligence import protected_bytes
from aegis_preflight import read_protected_trust
from aegis_scanner_contract import attestation, normalize, parse_report, sha256, strict_json
from aegis_scanner_execution import MAX_ARTIFACTS, _write_artifacts, binary_bytes, sealed_file
from aegis_scanner_import import ScannerImportSupervisor, selected_input
from aegis_staging_protocol import PROFILE, MAX_BODY, MAX_FRAME, decode_frame, encode_frame
from aegis_staging_sandbox import launch
from aegis_supervisor import ExecutionDenied, open_directory_nofollow, private_directory

CONTEXT = b"AEGIS-STAGING-EXECUTION-PROFILE-v1\x00"
NUCLEI_SHA256 = "63f881a5b1df284710daf02e880f3ceaf0eca269e0885dd860d0f31715153a9c"


def utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _time(value):
    require(isinstance(value, str) and len(value) == 20 and value.endswith("Z"), "profile time must be UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        require(False, "invalid profile time")


def validate_profile(profile, info, scope):
    fields(profile, {"schema_version", "configured", "engagement_id", "operation_id", "profile", "executable", "configuration",
                     "origin", "routes", "networks", "methods", "test_identity", "mutation_permitted", "deployment_sha256",
                     "valid_from_utc", "valid_until_utc", "seconds", "max_requests", "max_requests_per_minute", "body_limit", "rule_id"})
    require(type(profile["schema_version"]) is int and profile["schema_version"] == 1 and profile["configured"] is True and
            profile["engagement_id"] == info["engagement_id"] and profile["profile"] == PROFILE, "staging profile is unconfigured or foreign")
    require(str(uuid.UUID(profile["operation_id"])) == profile["operation_id"], "staging operation needs a unique UUID")
    require("controlled_http_testing" in info["approved_methods"], "signed staging execution method missing")
    fields(profile["executable"], {"path", "sha256"}); fields(profile["configuration"], {"path", "sha256"})
    require(profile["executable"]["sha256"] == NUCLEI_SHA256, "only pinned Linux x86-64 Nuclei 3.3.8 is supported")
    sha256(profile["configuration"]["sha256"]); sha256(profile["deployment_sha256"])
    target = inspect_url(profile["origin"], info["authorized_origins"], scope["targets"]["excluded_origins"])
    require(target["scheme"] == "http" and target["target"] == "/" and target["origin"] == profile["origin"], "only exact HTTP origins are supported")
    require(profile["methods"] in (["GET"], ["HEAD"]) and profile["test_identity"] == "anonymous-disposable-staging" and
            profile["mutation_permitted"] is False, "unsupported method, test identity or mutation authority")
    require(isinstance(profile["routes"], list) and 1 <= len(profile["routes"]) <= 8 and len(set(profile["routes"])) == len(profile["routes"]), "bounded distinct routes required")
    for route in profile["routes"]:
        require(isinstance(route, str) and route.startswith("/") and len(route) <= 256 and route.isascii() and
                not any(ord(c) <= 32 for c in route) and not any(c in route for c in "?%#\\;") and "//" not in route and
                not any(p in (".", "..") for p in route.split("/")), "unsupported staging path")
    require(isinstance(profile["networks"], list) and 1 <= len(profile["networks"]) <= 16, "explicit staging destination networks required")
    for network in profile["networks"]:
        ipaddress.ip_network(network, strict=True)
    for key, maximum in (("seconds", min(120, scope["limits"]["max_single_run_minutes"] * 60)),
                         ("max_requests", min(64, scope["limits"]["max_total_requests"])),
                         ("max_requests_per_minute", scope["limits"]["max_requests_per_minute_per_origin"]),
                         ("body_limit", min(MAX_BODY, scope["limits"]["max_response_body_bytes"]))):
        require(type(profile[key]) is int and 1 <= profile[key] <= maximum, "staging limit exceeds signed scope")
    require(profile["max_requests"] >= len(profile["routes"]), "request budget cannot cover selected routes")
    start, finish = _time(profile["valid_from_utc"]), _time(profile["valid_until_utc"])
    require(_time(scope["engagement"]["valid_from_utc"]) <= start <= datetime.now(timezone.utc) < finish <=
            _time(scope["engagement"]["valid_until_utc"]), "staging profile is expired or outside signed engagement")
    require(isinstance(profile["rule_id"], str) and 1 <= len(profile["rule_id"]) <= 80 and
            all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in profile["rule_id"]), "invalid selected template ID")


def validate_template(raw, profile):
    """One deliberately small data-only Nuclei template subset; no DSL or expressions."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= 16384, "template exceeds bound")
    class UniqueLoader(yaml.SafeLoader):
        depth = 0
        nodes = 0
        def compose_node(self, parent, index):
            self.depth += 1
            self.nodes += 1
            try:
                require(self.depth <= 12 and self.nodes <= 256 and not self.check_event(yaml.AliasEvent),
                        "template aliases or structural limits denied")
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1
    def mapping(loader, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            require(isinstance(key, str) and key not in result, "duplicate or nonstring template key")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        document = yaml.load(raw, Loader=UniqueLoader)
    except (yaml.YAMLError, RecursionError):
        require(False, "invalid template YAML")
    fields(document, {"id", "info", "http"})
    require(document["id"] == profile["rule_id"], "template ID differs from signed profile")
    fields(document["info"], {"name", "author", "severity"})
    require(all(isinstance(v, str) and 1 <= len(v) <= 160 and v.isascii() and "{{" not in v for v in document["info"].values()) and
            document["info"]["severity"] in {"info", "low", "medium", "high", "critical"}, "unsupported template metadata")
    require(isinstance(document["http"], list) and len(document["http"]) == 1, "one HTTP request definition required")
    request = document["http"][0]
    fields(request, {"method", "path", "matchers"})
    require(request["method"] in profile["methods"] and request["path"] == ["{{BaseURL}}"], "template method/path exceeds profile")
    require(isinstance(request["matchers"], list) and len(request["matchers"]) == 1, "one literal matcher required")
    matcher = request["matchers"][0]
    fields(matcher, {"type", "words"})
    require(matcher["type"] == "word" and isinstance(matcher["words"], list) and 1 <= len(matcher["words"]) <= 8 and
            all(isinstance(w, str) and 1 <= len(w) <= 128 and w.isascii() and "{{" not in w and
                all(32 <= ord(c) < 127 for c in w) for w in matcher["words"]), "only literal bounded body-word matchers supported")


class StagingExecutionSupervisor(ScannerImportSupervisor, AegisHttpSupervisor):
    def _signed_profile(self, path, signature_path, info, scope):
        raw = _protected(path, 32768, info, self.state_root)
        signature = _protected(signature_path, 64, info, self.state_root)
        profile = strict_json(raw)
        require(canonical(profile) == raw, "staging profile must use canonical JSON")
        trust = read_protected_trust(self.trust_path)
        key_raw = protected_bytes(Path(trust["operator"]["public_key_pem_path"]), 8192)
        try:
            key = load_pem_public_key(key_raw)
            require(isinstance(key, Ed25519PublicKey), "operator key must be Ed25519")
            key.verify(signature, CONTEXT + raw)
        except (InvalidSignature, ValueError):
            require(False, "staging profile signature is invalid")
        validate_profile(profile, info, scope)
        return profile, raw, signature

    def _staging_tables(self, con):
        con.execute("CREATE TABLE IF NOT EXISTS staging_executions (engagement_id TEXT NOT NULL, operation_id TEXT NOT NULL, run_id TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY(engagement_id,operation_id))")

    def _recover_locked(self):
        with self._database() as con:
            con.execute("BEGIN IMMEDIATE"); self._staging_tables(con)
            rows = con.execute("SELECT engagement_id,operation_id,run_id FROM staging_executions WHERE status IN ('reserved','running')").fetchall()
            for eid, operation, run_id in rows:
                con.execute("UPDATE staging_executions SET status='interrupted_requires_reconciliation' WHERE engagement_id=? AND operation_id=?", (eid, operation))
                con.execute("UPDATE runs SET status='interrupted',ended_utc=? WHERE run_id=? AND engagement_id=?", (utc(), run_id, eid))
                self._event(con, {"type":"staging_execution_interrupted", "engagement_id":eid, "run_id":run_id,
                                  "operation_id":operation, "requests_replayed":False})
            con.commit()
        return len(rows)

    def execute(self, profile_path, signature_path, *, import_result=True, max_seconds=None):
        require(os.geteuid() != 0 and hasattr(os, "memfd_create"), "staging execution requires non-root Linux")
        require(max_seconds is None or type(max_seconds) is int and 1 <= max_seconds <= 120,
                "invalid invoking workflow runtime ceiling")
        self._guard()
        with open_directory_nofollow(self.state_root) as directory:
            private_directory(directory)
            lock = os.open("staging-execution.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            st = os.fstat(lock)
            require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.geteuid() and not st.st_mode & 0o077, "staging lock custody invalid")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._recover_locked()
            return self._execute(Path(profile_path), Path(signature_path), import_result, max_seconds)
        finally:
            os.close(lock)

    def _fetch_body(self, request, timeout, guard):
        parent = os.getpid()
        worker = subprocess.Popen(["/usr/bin/python3", "-I", "-S", str(Path(__file__).with_name("aegis_staging_broker.py")), str(parent)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/", start_new_session=True,
            env={"PATH":"/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE":"1"}, preexec_fn=lambda: parent_death_guard(parent))
        try:
            return bounded_exchange(worker, request, timeout, guard=guard, output_limit=MAX_FRAME)
        except TransportError as exc:
            raise ExecutionDenied("staging response rejected by bounded broker") from exc
        finally:
            if worker.poll() is None:
                self._kill_worker(worker)
            for stream in (worker.stdin, worker.stdout, worker.stderr):
                if not stream.closed:
                    stream.close()

    def _execute(self, profile_path, signature_path, import_result, max_seconds=None):
        info, scope = self._guard()
        profile, profile_raw, signature = self._signed_profile(profile_path, signature_path, info, scope)
        require(max_seconds is None or profile["seconds"] <= max_seconds, "signed profile runtime exceeds invoking workflow ceiling")
        config = _protected(Path(profile["configuration"]["path"]), 16384, info, self.state_root)
        require(hashlib.sha256(config).hexdigest() == profile["configuration"]["sha256"], "template hash differs")
        validate_template(config, profile)
        binary = binary_bytes(profile["executable"]["path"], NUCLEI_SHA256)
        eid, operation = info["engagement_id"], profile["operation_id"]
        with self._database() as con:
            self._staging_tables(con)
            require(con.execute("SELECT run_id FROM staging_executions WHERE engagement_id=? AND operation_id=?", (eid, operation)).fetchone() is None,
                    "staging operation already reserved; reconcile it and never automatically replay")
        info, scope, run_id = self.reserve(profile["seconds"], "controlled_http_testing", evidence_bytes=MAX_ARTIFACTS)
        began, started_utc = time.monotonic(), utc()
        deadline = began + profile["seconds"]
        worker, fds, requests, request_times = None, [], [], []
        totals = {"stdout":0, "stderr":0}; hashes = {k:hashlib.sha256() for k in totals}
        boundary_ready, boundary_exit = False, None
        raw_sha = None

        def guard():
            active, current_scope = self._guard()
            require(active["manifest_sha256"] == info["manifest_sha256"] and time.monotonic() < deadline,
                    "staging scope changed or runtime expired")
            _, current_raw, current_sig = self._signed_profile(profile_path, signature_path, active, current_scope)
            require(current_raw == profile_raw and current_sig == signature and
                    config == _protected(Path(profile["configuration"]["path"]), 16384, active, self.state_root),
                    "protected staging inputs changed")
            return active, current_scope

        def broker(message):
            active, current_scope = guard()
            fields(message, {"kind", "method", "url"})
            require(message["kind"] == "request" and message["method"] in profile["methods"], "staging method denied")
            plan = inspect_url(message["url"], active["authorized_origins"], current_scope["targets"]["excluded_origins"])
            require(plan["scheme"] == "http" and plan["origin"] == profile["origin"] and plan["target"] in profile["routes"], "staging route/origin denied")
            self._operator_route_guard(plan)
            now = time.monotonic()
            require(len(request_times) < profile["max_requests"] and sum(t > now-60 for t in request_times) < profile["max_requests_per_minute"], "staging request/rate limit exhausted")
            seconds = min(3, int(deadline-now))
            require(seconds >= 1, "staging request has no remaining time")
            request_id = self._reserve_request(active, current_scope, plan["origin"], message["method"], seconds)
            request_times.append(now)
            try:
                with self._database() as con:
                    self._event(con, {"type":"staging_request_reserved", "engagement_id":eid, "run_id":run_id,
                                      "request_id":request_id, "operation_id":operation}); con.commit()
                addresses = self._resolve(plan["hostname"], plan["port"], min(1, seconds), plan)
                guard(); self._operator_route_guard(plan)
                address = pinned_address(addresses, active["authorized_networks"], current_scope["targets"]["excluded_networks"], plan["hostname"])
                pinned_address(addresses, profile["networks"], current_scope["targets"]["excluded_networks"], plan["hostname"])
                def request_guard():
                    guard(); self._operator_route_guard(plan)
                result = self._fetch_body({"address":address, "port":plan["port"], "hostname":plan["hostname"],
                    "method":message["method"], "target":plan["target"], "timeout":min(2, seconds), "body_limit":profile["body_limit"]},
                    min(seconds, deadline-time.monotonic()), request_guard)
                guard()
                fields(result, {"status", "content_type", "body_b64", "body_bytes"})
                body = base64.b64decode(result["body_b64"], validate=True)
                require(type(result["body_bytes"]) is int and len(body) <= profile["body_limit"] and len(body) == result["body_bytes"], "broker response bound differs")
                require(type(result["status"]) is int and 100 <= result["status"] <= 599 and not 300 <= result["status"] < 400,
                        "broker response status differs")
                requests.append({"request_id":request_id, "method":message["method"], "route":plan["target"],
                    "destination_ip":address, "status":result["status"], "body_bytes":len(body), "body_sha256":hashlib.sha256(body).hexdigest()})
                self._finish_request(eid, request_id, "completed", "restricted staging body transient; no credentials")
                return {"kind":"response", **result}
            except BaseException:
                self._finish_request(eid, request_id, "aborted", "staging dispatch uncertain; no automatic replay")
                raise

        try:
            with self._database() as con:
                con.execute("BEGIN IMMEDIATE"); con.execute("INSERT INTO staging_executions VALUES(?,?,?,?)", (eid, operation, run_id, "reserved"))
                self._event(con, {"type":"staging_execution_reserved", "engagement_id":eid, "run_id":run_id, "operation_id":operation,
                                  "profile_sha256":hashlib.sha256(profile_raw).hexdigest(), "profile_signature_sha256":hashlib.sha256(signature).hexdigest()}); con.commit()
            with tempfile.TemporaryDirectory(prefix="staging-", dir=self.state_root) as directory:
                jail = Path(directory)/"jail"; jail.mkdir(mode=0o700)
                binary_fd = sealed_file("staging-scanner", binary, True); fds.append(binary_fd)
                config_fd = sealed_file("staging-template", config); fds.append(config_fd)
                targets_fd = sealed_file("staging-targets", "".join(profile["origin"]+r+"\n" for r in profile["routes"]).encode("ascii")); fds.append(targets_fd)
                output_fd = os.memfd_create("staging-output", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING); fds.append(output_fd)
                from_relay, relay_write = os.pipe2(os.O_CLOEXEC); relay_read, to_relay = os.pipe2(os.O_CLOEXEC)
                fds.extend((from_relay, relay_write, relay_read, to_relay))
                argv = launch(binary_fd, config_fd, targets_fd, relay_read, relay_write, jail, profile["seconds"])
                parent = os.getpid()
                worker = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/",
                    env={"PATH":"/usr/bin:/bin"}, pass_fds=(binary_fd,config_fd,targets_fd,relay_read,relay_write),
                    start_new_session=True, preexec_fn=lambda: parent_death_guard(parent))
                os.close(relay_read); fds.remove(relay_read); os.close(relay_write); fds.remove(relay_write)
                with self._database() as con:
                    con.execute("UPDATE staging_executions SET status='running' WHERE engagement_id=? AND operation_id=?", (eid, operation)); con.commit()
                incoming = bytearray(); outgoing = bytearray()
                with selectors.DefaultSelector() as selector:
                    for stream, name in ((worker.stdout, "stdout"), (worker.stderr, "stderr"), (from_relay, "relay")):
                        os.set_blocking(stream if isinstance(stream,int) else stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, name)
                    os.set_blocking(to_relay, False)
                    while selector.get_map() or worker.poll() is None:
                        guard(); require(os.fstat(output_fd).st_size <= 524288, "staging export exceeded bound")
                        for key, _ in selector.select(0.1):
                            if key.data == "reply":
                                del outgoing[:os.write(to_relay, outgoing[:65536])]
                                if not outgoing:
                                    selector.unregister(to_relay)
                                continue
                            chunk = os.read(key.fd, 8192)
                            if not chunk:
                                selector.unregister(key.fileobj); continue
                            if key.data != "relay":
                                totals[key.data] += len(chunk); hashes[key.data].update(chunk)
                                require(totals[key.data] <= 32768, "staging scanner log flood")
                                continue
                            incoming.extend(chunk)
                            require(len(incoming) <= MAX_FRAME+4, "staging relay frame exceeds bound")
                            while len(incoming) >= 4:
                                size = struct.unpack("!I", incoming[:4])[0]
                                require(0 < size <= MAX_FRAME, "invalid relay frame size")
                                if len(incoming) < size+4:
                                    break
                                message = decode_frame(bytes(incoming[4:size+4])); del incoming[:size+4]
                                if message.get("kind") == "ready":
                                    require(not boundary_ready and message == {"kind":"ready", "profile":PROFILE, "network":"private-loopback-only", "scanner_broker_fds":False} and
                                            message["scanner_broker_fds"] is False, "invalid staging boundary receipt")
                                    boundary_ready = True
                                elif message.get("kind") == "request":
                                    require(boundary_ready and boundary_exit is None and not outgoing, "relay request outside active boundary")
                                    outgoing.extend(encode_frame(broker(message))); selector.register(to_relay, selectors.EVENT_WRITE, "reply")
                                elif message.get("kind") == "report_chunk":
                                    fields(message, {"kind", "data"})
                                    require(boundary_ready and boundary_exit is None and not outgoing, "export chunk outside active boundary")
                                    chunk = base64.b64decode(message["data"], validate=True)
                                    require(0 < len(chunk) <= 32768 and os.fstat(output_fd).st_size+len(chunk) <= 524288, "staging export exceeds bound")
                                    require(os.write(output_fd,chunk) == len(chunk), "partial staging export write")
                                else:
                                    fields(message, {"kind", "exit_code"}); require(message["kind"] == "finished" and boundary_exit is None and
                                            type(message["exit_code"]) is int and -128 <= message["exit_code"] <= 255, "invalid relay completion")
                                    boundary_exit = message["exit_code"]
                require(worker.wait(timeout=1) == 0 and boundary_ready and boundary_exit == 0 and not incoming and not outgoing,
                        "staging boundary or scanner failed")
                require(len(requests) == len(profile["routes"]) and {r["route"] for r in requests} == set(profile["routes"]),
                        "scanner did not complete exactly the selected routes")
                os.lseek(output_fd, 0, os.SEEK_SET); raw = os.read(output_fd, 524289)
                require(0 < len(raw) <= 524288, "staging report empty or oversized")
                raw_sha = hashlib.sha256(raw).hexdigest()
                # Export timestamps may have subsecond precision; wait until the next UTC second so
                # the signed/admitted inclusive second endpoint covers every observed event.
                previous_second = utc()
                while utc() == previous_second:
                    guard(); time.sleep(0.02)
                observed = utc()
                selected = {"kind":"staging", "origin":profile["origin"], "routes":profile["routes"], "deployment_sha256":profile["deployment_sha256"],
                            "scan_started_at_utc":started_utc, "scan_finished_at_utc":observed}
                admission = {"schema_version":1, "configured":True, "engagement_id":eid,
                    "detector":{"name":"nuclei","version":"3.3.8","report_schema":"nuclei-json-export-v3.3.8"},
                    "configuration":{"path":str(Path(info["report_directory"])/"runs"/run_id/"scanner-config.bin"), "sha256":profile["configuration"]["sha256"]},
                    "report_sha256":raw_sha, "observed_at_utc":observed, "max_age_seconds":3600, "input":selected, "allowed_rule_ids":[profile["rule_id"]],
                    "provenance":{"mode":"aegis_governed","producer":"aegis-restricted-staging-v1","attestation_path":None,"signature_path":None,"public_key_path":None,"execution_run_id":run_id}, "database":None}
                identity, context = selected_input(admission, info, self.state_root, guard, scope); context["input_identity"] = identity
                normalized = normalize(parse_report(raw, admission, context), admission, context)
                sanitized = canonical({"schema_version":1, "observations":[{k:v for k,v in r.items() if k != "fingerprint"} for r in normalized["observations"]], "coverage":normalized["coverage"]})
                admission["report_sha256"] = hashlib.sha256(sanitized).hexdigest()
                stats = {"elapsed_ms":int((time.monotonic()-began)*1000), **{k+"_bytes":v for k,v in totals.items()}, **{k+"_sha256":v.hexdigest() for k,v in hashes.items()}}
                receipt = canonical({"admission":admission, "input_identity":identity, "original_report_sha256":raw_sha, "original_report_bytes":len(raw),
                    "operation_id":operation, "profile":PROFILE, "profile_sha256":hashlib.sha256(profile_raw).hexdigest(),
                    "profile_signature_sha256":hashlib.sha256(signature).hexdigest(), "executable_sha256":NUCLEI_SHA256, "requests":requests, "resources":stats,
                    "network":"private-loopback-relay; trusted per-request numeric-IP broker", "credentials_used":False,"mutations_authorized":False,"raw_responses_retained":False})
                artifacts = {"scanner-execution.json":receipt, "scanner-report.json":sanitized, "scanner-config.bin":config}
                guard(); _write_artifacts(info, run_id, artifacts)
                with self._database() as con:
                    con.execute("BEGIN IMMEDIATE")
                    self._event(con, {"type":"scanner_execution_completed", "engagement_id":eid, "run_id":run_id, "attestation":attestation(admission,identity),
                                      "artifacts":{k:hashlib.sha256(v).hexdigest() for k,v in artifacts.items()}})
                    con.execute("UPDATE runs SET status='completed',ended_utc=? WHERE run_id=? AND engagement_id=?", (utc(), run_id, eid))
                    con.execute("UPDATE staging_executions SET status='completed' WHERE engagement_id=? AND operation_id=?", (eid,operation)); con.commit()
                result = {"status":"STAGING_EXECUTION_COMPLETED_UNVERIFIED", "execution_run_id":run_id, "requests_completed":len(requests), "observations":len(normalized["observations"])}
        except BaseException:
            if worker is not None and worker.poll() is None:
                self._kill_worker(worker)
            with self._database() as con:
                con.execute("UPDATE staging_executions SET status='aborted_requires_reconciliation' WHERE engagement_id=? AND operation_id=? AND run_id=?", (eid,operation,run_id))
                self._event(con, {"type":"staging_execution_aborted", "engagement_id":eid,"run_id":run_id,"operation_id":operation,
                                  "completed_requests":len(requests),"requests_replayed":False,"partial_report_sha256":raw_sha,
                                  "boundary_ready":boundary_ready, **{k+"_bytes":v for k,v in totals.items()},
                                  **{k+"_sha256":v.hexdigest() for k,v in hashes.items()}}); con.commit()
            self._finish(eid,run_id,"aborted","staging execution uncertain; no automatic replay; raw content discarded")
            raise
        finally:
            for fd in fds:
                os.close(fd)
            if worker is not None:
                for stream in (worker.stdout, worker.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
        if import_result:
            result["import"] = self.import_governed_report(run_id)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "signature", "trust", "state-root", "profile", "profile-signature"):
        parser.add_argument("--"+name, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = StagingExecutionSupervisor(args.manifest,args.signature,args.trust,args.state_root).execute(args.profile,args.profile_signature)
        print(json.dumps(result, sort_keys=True)); return 0
    except (ExecutionDenied, OSError, ValueError, KeyError, sqlite3.Error, subprocess.SubprocessError):
        print("STAGING_EXECUTION_DENIED"); return 2


if __name__ == "__main__":
    raise SystemExit(main())
