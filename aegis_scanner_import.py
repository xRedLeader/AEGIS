"""Operator-scoped, non-executing admission of bounded external scanner reports."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import sys
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from aegis_agent_gateway import _protected
from aegis_audit_contract import canonical, digest, fields, read_relative, relative_path, require, source_snapshot
from aegis_http_policy import inspect_url
from aegis_reporting import ReportingSupervisor, report_package
from aegis_scanner_contract import (ATTESTATION_CONTEXT, MAX_INPUT, attestation, normalize,
    parse_report, report_projection, sha256, strict_json, validate_policy)
from aegis_supervisor import ExecutionDenied, open_directory_nofollow, private_directory


def selected_input(policy, info, state, guard, scope=None):
    selected = policy["input"]
    require(isinstance(selected, dict), "scanner input selection is invalid")
    kind = selected.get("kind")
    if kind in {"source", "history"}:
        expected = {"kind", "repository", "revisions" if kind == "history" else "files"}
        fields(selected, expected)
        repository = Path(selected["repository"])
        require(repository.is_absolute() and str(repository.resolve()) == str(repository) and
                str(repository) in info["authorized_repositories"], "scanner source escaped signed repository scope")
        if kind == "history":
            from aegis_git_evidence import read_commit
            require(isinstance(selected["revisions"], dict) and 1 <= len(selected["revisions"]) <= 8,
                    "history import needs explicit bounded revision snapshots")
            snapshots, identities, total_files, total_bytes = {}, {}, 0, 0
            for revision, files in sorted(selected["revisions"].items()):
                guard()
                require(isinstance(files, dict) and 1 <= len(files) <= 128, "bounded historical file manifest required")
                for path, expected_sha in files.items():
                    relative_path(path); sha256(expected_sha)
                total_files += len(files)
                require(total_files <= 128, "historical file count exceeds source bound")
                blobs = read_commit(repository, revision, sorted(files), maximum_file=1024*1024, maximum_total=8*1024*1024, guard=guard)
                actual = {p: hashlib.sha256(body).hexdigest() for p, body in blobs.items()}
                total_bytes += sum(map(len, blobs.values()))
                require(total_bytes <= 8*1024*1024 and actual == files, "historical source differs from selected revision content")
                snapshots[revision] = {p: {"sha256": actual[p], "lines": body.decode("utf-8").splitlines()} for p, body in blobs.items()}
                identities[revision] = actual
                guard()
            return {"kind": kind, "revisions": identities}, {"source": {}, "approved_revisions": sorted(snapshots), "history_sources": snapshots}
        require(isinstance(selected["files"], dict) and 1 <= len(selected["files"]) <= 128, "bounded exact source manifest required")
        for path, expected_sha in selected["files"].items():
            relative_path(path); sha256(expected_sha)
        snapshot = source_snapshot(repository, sorted(selected["files"]), guard)
        actual = {p: value["sha256"] for p, value in snapshot.items()}
        require(actual == selected["files"], "scanner evidence refers to changed source")
        context = {"source": snapshot, "approved_revisions": []}
        identity = {"kind": kind, "files": actual}
        return identity, context
    if kind in {"sbom", "image"}:
        fields(selected, {"kind", "artifact_path", "artifact_sha256", "format", "image_digest"} |
               ({"image_digest_kind"} if kind == "image" else set()))
        body = _protected(Path(selected["artifact_path"]), MAX_INPUT, info, state)
        require(hashlib.sha256(body).hexdigest() == sha256(selected["artifact_sha256"]), "selected artifact digest differs")
        require(selected["format"] in {"cyclonedx-1.5", "cyclonedx-1.6", "spdx-2.3", "oci-descriptor-v1"},
                "unsupported independently selected artifact schema")
        document = strict_json(body)
        if kind == "image":
            require(selected["format"] == "oci-descriptor-v1", "image requires an independently selected OCI descriptor")
            require(isinstance(selected["image_digest"], str) and selected["image_digest"].startswith("sha256:"),
                    "image input needs an immutable digest")
            sha256(selected["image_digest"][7:])
            require(isinstance(document, dict) and document.get("digest") == selected["image_digest"],
                    "image identity is not present in selected descriptor")
            media = {"manifest": {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"},
                     "config": {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}}
            require(selected["image_digest_kind"] in media and document.get("mediaType") in media[selected["image_digest_kind"]] and
                    type(document.get("size")) is int and document["size"] > 0, "image descriptor kind/size is invalid")
        else:
            require(selected["image_digest"] is None, "SBOM input cannot assert image contents")
            require(isinstance(document, dict), "SBOM must be an object")
            if selected["format"] in {"cyclonedx-1.5", "cyclonedx-1.6"}:
                require(document.get("bomFormat") == "CycloneDX" and document.get("specVersion") == selected["format"].split("-", 1)[1],
                        "selected CycloneDX schema differs from artifact")
            else:
                require(selected["format"] == "spdx-2.3" and document.get("spdxVersion") == "SPDX-2.3" and
                        document.get("SPDXID") == "SPDXRef-DOCUMENT", "selected SPDX schema differs from artifact")
        identity = {k: v for k, v in selected.items() if k != "artifact_path"}
        return identity, {"source": {}, "artifact": document, "image_digest": selected["image_digest"]}
    if kind == "staging":
        require("controlled_http_testing" in info["approved_methods"], "staging import lacks signed testing authority")
        fields(selected, {"kind", "origin", "routes", "deployment_sha256", "scan_started_at_utc", "scan_finished_at_utc"})
        from aegis_preflight import parse_utc
        from aegis_scanner_contract import observed_time
        for field in ("scan_started_at_utc", "scan_finished_at_utc"):
            observed_time(selected[field], policy["max_age_seconds"])
        require(scope is not None and selected["scan_finished_at_utc"] == policy["observed_at_utc"] and
                parse_utc(scope["engagement"]["valid_from_utc"]) <= parse_utc(selected["scan_started_at_utc"]) <=
                parse_utc(selected["scan_finished_at_utc"]) < parse_utc(scope["engagement"]["valid_until_utc"]),
                "staging scan time escaped signed authorization")
        target = inspect_url(selected["origin"], info["authorized_origins"], [])
        require(target["origin"] == selected["origin"] and target["target"] == "/", "staging origin is not canonical")
        require(isinstance(selected["routes"], list) and 1 <= len(selected["routes"]) <= 64, "bounded exact staging routes required")
        for route in selected["routes"]:
            require(isinstance(route, str) and 1 <= len(route) <= 256 and route.startswith("/") and
                    not any(c in route for c in ("?", "%", "#", "\\")) and "//" not in route and
                    not any(part in {".", ".."} for part in route.split("/")),
                    "staging admission routes must be query-free exact paths")
            require(inspect_url(selected["origin"] + route, info["authorized_origins"], [])["origin"] == selected["origin"],
                    "staging route escaped scope")
        require(len(set(selected["routes"])) == len(selected["routes"]), "duplicate staging admission route")
        sha256(selected["deployment_sha256"])
        return selected, {"source": {}, "origin": selected["origin"], "routes": selected["routes"]}
    require(False, "unsupported scanner input kind")


def verify_provenance(supervisor, policy, identity, info):
    provenance = policy["provenance"]
    expected = attestation(policy, identity)
    mode = provenance["mode"]
    if mode == "verified_ci":
        raw = _protected(Path(provenance["attestation_path"]), 32768, info, supervisor.state_root)
        require(strict_json(raw) == expected and raw == canonical(expected), "CI attestation differs from selected evidence")
        signature = _protected(Path(provenance["signature_path"]), 64, info, supervisor.state_root)
        public = _protected(Path(provenance["public_key_path"]), 8192, info, supervisor.state_root)
        try:
            key = load_pem_public_key(public)
            require(isinstance(key, Ed25519PublicKey), "CI signer must use Ed25519")
            key.verify(signature, ATTESTATION_CONTEXT + raw)
        except (InvalidSignature, ValueError) as exc:
            raise ExecutionDenied("scanner CI provenance verification failed") from exc
        return {"mode": mode, "producer": provenance["producer"], "attestation_sha256": hashlib.sha256(raw).hexdigest(),
                "public_key_sha256": hashlib.sha256(public).hexdigest(), "execution_run_id": None}
    if mode == "aegis_governed":
        execution = provenance["execution_run_id"]
        require(str(uuid.UUID(execution)) == execution, "invalid scanner execution receipt identity")
        require(supervisor.verify_audit_chain(), "scanner execution audit is invalid")
        with supervisor._database() as con:
            row = con.execute("SELECT status FROM runs WHERE run_id=? AND engagement_id=?", (execution, info["engagement_id"])).fetchone()
            require(row == ("completed",), "governed scanner execution is incomplete or foreign")
            events = (strict_json(row[0].encode()) for row in con.execute("SELECT event FROM audit"))
            require(any(e.get("type") == "scanner_execution_completed" and e.get("run_id") == execution and
                        e.get("attestation") == expected for e in events), "governed execution provenance is absent or mismatched")
        return {"mode": mode, "producer": provenance["producer"], "attestation_sha256": digest(expected),
                "public_key_sha256": None, "execution_run_id": execution}
    return {"mode": mode, "producer": provenance["producer"], "attestation_sha256": None,
            "public_key_sha256": None, "execution_run_id": None}


def retained_import(supervisor, info, run_id):
    require(str(uuid.UUID(run_id)) == run_id, "invalid scanner evidence run")
    require(supervisor.verify_audit_chain(), "scanner evidence audit is invalid")
    raw = supervisor._read_source(info, run_id, "scanner-import.json")
    sha = hashlib.sha256(raw).hexdigest()
    with supervisor._database() as con:
        row = con.execute("SELECT status FROM runs WHERE run_id=? AND engagement_id=?", (run_id, info["engagement_id"])).fetchone()
        require(row == ("completed",), "scanner evidence is incomplete or foreign")
        events = (strict_json(row[0].encode()) for row in con.execute("SELECT event FROM audit"))
        require(any(e.get("type") == "completed" and e.get("run_id") == run_id and
                    e.get("engagement_id") == info["engagement_id"] and e.get("notes") == "scanner-import:" + sha for e in events),
                "scanner evidence differs from its audited bytes")
    return raw


class ScannerImportSupervisor(ReportingSupervisor):
    def admit(self, policy_path, report_path, *, seconds=5, expected_repository=None):
        return self._admit(policy_path, report_path, seconds=seconds, expected_repository=expected_repository)

    def import_governed_report(self, execution_run_id, *, seconds=5, expected_repository=None):
        """Only audited sanitized execution artifacts can cross this internal handoff."""
        require(str(uuid.UUID(execution_run_id)) == execution_run_id, "invalid execution handoff run")
        info, _ = self._guard()
        require(self.verify_audit_chain(), "execution handoff audit is invalid")
        with self._database() as con:
            row = con.execute("SELECT status FROM runs WHERE run_id=? AND engagement_id=?", (execution_run_id, info["engagement_id"])).fetchone()
            require(row == ("completed",), "execution handoff is incomplete or foreign")
            events = [strict_json(row[0].encode()) for row in con.execute("SELECT event FROM audit")]
        receipts = [e for e in events if e.get("type") == "scanner_execution_completed" and
                    e.get("run_id") == execution_run_id and e.get("engagement_id") == info["engagement_id"]]
        require(len(receipts) == 1, "execution handoff receipt is missing or ambiguous")
        receipt = receipts[0]
        names = {"scanner-execution.json", "scanner-report.json", "scanner-config.bin"}
        fields(receipt.get("artifacts"), names)
        directory = Path(info["report_directory"])/"runs"/execution_run_id
        def read(path, maximum):
            path = Path(path)
            require(path.parent == directory and path.name in names, "execution handoff escaped fixed artifact set")
            with open_directory_nofollow(directory) as root:
                private_directory(root)
                raw = read_relative(root, path.name, MAX_INPUT)
            require(hashlib.sha256(raw).hexdigest() == sha256(receipt["artifacts"][path.name]), "execution handoff artifact changed")
            if path.name == "scanner-execution.json":
                execution = strict_json(raw)
                require(isinstance(execution, dict) and "admission" in execution and "input_identity" in execution,
                        "execution handoff metadata missing")
                policy = execution["admission"]
                validate_policy(policy)
                require(policy["provenance"]["mode"] == "aegis_governed" and policy["provenance"]["execution_run_id"] == execution_run_id and
                        policy["configuration"]["path"] == str(directory/"scanner-config.bin") and
                        receipt.get("attestation") == attestation(policy, execution["input_identity"]), "execution handoff binding differs")
                sha256(execution.get("original_report_sha256"))
                raw = canonical(policy)
            require(len(raw) <= maximum, "execution handoff input exceeds bound")
            return raw
        return self._admit(directory/"scanner-execution.json", directory/"scanner-report.json",
                           seconds=seconds, expected_repository=expected_repository, read=read, governed=True)

    def _admit(self, policy_path, report_path, *, seconds, expected_repository=None, read=None, governed=False):
        require(sys.platform == "linux" and os.geteuid() != 0, "scanner admission requires non-root Linux")
        info, _ = self._guard()
        if read is None:
            read = lambda path, maximum: _protected(Path(path), maximum, info, self.state_root)
        policy_raw = read(policy_path, 32768)
        policy = strict_json(policy_raw)
        validate_policy(policy)
        if expected_repository is not None and policy["input"].get("kind") in {"source", "history"}:
            require(policy["input"].get("repository") == str(expected_repository), "scanner input differs from assessment repository")
        require(canonical(policy) == policy_raw and policy["engagement_id"] == info["engagement_id"], "scanner policy is not canonical/current")
        raw = read(report_path, MAX_INPUT)
        require(hashlib.sha256(raw).hexdigest() == policy["report_sha256"], "scanner report digest differs from protected admission")
        config = read(Path(policy["configuration"]["path"]), MAX_INPUT)
        require(hashlib.sha256(config).hexdigest() == policy["configuration"]["sha256"], "scanner configuration identity changed")
        method = ("controlled_http_testing" if policy["input"].get("kind") == "staging" else
                  "dependency_analysis" if policy["input"].get("kind") in {"sbom", "image"} or policy["detector"]["name"] in {"pip-audit", "npm-audit", "trivy", "grype"} else "source_review")
        info, scope, run_id = self.reserve(seconds, method)
        deadline = time.monotonic() + seconds
        def guard():
            self._guard()
            require(time.monotonic() < deadline, "scanner admission exceeded reserved runtime")
        try:
            identity, context = selected_input(policy, info, self.state_root, guard, scope)
            provenance = verify_provenance(self, policy, identity, info)
            context["input_identity"] = identity
            if governed:
                sanitized = strict_json(raw)
                fields(sanitized, {"schema_version", "observations", "coverage"})
                require(type(sanitized["schema_version"]) is int and sanitized["schema_version"] == 1,
                        "unsupported sanitized execution output")
                parsed = {k: sanitized[k] for k in ("observations", "coverage")}
            else:
                parsed = parse_report(raw, policy, context)
            normalized = normalize(parsed, policy, context)
            key = digest([info["engagement_id"], policy["detector"], policy["configuration"]["sha256"],
                          identity, policy["report_sha256"], provenance["mode"], provenance["producer"]])
            evidence = {"schema_version": 1, "status": "UNVERIFIED_SCANNER_IMPORT", "engagement_id": info["engagement_id"],
                        "import_id": key, "input_kind": identity["kind"], "input_sha256": digest(identity),
                        "input_identity": identity,
                        "detector": policy["detector"], "configuration_sha256": policy["configuration"]["sha256"],
                        "original_report_sha256": policy["report_sha256"], "observed_at_utc": policy["observed_at_utc"],
                        "database": policy["database"], "provenance": provenance, **normalized,
                        "redaction": "allowlisted_structural_fields_only", "independent_corroboration": False}
            encoded = canonical(evidence)
            require(len(encoded) <= 32768, "redacted scanner evidence exceeds reserved bytes")
            report_package(report_projection(encoded, info["engagement_id"], run_id, datetime.now(timezone.utc).isoformat()))
            again, _ = selected_input(policy, info, self.state_root, guard, scope)
            require(again == identity, "scanner input changed during admission")
            require(policy_raw == read(policy_path, 32768) and raw == read(report_path, MAX_INPUT) and
                    config == read(Path(policy["configuration"]["path"]), MAX_INPUT),
                    "scanner admission inputs changed during validation")
            require(verify_provenance(self, policy, identity, info) == provenance, "scanner provenance changed during admission")
            guard()
            with self._database() as con:
                con.execute("CREATE TABLE IF NOT EXISTS scanner_imports (engagement_id TEXT NOT NULL, import_id TEXT NOT NULL, source_run_id TEXT NOT NULL, PRIMARY KEY(engagement_id,import_id))")
                con.execute("BEGIN IMMEDIATE")
                old = con.execute("SELECT source_run_id FROM scanner_imports WHERE engagement_id=? AND import_id=?", (info["engagement_id"], key)).fetchone()
                if old:
                    con.rollback()
                else:
                    events = (strict_json(row[0].encode()) for row in con.execute("SELECT event FROM audit"))
                    previous = next((e for e in events if e.get("type") == "completed" and e.get("import_id") == key
                                     and e.get("engagement_id") == info["engagement_id"]), None)
                    require(previous is None, "scanner import receipt is missing; audited replay denied")
                    self._write_report(info, run_id, encoded, "scanner-import.json")
                    con.execute("INSERT INTO scanner_imports VALUES(?,?,?)", (info["engagement_id"], key, run_id))
                    con.execute("UPDATE runs SET status='completed',ended_utc=? WHERE run_id=? AND engagement_id=?",
                                (datetime.now(timezone.utc).isoformat(), run_id, info["engagement_id"]))
                    self._event(con, {"type": "completed", "engagement_id": info["engagement_id"], "run_id": run_id,
                                      "import_id": key, "notes": "scanner-import:" + hashlib.sha256(encoded).hexdigest()})
                    con.commit()
            if old:
                retained_import(self, info, old[0])
                self._finish(info["engagement_id"], run_id, "duplicate_import", "reused existing scanner evidence")
                return {"status": "SCANNER_IMPORT_ALREADY_RECORDED", "run_id": old[0], "import_id": key}
            return {"status": "SCANNER_IMPORT_RECORDED", "run_id": run_id, "import_id": key,
                    "observation_count": len(normalized["observations"])}
        except BaseException:
            self._finish(info["engagement_id"], run_id, "failed", "scanner admission failed")
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "signature", "policy", "report"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--seconds", default=5, type=int)
    args = parser.parse_args(argv)
    try:
        state, trust = os.environ.get("AEGIS_STATE_ROOT"), os.environ.get("AEGIS_TRUST_POLICY")
        require(state and trust and Path(state).is_absolute() and Path(trust).is_absolute(), "protected operator state and trust required")
        supervisor = ScannerImportSupervisor(args.manifest, args.signature, Path(trust), Path(state))
        print(canonical(supervisor.admit(args.policy, args.report, seconds=args.seconds)).decode())
        return 0
    except (ExecutionDenied, ValueError, OSError, TypeError, KeyError, sqlite3.Error):
        print("DENIED: scanner admission failed; inspect protected inputs locally", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
