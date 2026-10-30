"""Actual pinned synthetic exports plus explicitly adversarial parser mutations."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from aegis_audit_contract import canonical, source_snapshot
from aegis_scanner_contract import normalize, parse_report, strict_json
from aegis_scanner_import import retained_import
from aegis_source_scanners import PINS
from aegis_supervisor import ExecutionDenied
import test_scanner_admission as admission_tests

FIXTURE = Path(__file__).parent/"fixtures/source_scanners"
CANARY = "AEGIS_TEST_SECRET_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
SAST_PATHS = ["Example.cs", "example.js", "typed-example.ts"]
SECRET_PATHS = ["secrets-positive.txt", "secrets-safe.txt"]
RULES = {"semgrep": ["aegis-js-dynamic-eval", "aegis-csharp-process-start"],
         "codeql": ["aegis/js-dynamic-eval", "aegis/csharp-process-start"], "gitleaks": ["aegis-synthetic-canary"]}


def policy(name, kind="source"):
    return {"detector": {"name": name, "version": PINS[name][0], "report_schema": PINS[name][1]},
            "allowed_rule_ids": RULES[name], "input": {"kind": kind}}


def context(safe=False, secrets=False):
    root = FIXTURE/("safe-source" if safe else "source")
    paths = (["secrets-safe.txt"] if safe else SECRET_PATHS) if secrets else SAST_PATHS
    return {"source": source_snapshot(root.resolve(), paths), "approved_revisions": []}


def report(name):
    return (FIXTURE/"reports"/name).read_bytes()


class SourceParserTests(unittest.TestCase):
    def test_captured_reports_and_configuration_are_hash_verified(self):
        capture = strict_json((FIXTURE/"capture.json").read_bytes())
        self.assertEqual(capture["versions"], {"semgrep":"1.125.0", "codeql":"2.23.8", "gitleaks":"8.24.3"})
        for path, expected in capture["files"].items():
            self.assertEqual(hashlib.sha256((FIXTURE/path).read_bytes()).hexdigest(), expected, path)

    def test_real_semgrep_positive_safe_and_csharp_javascript_typescript_locations(self):
        p, c = policy("semgrep"), context()
        parsed = normalize(parse_report(report("semgrep.json"), p, c), p, c)
        self.assertEqual([(o["path"], o["start_line"]) for o in sorted(parsed["observations"], key=lambda o:o["path"])],
                         [("Example.cs", 4), ("example.js", 2), ("typed-example.ts", 2)])
        self.assertEqual(parse_report(report("semgrep-safe.json"), p, context(safe=True))["observations"], [])

    def test_real_codeql_positive_safe_exports(self):
        p, c = policy("codeql"), context()
        for language, expected in (("javascript", 2), ("csharp", 1)):
            parsed = normalize(parse_report(report("codeql-"+language+".sarif"), p, c), p, c)
            self.assertEqual(len(parsed["observations"]), expected)
            self.assertEqual(parse_report(report("codeql-"+language+"-safe.sarif"), p, context(safe=True))["observations"], [])

    def test_real_gitleaks_raw_redacted_and_safe_exports(self):
        p, c = policy("gitleaks"), context(secrets=True)
        raw = normalize(parse_report(report("gitleaks-current.json"), p, c), p, c)
        redacted = normalize(parse_report(report("gitleaks-redacted.json"), p, c), p, c)
        self.assertEqual(raw, redacted)
        self.assertNotIn(CANARY, json.dumps(raw))
        self.assertEqual(parse_report(report("gitleaks-safe.json"), p, context(safe=True, secrets=True))["observations"], [])

    def test_wrong_versions_and_unselected_rules_are_rejected(self):
        for name, file in (("semgrep","semgrep.json"),("codeql","codeql-csharp.sarif"),("gitleaks","gitleaks-current.json")):
            p, c = policy(name), context(secrets=name=="gitleaks")
            p["detector"]["version"] = "999.0.0"
            with self.assertRaises(ExecutionDenied): parse_report(report(file), p, c)
            p = policy(name); p["allowed_rule_ids"] = []
            with self.assertRaises(ExecutionDenied): normalize(parse_report(report(file), p, c), p, c)

    def test_semgrep_paths_columns_and_incomplete_assessment(self):
        original = strict_json(report("semgrep.json")); p, c = policy("semgrep"), context()
        for path in ("/etc/passwd", "../example.js", "file:///example.js", "example%2ejs", "outside.js"):
            doc = copy.deepcopy(original); doc["results"][0]["path"] = path
            with self.assertRaises(ExecutionDenied): parse_report(canonical(doc), p, c)
        doc = copy.deepcopy(original); doc["results"][0]["end"]["col"] = 99999
        with self.assertRaises(ExecutionDenied): parse_report(canonical(doc), p, c)
        doc = copy.deepcopy(original); doc["errors"] = [{"message":CANARY}]
        parsed = parse_report(canonical(doc), p, c)
        self.assertEqual(parsed["coverage"]["unresolved_records"], 1)
        self.assertNotIn(CANARY, json.dumps(parsed))

    def test_sarif_external_unsafe_and_inconsistent_locations(self):
        original = strict_json(report("codeql-csharp.sarif")); p, c = policy("codeql"), context()
        for change in (lambda r:r["locations"][0]["physicalLocation"]["artifactLocation"].update(uri="/etc/passwd"),
                       lambda r:r["locations"][0]["physicalLocation"]["artifactLocation"].update(uriBaseId="REMOTE"),
                       lambda r:r["locations"][0]["physicalLocation"]["artifactLocation"].update(index=999),
                       lambda r:r["locations"][0]["physicalLocation"]["region"].update(endLine=1000),
                       lambda r:r.update(ruleIndex=200)):
            doc = copy.deepcopy(original); change(doc["runs"][0]["results"][0])
            with self.assertRaises(ExecutionDenied): parse_report(canonical(doc), p, c)
        doc = copy.deepcopy(original); doc["runs"][0]["invocations"][0]["executionSuccessful"] = False
        self.assertGreater(parse_report(canonical(doc), p, c)["coverage"]["unresolved_records"], 0)

    def test_secret_nested_repeated_fields_and_vendor_fingerprints_do_not_survive(self):
        doc = strict_json(report("gitleaks-current.json")); p, c = policy("gitleaks"), context(secrets=True)
        doc[0].update(Description=CANARY, Fingerprint=CANARY, Author=CANARY, Email=CANARY,
                      Message=CANARY, Tags=[CANARY], nested={"Secret":[CANARY]*40})
        doc *= 2
        result = normalize(parse_report(canonical(doc), p, c), p, c)
        self.assertEqual(result["duplicates_removed"], 1)
        self.assertNotIn(CANARY, json.dumps(result))

    def test_secret_source_and_current_history_scope_tampering_is_rejected(self):
        doc = strict_json(report("gitleaks-current.json")); p, c = policy("gitleaks"), context(secrets=True)
        for change in (lambda r:r.update(Commit="a"*40), lambda r:r.update(File="../escape"),
                       lambda r:r.update(Secret="DIFFERENT_SYNTHETIC_SECRET"),lambda r:r.update(SymlinkFile="outside"),
                       lambda r:r.update(StartLine=True), lambda r:r.update(EndColumn=10000)):
            changed=copy.deepcopy(doc); change(changed[0])
            with self.assertRaises(ExecutionDenied) as denied: parse_report(canonical(changed), p, c)
            self.assertNotIn(CANARY, str(denied.exception))

    def test_explicit_history_uses_revision_snapshot_and_no_current_source(self):
        doc = strict_json(report("gitleaks-history.json")); revision = doc[0]["Commit"]
        c = {"source": {}, "approved_revisions":[revision], "history_sources":{revision:context(secrets=True)["source"]}}
        result = normalize(parse_report(canonical(doc), policy("gitleaks","history"), c), policy("gitleaks","history"), c)
        self.assertEqual(result["observations"][0]["revision"], revision)
        c["history_sources"][revision]["secrets-positive.txt"]["lines"] = ["current tree has no canary"]
        with self.assertRaises(ExecutionDenied): parse_report(canonical(doc), policy("gitleaks","history"), c)

    def test_malformed_oversized_and_duplicate_json_fail_without_secret_echo(self):
        p,c = policy("gitleaks"), context(secrets=True)
        for raw in (b'{"Secret":"'+CANARY.encode()+b'","Secret":"again"}',
                    b'{"Secret":NaN}', b"["+b"["*40+b"]"*40+b"]", b"x"*524289,
                    canonical(strict_json(report("gitleaks-current.json"))*65)):
            with self.assertRaises(ExecutionDenied) as denied: parse_report(raw,p,c)
            self.assertNotIn(CANARY, str(denied.exception))


class SourceAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.helper = admission_tests.ScannerAdmissionTests("test_readonly_import_canonical_report_and_sensitive_output_absence")
        self.helper.setUp(); self.addCleanup(self.helper.doCleanups)

    def configure(self, name, filename, *, history=False):
        h = self.helper
        paths = SECRET_PATHS if name == "gitleaks" else SAST_PATHS
        for path in paths: (h.fx.fx.repo/path).write_bytes((FIXTURE/"source"/path).read_bytes())
        h.admission.update(policy(name, "history" if history else "source"))
        h.admission["input"] = {"kind":"source","repository":str(h.fx.fx.repo),
            "files":{path:hashlib.sha256((FIXTURE/"source"/path).read_bytes()).hexdigest() for path in paths}}
        if history:
            env = {**os.environ, "GIT_CONFIG_GLOBAL":"/dev/null", "GIT_CONFIG_NOSYSTEM":"1"}
            for args in (["git","-c","core.hooksPath=/dev/null","init","-q"],
                         ["git","-c","core.hooksPath=/dev/null","fetch","-q",str(FIXTURE/"synthetic-history.bundle"),"main:refs/heads/fixture"]):
                subprocess.run(args,cwd=h.fx.fx.repo,env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            revision = strict_json(report(filename))[0]["Commit"]
            h.admission["input"] = {"kind":"history","repository":str(h.fx.fx.repo),"revisions":{revision:h.admission["input"]["files"]}}
            (h.fx.fx.repo/"secrets-positive.txt").write_text("Current working tree is deliberately different.\n")
        config = (FIXTURE/("gitleaks.toml" if name=="gitleaks" else "semgrep.yaml" if name=="semgrep" else "codeql-config-manifest.json")).read_bytes()
        h.config_path.write_bytes(config)
        h.admission["configuration"]["sha256"] = hashlib.sha256(config).hexdigest()
        self.write_report(report(filename))

    def write_report(self, raw):
        h = self.helper
        h.report_path.write_bytes(raw); h.report_path.chmod(0o600)
        h.admission["report_sha256"] = hashlib.sha256(raw).hexdigest()
        h.admission_path.write_bytes(canonical(h.admission)); h.admission_path.chmod(0o600)

    def test_actual_gitleaks_export_and_nested_canary_absent_from_all_downstream_files(self):
        self.configure("gitleaks", "gitleaks-current.json")
        doc = strict_json(report("gitleaks-current.json"))
        doc[0].update(Description=CANARY, Fingerprint=CANARY, extra={"Secret":[CANARY]*30})
        self.write_report(canonical(doc))
        h = self.helper
        with patch("subprocess.Popen", side_effect=AssertionError("import may not execute tools")), \
             patch("socket.create_connection", side_effect=AssertionError("import may not connect")):
            result = h.admit()
            generated = h.sup.generate(result["run_id"], "scanner-import.json")
        for root in (h.fx.state, h.fx.fx.report_root):
            for path in root.rglob("*"):
                if path.is_file(): self.assertNotIn(CANARY.encode(), path.read_bytes(), str(path))
        self.assertEqual(json.loads(Path(generated["report"]).read_bytes())["findings"][0]["verdict"], "needs_validation")

    def test_actual_sast_exports_admit_without_scanner_or_build_execution(self):
        for name, filename, expected in (("semgrep","semgrep.json",3),("codeql","codeql-csharp.sarif",1)):
            self.configure(name, filename)
            with patch("subprocess.Popen", side_effect=AssertionError("no scanner/build execution")):
                result = self.helper.admit()
            info,_ = self.helper.importer._guard()
            evidence = strict_json(retained_import(self.helper.importer,info,result["run_id"]))
            self.assertEqual(len(evidence["observations"]),expected)

    def test_history_import_binds_actual_git_blob_and_rejects_other_revision(self):
        self.configure("gitleaks", "gitleaks-history.json", history=True)
        h=self.helper; outcome=h.admit()
        info,_=h.importer._guard(); evidence=strict_json(retained_import(h.importer,info,outcome["run_id"]))
        self.assertEqual(evidence["input_kind"],"history")
        self.assertNotIn(CANARY, json.dumps(evidence))
        revision=next(iter(h.admission["input"]["revisions"]))
        h.admission["input"]["revisions"][revision]["secrets-positive.txt"]="0"*64
        self.write_report(report("gitleaks-history.json"))
        with self.assertRaises(ExecutionDenied): h.admit()

    def test_rejected_secret_report_never_leaks_canary_into_failure_ledger(self):
        self.configure("gitleaks", "gitleaks-current.json")
        doc=strict_json(report("gitleaks-current.json")); doc[0]["RuleID"]=CANARY
        self.write_report(canonical(doc))
        with self.assertRaises(ExecutionDenied) as denied:self.helper.admit()
        self.assertNotIn(CANARY,str(denied.exception))
        self.assertNotIn(CANARY.encode(),(self.helper.fx.state/"ledger.sqlite3").read_bytes())
