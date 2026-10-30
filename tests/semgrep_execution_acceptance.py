"""Actual pinned static Semgrep core under the governed offline kernel profile."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/"tests")]
from aegis_audit_contract import canonical
from aegis_scanner_execution import ScannerExecutionSupervisor
from aegis_semgrep_sandbox import PROFILE,BINARY_SHA256
from aegis_supervisor import ExecutionDenied
from test_runtime import AegisRuntimeTests


def run(binary):
    fixture=AegisRuntimeTests();fixture.setUp()
    try:
        fx=fixture.fx
        fx.manifest["limits"]["engagement_runtime_minutes"]=5
        fx.manifest["limits"]["max_single_run_minutes"]=1;fx.save()
        source=ROOT/"tests/fixtures/source_scanners"
        selected=["Example.cs","example.js","typed-example.ts","react.jsx","typed-react.tsx"]
        rules={"rules":[{"id":"aegis-js-dynamic-eval","languages":["javascript","typescript"],"pattern":"eval($VALUE)",
                         "message":"Synthetic evaluation boundary only","severity":"WARNING"},
                        {"id":"aegis-csharp-process-start","languages":["csharp"],"pattern":"Process.Start($VALUE)",
                         "message":"Synthetic process boundary only","severity":"WARNING"}]}
        config=fx.p/"semgrep-rules.json";config.write_bytes(canonical(rules));config.chmod(0o600)
        engine=ScannerExecutionSupervisor(fx.manifest_path,fx.sig_path,fx.trust_path,fixture.state)
        outcomes=[]
        for variant,expected in (("source",5),("safe-source",0)):
            for name in selected[:3]:(fx.repo/name).write_bytes((source/variant/name).read_bytes())
            expression="eval(value)" if variant=="source" else "value"
            (fx.repo/"react.jsx").write_text("export function Component(value) { return <span>{"+expression+"}</span>; }\n")
            (fx.repo/"typed-react.tsx").write_text("export function TypedComponent(value: string) { return <span>{"+expression+"}</span>; }\n")
            # This candidate is deliberately excluded from the approved snapshot.
            (fx.repo/"unselected.js").write_text("eval(untrusted);\n")
            policy={"schema_version":1,"configured":True,"engagement_id":fx.manifest["engagement"]["id"],
                    "operation_id":str(uuid.uuid4()),"profile":PROFILE,
                    "executable":{"path":str(binary),"sha256":BINARY_SHA256},
                    "configuration":{"path":str(config),"sha256":hashlib.sha256(config.read_bytes()).hexdigest()},
                    "input":{"kind":"source","repository":str(fx.repo),
                             "files":{name:hashlib.sha256((fx.repo/name).read_bytes()).hexdigest() for name in selected}},
                    "allowed_rule_ids":[rule["id"] for rule in rules["rules"]],"seconds":30}
            path=fx.p/"semgrep-execution.json";path.write_bytes(canonical(policy));path.chmod(0o600)
            outcome=engine.execute(path)
            assert outcome["observations"]==expected,outcome
            assert outcome["import"]["status"]=="SCANNER_IMPORT_RECORDED",outcome
            generated=engine.generate(outcome["import"]["run_id"],"scanner-import.json")
            report=json.loads(Path(generated["report"]).read_bytes())
            assert len(report["findings"])==expected
            assert all(f["verdict"]=="needs_validation" for f in report["findings"])
            try:engine.execute(path)
            except ExecutionDenied:pass
            else:raise AssertionError("completed Semgrep operation silently reran")
            outcomes.append({"case":variant,"observations":expected,"governed_import":True,"replay_denied":True})
        assert engine.verify_audit_chain()
        return {"status":"REAL_PINNED_SEMGREP_ACCEPTANCE_PASSED","binary_sha256":BINARY_SHA256,
                "languages":["C#","JavaScript","TypeScript","JSX","TSX"],"cases":outcomes,
                "process_creation":"denied","network":"denied","assessment_status":"unverified_only"}
    finally:fixture.tearDown();fixture.doCleanups()


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--binary",type=Path,required=True)
    print(json.dumps(run(parser.parse_args().binary),sort_keys=True))
