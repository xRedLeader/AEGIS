"""Attempt prohibited operations through the actual Semgrep root/bootstrap."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/"tests")]
from aegis_scanner_execution import sealed_file
from aegis_semgrep_sandbox import PROFILE, launch


def confinement(binary):
    assert 0 < binary.stat().st_size <= 1024*1024, "expected compiled synthetic probe"
    fds = []
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-semgrep-probe-") as folder:
            root = Path(folder)
            (root/"source").mkdir()
            source = root/"source/safe.js"
            source.write_bytes(b"const example = 'safe';\n")
            (root/"jail").mkdir(mode=0o700)
            fds = [sealed_file("semgrep-test-probe", binary.read_bytes(), True),
                   sealed_file("semgrep-test-rules", b"probe"),
                   os.open(root/"source", os.O_RDONLY|os.O_DIRECTORY)]
            result = subprocess.run(launch(PROFILE, *fds, root/"jail", 10), pass_fds=fds,
                                    capture_output=True, timeout=15)
            assert result.returncode == 0, (result.returncode, result.stdout.decode(), result.stderr.decode())
            health = json.loads(result.stderr.splitlines()[0])
            assert health["status"] == "NATIVE_OFFLINE_BOUNDARY_ENTERED" and health["profile"] == PROFILE
            proof = json.loads(result.stdout)
            assert len(proof["checks"]) == 16 and all(proof["checks"].values()), proof
            assert source.read_bytes() == b"const example = 'safe';\n"
            return proof["checks"]
    finally:
        for fd in fds:
            os.close(fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    print(json.dumps({"status": "SEMGREP_KERNEL_CONFINEMENT_PASSED",
                      "checks": confinement(parser.parse_args().probe)}, sort_keys=True))
