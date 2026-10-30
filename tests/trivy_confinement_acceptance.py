"""Hostile probes through Trivy's separate read-only root and DB bootstrap."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from aegis_scanner_execution import sealed_file
from aegis_trivy_sandbox import launch,PROFILE


def confinement(binary):
    fds=[]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.mkdir();(source/'safe.env').write_bytes(b'EXAMPLE=value\n')
            database=root/'database';database.mkdir();(database/'trivy.db').write_bytes(b'0'*4096)
            (root/'jail').mkdir(mode=0o700)
            fds=[sealed_file('trivy-probe',binary.read_bytes(),True),sealed_file('trivy-rules',b'{}'),
                 os.open(source,os.O_RDONLY|os.O_DIRECTORY),os.open(database,os.O_RDONLY|os.O_DIRECTORY)]
            result=subprocess.run(launch(PROFILE,*fds[:3],root/'jail',10,database_fd=fds[3]),
                                  pass_fds=fds,capture_output=True,timeout=15)
            assert result.returncode==0,(result.returncode,result.stderr.decode(),result.stdout.decode())
            proof=json.loads(result.stdout);assert len(proof['checks'])==17 and all(proof['checks'].values()),proof
            assert (source/'safe.env').read_bytes()==b'EXAMPLE=value\n'
            assert (database/'trivy.db').read_bytes()==b'0'*4096
            return proof['checks']
    finally:
        for fd in fds:os.close(fd)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--probe',type=Path,required=True)
    print(json.dumps(confinement(parser.parse_args().probe),sort_keys=True))
