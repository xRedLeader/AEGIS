"""Run real profiles inside an explicitly bounded ephemeral systemd test unit."""
import argparse
import json
import os
from pathlib import Path

from scanner_execution_acceptance import run as gitleaks
from semgrep_execution_acceptance import run as semgrep
from trivy_execution_acceptance import run as trivy
from native_scanner_recovery_acceptance import confinement,failures,crash
from semgrep_confinement_acceptance import confinement as semgrep_confinement
from trivy_confinement_acceptance import confinement as trivy_confinement


def run(tools,database=None):
    assert os.geteuid()!=0
    group=next(line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    root=Path('/sys/fs/cgroup')/group.lstrip('/')
    assert (root/'memory.max').read_text().strip()==str(1024**3),'actual scanner test unit needs a 1024 MiB hard cgroup memory ceiling'
    assert (root/'pids.max').read_text().strip()=='96','actual task ceiling differs'
    cpu=(root/'cpu.max').read_text().split();assert len(cpu)==2 and cpu[0]==cpu[1],'actual CPU ceiling differs'
    result={'gitleaks':gitleaks(tools/'gitleaks'),'semgrep':semgrep(tools/'semgrep-core'),
            'trivy':trivy(tools/'trivy',database or tools/'trivy-db'),
            'recovery':{'kernel':confinement(tools/'native-probe'),'semgrep_kernel':semgrep_confinement(tools/'semgrep-probe'),
                        'trivy_kernel':trivy_confinement(tools/'trivy-probe'),
                        'failure_drills':failures(tools/'native-probe'),'crash':crash(tools/'native-probe')}}
    result['unit']={'uid':os.geteuid(),'memory_max_bytes':1024**3,'tasks_max':96,'cpu_quota_percent':100,
                    'memory_peak_bytes':int((root/'memory.peak').read_text()) if (root/'memory.peak').exists() else None}
    result['status']='ALL_OFFLINE_PROFILES_AND_RECOVERY_PASSED_IN_BOUNDED_UNIT'
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--tools',type=Path,required=True)
    parser.add_argument('--database',type=Path,help='Existing protected prepared DB; avoids duplicating a large local fixture')
    args=parser.parse_args();print(json.dumps(run(args.tools,args.database),sort_keys=True))
