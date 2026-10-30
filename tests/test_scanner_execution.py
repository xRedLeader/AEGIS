"""Governed native profile admission rejects unsafe operator configuration."""
import hashlib
from datetime import datetime,timezone
import os
from pathlib import Path
import unittest
import uuid
from unittest.mock import patch

from aegis_scanner_execution import validate_execution,_rules_only,GITLEAKS_SHA256,sealed_file,ScannerExecutionSupervisor,report_observed_at
from aegis_audit_contract import canonical
from aegis_scanner_sandbox import launch
from aegis_sandbox import SandboxFailure
from aegis_supervisor import ExecutionDenied


class NativePolicyTests(unittest.TestCase):
    def test_trivy_report_time_survives_second_boundary_without_accepting_stale_or_future_output(self):
        start=datetime(2026,10,30,12,0,0,900000,tzinfo=timezone.utc)
        finish=datetime(2026,10,30,12,0,1,100000,tzinfo=timezone.utc)
        raw=canonical({'CreatedAt':'2026-10-30T12:00:00.999999999Z'})
        self.assertEqual(report_observed_at(raw,'trivy-sbom-v0.76.1',start,finish),'2026-10-30T12:00:00Z')
        for stamp in ('2026-10-30T12:00:00.899999999Z','2026-10-30T12:00:01.100000001Z',None):
            with self.subTest(timestamp=stamp),self.assertRaises(ExecutionDenied):
                report_observed_at(canonical({'CreatedAt':stamp}),'trivy-sbom-v0.76.1',start,finish)
        self.assertEqual(report_observed_at(b'[]','gitleaks-dir-v8.24.3',start,finish),'2026-10-30T12:00:01Z')

    def setUp(self):
        self.policy={'schema_version':1,'configured':True,'engagement_id':'fixture','operation_id':str(uuid.uuid4()),
            'profile':'gitleaks-dir-v8.24.3','executable':{'path':'/opt/tools/gitleaks','sha256':GITLEAKS_SHA256},
            'configuration':{'path':'/etc/aegis/rules.toml','sha256':'a'*64},'input':{'kind':'source'},
            'allowed_rule_ids':['fixture'],'seconds':15}

    def test_profile_has_no_command_or_flag_escape(self):
        validate_execution(self.policy)
        for key,value in (('profile','shell'),('seconds',True),('seconds',121),('configured',False),('operation_id',3)):
            bad={**self.policy,key:value}
            with self.subTest(key=key),self.assertRaises((ExecutionDenied,ValueError)):validate_execution(bad)
        bad={**self.policy,'flags':['--exec','sh']}
        with self.assertRaises(ExecutionDenied):validate_execution(bad)

    def test_binary_digest_and_history_are_not_model_selected(self):
        bad={**self.policy,'executable':{'path':'/opt/tools/gitleaks','sha256':'b'*64}}
        with self.assertRaises(ExecutionDenied):validate_execution(bad)
        bad={**self.policy,'input':{'kind':'history'}}
        with self.assertRaises(ExecutionDenied):validate_execution(bad)

    def test_offline_launch_rejects_network_capability(self):
        with self.assertRaises(SandboxFailure):launch('gitleaks-dir-v8.24.3',3,4,5,Path('/private/jail'),5,broker_fd=9)
        with self.assertRaises(SandboxFailure):launch('nuclei',3,4,5,Path('/private/jail'),5)

    def test_rules_cannot_import_files_or_extend_configuration(self):
        raw=b'''title = "synthetic only"\n[[rules]]\nid = "fixture"\nregex = '''+b"'''EXAMPLE_[A-Z]{8}'''\n"
        _rules_only(raw,['fixture'])
        for suffix in (b'\n[extend]\npath = "/host/secret"\n',b'\ncredential = "hidden"\n',b'\nregex = "changed"\n'):
            with self.assertRaises(ExecutionDenied):_rules_only(raw+suffix,['fixture'])
        with self.assertRaises(ExecutionDenied):_rules_only(raw,['other'])

    def test_memfd_binary_snapshot_is_immutable(self):
        fd=sealed_file('fixture',b'fixed bytes',True)
        try:
            with self.assertRaises(OSError):os.write(fd,b'changed')
            with self.assertRaises(OSError):os.ftruncate(fd,0)
            self.assertEqual(os.read(fd,100),b'fixed bytes')
        finally:os.close(fd)

    def test_integrated_repository_and_duration_are_checked_before_reservation(self):
        engine=object.__new__(ScannerExecutionSupervisor);engine.state_root=Path('/var/lib/aegis-fixture')
        self.policy['input']['repository']='/srv/approved-source'
        for kwargs,reason in (({'expected_repository':'/srv/different-source'},'repository'),({'max_seconds':14},'duration')):
            with self.subTest(kwargs=kwargs),patch.object(engine,'_guard',return_value=({'engagement_id':'fixture'},{})), \
                 patch('aegis_scanner_execution._protected',return_value=canonical(self.policy)),patch.object(engine,'reserve') as reserve:
                with self.assertRaisesRegex(ExecutionDenied,reason):engine.execute('/etc/aegis/execution.json',**kwargs)
                reserve.assert_not_called()
