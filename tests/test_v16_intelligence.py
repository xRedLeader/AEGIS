"""v1.6 signed OSV snapshot, exact dependency matching and real offline jail."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import os
import tempfile
import unittest

from aegis_intelligence import (CONTEXT, IntelligenceDenied, MAX_BUNDLE,
                               correlate, validate_snapshot, load_signed_snapshot)
from aegis_intelligence_runtime import AegisIntelligenceSupervisor
from aegis_supervisor import ExecutionDenied, operator_stop
from aegis_intel_admin import sign_file
import test_preflight


def utc(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


class IntelligenceFixture(unittest.TestCase):
    def setUp(self):
        self.fx = test_preflight.AegisPreflightTests('test_valid_signed_scope')
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.state = self.fx.p / 'state'
        self.state.mkdir(mode=0o700)
        self.fx.manifest['targets']['origins'] = []
        self.fx.manifest['accounts'] = []
        self.fx.manifest['methods']['allowed'] = ['dependency_analysis']
        self.fx.trust['approved_methods'] = ['dependency_analysis']
        self.fx.manifest['limits'].update(max_total_requests=0,
          max_requests_per_minute_per_origin=0, max_concurrent_requests=0,
          max_single_run_minutes=1, engagement_runtime_minutes=2,
          deterministic_hypothesis_minutes=1)
        self.fx.save()
        (self.fx.repo / 'requirements.txt').write_text('requests==2.31.0\ncolorama>=0.2\n-c constraints.txt\n# comment\n')
        (self.fx.repo / 'package-lock.json').write_text(json.dumps({
          'lockfileVersion': 3, 'packages': {'': {'version': '1.0.0'},
          'node_modules/lodash': {'version': '4.17.20'},
          'node_modules/@types/node': {'version': '18.1.0'},
          'node_modules/a-link': {'link': True, 'version':'1.0.0'}}}))
        self.bundle = self.fx.p / 'osv-bundle.json'
        self.sig = self.fx.p / 'osv-bundle.sig'
        self.snapshot = {'format':'AEGIS-OSV-v1', 'source':'OSV',
          'source_url':'https://api.osv.dev','retrieved_at_utc':utc(datetime.now(timezone.utc)),
          'records':[
             {'id':'GHSA-TEST-1001', 'affected':[{'package':{'ecosystem':'PyPI', 'name':'requests'}, 'versions':['2.31.0']}]},
             {'id':'GHSA-TEST-1002', 'affected':[{'package':{'ecosystem':'npm','name':'lodash'},'versions':['4.17.20']} ]},
             {'id':'GHSA-TEST-1003', 'affected':[{'package':{'ecosystem':'npm','name':'@types/node'},
                                                  'ranges':[{'type':'SEMVER','events':[{'introduced':'18.0.0'}]}]}]},
          ]}
        self.sign()

    def sign(self):
        raw = json.dumps(self.snapshot, sort_keys=True, separators=(',', ':')).encode('utf-8')
        self.bundle.write_bytes(raw)
        self.sig.write_bytes(self.fx.key.sign(CONTEXT + raw))
        self.sig.chmod(0o600)

    def supervisor(self):
        return AegisIntelligenceSupervisor(self.fx.manifest_path,self.fx.sig_path,
              self.fx.trust_path,self.state)


class PureIntelligenceTests(IntelligenceFixture):
    def test_exact_enumeration_and_uncertain_range(self):
        inv = {'status':'OFFLINE_DEPENDENCY_INVENTORY_NOT_VULNERABILITY_VERIFICATION',
               'packages':[{'ecosystem':'PyPI','name':'requests','version':'2.31.0','source':'requirements.txt','classification':'declared_pin_not_verified_installed'},
                           {'ecosystem':'npm','name':'lodash','version':'4.17.20','source':'package-lock.json','classification':'lockfile_entry_not_verified_installed'},
                           {'ecosystem':'npm','name':'@types/node','version':'18.1.0','source':'package-lock.json','classification':'lockfile_entry_not_verified_installed'}]}
        res = correlate(inv, validate_snapshot(self.snapshot))
        self.assertEqual([x['advisory_id'] for x in res['leads']], ['GHSA-TEST-1001','GHSA-TEST-1002'])
        self.assertEqual(res['summary']['range_only_associations_unresolved'],1)

    def test_tampered_bundle_denied(self):
        self.bundle.write_bytes(self.bundle.read_bytes()+b' ')
        with self.assertRaisesRegex(IntelligenceDenied,'signature'):
            load_signed_snapshot(self.bundle,self.sig,self.fx.pub)

    def test_wrong_signature_denied(self):
        self.sig.write_bytes(b'0'*64)
        with self.assertRaises(IntelligenceDenied):
            load_signed_snapshot(self.bundle,self.sig,self.fx.pub)

    def test_stale_and_future_snapshots(self):
        for seconds in (-4*86400, 60):
            self.snapshot['retrieved_at_utc']=utc(datetime.now(timezone.utc)+timedelta(seconds=seconds))
            self.sign()
            with self.subTest(seconds=seconds),self.assertRaisesRegex(IntelligenceDenied, 'stale or future'):
                load_signed_snapshot(self.bundle,self.sig,self.fx.pub)

    def test_withdrawn_record_ignored(self):
        self.snapshot['records'][0]['withdrawn']=utc(datetime.now(timezone.utc))
        self.sign()
        inv={'status':'OFFLINE_DEPENDENCY_INVENTORY_NOT_VULNERABILITY_VERIFICATION',
             'packages':[{'ecosystem':'PyPI','name':'requests','version':'2.31.0','source':'requirements.txt','classification':'declared_pin_not_verified_installed'}]}
        r=correlate(inv,validate_snapshot(self.snapshot))
        self.assertFalse(r['leads'])

    def test_sanitized_output_without_advisory_body(self):
        self.snapshot['records'][0]['details']='confidential example string' 
        self.sign()
        inv={'status':'OFFLINE_DEPENDENCY_INVENTORY_NOT_VULNERABILITY_VERIFICATION',
             'packages':[{'ecosystem':'PyPI','name':'requests','version':'2.31.0','source':'requirements.txt','classification':'declared_pin_not_verified_installed'}]}
        result=correlate(inv,validate_snapshot(self.snapshot))
        self.assertNotIn('confidential example string',json.dumps(result))

    def test_duplicate_json_key_denied(self):
        from aegis_intelligence import _json_no_dupes
        with self.assertRaisesRegex(IntelligenceDenied,'duplicate'):
            _json_no_dupes(b'{"source":"OSV","source":"BAD"}')

    def test_signing_validates_before_signature_created(self):
        self.snapshot['source_url']='https://evil.example'
        self.sign()
        from cryptography.hazmat.primitives.serialization import PrivateFormat, Encoding, NoEncryption
        keypath=self.fx.p/'key.pem'
        keypath.write_bytes(self.fx.key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
        keypath.chmod(0o600)
        dst=self.fx.p/'test-signature.sig'
        with self.assertRaises(IntelligenceDenied):
            sign_file(self.bundle,keypath,dst)
        self.assertFalse(dst.exists())


class KernelDependencyTests(IntelligenceFixture):
    def test_scope_gated_real_isolation_and_signed_correlation(self):
        supervisor=self.supervisor()
        result=supervisor.assess_dependencies(self.fx.repo,self.bundle,self.sig,budget_seconds=5)
        self.assertEqual(result['summary']['exact_version_leads'],2)
        self.assertEqual(result['summary']['range_only_associations_unresolved'],1)
        inv=json.loads(Path(result['inventory_report']).read_text())
        self.assertEqual(inv['summary']['packages_recorded'],3)
        self.assertEqual(inv['summary']['entries_unresolved'],4)
        leads=json.loads(Path(result['candidates_report']).read_text())
        self.assertEqual(len(leads['leads']),2)
        self.assertTrue(supervisor.verify_audit_chain())
        self.assertEqual(supervisor.usage(result['engagement_id'])['reserved_seconds'],5)

    def test_method_must_be_approved(self):
        self.fx.manifest['methods']['allowed']=['source_review']
        self.fx.trust['approved_methods']=['source_review']
        self.fx.save()
        with self.assertRaisesRegex(ExecutionDenied,'dependency_analysis'):
            self.supervisor().assess_dependencies(self.fx.repo,self.bundle,self.sig,5)

    def test_invalid_feed_denied_before_budget_reservation(self):
        self.bundle.write_bytes(b'{}')
        with self.assertRaises(IntelligenceDenied):
            self.supervisor().assess_dependencies(self.fx.repo,self.bundle,self.sig,5)
        self.assertFalse((self.state/'ledger.sqlite3').exists())

    def test_symlink_manifest_fails_closed(self):
        outside=self.fx.p/'private.txt'
        outside.write_text('Do not access')
        (self.fx.repo/'requirements.txt').unlink()
        (self.fx.repo/'requirements.txt').symlink_to(outside)
        with self.assertRaisesRegex(ExecutionDenied,'worker failed'):
            self.supervisor().assess_dependencies(self.fx.repo,self.bundle,self.sig,5)

    def test_outside_repo_denied(self):
        other=self.fx.p/'unapproved';other.mkdir()
        with self.assertRaisesRegex(ExecutionDenied,'outside verified'):
            self.supervisor().assess_dependencies(other,self.bundle,self.sig,5)

    def test_live_emergency_stop(self):
        operator_stop(self.state, self.fx.manifest['engagement']['id'])
        with self.assertRaisesRegex(ExecutionDenied,'emergency stop'):
            self.supervisor().assess_dependencies(self.fx.repo,self.bundle,self.sig,5)

if __name__=='__main__': unittest.main()


class ImportedScannerDataTests(unittest.TestCase):
    def test_pip_audit_leads_sanitized(self):
        from aegis_security_tool_adapters import import_scanner_report
        raw=json.dumps({"dependencies":[{"name":"Requests", "version":"2.31.0",
            "vulns":[{"id":"CVE-2026-12345","description":"PRIVATE_TOKEN=not-output"}]}]}).encode()
        result=import_scanner_report("pip-audit-json",raw)
        self.assertEqual(result["leads"][0]["package"],"requests")
        self.assertNotIn("PRIVATE_TOKEN",json.dumps(result))

    def test_npm_audit_never_invents_installed_version(self):
        from aegis_security_tool_adapters import import_scanner_report
        raw=json.dumps({"vulnerabilities":{"lodash":{"via":[{"name":"GHSA-1111-2222-3333",
            "range":"<4.17.21","title":"untrusted text"}]}}}).encode()
        result=import_scanner_report("npm-audit-v2",raw)
        self.assertIsNone(result["leads"][0]["version"])
        self.assertNotIn("untrusted text",json.dumps(result))

    def test_oversized_and_unknown_scanners_denied(self):
        from aegis_security_tool_adapters import import_scanner_report
        for kind,raw in [("unsupported",b"{}"),("npm-audit-v2",b"x"*(512*1024+1))]:
            with self.assertRaises(IntelligenceDenied):
                import_scanner_report(kind,raw)

    def test_scanner_duplicate_keys_denied(self):
        from aegis_security_tool_adapters import import_scanner_report
        with self.assertRaises(IntelligenceDenied):
            import_scanner_report("pip-audit-json",b'{"dependencies":[],"dependencies":[]}')
