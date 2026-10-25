from pathlib import Path
import json
import unittest

from jsonschema import Draft202012Validator

BASE = Path(__file__).resolve().parents[1]


class ReportSchemaTests(unittest.TestCase):
    def setUp(self):
        self.schema = json.loads((BASE / 'findings.schema.json').read_text())
        self.report = json.loads((BASE / 'findings.example.json').read_text())
        self.v = Draft202012Validator(self.schema)

    def test_valid_empty_assessment_is_explicitly_unexecuted(self):
        self.assertFalse(list(self.v.iter_errors(self.report)))
        self.assertIn('No assessment', self.report['coverage']['untested'][0])

    def test_high_finding_requires_additional_details(self):
        self.report['findings'].append({
            'id':'A-001','title':'Synthetic example','status':'confirmed',
            'severity':'high','confidence':'high','affected_asset':'isolated test',
            'attacker_prerequisites':[], 'expected_behavior':'blocked',
            'observed_behavior':'allowed', 'reproduction_steps':[],
            'evidence_refs':[], 'demonstrated_impact':'synthetic',
            'root_cause':'synthetic', 'remediation':'synthetic'
        })
        self.assertTrue(list(self.v.iter_errors(self.report)))
        self.report['findings'][0]['cvss_assessment'] = {
            'applicable': False, 'reason': 'Not applicable to this synthetic example'
        }
        self.report['findings'][0]['regression_test_guidance'] = ['Add a synthetic regression test']
        self.assertFalse(list(self.v.iter_errors(self.report)))


if __name__ == '__main__':
    unittest.main()
