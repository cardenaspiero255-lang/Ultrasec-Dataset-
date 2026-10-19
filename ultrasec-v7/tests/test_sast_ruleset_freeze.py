"""Fail-closed synthetic tests for offline SAST rule-byte preregistration."""
import hashlib
import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'tools' / 'sast_ruleset_freeze.py'
spec = importlib.util.spec_from_file_location('sast_ruleset_freeze', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(root):
    (root / 'rules').mkdir()
    body = b'rules:\n  - id: synthetic.test\n    languages: [python]\n    severity: WARNING\n    message: synthetic\n    pattern: exec($X)\n'
    (root / 'rules' / 'rule.yml').write_bytes(body)
    return {
        'schema': 'ultrasec.sast-rule-byte-plan.v1',
        'certification': 'NOT_CERTIFIED',
        'gold_count': 0,
        'holdout_status': 'UNASSIGNED',
        'scoring_enabled': False,
        'purpose': 'FUTURE_UNSEEN_PRE_REGISTRATION',
        'known_case_exclusions': ['CVE-2026-58428', 'CVE-2024-2395', 'CVE-2024-0683'],
        'entries': [{'tool': 'semgrep', 'version': '1.180.0',
                     'path': 'rules/rule.yml',
                     'sha256': hashlib.sha256(body).hexdigest(),
                     'cwes': ['CWE-94']}],
    }


class RuleFreezeGateTest(unittest.TestCase):
    def test_valid_bytes_can_be_locked_but_not_claimed_as_blind_benchmark(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            plan = fixture(root)
            receipt = module.freeze(plan, root)
            self.assertTrue(receipt['rule_bytes_verified'])
            self.assertEqual(receipt['verified_rule_files'], 1)
            self.assertFalse(receipt['blind_benchmark_ready'])
            self.assertFalse(receipt['external_chronology_verified'])
            self.assertEqual(receipt['gold_admitted'], 0)
            self.assertEqual(receipt['certification'], 'NOT_CERTIFIED')
            self.assertNotIn('synthetic.test', str(receipt))
            self.assertEqual(receipt['rulepack_sha256'], module.freeze(plan, root)['rulepack_sha256'])

    def test_mutating_locked_rule_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            plan = fixture(root)
            (root / 'rules' / 'rule.yml').write_text('rules: []\n')
            with self.assertRaisesRegex(ValueError, 'digest_mismatch'):
                module.freeze(plan, root)

    def test_registry_alias_is_not_pinned(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            plan = fixture(root)
            plan['entries'][0]['path'] = 'p/security-audit'
            with self.assertRaisesRegex(ValueError, 'unsafe_rule_path'):
                module.freeze(plan, root)

    def test_symlink_and_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            plan = fixture(root)
            (root / 'rules' / 'alias.yml').symlink_to(root / 'rules' / 'rule.yml')
            plan['entries'][0]['path'] = 'rules/alias.yml'
            with self.assertRaisesRegex(ValueError, 'unsafe_rule_path'):
                module.freeze(plan, root)
            plan['entries'][0]['path'] = '../private.json'
            with self.assertRaisesRegex(ValueError, 'unsafe_rule_path'):
                module.freeze(plan, root)

    def test_gold_scoring_certification_and_assigned_splits_rejected(self):
        for key, bad in [('scoring_enabled', True), ('gold_count', 1),
                         ('certification', 'CERTIFIED'), ('holdout_status', 'TEST_ASSIGNED')]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                plan = fixture(root)
                plan[key] = bad
                with self.assertRaisesRegex(ValueError, 'unsupported_evaluation_claim'):
                    module.freeze(plan, root)

    def test_known_cases_must_be_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            plan = fixture(root)
            plan['known_case_exclusions'] = []
            with self.assertRaisesRegex(ValueError, 'missing_known_case_exclusions'):
                module.freeze(plan, root)

    def test_private_receipt_mode_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            plan = fixture(root)
            destination = root / 'lock-private.json'
            module.write_receipt(module.freeze(plan, root), destination)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(json.loads(destination.read_text())['certification'], 'NOT_CERTIFIED')
            with self.assertRaises(FileExistsError):
                module.write_receipt(module.freeze(plan, root), destination)


if __name__ == '__main__':
    unittest.main()
