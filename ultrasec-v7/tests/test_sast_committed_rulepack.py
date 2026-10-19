"""Verify committed SAST preregistration bytes; no private holdout is read."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools' / 'sast_ruleset_freeze.py'
spec = importlib.util.spec_from_file_location('sast_rule_bytes_gate', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CommittedRulepackTest(unittest.TestCase):
    def test_pinned_public_baseline_remains_immutable_and_unscored(self):
        plan = json.loads((ROOT / 'verification' / 'research' /
                           'FUTURE_UNSEEN_SAST_BYTE_FREEZE_PLAN.json').read_text('utf-8'))
        receipt = module.freeze(plan, ROOT)
        self.assertEqual(receipt['rulepack_sha256'],
                         '1c4ea1fdfcf1955e28adf758e8c08421ab8cd279cfa058a378cb0bef84ab2eb3')
        self.assertEqual(receipt['verified_rule_files'], 1)
        self.assertEqual(receipt['known_research_exclusions'], 8)
        self.assertFalse(receipt['blind_benchmark_ready'])
        self.assertFalse(receipt['external_chronology_verified'])
        self.assertEqual(receipt['gold_admitted'], 0)


if __name__ == '__main__':
    unittest.main()
