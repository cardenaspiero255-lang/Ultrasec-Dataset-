"""Contract tests for MISP CTI-Transmute original, isolated privacy oracle."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW=ROOT/".github/workflows/v7-misp-original-evaluation-privacy.yml"
HARNESS=ROOT/"ultrasec-v7/verification/research/misp_original_evaluation_privacy.py"


class MispOriginalPrivacyContracts(unittest.TestCase):
    def test_exact_original_immutable_git_commits_both_stages(self):
        self.assertTrue(WORKFLOW.is_file(), 'Need original-source workflow')
        s=WORKFLOW.read_text('utf-8')
        self.assertIn('06d408e3496fdfc31da22d7b2b427434c67eae94',s)
        self.assertIn('5dbd19b39a61eab793586731f1a80d8c38907c42',s)
        self.assertIn('git -C upstream rev-parse HEAD',s)
        self.assertIn('misp-evaluation-privacy-',s)
        self.assertIn('native_verdict_sha256.txt',s)
        self.assertNotIn('upstream/**',s)

    def test_exact_original_function_with_safe_orm_stubs(self):
        self.assertTrue(HARNESS.is_file(), 'Need original function AST oracle')
        s=HARNESS.read_text('utf-8')
        self.assertIn('website/web/evaluate/evaluate_core.py',s)
        self.assertIn('website/lib/access.py',s)
        self.assertIn('build_evaluation_report',s)
        self.assertIn('BEFORE_PRIVATE_COMMENT_EXPOSED',s)
        self.assertIn('AFTER_PRIVATE_COMMENT_REDACTED',s)
        self.assertIn('NEGATIVE_OWNER_SEES_PRIVATE',s)
        self.assertIn('NEGATIVE_PUBLIC_COMMENT_PRESERVED',s)
        self.assertIn('GOLD_ADMITTED=0',s)


if __name__ == '__main__':
    unittest.main()
