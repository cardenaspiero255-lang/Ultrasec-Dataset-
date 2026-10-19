"""RED-first contract: new upstream-original MISP isolated witness is required."""
from pathlib import Path
import unittest
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ultrasec-v7/verification/research/misp_original_evaluation_report_witness.py"
WF = ROOT / ".github/workflows/v7-misp-comment-export-witness.yml"


class MispNativeCausalityContract(unittest.TestCase):
    def test_original_sha_pinned_revisions_and_isolated_source_function(self):
        self.assertTrue(SCRIPT.is_file(), "Original-function test harness missing")
        text=SCRIPT.read_text(encoding="utf-8")
        self.assertIn("build_evaluation_report",text)
        self.assertIn("ast.parse(",text)
        self.assertIn("outsider_private_comment",text)
        self.assertIn("legitimate_owner_comment",text)
        self.assertIn("public_comment",text)
        self.assertIn("ORIGINAL_FUNCTION_ISOLATED_NOT_FULL_APPLICATION",text)

    def test_workflow_reexecutes_on_both_immutable_upstream_revisions(self):
        self.assertTrue(WF.is_file(),"Genuine upstream source CI missing")
        txt=WF.read_text(encoding="utf-8")
        for sha in ("06d408e3496fdfc31da22d7b2b427434c67eae94",
                    "5dbd19b39a61eab793586731f1a80d8c38907c42"):
            self.assertIn(sha,txt)
        self.assertIn("git -C upstream rev-parse HEAD",txt)
        self.assertIn("misp_original_evaluation_report_witness.py",txt)
        self.assertIn("MISP_ORIGINAL_ISOLATED_BEHAVIOR_VERIFIED",txt)
        self.assertIn("GOLD_ADMITTED=0",txt)
        self.assertIn("witness_sha256.txt",txt)

if __name__=="__main__":unittest.main()
