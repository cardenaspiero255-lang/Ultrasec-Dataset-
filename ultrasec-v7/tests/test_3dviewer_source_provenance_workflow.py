"""No external CVE case may be admitted from version metadata alone."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
WORKFLOW=ROOT/".github/workflows/v7-3dvieweronline-original-source.yml"


class ThreeDViewerEvidenceWorkflowTest(unittest.TestCase):
    def test_original_official_versions_are_explicit(self):
        text=WORKFLOW.read_text()
        self.assertIn("https://downloads.wordpress.org/plugin/3dvieweronline-wp.2.2.2.zip",text)
        self.assertIn("https://downloads.wordpress.org/plugin/3dvieweronline-wp.2.2.3.zip",text)
        self.assertIn("public/class-threedvieweronline-iframe-public.php",text)

    def test_only_sanitized_metadata_artifacts(self):
        text=WORKFLOW.read_text()
        self.assertIn("if-no-files-found: error",text)
        self.assertIn("source_verification_receipt.json",text)
        self.assertNotIn("path: upstream",text)
        self.assertNotIn("path: src",text)

    def test_no_gold_in_workflow(self):
        text=WORKFLOW.read_text()
        self.assertIn('"gold_status":"NOT_ADMITTED"',text)
        self.assertIn('"license_clearance":"NOT_VERIFIED"',text)
        self.assertIn("php -l",text)

    def test_download_fail_closed_and_no_php_exec(self):
        text=WORKFLOW.read_text()
        self.assertIn("curl --fail --location",text)
        self.assertNotIn("php -f ",text)
        self.assertNotIn("php -r ",text)


if __name__=="__main__":
    unittest.main()
