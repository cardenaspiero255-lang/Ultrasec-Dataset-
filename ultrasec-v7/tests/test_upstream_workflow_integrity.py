"""Regression tests for real upstream witness workflow wiring (stdlib only)."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "v7-gitea-native-regression.yml"


class GiteaNativeWorkflowContract(unittest.TestCase):
    def test_gitea_witness_is_one_atomic_command(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "go test -tags sqlite -count=1 -timeout 10m -run '^TestRelease_Update$' ./services/release -v",
            text,
        )
        self.assertIn('test_exit="${PIPESTATUS[0]}"', text)
        self.assertIn("EXPECTED_RED_VERIFIED=true", text)
        self.assertIn("FIXED_GREEN_VERIFIED=true", text)

    def test_artifacts_uploaded_once_after_execution(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(text.count("- name: Preserve public logs and SHA; never archive source"), 1)
        self.assertLess(text.index("go test -tags sqlite"), text.index("- name: Preserve public logs and SHA"))
        self.assertIn("native_verdict.txt", text)
        self.assertIn("log_sha256.txt", text)

    def test_before_and_after_use_immutable_real_commits(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("7fdfb8d642201b388014f29889ef28e35b8c1872", text)
        self.assertIn("e4ef995f2a162e3aca3f3a0b536afae067975d71", text)
        self.assertIn("git -C upstream rev-parse HEAD", text)


if __name__ == "__main__":
    unittest.main()
