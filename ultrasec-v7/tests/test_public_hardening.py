"""Regression tests for public-only CI security controls (no proprietary corpus)."""
from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
VERIFY = ROOT / "ultrasec-v7" / "tools" / "verify_public.py"

spec = importlib.util.spec_from_file_location("verify_public_policy", VERIFY)
assert spec is not None and spec.loader is not None
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class CiHardeningTests(unittest.TestCase):
    def test_semgrep_blocks_actual_findings(self):
        sast = (WORKFLOW_DIR / "ultrasec-public-sast.yml").read_text()
        self.assertIn("semgrep scan --error ", sast)

    def test_semgrep_covers_policy_validator(self):
        sast = (WORKFLOW_DIR / "ultrasec-public-sast.yml").read_text()
        self.assertIn("ultrasec-v7/tools", sast.split("  codeql_python_public:")[0])

    def test_sast_runs_when_public_validator_changes(self):
        sast = (WORKFLOW_DIR / "ultrasec-public-sast.yml").read_text()
        self.assertGreaterEqual(sast.count("'ultrasec-v7/tools/**'"), 2)

    def test_codeql_uses_sha_pinned_v4(self):
        sast = (WORKFLOW_DIR / "ultrasec-public-sast.yml").read_text()
        self.assertIn("github/codeql-action/init@24c54180a607b1449ed407dd24f251e4e9147c8d", sast)
        self.assertIn("github/codeql-action/analyze@24c54180a607b1449ed407dd24f251e4e9147c8d", sast)

    def test_gitleaks_checks_complete_git_history(self):
        workflow = (WORKFLOW_DIR / "ultrasec-public-ci.yml").read_text()
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e", workflow)
        self.assertIn('detect --source . --log-opts="--all"', workflow)
        self.assertIn('GITLEAKS_VERSION: "8.24.3"', workflow)

    def test_git_history_scanner_does_not_request_write_token(self):
        workflow = (WORKFLOW_DIR / "ultrasec-public-ci.yml").read_text()
        self.assertIn('GITLEAKS_ENABLE_COMMENTS: "false"', workflow)
        self.assertIn("  contents: read", workflow)

    def test_aws_access_key_pattern_is_detected(self):
        synthetic = "AKIA" + "Q" * 16
        self.assertIsNotNone(policy.SECRET_PATTERN.search(synthetic))

    def test_slack_bot_token_pattern_is_detected(self):
        synthetic = "xoxb-" + "123456789012-" + "123456789012-" + "a" * 24
        self.assertIsNotNone(policy.SECRET_PATTERN.search(synthetic))

    def test_google_api_key_pattern_is_detected(self):
        synthetic = "AIza" + "A" * 35
        self.assertIsNotNone(policy.SECRET_PATTERN.search(synthetic))

    def test_public_secret_scanner_rejects_synthetic_access_key(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "public_note.txt").write_text("AKIA" + "Q" * 16)
            with patch.object(policy, "tracked_files", return_value=[pathlib.Path("public_note.txt")]):
                with self.assertRaisesRegex(AssertionError, "Potential credential"):
                    policy.secrets(root)


if __name__ == "__main__":
    unittest.main()
