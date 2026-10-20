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
        # GitHub may choose CLI --error or a stronger fail-closed JSON gate.
        # Never accept warning-only scans that silently succeed on findings.
        cli_blocks = "semgrep scan --error " in sast
        json_gate_blocks = (
            "semgrep scan --oss-only " in sast
            and "if errors: raise SystemExit(" in sast
            and "if findings: raise SystemExit(" in sast
            and "SEMGREP_FINDING:" in sast
        )
        self.assertTrue(cli_blocks or json_gate_blocks,
                        "Semgrep must block on real findings and parser errors")

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


class CodeqlSarifGateTests(unittest.TestCase):
    def load_gate(self):
        module_path = ROOT / "ultrasec-v7" / "tools" / "check_codeql_sarif.py"
        self.assertTrue(module_path.is_file(), "CodeQL SARIF quality gate must exist")
        spec = importlib.util.spec_from_file_location("codeql_quality_gate", module_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def write_sarif(self, root, results):
        import json
        (root / "python.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [{"results": results}]}))

    def test_missing_sarif_fails_closed(self):
        gate = self.load_gate()
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                gate.scan_sarif(pathlib.Path(d))

    def test_codeql_warning_blocks_merge(self):
        gate = self.load_gate()
        with tempfile.TemporaryDirectory() as d:
            directory = pathlib.Path(d)
            self.write_sarif(directory, [{"ruleId": "py/test-warning", "level": "warning"}])
            with self.assertRaises(ValueError):
                gate.scan_sarif(directory)

    def test_codeql_error_blocks_merge(self):
        gate = self.load_gate()
        with tempfile.TemporaryDirectory() as d:
            directory = pathlib.Path(d)
            self.write_sarif(directory, [{"ruleId": "py/test-error", "level": "error"}])
            with self.assertRaises(ValueError):
                gate.scan_sarif(directory)

    def test_clean_sarif_accepted(self):
        gate = self.load_gate()
        with tempfile.TemporaryDirectory() as d:
            directory = pathlib.Path(d)
            self.write_sarif(directory, [])
            self.assertEqual(gate.scan_sarif(directory)["blocking"], 0)

    def test_codeql_sarif_gate_is_executed_in_workflow(self):
        sast = (WORKFLOW_DIR / "ultrasec-public-sast.yml").read_text()
        self.assertIn("check_codeql_sarif.py", sast)
        self.assertIn("sarif-output", sast)


if __name__ == "__main__":
    unittest.main()
