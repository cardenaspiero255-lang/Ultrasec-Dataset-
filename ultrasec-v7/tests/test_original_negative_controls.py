"""TDD workflow requirements for genuine upstream negative controls.

These assertions intentionally fail until both source-level original test
harnesses and their independent receipts have been wired into GitHub Actions.
Only public research test source; never private examples or GOLD.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GITEA = ROOT / ".github/workflows/v7-gitea-native-regression.yml"
BULGAR = ROOT / ".github/workflows/v7-bulgarisation-wp-ajax-csrf.yml"
GO_TEST = ROOT / "ultrasec-v7/verification/research/gitea_release_negative_control_test.go"


class GenuineNegativeControlContract(unittest.TestCase):
    def test_gitea_original_allowlisted_rename_executes_in_both_revisions(self):
        self.assertTrue(GO_TEST.is_file())
        go = GO_TEST.read_text(encoding="utf-8")
        wf = GITEA.read_text(encoding="utf-8")
        self.assertIn("func TestUltraSecReleaseAllowedRename", go)
        self.assertIn('TestUltraSecReleaseAllowedRename', wf)
        self.assertIn('ULTRASEC_NEGATIVE_ALLOWED_RENAME=PASS', go)
        self.assertIn('ULTRASEC_NEGATIVE_NOOP=PASS', go)
        self.assertIn('grep -Fq "ULTRASEC_NEGATIVE_ALLOWED_RENAME=PASS"', wf)
        self.assertIn('grep -Fq "ULTRASEC_NEGATIVE_NOOP=PASS"', wf)
        self.assertIn("gitea-negative-control-", wf)
        self.assertIn("negative_control_sha256.txt", wf)

    def test_bulgarisation_mechanisms_have_separately_replayed_original_handler(self):
        wf = BULGAR.read_text(encoding="utf-8")
        for slug in ("csrf", "authorization", "authorized-manager"):
            self.assertIn(f"mechanism-{slug}-$VER.log", wf)
        self.assertIn("--filter", wf)
        self.assertIn('grep -Fq "SECURITY_TERMINATION=BLOCKED_OUTBOUND_PROVIDER_REQUEST"', wf)
        self.assertIn('grep -Fq "SUBSCRIBER_TERMINATION=BLOCKED_OUTBOUND_PROVIDER_REQUEST"', wf)
        self.assertIn("NEGATIVE_AUTHORIZED_MANAGER=PASS_BOTH_VERSIONS", wf)
        self.assertIn("MECHANISMS_RECORDED_SEPARATELY_NOT_TWO_GOLD", wf)
        self.assertIn("mechanism_receipts_sha256.txt", wf)


if __name__ == "__main__":
    unittest.main()
