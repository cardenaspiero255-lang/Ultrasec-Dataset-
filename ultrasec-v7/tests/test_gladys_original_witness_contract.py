"""Require native original-tree Gladys path-traversal witness and benign controls.

This is a public workflow contract; actual RED/GREEN results come from CI
executing the original upstream controller in a bounded ephemeral directory.
"""
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
WORKFLOW=ROOT/".github/workflows/v7-gladys-original-stream-witness.yml"
HARNESS=ROOT/"ultrasec-v7/verification/research/gladys_original_stream_witness.js"


class GladysUpstreamWitnessContracts(unittest.TestCase):
    def test_witness_is_sha_pinned_and_does_not_upload_third_party_source(self):
        self.assertTrue(WORKFLOW.is_file(), 'Add native original-tree workflow before GREEN')
        source=WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("8d09d2be050b4f505fefe4b2528f9b9b1d07f830",source)
        self.assertIn("f27d0ea4689c3deca5739b5f9ed45a2ddbf00b7b",source)
        self.assertIn("git -C upstream rev-parse HEAD",source)
        self.assertIn("gladys-original-stream-",source)
        self.assertIn("node ultrasec-v7/verification/research/gladys_original_stream_witness.js",source)
        self.assertIn("source_hashes.txt",source)
        self.assertIn("native_verdict_sha256.txt",source)
        self.assertNotIn("upstream/**",source)

    def test_harness_uses_original_controller_and_bounded_canary(self):
        self.assertTrue(HARNESS.is_file())
        source=HARNESS.read_text(encoding="utf-8")
        self.assertIn("server/services/rtsp-camera/api/rtspCamera.controller.js",source)
        self.assertIn("server/services/rtsp-camera/utils/validateStreamParams.js",source)
        self.assertIn("BEFORE_CANARY_READ_CONFIRMED",source)
        self.assertIn("AFTER_PATH_TRAVERSAL_REJECTED",source)
        self.assertIn("NEGATIVE_VALID_STREAM_PASS",source)
        self.assertIn("NEGATIVE_VALID_TS_PASS",source)
        self.assertIn("NO_EXTERNAL_IO",source)


if __name__=="__main__":
    unittest.main()
