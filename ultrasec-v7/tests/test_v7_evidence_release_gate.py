"""Fail-closed evidence-index tests: synthetic fixtures only, never private data."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ultrasec-v7/tools/v7_evidence_release_gate.py"
SAMPLE = ROOT / "ultrasec-v7/verification/COMMERCIAL_EVIDENCE_INDEX.json"
spec = importlib.util.spec_from_file_location("v7_evidence_release_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def pending():
    return {"schema_version": 1, "controls": [
        {"id": key, "status": "NOT_VERIFIED"} for key in sorted(gate.REQUIRED)
    ]}


class EvidenceReleaseGateTests(unittest.TestCase):
    def test_public_index_remains_uncertified_and_incomplete(self):
        manifest = gate.load_manifest(SAMPLE)
        result = gate.evaluate(manifest, ROOT)
        self.assertFalse(result["evidence_index_complete"])
        self.assertEqual(result["certification"], "NOT_CERTIFIED")
        self.assertEqual(result["commercial_distribution"], "NOT_VERIFIED")
        self.assertEqual(result["failures"], [])

    def test_all_evidence_hashes_are_verified_but_not_certification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "proofs"
            folder.mkdir()
            controls = []
            for key in sorted(gate.REQUIRED):
                path = folder / (key + ".json")
                path.write_text('{"fixture":true}', encoding="utf-8")
                controls.append({
                    "id": key, "status": "PASS", "source_kind": "claimed",
                    "evidence_path": "proofs/" + key + ".json",
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                })
            result = gate.evaluate({"schema_version": 1, "controls": controls}, root)
            self.assertTrue(result["evidence_index_complete"])
            self.assertEqual(result["certification"], "NOT_CERTIFIED")
            self.assertEqual(result["commercial_distribution"], "NOT_VERIFIED")
            self.assertEqual(result["verified_evidence_files"], len(gate.REQUIRED))

    def test_no_unbacked_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            m = pending()
            m["controls"][0] = {"id": m["controls"][0]["id"], "status": "PASS"}
            self.assertIn("invalid_control", gate.evaluate(m, Path(temp))["failures"])

    def test_digest_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "proof.json"
            path.write_text("evidence")
            m = pending()
            m["controls"][0] = {"id": m["controls"][0]["id"], "status": "PASS",
                "source_kind": "claimed", "evidence_path": "proof.json", "sha256": "0" * 64}
            self.assertIn("digest_mismatch", gate.evaluate(m, Path(temp))["failures"])

    def test_directory_traversal_and_absolute_paths_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            for unsafe in ("../secret", "/etc/passwd", "proofs/../secret", "a\\b"):
                m = pending()
                m["controls"][0] = {"id": m["controls"][0]["id"], "status": "PASS",
                    "source_kind": "claimed", "evidence_path": unsafe, "sha256": "0" * 64}
                self.assertIn("unsafe_evidence_path",
                              gate.evaluate(m, Path(temp))["failures"], unsafe)

    def test_symlink_is_rejected_even_inside_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "real.txt").write_text("x")
            (root / "link.txt").symlink_to(root / "real.txt")
            m = pending()
            m["controls"][0] = {"id": m["controls"][0]["id"], "status": "PASS",
                "source_kind": "claimed", "evidence_path": "link.txt",
                "sha256": hashlib.sha256(b"x").hexdigest()}
            self.assertIn("unsafe_evidence_path", gate.evaluate(m, root)["failures"])

    def test_duplicate_gate_and_unknown_gate_fail(self):
        m = pending()
        m["controls"].append(dict(m["controls"][0]))
        self.assertIn("duplicate_control", gate.evaluate(m, ROOT)["failures"])
        m = pending()
        m["controls"][0]["id"] = "imaginary_certificate"
        r = gate.evaluate(m, ROOT)
        self.assertIn("unknown_control", r["failures"])
        self.assertIn("missing_control", r["failures"])

    def test_certified_status_and_extra_fields_fail(self):
        m = pending()
        m["controls"][0]["status"] = "CERTIFIED"
        self.assertIn("invalid_control", gate.evaluate(m, ROOT)["failures"])
        m = pending()
        m["certification"] = "ISO_CERTIFIED"
        self.assertIn("invalid_schema", gate.evaluate(m, ROOT)["failures"])

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            f = Path(temp) / "dup.json"
            f.write_text('{"schema_version":1,"schema_version":2,"controls":[]}')
            with self.assertRaises(ValueError):
                gate.load_manifest(f)

    def test_cli_check_blocked_public_index(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "--manifest", str(SAMPLE),
            "--root", str(ROOT), "--expect-blocked"], text=True, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertNotIn("CERTIFIED\\\": true", run.stdout)


if __name__ == "__main__":
    unittest.main()
