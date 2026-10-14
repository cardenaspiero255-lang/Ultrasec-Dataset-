"""Synthetic-only tests: archived owner corpus is never checked into GitHub."""
from __future__ import annotations
import gzip
import hashlib
import inspect
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ultrasec-v7/tools/private_corpus_attestation.py"
spec = importlib.util.spec_from_file_location("corpus_attestation", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def pair(pid, template, split="train", valid=False, rights="author_review_required"):
    return [{
        "id": pid + "-" + label,
        "pair_id": pid,
        "template_id": template,
        "code": "synthetic-safe-code-" + pid + "-" + label,
        "label": label,
        "language": "python",
        "family": "synthetic-family",
        "split": split,
        "independently_validated": valid,
        "license_clearance": rights,
        "verification_tier": "synthetic_unverified" if not valid else "independently_verified",
        "label_provenance": "generator_intent_unverified" if not valid else "expert_adjudicated",
        "origin": "original_offline_synthetic",
    } for label in ("vulnerable", "mitigated_example")]


class CorpusAttestationTests(unittest.TestCase):
    def setUp(self):
        self.rows = pair("a", "template-a") + pair("b", "template-b", split="test")

    def test_valid_pairs_are_counted_without_certification(self):
        report = module.audit_rows(self.rows)
        self.assertEqual(report["metrics"]["records"], 4)
        self.assertEqual(report["metrics"]["complete_pairs"], 2)
        self.assertEqual(report["metrics"]["template_ids"], 2)
        self.assertEqual(report["metrics"]["unverified_records"], 4)
        self.assertEqual(report["metrics"]["rights_pending_records"], 4)
        self.assertEqual(report["certification"], "NOT_CERTIFIED")
        self.assertEqual(report["errors"], {})

    def test_duplicate_code_content_is_rejected(self):
        rows = [dict(r) for r in self.rows]
        rows[2]["code"] = rows[0]["code"]
        self.assertIn("duplicate_code", module.audit_rows(rows)["errors"])

    def test_incomplete_pairs_are_rejected(self):
        self.assertIn("incomplete_pair", module.audit_rows(self.rows[:-1])["errors"])

    def test_duplicate_pair_variants_are_rejected(self):
        self.assertIn("duplicate_pair_variant", module.audit_rows(self.rows + [dict(self.rows[0], id="other")])["errors"])

    def test_pair_metadata_mismatch_is_rejected(self):
        rows = [dict(r) for r in self.rows]
        rows[1]["family"] = "other"
        self.assertIn("pair_metadata_mismatch", module.audit_rows(rows)["errors"])

    def test_template_split_leakage_is_rejected(self):
        rows = pair("a", "same", split="train") + pair("b", "same", split="test")
        self.assertIn("template_split_leakage", module.audit_rows(rows)["errors"])

    def test_report_never_contains_codes_identifiers_or_labels(self):
        report = json.dumps(module.audit_rows(pair("owner-confidential", "secret-template")))
        self.assertNotIn("owner-confidential", report)
        self.assertNotIn("secret-template", report)
        self.assertNotIn("synthetic-safe-code", report)

    def test_rejects_improper_record_types(self):
        rows = [dict(r) for r in self.rows]
        rows[0]["independently_validated"] = "false"
        self.assertIn("invalid_record_schema", module.audit_rows(rows)["errors"])

    def test_private_archive_sha256_and_one_shot_sealed_report(self):
        with tempfile.TemporaryDirectory() as d:
            zpath = Path(d) / "private.zip"
            encoded = "".join(json.dumps(r)+"\n" for r in self.rows).encode()
            with zipfile.ZipFile(zpath,"w") as z:
                z.writestr("owner/master.jsonl.gz",gzip.compress(encoded))
            reportpath,lockpath=Path(d)/"report.json",Path(d)/"lock"
            cmd=[sys.executable,str(SCRIPT),"--archive",str(zpath),"--member",
                 "owner/master.jsonl.gz","--expected-sha256",hashlib.sha256(encoded).hexdigest(),
                 "--sealed-report",str(reportpath),"--session-lock",str(lockpath)]
            p=subprocess.run(cmd,text=True,capture_output=True)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(json.loads(p.stdout),{"status":"SEALED"})
            report=json.loads(reportpath.read_text())
            self.assertTrue(report["integrity"]["sha256_matches_expected"])
            self.assertTrue(report["owner_integrity_pass"])
            self.assertEqual(reportpath.stat().st_mode & 0o777,0o600)
            again=subprocess.run(cmd,text=True,capture_output=True)
            self.assertNotEqual(again.returncode,0)

    def test_wrong_checksum_is_reported_privately(self):
        with tempfile.TemporaryDirectory() as d:
            zpath=Path(d)/"private.zip"
            content=json.dumps(self.rows[0])+"\n"
            with zipfile.ZipFile(zpath,"w") as z:z.writestr("data.jsonl",content)
            cmd=[sys.executable,str(SCRIPT),"--archive",str(zpath),"--member","data.jsonl",
                 "--expected-sha256","0"*64,"--sealed-report",str(Path(d)/"r.json"),
                 "--session-lock",str(Path(d)/"lock")]
            p=subprocess.run(cmd,text=True,capture_output=True)
            self.assertEqual(json.loads(p.stdout),{"status":"SEALED"})
            self.assertIn("sha256_mismatch",json.loads((Path(d)/"r.json").read_text())["errors"])

    def test_many_pairs_use_private_disk_index_and_cleanup(self):
        import tempfile
        with tempfile.TemporaryDirectory() as scratch:
            rows = (r for i in range(3500)
                    for r in pair("pair-"+str(i), "template-"+str(i)))
            result = module.audit_rows(rows, scratch_dir=Path(scratch))
            self.assertEqual(result["metrics"]["records"], 7000)
            self.assertEqual(result["metrics"]["complete_pairs"], 3500)
            self.assertEqual(result["metrics"]["template_ids"], 3500)
            self.assertEqual(result["index_backend"], "sqlite-private-temporary")
            self.assertEqual(list(Path(scratch).iterdir()), [])

    def test_deep_json_corpus_seals_input_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            zpath = Path(d) / "private.zip"
            with zipfile.ZipFile(zpath, "w") as archive:
                archive.writestr("nested.jsonl", "[" * 3000 + "0" + "]" * 3000 + "\\n")
            reportpath = Path(d) / "private-report.json"
            cmd = [sys.executable, str(SCRIPT), "--archive", str(zpath), "--member",
                   "nested.jsonl", "--expected-sha256", "0"*64,
                   "--sealed-report", str(reportpath), "--session-lock", str(Path(d)/"lock")]
            p = subprocess.run(cmd, text=True, capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout), {"status": "SEALED"})
            self.assertIn("input_parse_error", json.loads(reportpath.read_text())["errors"])
            self.assertNotIn("Traceback", p.stderr)

    def test_encrypted_member_runtime_error_seals_input_error(self):
        from unittest.mock import patch
        class BrokenArchive:
            def __enter__(self): return self
            def __exit__(self, *args): return None
            def open(self, name): raise RuntimeError("password required")
        with patch.object(module.zipfile, "ZipFile", return_value=BrokenArchive()):
            # Pure function / parser must never leak member errors to caller.
            with self.assertRaises(RuntimeError):
                next(module._archive_records(Path("unused"), "private.jsonl", hashlib.sha256()))
            # The CLI handler must also include RuntimeError as a sealed failure.
            self.assertIn("RuntimeError", inspect.getsource(module.main))

    def test_duplicate_json_properties_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            zpath=Path(d)/"private.zip"
            with zipfile.ZipFile(zpath,"w") as z:z.writestr("data.jsonl",'{"id":"x","id":"y"}\n')
            cmd=[sys.executable,str(SCRIPT),"--archive",str(zpath),"--member","data.jsonl",
                 "--expected-sha256","0"*64,"--sealed-report",str(Path(d)/"r.json"),
                 "--session-lock",str(Path(d)/"lock")]
            p=subprocess.run(cmd,text=True,capture_output=True)
            self.assertEqual(json.loads(p.stdout),{"status":"SEALED"})
            self.assertIn("input_parse_error",json.loads((Path(d)/"r.json").read_text())["errors"])


if __name__ == "__main__":
    unittest.main()
