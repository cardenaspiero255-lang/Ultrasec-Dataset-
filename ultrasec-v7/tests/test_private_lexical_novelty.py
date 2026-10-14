"""Synthetic-only lexical novelty screen regressions; no private code in CI."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ultrasec-v7" / "tools" / "private_lexical_novelty.py"
spec = importlib.util.spec_from_file_location("ultrasec_lexical_novelty", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def row(code, language="python", family="CWE-SYNTHETIC"):
    return {"code": code, "language": language, "family": family}


class LexicalNoveltyTests(unittest.TestCase):
    def test_identifier_and_number_renaming_collides(self):
        self.assertEqual(module.lexical_shape("value = 123"), module.lexical_shape("other = 456"))

    def test_operator_change_is_not_silently_identical(self):
        self.assertNotEqual(module.lexical_shape("x + 1"), module.lexical_shape("x - 1"))

    def test_exact_unique_and_lexical_unique_are_separate_metrics(self):
        report = module.screen_records([row("alpha = 10"), row("beta = 20"), row("x -= 3")], 0.5)
        self.assertEqual(report["metrics"]["records"], 3)
        self.assertEqual(report["metrics"]["exact_unique_code"], 3)
        self.assertEqual(report["metrics"]["lexical_patterns"], 2)
        self.assertEqual(report["metrics"]["additional_lexical_collisions"], 1)
        self.assertTrue(report["lexical_screen_pass"])
        self.assertEqual(report["certification"], "NOT_CERTIFIED")

    def test_exact_duplicates_are_not_misclassified_as_lexical_collisions(self):
        report = module.screen_records([row("a = 1"), row("a = 1"), row("b = 2")], 0.0)
        self.assertEqual(report["metrics"]["records"], 3)
        self.assertEqual(report["metrics"]["exact_unique_code"], 2)
        self.assertEqual(report["metrics"]["lexical_patterns"], 1)
        self.assertEqual(report["metrics"]["exact_duplicate_rows"], 1)
        self.assertEqual(report["metrics"]["additional_lexical_collisions"], 1)
        self.assertEqual(report["metrics"]["total_redundant_rows"], 2)

    def test_threshold_blocks_claim_when_distinct_fraction_below_target(self):
        report = module.screen_records([row("alpha = 10"), row("beta = 20"), row("x -= 3")], 0.9)
        self.assertFalse(report["lexical_screen_pass"])
        self.assertIn("below_lexical_uniqueness_threshold", report["failures"])
        self.assertEqual(report["criteria"]["minimum_lexical_unique_fraction"], 0.9)

    def test_invalid_records_do_not_count_as_duplicates(self):
        report=module.screen_records([
            row("x=1"),
            {"code":"bad", "language":42, "family":"F"},
        ],0.0)
        self.assertFalse(report["lexical_screen_pass"])
        self.assertEqual(report["metrics"]["records"],2)
        self.assertEqual(report["metrics"]["valid_records"],1)
        self.assertEqual(report["metrics"]["exact_duplicate_rows"],0)
        self.assertEqual(report["metrics"]["total_redundant_rows"],0)

    def test_common_numeric_literal_variants_have_same_shape(self):
        examples=["mask = 0xff","mask = 0xaa","mask = 0b1111","mask = 0o77",
                  "mask = 12_345","mask = 1.2e+3","mask = 9.8e+4"]
        shapes={module.lexical_shape(x) for x in examples}
        self.assertEqual(len(shapes),1)

    def test_empty_and_invalid_rows_fail_closed(self):
        report = module.screen_records([], 0.5)
        self.assertFalse(report["lexical_screen_pass"])
        self.assertIn("empty_corpus", report["failures"])
        report = module.screen_records([row("correct"), {"code": "invalid", "language": 1}], 0.2)
        self.assertIn("invalid_record_schema", report["failures"])

    def test_leading_trailing_decimal_float_literals_collapse(self):
        variants=["x=.5","x=0.5","x=1.","x=1.0","x=1.e3","x=1e3","x=10e+2"]
        shapes={module.lexical_shape(text) for text in variants}
        self.assertEqual(len(shapes),1)

    def test_unicode_identifier_starts_are_normalized(self):
        forms=[module.lexical_shape("α=1"),module.lexical_shape("β=2"),
               module.lexical_shape("código=3"),module.lexical_shape("nombre=4")]
        self.assertEqual(len(set(forms)),1)

    def test_decomposed_and_composed_unicode_identifiers_normalize_equally(self):
        cases = [
            "cafe\u0301=2",
            "caf\u00e9=1",
            "nombre=3",
            "\u03b1=4",
            "\u03b2=5",
        ]
        shapes = {module.lexical_shape(code) for code in cases}
        self.assertEqual(len(shapes), 1)

    def test_unicode_identifiers_do_not_inflate_uniqueness_gate(self):
        report = module.screen_records([
            row("cafe\u0301=2"), row("caf\u00e9=1"),
            row("\u03b1=3"), row("\u03b2=4"),
        ], 0.5)
        self.assertFalse(report["lexical_screen_pass"])
        self.assertEqual(report["metrics"]["lexical_patterns"], 1)
        self.assertEqual(report["metrics"]["exact_unique_code"], 4)
        self.assertIn("below_lexical_uniqueness_threshold", report["failures"])

    def test_unsupported_thresholds_rejected(self):
        for value in (float("nan"), float("inf"), -0.1, 1.01):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.screen_records([row("valid")], value)

    def test_aggregate_report_has_no_source_or_family_names(self):
        report = module.screen_records([row("PRIVATE_SOME_SECRET_123", family="OWNER-CONFIDENTIAL")], 0.5)
        dumped = json.dumps(report)
        self.assertNotIn("PRIVATE_SOME_SECRET", dumped)
        self.assertNotIn("OWNER-CONFIDENTIAL", dumped)

    def test_disk_indexes_are_removed(self):
        with tempfile.TemporaryDirectory() as d:
            r = module.screen_records((row("item_"+str(i)+"=3", family="family"+str(i)) for i in range(250)), 0.0, scratch_dir=Path(d))
            self.assertEqual(r["metrics"]["records"], 250)
            self.assertEqual(r["index_backend"], "sqlite-private-temporary")
            self.assertEqual(list(Path(d).iterdir()), [])

    def test_cli_verifies_archive_hash_and_seals_results(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "input.zip"
            data = "".join(json.dumps(x)+"\n" for x in [row("a=1"), row("b=2"), row("x+1")]).encode()
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("records.jsonl.gz", gzip.compress(data))
            report = Path(d) / "report.json"
            command = [
                sys.executable, str(SCRIPT), "--archive", str(path),
                "--member", "records.jsonl.gz",
                "--expected-sha256", hashlib.sha256(data).hexdigest(),
                "--minimum-lexical-unique-fraction", "0.6",
                "--sealed-report", str(report), "--session-lock", str(Path(d) / "lock"),
            ]
            p = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout), {"status": "SEALED"})
            audit = json.loads(report.read_text())
            self.assertTrue(audit["integrity"]["sha256_matches_expected"])
            self.assertTrue(audit["lexical_screen_pass"])
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)
            twice = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(twice.returncode, 0)

    def test_corrupt_jsonl_creates_sealed_failure_without_echo(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "input.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("records.jsonl", "PRIVATE-INVALID-DATA\n")
            report = Path(d) / "report.json"
            p = subprocess.run([sys.executable, str(SCRIPT), "--archive", str(path),
                "--member", "records.jsonl", "--expected-sha256", "0"*64,
                "--minimum-lexical-unique-fraction", "0.5", "--sealed-report", str(report),
                "--session-lock", str(Path(d)/"lock")], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(json.loads(p.stdout), {"status": "SEALED"})
            self.assertIn("input_parse_error", json.loads(report.read_text())["failures"])
            self.assertNotIn("PRIVATE-INVALID-DATA", p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
