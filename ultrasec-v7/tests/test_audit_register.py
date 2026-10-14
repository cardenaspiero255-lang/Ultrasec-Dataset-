"""Evidence-registry invariants for the public UltraSec V7 audit queue."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
REGISTER = ROOT / "ultrasec-v7" / "verification" / "FULL_AUDIT_REGISTER.md"
POLICY = ROOT / "ultrasec-v7" / "tools" / "verify_public.py"

spec = importlib.util.spec_from_file_location("ultrasec_public_policy_audits", POLICY)
assert spec is not None and spec.loader is not None
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class AuditRegisterTests(unittest.TestCase):
    def validate_modified(self, content: str) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dest = root / "ultrasec-v7" / "verification" / "FULL_AUDIT_REGISTER.md"
            dest.parent.mkdir(parents=True)
            dest.write_text(content, encoding="utf-8")
            policy.audit_register(root)

    def registry(self) -> str:
        return REGISTER.read_text(encoding="utf-8")

    def test_actual_registry_is_valid(self):
        policy.audit_register(ROOT)

    def test_unsubstantiated_private_pass_is_rejected(self):
        content = self.registry()
        self.assertIn("| BLOCKED |", content)
        content = content.replace("| BLOCKED |", "| PASS |", 1)
        with self.assertRaisesRegex(AssertionError, "PASS"):
            self.validate_modified(content)

    def test_public_pass_without_immutable_hash_is_rejected(self):
        content, count = re.subn(r"commit:[0-9a-f]{40}", "commit:unknown", self.registry(), count=1)
        self.assertEqual(count, 1)
        with self.assertRaisesRegex(AssertionError, "commit"):
            self.validate_modified(content)

    def test_public_pass_without_workflow_run_is_rejected(self):
        content = re.sub(r"https://github\.com/[^\s)]+/actions/runs/\d+", "no-execution", self.registry())
        self.assertNotEqual(content, self.registry())
        with self.assertRaisesRegex(AssertionError, "linked evidence|Actions"):
            self.validate_modified(content)

    def test_public_pass_without_timestamp_is_rejected(self):
        content, count = re.subn(r"2026-10-13T19:51:00Z", "date-unknown", self.registry(), count=1)
        self.assertEqual(count, 1)
        with self.assertRaisesRegex(AssertionError, "timestamp"):
            self.validate_modified(content)

    def test_unknown_audit_status_is_rejected(self):
        content = self.registry().replace("| BLOCKED |", "| VERIFIED |", 1)
        with self.assertRaisesRegex(AssertionError, "status"):
            self.validate_modified(content)

    def test_missing_required_audit_is_rejected(self):
        content = "\n".join(line for line in self.registry().splitlines() if not line.startswith("| Semantic uniqueness |"))
        with self.assertRaisesRegex(AssertionError, "Missing"):
            self.validate_modified(content)

    def test_duplicate_audit_is_rejected(self):
        content = self.registry()
        line = next(line for line in content.splitlines() if line.startswith("| Semantic uniqueness |"))
        with self.assertRaisesRegex(AssertionError, "Duplicate"):
            self.validate_modified(content + "\n" + line + "\n")


if __name__ == "__main__":
    unittest.main()
