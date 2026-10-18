"""Synthetic tests only. Private code is never uploaded to CI or printed."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "private_python_ast_screen.py"
spec = importlib.util.spec_from_file_location("private_python_ast_screen", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def row(case, split, vulnerable, fixed):
    return {"case_id":case,"split":split,"language":"python",
            "vulnerable_source":vulnerable,"fixed_source":fixed}


class PythonStructureScreenTests(unittest.TestCase):
    def test_simple_name_and_constant_changes_are_the_same_ast_shape(self):
        a="def check_one(x):\n    if x: return 3\n    return 0\n"
        b="def check_two(y):\n    if y: return 999\n    return 4\n"
        self.assertEqual(mod.ast_shape(a),mod.ast_shape(b))

    def test_changed_control_flow_is_not_collapsed_into_same_shape(self):
        a="def check(x):\n    if x: return 3\n    return 0\n"
        b="def check(x):\n    while x: return 3\n    return 0\n"
        self.assertNotEqual(mod.ast_shape(a),mod.ast_shape(b))

    def test_cross_split_synonyms_rejected_and_not_leaked(self):
        a=row("private-1","train","def evaluate(a):\n return bool(a)\n",
              "def evaluate(a):\n return True\n")
        b=row("private-2","test","def check(b):\n return bool(b)\n",
              "def check(b):\n return True\n")
        report=mod.audit([a,b])
        self.assertFalse(report["structural_preflight_pass"])
        self.assertIn("ast_structure_split_overlap",report["failures"])
        self.assertNotIn("private-1",str(report))
        self.assertNotIn("evaluate",str(report))

    def test_duplicate_test_shapes_are_not_independent(self):
        a=row("a","test","def f(x):\n return x+1\n","def f(x):\n return x-1\n")
        b=row("b","test","def g(y):\n return y+2\n","def g(y):\n return y-2\n")
        report=mod.audit([a,b])
        self.assertIn("duplicate_test_ast_structure",report["failures"])

    def test_invalid_python_is_not_silently_accepted(self):
        a=row("a","train","def broken(","x=2\n")
        report=mod.audit([a])
        self.assertIn("invalid_python_source",report["failures"])
        self.assertEqual(report["certification"],"NOT_CERTIFIED")

    def test_empty_private_input_must_fail_closed(self):
        report=mod.audit([])
        self.assertFalse(report["structural_preflight_pass"])
        self.assertIn("missing_train_or_test", report["failures"])

    def test_only_test_records_cannot_claim_independence(self):
        report=mod.audit([row("a","test","print(1)","print(2)")])
        self.assertFalse(report["structural_preflight_pass"])
        self.assertIn("missing_train_or_test", report["failures"])

    def test_distinct_shapes_can_pass_screen_without_becoming_gold(self):
        a=row("a","train","x=1\n","y=2\n")
        b=row("b","test","if True:\n    print(3)\n","while False:\n    break\n")
        report=mod.audit([a,b])
        self.assertTrue(report["structural_preflight_pass"])
        self.assertEqual(report["real_world_gold_verified"],False)
        self.assertEqual(report["certification"],"NOT_CERTIFIED")


if __name__ == "__main__":
    unittest.main()
