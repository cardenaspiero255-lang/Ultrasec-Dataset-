"""Regression tests for four Codex findings on the enterprise evidence gates."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

TOOLS=Path(__file__).resolve().parents[1]/"tools"

def load(name):
    spec=importlib.util.spec_from_file_location(name,TOOLS/(name+".py"))
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class CodexFourRegressions(unittest.TestCase):
    def test_constant_size_wholesale_rewrite(self):
        gate=load("premium_evidence")
        before=";".join(f"a{i}={i}" for i in range(50))
        after=";".join(f"print({i})" for i in range(50))
        result=gate.causal_patch_gate(before,after,{"vulnerable_reproduced":True,"fix_verified":True})
        self.assertFalse(result["causal_gate_pass"])
        self.assertIn("nonminimal_patch",result["failures"])

    def test_deeply_nested_small_fix_is_not_nonminimal(self):
        gate=load("premium_evidence")
        before="sink(user)"
        after="sink(sanitize(user))"
        for i in range(8):
            before="if allowed:\n"+ "\n".join("    "+line for line in before.splitlines())
            after="if allowed:\n"+ "\n".join("    "+line for line in after.splitlines())
        result=gate.causal_patch_gate(before,after,{"vulnerable_reproduced":True,"fix_verified":True})
        self.assertNotIn("nonminimal_patch",result["failures"])

    def test_large_expression_operator_rewrite_is_nonminimal(self):
        gate=load("premium_evidence")
        before="x = "+" + ".join(str(i) for i in range(200))
        after="x = "+" * ".join(str(i) for i in range(200))
        result=gate.causal_patch_gate(before,after,{"vulnerable_reproduced":True,"fix_verified":True})
        self.assertIn("nonminimal_patch",result["failures"])

    def test_large_string_literal_rewrite_is_nonminimal(self):
        gate=load("premium_evidence")
        before="payload = "+repr("A"*10000)
        after="payload = "+repr("B"*10000)
        result=gate.causal_patch_gate(before,after,{"vulnerable_reproduced":True,"fix_verified":True})
        self.assertIn("nonminimal_patch",result["failures"])

    def test_parenthesized_large_literal_rewrite_is_nonminimal(self):
        gate=load("premium_evidence")
        before="payload = "+repr("A"*10000)
        after="payload = ("+repr("B"*10000)+")"
        result=gate.causal_patch_gate(before,after,{"vulnerable_reproduced":True,"fix_verified":True})
        self.assertIn("nonminimal_patch",result["failures"])

    def test_unchanged_large_literals_cannot_dilute_another_rewrite(self):
        gate=load("premium_evidence")
        before_values=["A"*10000,"B"*10000,"C"*10000,"D"*10000]
        after_values=["A"*10000,"X"*10000,"C"*10000,"D"*10000]
        before="payload = ("+", ".join(map(repr,before_values))+")"
        after="payload = ("+", ".join(map(repr,after_values))+")"
        result=gate.causal_patch_gate(
            before,after,{"vulnerable_reproduced":True,"fix_verified":True})
        self.assertFalse(result["causal_gate_pass"])
        self.assertIn("nonminimal_patch",result["failures"])

    def test_small_literal_edit_near_large_unchanged_literal_remains_minimal(self):
        gate=load("premium_evidence")
        before="payload = ("+repr("A"*10000)+", 'unsafe')"
        after="payload = ("+repr("A"*10000)+", 'safe')"
        result=gate.causal_patch_gate(
            before,after,{"vulnerable_reproduced":True,"fix_verified":True})
        self.assertNotIn("nonminimal_patch",result["failures"])

    def test_partial_edit_in_large_literal_cannot_dilute_wholesale_rewrite(self):
        gate=load("premium_evidence")
        before_values=["A"*10000,"B"*1000]
        after_values=["A"*9999+"Z","C"*1000]
        before="payload = ("+", ".join(map(repr,before_values))+")"
        after="payload = ("+", ".join(map(repr,after_values))+")"
        report=gate.causal_patch_gate(before,after,
            {"vulnerable_reproduced":True,"fix_verified":True})
        self.assertFalse(report["causal_gate_pass"])
        self.assertIn("nonminimal_patch",report["failures"])

    def test_independent_small_edits_in_two_large_literals_are_permitted(self):
        gate=load("premium_evidence")
        before="payload = ("+repr("A"*10000)+", "+repr("B"*1000)+")"
        after="payload = ("+repr("A"*9999+"Z")+", "+repr("B"*999+"Y")+")"
        report=gate.causal_patch_gate(before,after,
            {"vulnerable_reproduced":True,"fix_verified":True})
        self.assertNotIn("nonminimal_patch",report["failures"])

    def test_implicit_adjacent_literals_cannot_fragment_large_rewrite(self):
        gate=load("premium_evidence")
        unchanged_padding=" + ".join(f"x{i}" for i in range(150))
        before=(
            "small = "+repr("A"*5000)+"\n"
            +"padding = "+unchanged_padding+"\n"
            +"payload = ("+" ".join([repr("C"*60)]*20)+")"
        )
        after=(
            "small = "+repr("A"*4999+"Z")+"\n"
            +"padding = "+unchanged_padding+"\n"
            +"payload = ("+" ".join([repr("D"*60)]*20)+")"
        )
        result=gate.causal_patch_gate(
            before,after,{"vulnerable_reproduced":True,"fix_verified":True})
        self.assertIn("nonminimal_patch",result["failures"])

    def test_large_repeated_literal_single_char_edit_does_not_stall(self):
        # Run the gate in a subprocess so a regressed quadratic diff cannot
        # lock up CI indefinitely.
        script=(
            "import importlib.util, pathlib; "
            "p=pathlib.Path("+repr(str("ultrasec-v7/tools/premium_evidence.py"))+"); "
            "spec=importlib.util.spec_from_file_location('premium_evidence',p); "
            "m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); "
            "a='payload = '+repr('A'*10000); "
            "b='payload = '+repr('A'*9999+'Z'); "
            "r=m.causal_patch_gate(a,b,{'vulnerable_reproduced':True,'fix_verified':True}); "
            "assert 'nonminimal_patch' not in r['failures']"
        )
        subprocess.run([sys.executable,"-c",script],
            cwd=TOOLS.parents[1],check=True,capture_output=True,timeout=5)

    def test_pattern_capture_renames_are_trivial(self):
        gate=load("premium_evidence")
        before='match obj:\n    case {"x": value}:\n        print(value)'
        after='match obj:\n    case {"x": renamed}:\n        print(renamed)'
        result=gate.causal_patch_gate(before,after,{"vulnerable_reproduced":True,"fix_verified":True})
        self.assertFalse(result["causal_gate_pass"])
        self.assertIn("trivial_identifier_only_change",result["failures"])

    def test_large_container_rejected_before_loading(self):
        import ast
        tree=ast.parse((TOOLS/"premium_eval_cli.py").read_text())
        func=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="_owner_holdout_ids")
        attrs=[n.attr for n in ast.walk(func) if isinstance(n,ast.Attribute)]
        self.assertIn("stat",attrs)
        self.assertIn("open",attrs)

    def test_unsupported_zip_method_yields_sealed_invalid_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            owner=root/"owner.zip"
            with zipfile.ZipFile(owner,"w") as z:
                z.writestr("owner_key.jsonl",json.dumps({"case_id":"x"})+"\n")
            data=bytearray(owner.read_bytes())
            # Replace ZIP method in local and central headers with unsupported 99.
            for signature,offset in ((bytes.fromhex("504b0304"),8),(bytes.fromhex("504b0102"),10)):
                pos=data.find(signature)
                self.assertGreaterEqual(pos,0)
                data[pos+offset:pos+offset+2]=(99).to_bytes(2,"little")
            owner.write_bytes(data)
            digest=hashlib.sha256(data).hexdigest()
            for name in ("a","b"):
                (root/(name+".jsonl")).write_text(json.dumps({"case_id":"x","vulnerable_side":"A"})+"\n")
            report=root/"report.json"
            proc=subprocess.run([sys.executable,str(TOOLS/"premium_eval_cli.py"),"agreement",
                "--reviewer-a",str(root/"a.jsonl"),"--reviewer-b",str(root/"b.jsonl"),
                "--owner-key-zip",str(owner),"--owner-key-sha256",digest,
                "--required-cases","1","--sealed-report",str(report),
                "--session-lock",str(root/"lock")],capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertIn("owner_holdout_manifest_invalid",json.loads(report.read_text())["failures"])

if __name__=="__main__":
    unittest.main()
