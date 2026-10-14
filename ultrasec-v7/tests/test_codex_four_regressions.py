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
            for signature,offset in ((b"PK\\x03\\x04",8),(b"PK\\x01\\x02",10)):
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
