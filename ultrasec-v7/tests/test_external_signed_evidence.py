"""Contract tests for locally supplied, genuinely signed review evidence.

Ephemeral fixture signing keys are not external reviewers or certification.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/"tools"/"external_signed_evidence.py"


def run(*argv):
    return subprocess.run(argv,check=True,capture_output=True)


def load():
    spec=importlib.util.spec_from_file_location("external_signed_evidence",SCRIPT)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SignedEvidenceContracts(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"),"OpenSSL CLI needed for Ed25519 fixture")
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        ids=[f"opaque-{i:03d}" for i in range(100)]
        owner=self.root/"owner_ids.json"
        owner.write_text(json.dumps(ids),encoding="utf-8")
        self.manifest={"owner_ids":"owner_ids.json",
                       "owner_ids_sha256":hashlib.sha256(owner.read_bytes()).hexdigest(),
                       "reviewers":{}}
        for name in ("a","b"):
            key=self.root/f"{name}.pem"
            pub=self.root/f"{name}.pub.pem"
            report=self.root/f"{name}.jsonl"
            sig=self.root/f"{name}.sig"
            run("openssl","genpkey","-algorithm","ED25519","-out",str(key))
            run("openssl","pkey","-in",str(key),"-pubout","-out",str(pub))
            rows=[{"case_id":i,"vulnerable_side":"A" if n%2 else "B"}
                  for n,i in enumerate(ids)]
            report.write_text("".join(json.dumps(r,sort_keys=True)+"\n" for r in rows))
            run("openssl","pkeyutl","-sign","-rawin","-inkey",str(key),
                "-in",str(report),"-out",str(sig))
            self.manifest["reviewers"][name]={
                "report":report.name,"signature":sig.name,"public_key":pub.name,
                "trusted_public_key_sha256":hashlib.sha256(pub.read_bytes()).hexdigest(),
                "report_sha256":hashlib.sha256(report.read_bytes()).hexdigest()
            }

    def test_signed_reports_verify_but_not_human_independence_or_rights(self):
        result=load().audit(self.root,self.manifest)
        self.assertTrue(result["signatures_valid"])
        self.assertTrue(result["membership_verified"])
        self.assertFalse(result["externally_certified"])
        self.assertEqual(result["human_independence"],"NOT_VERIFIED")
        self.assertEqual(result["commercial_rights"],"NOT_VERIFIED")
        self.assertNotIn("opaque-",str(result))

    def test_cli_reports_only_aggregate_signature_state(self):
        manifest=self.root/"manifest.json"
        manifest.write_text(json.dumps(self.manifest),encoding="utf-8")
        proc=subprocess.run([sys.executable,str(SCRIPT),"--root",
            str(self.root),"--manifest",str(manifest)],
            capture_output=True,text=True,timeout=10)
        self.assertEqual(proc.returncode,0,proc.stderr)
        body=json.loads(proc.stdout)
        self.assertTrue(body["signatures_valid"])
        self.assertTrue(body["membership_verified"])
        self.assertFalse(body["externally_certified"])
        self.assertNotIn("opaque-",proc.stdout)

    def test_tampered_review_is_rejected(self):
        with (self.root/"a.jsonl").open("ab") as stream:
            stream.write(b" ")
        result=load().audit(self.root,self.manifest)
        self.assertFalse(result["signatures_valid"])
        self.assertIn("a:review_hash_mismatch",result["failures"])

    def test_untrusted_public_key_is_rejected(self):
        self.manifest["reviewers"]["a"]["trusted_public_key_sha256"]="0"*64
        result=load().audit(self.root,self.manifest)
        self.assertFalse(result["signatures_valid"])
        self.assertIn("a:untrusted_public_key",result["failures"])

    def test_missing_or_forged_signature_is_rejected(self):
        (self.root/"b.sig").write_bytes(b"forged signature")
        result=load().audit(self.root,self.manifest)
        self.assertFalse(result["signatures_valid"])
        self.assertIn("b:invalid_signature",result["failures"])

    def test_duplicate_or_unrelated_case_is_rejected(self):
        source=self.root/"b.jsonl"
        rows=[json.loads(s) for s in source.read_text().splitlines()]
        rows[-1]["case_id"]=rows[0]["case_id"]
        source.write_text("".join(json.dumps(x)+"\n" for x in rows))
        # Cryptographic integrity fails too; membership must be checked independently.
        result=load().audit(self.root,self.manifest)
        self.assertFalse(result["membership_verified"])
        self.assertIn("b:holdout_membership_invalid",result["failures"])

    def test_path_swapped_after_read_cannot_change_verified_bytes(self):
        # Simulated TOCTOU: a file can change after it was read for hashing,
        # but signature verification must use those exact captured bytes.
        from unittest import mock
        tool=load()
        original=tool._read_private
        def swap(root,name,limit):
            result=original(root,name,limit)
            if name=="a.sig":
                (self.root/"a.jsonl").write_text("tampered after read")
            return result
        with mock.patch.object(tool,"_read_private",side_effect=swap):
            outcome=tool.audit(self.root,self.manifest)
        self.assertTrue(outcome["signatures_valid"])
        self.assertTrue(outcome["membership_verified"])

    def test_traversal_outside_private_directory_fails_closed(self):
        self.manifest["reviewers"]["a"]["report"]="../../secret"
        result=load().audit(self.root,self.manifest)
        self.assertFalse(result["signatures_valid"])
        self.assertIn("a:invalid_path",result["failures"])

if __name__=="__main__":
    unittest.main()
