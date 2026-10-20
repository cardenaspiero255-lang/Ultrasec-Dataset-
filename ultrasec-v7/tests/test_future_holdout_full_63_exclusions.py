"""The 63 published, previously researched CVE IDs cannot enter a fresh blind holdout."""
import hashlib, importlib.util, unittest
from pathlib import Path
SRC=Path(__file__).resolve().parents[1]/"tools"/"future_holdout_exposure.py"
spec=importlib.util.spec_from_file_location("future_holdout_full_inventory",SRC)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def row(cve):
    h=lambda x:hashlib.sha256(x.encode()).hexdigest()
    return {"case_id":"research-overlap","cve_id":cve,
      "project_fingerprint":m.project_fingerprint("https://github.com/unseen/unseen-project"),
      "mechanism_fingerprint":h("new-mechanism"),
      "source_commit":hashlib.sha1(b"before").hexdigest(),
      "fix_commit":hashlib.sha1(b"after").hexdigest(),
      "source_sha256":h("before"),"fix_sha256":h("after")}

class PreviouslyResearched63AreNotUnseen(unittest.TestCase):
    def test_different_unscanned_cves_from_63_still_rejected_by_id(self):
        for cve in ("CVE-2022-1519","CVE-2021-25932","CVE-2026-73140","CVE-2020-36280"):
            with self.subTest(cve=cve):
                r=m.screen([row(cve)])
                self.assertIn("previously_studied_cve",r["failures"])
                self.assertFalse(r["candidate_metadata_screen_pass"])

    def test_immutable_public_inventory_contains_exactly_63_distinct_ids(self):
        ids=m._read_original_public_cves()
        self.assertEqual(len(ids),63)
        self.assertIn("CVE-2023-43256",ids)
        self.assertIn("CVE-2024-2395",ids)
        self.assertIn("CVE-2022-1519",ids)

    def test_unlisted_new_cve_remains_only_metadata_candidate(self):
        r=m.screen([row("CVE-2026-989898")])
        self.assertTrue(r["candidate_metadata_screen_pass"])
        self.assertFalse(r["independence_verified"])
        self.assertFalse(r["holdout_assigned"])

if __name__=="__main__":unittest.main()
