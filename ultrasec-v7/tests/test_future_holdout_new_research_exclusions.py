"""RED: already inspected external projects cannot be re-used as unseen holdout."""
import importlib.util
import hashlib
import unittest
from pathlib import Path

p=Path(__file__).resolve().parents[1]/"tools"/"future_holdout_exposure.py"
spec=importlib.util.spec_from_file_location("future_exposure_new_known",p)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

STUDIED=(
    ("CVE-2026-73140","https://github.com/MISP/cti-transmute"),
    ("CVE-2023-43256","https://github.com/GladysAssistant/Gladys"),
    ("CVE-2026-61433","https://github.com/MervinPraison/PraisonAI"),
    ("CVE-2026-42079","https://github.com/icip-cas/PPTAgent"),
    ("CVE-2026-68770","https://github.com/huggingface/sentence-transformers"),
)


def fake_case(cve,repo,i):
    h=lambda x:hashlib.sha256(x.encode()).hexdigest()
    return {"case_id":f"future-fake-{i}", "cve_id":cve,
       "project_fingerprint":mod.project_fingerprint(repo),
       "mechanism_fingerprint":h("new-mechanism-"+str(i)),
       "source_commit":hashlib.sha1(f"older-{i}".encode()).hexdigest(),
       "fix_commit":hashlib.sha1(f"later-{i}".encode()).hexdigest(),
       "source_sha256":h("source-"+str(i)), "fix_sha256":h("patched-"+str(i))}


class RecentlyInspectedMustNeverAppearAsUnseen(unittest.TestCase):
    def test_every_studied_cve_or_project_is_not_future_unseen(self):
        for i,(cve,repo) in enumerate(STUDIED):
            with self.subTest(cve=cve):
                res=mod.screen([fake_case(cve,repo,i)])
                self.assertIn("previously_studied_cve",res["failures"])
                self.assertIn("previously_studied_project",res["failures"])
                self.assertFalse(res["candidate_metadata_screen_pass"])
                self.assertFalse(res["blind_benchmark_ready"])

    def test_alias_project_with_renamed_cve_still_rejected(self):
        row=fake_case("CVE-2026-999991","https://github.com/misp/CTI-Transmute.git/",50)
        res=mod.screen([row])
        self.assertIn("previously_studied_project",res["failures"])


if __name__=="__main__":
    unittest.main()
