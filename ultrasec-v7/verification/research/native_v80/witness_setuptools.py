"""Bounded upstream setuptools CVE filename witness. Network/filesystem output disabled."""
import json
import os
import sys
import tempfile
from pathlib import Path
from setuptools.package_index import PackageIndex

variant = sys.argv[1]
assert variant in ("vulnerable", "patched")

with tempfile.TemporaryDirectory(prefix="ultrasec_v80_set_") as root:
    target = Path(root) / "download"
    target.mkdir()
    idx = PackageIndex(index_url="https://example.invalid/")
    # Both hooks are replaced so no download or filesystem write is possible.
    idx._download_vcs = lambda url, filename: str(filename)
    def forbidden_network(*args, **kwargs):
        raise AssertionError("Network access was forbidden by the witness")
    idx._download_other = forbidden_network
    attack = "https://example.invalid/%2fhome%2fuser%2f.ssh%2fauthorized_keys"
    try:
        filename = idx._download_url(attack, str(target))
        outside = os.path.commonpath([str(target.resolve()), os.path.realpath(filename)]) != str(target.resolve())
    except ValueError:
        outside = False
    normal = idx._download_url("https://example.invalid/normal.tar.gz", str(target))
    legitimate = os.path.commonpath([str(target.resolve()), os.path.realpath(normal)]) == str(target.resolve())
    assert legitimate, "benign path is not contained"
    assert outside == (variant == "vulnerable"), (variant, "outside_path_accepted", outside)
    print(json.dumps({"project": "setuptools", "variant": variant,
                      "original_download_filename_logic": True,
                      "outside_path_accepted": outside, "benign_path_contained": legitimate,
                      "network_disabled": True, "no_file_written": True,
                      "red_green_expected": True}))
