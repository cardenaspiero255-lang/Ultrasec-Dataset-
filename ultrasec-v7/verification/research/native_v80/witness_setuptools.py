"""Bounded upstream setuptools source method witness: NO file or network writes."""
import json,os,sys,tempfile
from pathlib import Path
from setuptools.package_index import PackageIndex
variant=sys.argv[1]
assert variant in ('vulnerable','patched')
with tempfile.TemporaryDirectory(prefix='ultrasec_v80_set_') as t:
    dest=Path(t)/'download'
    dest.mkdir()
    malicious='https://anyhost/%2fhome%2fuser%2f.ssh%2fauthorized_keys'
    fn=PackageIndex._resolve_download_filename(malicious,dest)
    inside=os.path.commonpath([str(dest.resolve()),os.path.realpath(fn)])==str(dest.resolve())
    good=PackageIndex._resolve_download_filename('https://example.invalid/normal.tar.gz',dest)
    good_inside=os.path.commonpath([str(dest.resolve()),os.path.realpath(good)])==str(dest.resolve())
    assert good_inside
    assert inside==(variant=='patched'),(variant,'traversal',inside,fn)
    print(json.dumps({'project':'setuptools','variant':variant,'original_method':True,
                      'outside_path_accepted':not inside,'benign_path_contained':good_inside,
                      'no_file_written':True,'red_green_expected':True}))
