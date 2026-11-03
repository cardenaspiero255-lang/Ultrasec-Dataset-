"""Bounded original GitPython reference traversal witness; every file is temporary."""
import json,sys,tempfile
from pathlib import Path
from git import Repo
from git.refs.reference import Reference
from git.refs.symbolic import SymbolicReference
variant=sys.argv[1]
assert variant in ('vulnerable','patched')
with tempfile.TemporaryDirectory(prefix='ultrasec_v80_git_') as t:
    base=Path(t)
    repo=Repo.init(base/'repo')
    (base/'repo'/'init.txt').write_text('local only\n')
    repo.index.add(['init.txt'])
    repo.index.commit('local commit')
    outside_write=base/'outside_write.txt'
    outside_delete=base/'outside_delete.txt'
    outside_delete.write_text('DELETE ME')
    err_write=err_delete=None
    try:
        Reference.create(repo,'../../../outside_write.txt','HEAD')
    except (OSError,ValueError,AssertionError) as e:err_write=type(e).__name__
    try:
        SymbolicReference.delete(repo,'../../../outside_delete.txt')
    except (OSError,ValueError,AssertionError) as e:err_delete=type(e).__name__
    observed_write=outside_write.exists()
    observed_delete=not outside_delete.exists()
    benign=Reference.create(repo,'refs/heads/v80-safe','HEAD')
    assert benign
    assert observed_write==(variant=='vulnerable'),(variant,'write',err_write)
    assert observed_delete==(variant=='vulnerable'),(variant,'delete',err_delete)
    print(json.dumps({'project':'GitPython','variant':variant,'original_library':True,
                      'observed_outside_write':observed_write,'observed_outside_delete':observed_delete,
                      'benign_ref_created':True,'sandbox':'tempdir_only','red_green_expected':True}))
