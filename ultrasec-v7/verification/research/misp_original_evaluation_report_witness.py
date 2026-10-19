#!/usr/bin/env python3
"""Original SHA-pinned MISP evaluation export function, isolated causal witness.

Loads only the AST of the genuine upstream function from immutable commits;
does NOT execute the upstream package, DB, Flask route, or internet requests.
No third-party source files are distributed. A passing receipt is not GOLD.
"""
from __future__ import annotations

import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import types

VULNERABLE = "06d408e3496fdfc31da22d7b2b427434c67eae94"
FIXED = "5dbd19b39a61eab793586731f1a80d8c38907c42"
SOURCE = "website/web/evaluate/evaluate_core.py"
ACCESS = "website/lib/access.py"


def _read_original(tree: Path, rel: str) -> str:
    target = tree.joinpath(rel)
    if target.is_symlink() or not target.is_file() or target.stat().st_size > 1024*1024:
        raise ValueError("invalid_upstream_original_file")
    return target.read_text(encoding="utf-8")


def _original_function(text: str, name: str, globals_: dict):
    """Compile exactly one AST original upstream function, without module side effects."""
    module = ast.parse(text, filename=name)
    nodes = [n for n in module.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and n.name == name]
    if len(nodes) != 1 or not isinstance(nodes[0], ast.FunctionDef):
        raise ValueError("original_function_not_unique")
    fn=nodes[0]
    if fn.decorator_list:
        raise ValueError("unexpected_original_decorators")
    code=compile(ast.Module(body=[fn],type_ignores=[]), "<sha-pinned-original-function>", "exec")
    exec(code, globals_)
    return globals_[name], hashlib.sha256(ast.get_source_segment(text, fn).encode()).hexdigest()


class _Query:
    def __init__(self, items: list):
        self.items = list(items)
        self.filters = {}
    def get(self, value):
        return next((x for x in self.items if x.id == value), None)
    def filter_by(self, **fields):
        self.filters = fields
        return self
    def order_by(self, _):
        return self
    def all(self):
        return [x for x in self.items if all(getattr(x,k) == v for k,v in self.filters.items())]


class _Column:
    def asc(self):
        return self


def _actor(userid: int | None, *, admin: bool = False):
    if userid is None:
        return None
    return types.SimpleNamespace(id=userid,user_id=userid,is_admin=lambda:admin)


def _evaluate(tree: Path, phase: str) -> dict:
    fixed=(phase=="after")
    p=_read_original(tree,SOURCE)
    original_hashes={SOURCE:hashlib.sha256(p.encode()).hexdigest()}
    src_glob={"datetime":datetime}
    if fixed:
        a=_read_original(tree,ACCESS)
        original_hashes[ACCESS]=hashlib.sha256(a.encode()).hexdigest()
        policy={}
        for fname in ("is_admin","is_owner","is_owner_or_admin","can_see_comment"):
            _original_function(a,fname,policy)
        src_glob["access"]=types.SimpleNamespace(**{x:policy[x] for x in
          ("is_admin","is_owner","is_owner_or_admin","can_see_comment")})

    report_fn, function_digest=_original_function(p,"build_evaluation_report",src_glob)
    # Confirm selected input really contains the vulnerable/unprotected or
    # the fixed/protected evaluation comment loop, respectively.
    if fixed and "access.can_see_comment(actor, c, conversion)" not in p:
        raise ValueError("fixed_guard_not_in_original_source")
    if not fixed and ("access.can_see_comment(actor, c, conversion)" in p
                      or "actor=None" in str(report_fn.__code__.co_varnames)):
        raise ValueError("unexpected_original_vulnerable_source")

    import sys as _sys
    saved={k:_sys.modules.get(k) for k in
       ("website","website.db_class","website.db_class.db")}
    try:
        _sys.modules["website"]=types.ModuleType("website")
        _sys.modules["website"].__path__=[]
        _sys.modules["website.db_class"]=types.ModuleType("website.db_class")
        _sys.modules["website.db_class"].__path__=[]
        user_module=types.ModuleType("website.db_class.db")
        _sys.modules["website.db_class.db"]=user_module

        owner=_actor(10)
        private_author=_actor(30)
        outsider=_actor(40)
        admin=_actor(50,admin=True)
        public_comment_author=_actor(60)
        users=[
          types.SimpleNamespace(id=30,first_name="PRIVATE_AUTHOR"),
          types.SimpleNamespace(id=60,first_name="PUBLIC_AUTHOR"),
          types.SimpleNamespace(id=70,first_name="NON_EVALUATION_AUTHOR"),
        ]
        user_module.User=types.SimpleNamespace(query=_Query(users))
        conv=types.SimpleNamespace(id=12,user_id=10,public=True,name="safe-fixture",
            uuid="only-public-fixture",description="",conversion_type="MISP_TO_STIX",created_at=None)
        src_glob["Conversion"]=types.SimpleNamespace(query=_Query([conv]))
        now=datetime.datetime(2026,1,1,tzinfo=datetime.timezone.utc)
        comments=[
          types.SimpleNamespace(id=1,conversion_id=12,is_evaluation=True,is_deleted=False,
             is_private=True,user_id=30,content="ULTRASEC_PRIVATE_MARKER",created_at=now),
          types.SimpleNamespace(id=2,conversion_id=12,is_evaluation=True,is_deleted=False,
             is_private=False,user_id=60,content="ULTRASEC_PUBLIC_MARKER",created_at=now),
          types.SimpleNamespace(id=3,conversion_id=12,is_evaluation=False,is_deleted=False,
             is_private=False,user_id=70,content="ULTRASEC_NON_EVALUATION",created_at=now),
        ]
        src_glob["Comment"]=types.SimpleNamespace(query=_Query(comments),created_at=_Column())
        src_glob["get_summary"]=lambda x:{"likes":0,"dislikes":0,
                              "cti_categories":{}, "approval_score":None}
        src_glob["get_consensus_tags"]=lambda x,threshold: []
        src_glob["get_misp_push_tags"]=lambda x: []
        src_glob["_overall_level"]=lambda x:None
        src_glob["VALUE_ORDER"]=[]
        src_glob["DIMENSION_LABELS"]={}
        src_glob["DIMENSION_DESCRIPTIONS"]={}
        src_glob["SCORE_MAP"]={}
        receipts={}
        for label,user in (("outsider",outsider),("owner",owner),
                            ("author",private_author),("admin",admin),
                            ("anonymous",None)):
            src_glob["Comment"].query=_Query(comments)
            if fixed:
                report=report_fn(conv.id,user)
            else:
                report=report_fn(conv.id)
            visible={c["content"] for c in report["eval_comments"]}
            receipts[label]={
               "outsider_private_comment": "ULTRASEC_PRIVATE_MARKER" in visible,
               "legitimate_owner_comment": "ULTRASEC_PRIVATE_MARKER" in visible,
               "public_comment": "ULTRASEC_PUBLIC_MARKER" in visible,
               "non_evaluation_comment": "ULTRASEC_NON_EVALUATION" in visible,
            }
        assert all(row["public_comment"] and not row["non_evaluation_comment"] for row in receipts.values())
        assert receipts["owner"]["legitimate_owner_comment"]
        assert receipts["author"]["legitimate_owner_comment"]
        assert receipts["admin"]["legitimate_owner_comment"]
        outsider_private=receipts["outsider"]["outsider_private_comment"]
        anonymous_private=receipts["anonymous"]["outsider_private_comment"]
        if fixed:
            assert not outsider_private and not anonymous_private, "FIXED_LEAK_PERSISTS"
        else:
            assert outsider_private and anonymous_private, "VULNERABLE_LEAK_NOT_REPRODUCED"
        return {
            "scope":"ORIGINAL_FUNCTION_ISOLATED_NOT_FULL_APPLICATION",
            "phase":phase,
            "source_sha256":original_hashes,
            "original_function_ast_source_sha256":function_digest,
            "cases":len(receipts),
            "outsider_private_comment":outsider_private,
            "anonymous_private_comment":anonymous_private,
            "legitimate_owner_comment":receipts["owner"]["legitimate_owner_comment"],
            "private_author_comment":receipts["author"]["legitimate_owner_comment"],
            "admin_comment":receipts["admin"]["legitimate_owner_comment"],
            "public_comment":receipts["outsider"]["public_comment"],
            "non_evaluation_comment_excluded":True,
            "causal_result":"VULNERABLE_LEAK_OBSERVED" if not fixed else "FIX_GUARD_REJECTS_PRIVATE_COMMENT",
            "gold_admitted":0,"benchmark_eligible":False,
            "commercial_rights_verified":False,"certification":"NOT_CERTIFIED",
        }
    finally:
        for k,old in saved.items():
            if old is None:_sys.modules.pop(k,None)
            else:_sys.modules[k]=old


def main(argv=None) -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--tree",required=True,type=Path)
    parser.add_argument("--phase",required=True,choices=("before","after"))
    args=parser.parse_args(argv)
    expected=VULNERABLE if args.phase=="before" else FIXED
    try:
        actual=subprocess.check_output(
            ["git","-C",str(args.tree),"rev-parse","HEAD"],text=True).strip()
        if actual!=expected:
            raise ValueError("upstream_commit_sha_mismatch")
        report=_evaluate(args.tree,args.phase)
        report["original_upstream_commit"]=actual
        print(json.dumps(report,sort_keys=True))
    except (OSError,ValueError,AssertionError,subprocess.CalledProcessError,
            SyntaxError,TypeError,KeyError,AttributeError):
        print('{"status":"ORIGINAL_FUNCTION_WITNESS_FAILED","certification":"NOT_CERTIFIED"}')
        return 1
    return 0


if __name__=="__main__":
    sys.exit(main())
