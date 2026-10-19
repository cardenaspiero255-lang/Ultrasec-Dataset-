#!/usr/bin/env python3
"""Execute upstream ORIGINAL report builder, with hermetic ORM/HTTP-free adapters.

Load the exact AST for build_evaluation_report() from SHA-pinned MISP source,
not a rewritten simulation. Original Python access.can_see_comment() is
extracted from the corrected revision. Dummy rows contain NO real user data.

This exercises the builder only: NOT a full Flask/SQLAlchemy integration,
and NOT an independent GOLD truth set.
"""
from __future__ import annotations
import ast
import datetime
import hashlib
from pathlib import Path
import sys
import types


def _extract_original(path: Path, functions: set[str], namespace: dict) -> None:
    original = path.read_bytes()
    if not original or len(original) > 1024 * 1024:
        raise ValueError("UNSAFE_ORIGINAL_SOURCE_SIZE")
    tree = ast.parse(original, filename=str(path))
    selected = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name in functions]
    if set(node.name for node in selected) != functions:
        raise ValueError("ORIGINAL_FUNCTION_MISSING")
    module = ast.Module(body=selected, type_ignores=[])
    exec(compile(module, str(path), "exec"), namespace)


class _Query:
    def __init__(self, rows=None, item=None):
        self.rows = list(rows or [])
        self.item = item

    def get(self, key):
        if isinstance(self.item, dict):
            return self.item.get(key)
        return self.item

    def filter_by(self, **kwargs):
        return self

    def order_by(self, *args):
        return self

    def all(self):
        return self.rows


class _User:
    def __init__(self, uid: int, is_admin: bool = False):
        self.id = uid
        self.first_name = f"synthetic-user-{uid}"
        self._admin = is_admin

    def is_admin(self):
        return self._admin


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("before", "after"):
        raise SystemExit("USAGE: misp_original_evaluation_privacy.py before|after UPSTREAM_ROOT")
    phase, root = sys.argv[1], Path(sys.argv[2]).resolve(strict=True)
    builder_file = root / "website/web/evaluate/evaluate_core.py"
    access_file = root / "website/lib/access.py"
    if not builder_file.is_file() or not access_file.is_file():
        raise AssertionError("ORIGINAL_MISP_FILE_MISSING")
    owner = _User(1)
    author = _User(2)
    outsider = _User(7)
    admin = _User(9, is_admin=True)
    created = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    conversion = types.SimpleNamespace(
        id=13, name="synthetic-public-conversion", uuid="synthetic-only",
        description="", conversion_type="MISP_TO_STIX", created_at=created,
        public=True, user_id=owner.id)
    public = types.SimpleNamespace(
        user_id=4, content="PUBLIC_COMMENT_FIXTURE_ONLY", is_private=False,
        created_at=created)
    private = types.SimpleNamespace(
        user_id=author.id, content="PRIVATE_COMMENT_FIXTURE_ONLY", is_private=True,
        created_at=created)

    class Conversion:
        query = _Query(item=conversion)

    class Comment:
        created_at = types.SimpleNamespace(asc=lambda: None)
        query = _Query(rows=[public, private])

    class User:
        query = _Query(item={
            public.user_id: types.SimpleNamespace(first_name="public-user"),
            private.user_id: types.SimpleNamespace(first_name="private-author"),
        })

    # Original function uses a local import of the User ORM model.
    # Only the in-memory module is available in this isolated process.
    package_names = ("website", "website.db_class", "website.db_class.db")
    for name in package_names:
        if name in sys.modules:
            raise AssertionError("UNEXPECTED_REAL_WEB_APPLICATION_IMPORTED")
        m = types.ModuleType(name)
        if name == "website.db_class.db":
            m.User = User
        sys.modules[name] = m

    access_ns = {}
    if phase == "after":
        # The original helper is pure and does not import Flask.
        _extract_original(access_file,
            {"is_admin", "is_owner", "is_owner_or_admin", "can_see_comment"}, access_ns)
    access = types.SimpleNamespace(**access_ns)

    namespace = {
        "Conversion": Conversion, "Comment": Comment, "access": access,
        "datetime": datetime, "VALUE_ORDER": [],
        "DIMENSION_LABELS": {}, "DIMENSION_DESCRIPTIONS": {}, "SCORE_MAP": {},
        "get_summary": lambda conversion_id: {
            "likes": 0, "dislikes": 0, "cti_categories": {}, "approval_score": None,
        },
        "get_consensus_tags": lambda conversion_id, threshold=2: [],
        "get_misp_push_tags": lambda conversion_id: [],
        "_overall_level": lambda tags: None,
    }
    _extract_original(builder_file, {"build_evaluation_report"}, namespace)
    build = namespace["build_evaluation_report"]
    if phase == "before":
        # Before: the exporter had no actor argument, and public conversions
        # passed route-level visibility checks while all comments were emitted.
        report = build(conversion.id)
        contents = {r["content"] for r in report["eval_comments"]}
        assert "PUBLIC_COMMENT_FIXTURE_ONLY" in contents
        assert "PRIVATE_COMMENT_FIXTURE_ONLY" in contents
        print("BEFORE_PRIVATE_COMMENT_EXPOSED=true")
        print("NEGATIVE_PUBLIC_COMMENT_PRESERVED=true")
        print("NEGATIVE_OWNER_SEES_PRIVATE=LEGACY_GLOBAL_REPORT_NO_ACTOR")
    else:
        # After: run the exact original access.can_see_comment function.
        other = build(conversion.id, outsider)
        outsider_contents = {r["content"] for r in other["eval_comments"]}
        assert outsider_contents == {"PUBLIC_COMMENT_FIXTURE_ONLY"}, outsider_contents
        print("AFTER_PRIVATE_COMMENT_REDACTED=true")

        owner_report = build(conversion.id, owner)
        assert {r["content"] for r in owner_report["eval_comments"]} == {
            "PUBLIC_COMMENT_FIXTURE_ONLY", "PRIVATE_COMMENT_FIXTURE_ONLY",
        }
        author_report = build(conversion.id, author)
        assert {r["content"] for r in author_report["eval_comments"]} == {
            "PUBLIC_COMMENT_FIXTURE_ONLY", "PRIVATE_COMMENT_FIXTURE_ONLY",
        }
        admin_report = build(conversion.id, admin)
        assert {r["content"] for r in admin_report["eval_comments"]} == {
            "PUBLIC_COMMENT_FIXTURE_ONLY", "PRIVATE_COMMENT_FIXTURE_ONLY",
        }
        print("NEGATIVE_OWNER_SEES_PRIVATE=true")
        print("NEGATIVE_AUTHOR_SEES_PRIVATE=true")
        print("NEGATIVE_ADMIN_SEES_PRIVATE=true")
        print("NEGATIVE_PUBLIC_COMMENT_PRESERVED=true")
    print("ORIGINAL_EVALUATION_FUNCTION_AST=true")
    print("ORIGINAL_SOURCE_SHA256="+hashlib.sha256(builder_file.read_bytes()).hexdigest())
    print("NATIVE_SCOPE=ORIGINAL_FUNCTION_WITH_IN_MEMORY_ORM_ADAPTERS")
    print("NO_NETWORK_NO_EXTERNAL_DATABASE=true")
    print("GOLD_ADMITTED=0")
    print("HOLDOUT=UNASSIGNED")


if __name__=="__main__":
    try:
        main()
    except Exception as e:
        print("ORIGINAL_MISP_WITNESS_FAIL_CLOSED="+type(e).__name__,file=sys.stderr)
        raise
