#!/usr/bin/env python3
"""Local-only, non-executing Python AST shape screen. NOT a semantic proof."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys


class _Normalize(ast.NodeTransformer):
    """Erase names and constant values; preserve statement/control operators."""

    def visit_Name(self, node):
        node.id = "_IDENT_"
        return self.generic_visit(node)

    def visit_arg(self, node):
        node.arg = "_IDENT_"
        return self.generic_visit(node)

    def visit_FunctionDef(self, node):
        node.name = "_FUNCTION_"
        return self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        node.name = "_FUNCTION_"
        return self.generic_visit(node)

    def visit_ClassDef(self, node):
        node.name = "_CLASS_"
        return self.generic_visit(node)

    def visit_Attribute(self, node):
        node.attr = "_ATTR_"
        return self.generic_visit(node)

    def visit_keyword(self, node):
        if node.arg is not None:
            node.arg = "_ARG_"
        return self.generic_visit(node)

    def visit_Constant(self, node):
        node.value = "_CONST_"
        node.kind = None
        return node


def ast_shape(source: str) -> str:
    if not isinstance(source, str):
        raise ValueError("invalid_source")
    try:
        tree = ast.parse(source, mode="exec", type_comments=True)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise ValueError("invalid_python_source") from None
    normalized = _Normalize().visit(tree)
    shape = ast.dump(normalized, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(shape.encode("utf-8")).hexdigest()


def audit(rows: list[dict]) -> dict:
    if not isinstance(rows, list):
        raise ValueError("records must be an array")
    errors = Counter()
    variants = {}
    test_pair_shapes = set()
    test_cases = 0
    valid_cases = 0
    train_cases = 0
    for record in rows:
        if not isinstance(record, dict) or (
            set(record) != {"case_id","split","language","vulnerable_source","fixed_source"}
        ):
            errors["invalid_record"] += 1
            continue
        if record.get("language") != "python" or record.get("split") not in ("train","validation","test"):
            errors["invalid_record"] += 1
            continue
        if not isinstance(record.get("case_id"),str) or not record["case_id"]:
            errors["invalid_record"] += 1
            continue
        try:
            original = ast_shape(record["vulnerable_source"])
            corrected = ast_shape(record["fixed_source"])
        except ValueError:
            errors["invalid_python_source"] += 1
            continue
        valid_cases += 1
        split = record["split"]
        if split == "train":
            train_cases += 1
        if split == "test":
            test_cases += 1
            pair = (original, corrected)
            if pair in test_pair_shapes:
                errors["duplicate_test_ast_structure"] += 1
            test_pair_shapes.add(pair)
        for shape in {original, corrected}:
            first = variants.setdefault(shape, split)
            if first != split:
                errors["ast_structure_split_overlap"] += 1
    if train_cases == 0 or test_cases == 0:
        errors["missing_train_or_test"] += 1
    return {
        "schema":"ultrasec.private-python-ast-shape-audit.v1",
        "scope":"OWNER_LOCAL_ONLY_NO_SOURCE_EXPORTED",
        "structural_preflight_pass":not bool(errors),
        "real_world_gold_verified":False,
        "commercial_rights_verified":False,
        "certification":"NOT_CERTIFIED",
        "metrics":{
            "records":len(rows),
            "structurally_parseable_cases":valid_cases,
            "test_cases":test_cases,
            "structural_shape_count":len(variants),
        },
        "failures":dict(sorted(errors.items())),
        "interpretation":(
            "Checks simple AST-shape collisions, not causal mechanism equivalence. "
            "A clean result does NOT establish semantic independence; colliding "
            "shapes require source-level inspection, not invented gold labels."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline private Python AST screening")
    parser.add_argument("--input",type=Path,required=True)
    args = parser.parse_args(argv)
    try:
        with args.input.open(encoding="utf-8") as f:
            rows=[json.loads(line) for line in f if line.strip()]
        report=audit(rows)
    except (OSError,ValueError,UnicodeError,TypeError,json.JSONDecodeError):
        print('{"status":"INPUT_REJECTED","certification":"NOT_CERTIFIED"}')
        return 2
    print(json.dumps(report,sort_keys=True))
    return 0 if report["structural_preflight_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
