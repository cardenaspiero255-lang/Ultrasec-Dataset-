#!/usr/bin/env python3
"""UltraSec *public reference-fixture* quality gates.

Works exclusively on a small, synthetic, abstract data-flow fixture; NEVER
claims to scan the private dataset or prove semantic independence in production.
No runtime network requests or untrusted code execution.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "ultrasec-v7" / "fixtures" / "reference_pairs.json"
MANIFEST = ROOT / "ultrasec-v7" / "fixtures" / "reference_manifest.json"
LANGUAGES = ("python", "javascript", "go")
CWE = ("CWE-89", "CWE-78", "CWE-79", "CWE-22", "CWE-918", "CWE-639")
SPLITS = {"CWE-89": "train", "CWE-79": "train", "CWE-78": "validation", "CWE-22": "validation", "CWE-918": "test", "CWE-639": "test"}
KINDS = {"source", "forward", "join", "sanitize", "sink"}
GATES = ("core", "build", "coverage", "mutation", "adversarial", "self-review", "reliability")


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assert_valid(ok: bool, why: str) -> None:
    if not ok:
        raise ValueError(why)


def load_fixture(root: pathlib.Path = ROOT) -> dict:
    return json.loads((root / "ultrasec-v7/fixtures/reference_pairs.json").read_text(encoding="utf-8"))


def load_manifest(root: pathlib.Path = ROOT) -> dict:
    return json.loads((root / "ultrasec-v7/fixtures/reference_manifest.json").read_text(encoding="utf-8"))


def deterministic_fixture() -> dict:
    """Generate only *declarative* graphs; no exploit or proprietary code."""
    samples: list[dict] = []
    for fam_index, cwe in enumerate(CWE):
        for topo in range(4):
            pair_id = f"PUBLIC-REF-{fam_index:02d}-{topo:02d}"
            base = [
                {"id": "user_input", "kind": "source", "trust": "untrusted"},
                {"id": "trusted_context", "kind": "source", "trust": "trusted"},
                {"id": "entry", "kind": "forward", "inputs": ["user_input"]},
            ]
            if topo == 0:
                base.extend([{"id": "bridge", "kind": "forward", "inputs": ["entry"]}])
                previous = "bridge"
            elif topo == 1:
                base.extend([
                    {"id": "object_field", "kind": "forward", "inputs": ["entry"]},
                    {"id": "branch_join", "kind": "join", "inputs": ["object_field", "trusted_context"]},
                ])
                previous = "branch_join"
            elif topo == 2:
                base.extend([
                    {"id": "callback", "kind": "forward", "inputs": ["entry"]},
                    {"id": "alias", "kind": "forward", "inputs": ["callback"]},
                    {"id": "side_channel", "kind": "forward", "inputs": ["entry"]},
                    {"id": "merge", "kind": "join", "inputs": ["alias", "side_channel"]},
                ])
                previous = "merge"
            else:
                base.extend([
                    {"id": "dispatcher", "kind": "forward", "inputs": ["entry"]},
                    {"id": "decoy_safe", "kind": "sanitize", "inputs": ["trusted_context"], "protects": cwe},
                    {"id": "merge", "kind": "join", "inputs": ["dispatcher", "decoy_safe"]},
                ])
                previous = "merge"
            for label in ("vulnerable", "mitigated"):
                nodes = copy.deepcopy(base)
                nodes.append({"id": "boundary", "kind": "sanitize", "inputs": [previous],
                              "protects": "NONE" if label == "vulnerable" else cwe})
                nodes.append({"id": "operation", "kind": "sink", "inputs": ["boundary"], "requires": cwe})
                rec = {"id": pair_id + ("-V" if label == "vulnerable" else "-M"),
                       "pair_id": pair_id, "cwe": cwe, "language": LANGUAGES[(fam_index + topo) % 3],
                       "split": SPLITS[cwe], "label": label, "nodes": nodes}
                rec["graph_sha256"] = sha256(canonical(nodes))
                samples.append(rec)
    return {"schema_version": 1, "scope": "PUBLIC_SYNTHETIC_GRAPH_REFERENCE_ONLY",
            "about": "Abstract source/sanitize/sink graphs; NO private V7 data; NOT a security certificate",
            "records": samples}


def evaluate(record: dict) -> bool:
    """True iff an unsanitized untrusted source reaches a sink.

    Each graph node carries a set of (origin, protected_families) states;
    a trusted branch cannot make another untrusted branch trustworthy.
    """
    nodes = record.get("nodes")
    assert_valid(isinstance(nodes, list) and 4 <= len(nodes) <= 25, "invalid graph length")
    states: dict[str, set[tuple[str, frozenset[str]]]] = {}
    sinks = 0
    for node in nodes:
        assert_valid(isinstance(node, dict), "non-object graph node")
        ident = node.get("id")
        kind = node.get("kind")
        assert_valid(isinstance(ident, str) and ident and ident not in states, "duplicate/missing node ID")
        assert_valid(kind in KINDS, "unrecognized data-flow node kind")
        if kind == "source":
            assert_valid(node.get("trust") in {"trusted", "untrusted"}, "invalid source trust")
            assert_valid("inputs" not in node, "source must have no inputs")
            carried = {(node["trust"], frozenset())}
        else:
            parents = node.get("inputs")
            assert_valid(isinstance(parents, list) and len(parents) > 0, "missing incoming edges")
            assert_valid(all(isinstance(p, str) and p in states for p in parents), "future/missing graph input")
            carried = set().union(*(states[p] for p in parents))
            if kind == "sanitize":
                protects = node.get("protects")
                assert_valid(protects in set(CWE) | {"NONE"}, "invalid sanitizer contract")
                if protects != "NONE":
                    carried = {(origin, safe | frozenset((protects,))) for origin, safe in carried}
            if kind == "sink":
                sinks += 1
                assert_valid(node.get("requires") == record.get("cwe"), "sink contract mismatches CWE")
                assert_valid(ident == nodes[-1].get("id"), "sink not terminal")
                hazard = any(origin == "untrusted" and record["cwe"] not in safe for origin, safe in carried)
        states[ident] = carried
    assert_valid(sinks == 1, "must be exactly one sink")
    return hazard


def validate_rows(rows: list[dict]) -> dict:
    assert_valid(isinstance(rows, list) and rows, "records empty")
    ids: set[str] = set()
    graphs: set[str] = set()
    pairs: dict[str, list[dict]] = defaultdict(list)
    cwe_splits: dict[str, set[str]] = defaultdict(set)
    language_counts = Counter()
    for row in rows:
        assert_valid(row.get("id") not in ids, "duplicate record ID")
        assert_valid(isinstance(row.get("id"), str), "bad record ID")
        ids.add(row["id"])
        assert_valid(row.get("cwe") in CWE and row.get("split") in SPLITS.values(), "unexpected CWE/split")
        assert_valid(row.get("language") in LANGUAGES, "unexpected language")
        assert_valid(row.get("label") in ("vulnerable", "mitigated"), "unexpected label")
        assert_valid(row.get("split") == SPLITS[row["cwe"]], "wrong split for CWE")
        gh = sha256(canonical(row["nodes"]))
        assert_valid(gh == row.get("graph_sha256"), "incorrect graph fingerprint")
        assert_valid(gh not in graphs, "duplicate graph content")
        graphs.add(gh)
        computed = "vulnerable" if evaluate(row) else "mitigated"
        assert_valid(computed == row["label"], "incorrect causal label")
        pairs[row["pair_id"]].append(row)
        cwe_splits[row["cwe"]].add(row["split"])
        language_counts[row["language"]] += 1
    for pair_id, items in pairs.items():
        assert_valid(len(items) == 2, "incomplete pair " + pair_id)
        assert_valid({x["label"] for x in items} == {"vulnerable", "mitigated"}, "bad pair labels")
        assert_valid(len({x["split"] for x in items}) == len({x["cwe"] for x in items}) == 1, "mixed metadata")
        assert_valid({x["language"] for x in items}.__len__() == 1, "mixed languages")
    assert_valid(all(len(v) == 1 for v in cwe_splits.values()), "CWE split leakage")
    assert_valid(len(ids) == len(graphs) == len(rows), "record uniqueness mismatch")
    return {"records": len(rows), "pairs": len(pairs), "cwe": len(cwe_splits),
            "languages": dict(language_counts), "graphs_unique": len(graphs)}


def verify_fixture(root: pathlib.Path = ROOT) -> dict:
    fixture = load_fixture(root)
    assert_valid(fixture.get("schema_version") == 1, "unknown fixture schema version")
    assert_valid(fixture.get("scope") == "PUBLIC_SYNTHETIC_GRAPH_REFERENCE_ONLY", "not public reference material")
    computed = deterministic_fixture()
    assert_valid(canonical(fixture) == canonical(computed), "fixture not reproducible from pinned spec")
    manifest = load_manifest(root)
    assert_valid(manifest.get("scope") == fixture["scope"], "manifest scope mismatch")
    assert_valid(manifest.get("fixture_sha256") == sha256(canonical(fixture)), "manifest SHA256 mismatch")
    results = validate_rows(fixture["records"])
    assert_valid(manifest.get("records") == results["records"], "manifest row count mismatch")
    assert_valid(manifest.get("pairs") == results["pairs"], "manifest pair count mismatch")
    return results


def mutation_checks() -> dict:
    """Construct one sanitizer-null mutation and one label-swap per pair; reject all."""
    original = deterministic_fixture()["records"]
    pairs = defaultdict(dict)
    for r in original:
        pairs[r["pair_id"]][r["label"]] = r
    killed = 0
    for pair_id, v in pairs.items():
        for case in ("remove_fix", "false_label"):
            # Both mutants MUST fail the causal label check itself. Rejection
            # for duplicate code or an incomplete pair does not count.
            mutated = copy.deepcopy(v["mitigated"] if case == "remove_fix" else v["vulnerable"])
            if case == "remove_fix":
                boundary = next(x for x in mutated["nodes"] if x["id"] == "boundary")
                boundary["protects"] = "NONE"
            else:
                mutated["label"] = "mitigated"
            mutated["graph_sha256"] = sha256(canonical(mutated["nodes"]))
            try:
                validate_rows([mutated])
            except ValueError as ex:
                if "incorrect causal label" in str(ex):
                    killed += 1
                else:
                    raise AssertionError(f"Weak mutation rejection {pair_id} {case}: {ex}") from ex
            else:
                raise AssertionError(f"SURVIVING mutation {pair_id} {case}")
    return {"mutations": len(pairs) * 2, "killed": killed, "survivors": 0}


def adversarial_checks() -> dict:
    """Fail-closed testing of invalid graphs, partial fix, metadata leaks and splits."""
    records = deterministic_fixture()["records"]
    checks = 0
    invalid_kind = copy.deepcopy(records[0]); invalid_kind["nodes"][2]["kind"] = "magic"
    broken_edge = copy.deepcopy(records[1]); broken_edge["nodes"][2]["inputs"] = ["unknown"]
    cyclic = copy.deepcopy(records[0]); cyclic["nodes"][2]["inputs"] = ["operation"]
    safe_decoy = copy.deepcopy(records[7]); safe_decoy["nodes"][-2]["protects"] = "NONE"
    wrong_protection = copy.deepcopy(records[1]); wrong_protection["nodes"][-2]["protects"] = "CWE-918"
    for obj in (invalid_kind, broken_edge, cyclic, safe_decoy, wrong_protection):
        try:
            result = evaluate(obj)
        except ValueError:
            pass
        else:
            assert_valid(result, "adversarial graph hid an unsafe path")
        checks += 1
    # Every record checked for erroneous label and mismatch in split/pair/hash.
    for i, row in enumerate(records):
        wrong = copy.deepcopy(row)
        wrong["label"] = "mitigated" if row["label"] == "vulnerable" else "vulnerable"
        try:
            validate_rows([wrong])
        except ValueError:
            checks += 1
        else:
            raise AssertionError("false causal label accepted")
        bad_hash = copy.deepcopy(row)
        bad_hash["graph_sha256"] = "0" * 64
        try:
            validate_rows([bad_hash])
        except ValueError:
            checks += 1
        else:
            raise AssertionError("forged fingerprint accepted")
    assert_valid(checks >= 100, "too few adversarial trials")
    return {"adversarial_cases": checks, "rejected_or_detected": checks}


def static_self_review(root: pathlib.Path = ROOT) -> dict:
    filename = root / "ultrasec-v7/verification/reference_quality.py"
    source = filename.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert_valid("NO private V7 data" in source, "missing documentation of public-only scope")
    prohibited = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec", "compile"):
            prohibited.append(node.func.id)
    assert_valid(not prohibited, "unsafe dynamic-code evaluation")
    yaml_text = (root / ".github/workflows/ultrasec-enterprise-public.yml").read_text(encoding="utf-8")
    assert_valid("permissions:\n  contents: read" in yaml_text, "workflow must use read-only access")
    assert_valid("pull_request_target" not in yaml_text and "secrets." not in yaml_text, "workflow privacy escalation")
    jobs = re.findall(r"(?m)^  gate_(\d):\s*$", yaml_text)
    assert_valid(jobs == [str(x) for x in range(1, 8)], "expected seven distinct real jobs")
    assert_valid(yaml_text.count("runs-on: ubuntu-latest") == 7, "missing actual workflow jobs")
    assert_valid(yaml_text.count("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683") == 7, "checkout not fully SHA pinned")
    assert_valid("Semgrep" not in yaml_text and "CodeQL" not in yaml_text, "misleading scanner status")
    return {"jobs_checked": 7, "python_ast_parsed": True, "untrusted_exec_calls": 0}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("gate", choices=GATES)
    args = ap.parse_args()
    if args.gate == "core":
        result = verify_fixture()
    elif args.gate == "build":
        result = verify_fixture()
        assert_valid(canonical(load_fixture()) == canonical(deterministic_fixture()), "reproducible build failed")
        result["deterministic_rebuild"] = True
    elif args.gate == "coverage":
        raise SystemExit("Use the coverage command in the workflow; no fake coverage pass")
    elif args.gate == "mutation":
        result = mutation_checks()
    elif args.gate == "adversarial":
        result = adversarial_checks()
    elif args.gate == "self-review":
        result = static_self_review()
    else:
        assert_valid(verify_fixture()["pairs"] == 24, "unexpected fixture size")
        checks = []
        for _ in range(100):
            validated = verify_fixture()
            checks.append(sha256(canonical(validated)))
        assert_valid(len(set(checks)) == 1, "non-deterministic reliability failure")
        result = {"full_repetitions": 100, "all_passed": True, "consistent_digest": checks[0]}
    print(json.dumps({"gate": args.gate, "result": "PASS", "scope": "PUBLIC_REFERENCE_FIXTURE_ONLY", "evidence": result}, sort_keys=True))


if __name__ == "__main__":
    main()
