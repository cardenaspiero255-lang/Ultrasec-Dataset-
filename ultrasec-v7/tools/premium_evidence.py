#!/usr/bin/env python3
"""Fail-closed enterprise acceptance checks; never certifies self-attested labels."""
from __future__ import annotations

import ast
import copy
import difflib
import hashlib
from collections import Counter
import re

_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_CWE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
# Pinned MITRE CWE identifiers: intentionally conservative and incomplete.
_PINNED_MITRE_CWES = frozenset(("CWE-79","CWE-89","CWE-352","CWE-862","CWE-787","CWE-22",
    "CWE-416","CWE-125","CWE-78","CWE-94","CWE-120","CWE-434"))


def admission_report(cases: list[dict], required_cases: int = 100,
                     required_families: int = 12) -> dict:
    """Check mandatory owner-held evidence metadata, not truth of external claims.

    Truth, redistribution rights, and reproducible behavior require independent
    human and legal verification. No individual cases, URLs, IDs or code in report.
    """
    if not isinstance(required_cases,int) or required_cases<1 or not isinstance(required_families,int) or required_families<1:
        raise ValueError("Positive integer requirements")
    failures: Counter[str] = Counter()
    ids:set[str] = set()
    families:set[str] = set()
    cwes:set[str] = set()
    seen_source_pairs:set[tuple[str,str]] = set()
    seen_code_pairs:set[tuple[bytes,bytes]] = set()
    family_cwe:dict[str,str] = {}
    cwe_family:dict[str,str] = {}
    for case in cases:
        if not isinstance(case,dict):
            failures["invalid_schema"] += 1
            continue
        try:
            case_id=case["case_id"]
            family=case["family_id"]
            if not all(isinstance(case.get(k),str) and bool(case.get(k)) for k in
                       ("case_id","family_id","language","cwe_id","source_url","source_commit","fix_commit")):
                raise ValueError("missing fields")
            if not (_CWE.fullmatch(case["cwe_id"]) and _COMMIT.fullmatch(case["source_commit"])
                    and _COMMIT.fullmatch(case["fix_commit"])
                    and case["source_commit"]!=case["fix_commit"]
                    and case["source_url"].startswith("https://")):
                raise ValueError("invalid provenance")
        except (KeyError,ValueError,TypeError):
            failures["invalid_provenance_schema"]+=1
            continue
        if case_id in ids:
            failures["duplicate_case_id"]+=1
            continue
        ids.add(case_id)
        families.add(family)
        cwe=case["cwe_id"]
        if cwe not in _PINNED_MITRE_CWES:
            failures["unknown_cwe_id"]+=1
        cwes.add(cwe)
        if family in family_cwe and family_cwe[family]!=cwe:
            failures["family_cwe_conflict"]+=1
        if cwe in cwe_family and cwe_family[cwe]!=family:
            failures["family_alias_for_same_cwe"]+=1
        family_cwe[family]=cwe
        cwe_family[cwe]=family
        origin_pair=(case["source_commit"],case["fix_commit"])
        if origin_pair in seen_source_pairs:
            failures["duplicate_source_patch_pair"]+=1
        seen_source_pairs.add(origin_pair)
        vulnerable=case.get("vulnerable_code")
        fixed=case.get("fixed_code")
        if isinstance(vulnerable,str) and isinstance(fixed,str):
            code_pair=(hashlib.sha256(vulnerable.encode("utf-8")).digest(),
                       hashlib.sha256(fixed.encode("utf-8")).digest())
            if code_pair in seen_code_pairs:
                failures["duplicate_code_pair"]+=1
            seen_code_pairs.add(code_pair)
        if case.get("source_kind")!="real_world":
            failures["not_real_world"]+=1
        if case.get("split")!="test":
            failures["not_sealed_test"]+=1
        if case.get("provenance_reviewed") is not True:
            failures["unverified_provenance"]+=1
        if case.get("rights_clearance")!="cleared":
            failures["rights_not_cleared"]+=1
        if case.get("independent_label_status")!="expert_adjudicated":
            failures["unverified_independent_label"]+=1
        if case.get("vulnerable_reproduced") is not True or case.get("fix_verified") is not True:
            failures["missing_executable_witness"]+=1
        if not all(isinstance(case.get(k),str) and case[k].strip() for k in ("vulnerable_code","fixed_code")):
            failures["missing_case_code"]+=1
    if len(cases)!=required_cases:
        failures["wrong_case_count"]+=1
    if len(families)<required_families:
        failures["insufficient_families"]+=1
    if len(cwes)<required_families:
        failures["insufficient_distinct_cwe_families"]+=1
    return {
        "schema":"ultrasec.enterprise-real-world-admission.v1",
        "scope":"OWNER_LOCAL_EVIDENCE_SCREEN_ONLY",
        "certification":"NOT_CERTIFIED",
        "external_legal_and_appsec_verification":"REQUIRED",
        "admission_pass":not bool(failures),
        "criteria":{"required_cases":required_cases,"required_families":required_families},
        "metrics":{"submitted":len(cases),"unique_case_ids":len(ids),"families":len(families),
                   "distinct_cwe_ids":len(cwes),"unique_source_patch_pairs":len(seen_source_pairs),
                   "unique_code_pairs":len(seen_code_pairs)},
        "failures":dict(sorted(failures.items())),
    }


class _NameMask(ast.NodeTransformer):
    def visit_Name(self,node):
        return ast.copy_location(ast.Name(id="ID",ctx=node.ctx),node)
    def visit_arg(self,node):
        node.arg="ID"
        return node
    def visit_FunctionDef(self,node):
        node.name="ID"
        return self.generic_visit(node)
    def visit_AsyncFunctionDef(self,node):
        node.name="ID"
        return self.generic_visit(node)
    def visit_ClassDef(self,node):
        node.name="ID"
        return self.generic_visit(node)
    def visit_Attribute(self,node):
        node.attr="ID"
        return self.generic_visit(node)
    def visit_keyword(self,node):
        if node.arg is not None:
            node.arg="ID"
        return self.generic_visit(node)
    def visit_Global(self,node):
        node.names=["ID" for _ in node.names]
        return node
    def visit_Nonlocal(self,node):
        node.names=["ID" for _ in node.names]
        return node
    def visit_ExceptHandler(self,node):
        if node.name is not None:
            node.name="ID"
        return self.generic_visit(node)
    def visit_alias(self,node):
        node.name="ID"
        node.asname="ID" if node.asname is not None else None
        return node
    def visit_MatchAs(self,node):
        if node.name is not None:
            node.name="ID"
        return self.generic_visit(node)
    def visit_MatchStar(self,node):
        if node.name is not None:
            node.name="ID"
        return self.generic_visit(node)
    def visit_MatchMapping(self,node):
        if node.rest is not None:
            node.rest="ID"
        return self.generic_visit(node)



def _shape(code: str)->str:
    root=ast.parse(code)
    return ast.dump(_NameMask().visit(root),include_attributes=False)


def _trivial_guard_wrapper(before_source:str,after_source:str)->bool:
    """Reject guard-only wrappers at module, function, class and nested block scope.

    Removing a newly inserted guard must restore the same masked AST.  The
    comparison is structural only; an independent executable witness is still
    required to establish patch correctness.
    """
    before=ast.parse(before_source)
    after=ast.parse(after_source)
    normalized=ast.dump(_NameMask().visit(copy.deepcopy(before)),include_attributes=False)
    for container in ast.walk(after):
        for field in ("body","orelse","finalbody"):
            block=getattr(container,field,None)
            if not isinstance(block,list):
                continue
            for pos,node in enumerate(tuple(block)):
                if not isinstance(node,ast.If) or node.orelse:
                    continue
                block[pos:pos+1]=node.body
                try:
                    candidate=ast.dump(_NameMask().visit(copy.deepcopy(after)),include_attributes=False)
                finally:
                    block[pos:pos+len(node.body)]=[node]
                if candidate==normalized:
                    return True
    return False

def causal_patch_gate(vulnerable_code: str, fixed_code: str,
                      witness: dict | None = None)->dict:
    """Screen nontrivial diffs; only independent executable/human proof establishes causality."""
    fail:Counter[str]=Counter()
    witness=witness or {}
    try:
        before=_shape(vulnerable_code)
        after=_shape(fixed_code)
        if before==after:
            fail["trivial_identifier_only_change"]+=1
        if _trivial_guard_wrapper(vulnerable_code,fixed_code):
            fail["trivial_guard_only_change"]+=1
        if vulnerable_code.strip()==fixed_code.strip():
            fail["identical_patch"]+=1
        before_lines=vulnerable_code.strip().splitlines()
        after_lines=fixed_code.strip().splitlines()
        changes=sum(max(i2-i1,j2-j1) for tag,i1,i2,j1,j2 in
            difflib.SequenceMatcher(None,before_lines,after_lines,autojunk=False).get_opcodes()
            if tag!="equal")
        allowed_delta=max(3,len(before_lines)//2)
        # Physical lines alone miss semicolon-packed statements and huge expressions.
        before_ast=ast.parse(vulnerable_code)
        after_ast=ast.parse(fixed_code)
        before_nodes=sum(1 for _ in ast.walk(before_ast))
        after_nodes=sum(1 for _ in ast.walk(after_ast))
        before_statements=sum(isinstance(n,ast.stmt) for n in ast.walk(before_ast))
        after_statements=sum(isinstance(n,ast.stmt) for n in ast.walk(after_ast))
        if (after_nodes>before_nodes+max(8,before_nodes//2)
                or after_statements>before_statements+max(3,before_statements//2)
                or len(fixed_code.encode("utf-8"))>len(vulnerable_code.encode("utf-8"))*2+256):
            fail["nonminimal_patch"]+=1
        # Compare non-overlapping lexical tokens: a single nested edit is
        # counted once, while same-size expression rewrites remain visible.
        import io as _io
        import tokenize as _tokenize
        def tokens(source):
            return [(t.type,t.string) for t in _tokenize.generate_tokens(
                _io.StringIO(source).readline)
                if t.type not in (_tokenize.ENCODING,_tokenize.NL,
                                  _tokenize.NEWLINE,_tokenize.INDENT,
                                  _tokenize.DEDENT,_tokenize.ENDMARKER)]
        old_tokens=tokens(vulnerable_code)
        new_tokens=tokens(fixed_code)
        token_edits=sum(max(i2-i1,j2-j1)
            for tag,i1,i2,j1,j2 in difflib.SequenceMatcher(
                None,old_tokens,new_tokens,autojunk=False).get_opcodes()
            if tag!="equal")
        # A single STRING/NUMBER token may encode thousands of modified
        # characters; weight its changed content without double-counting tokens.
        literal_edits=0
        # A budget for the total edit is insufficient: a 1-byte change in
        # one giant literal must not hide a complete rewrite of another.
        # Count every changed literal separately as well as in aggregate.
        oversized_literal_change=False
        modified_literal_bytes=0
        literal_kinds=(_tokenize.STRING,_tokenize.NUMBER)
        for tag,i1,i2,j1,j2 in difflib.SequenceMatcher(
                None,old_tokens,new_tokens,autojunk=False).get_opcodes():
            if tag=="equal":
                continue
            old_literals=[t for t in old_tokens[i1:i2] if t[0] in literal_kinds]
            new_literals=[t for t in new_tokens[j1:j2] if t[0] in literal_kinds]
            for change,a1,a2,b1,b2 in difflib.SequenceMatcher(
                    None,old_literals,new_literals,autojunk=False).get_opcodes():
                if change=="equal":
                    continue
                old_changed=old_literals[a1:a2]
                new_changed=new_literals[b1:b2]
                for old,new in zip(old_changed,new_changed):
                    modified_literal_bytes+=len(old[1])
                    if old[0]!=new[0]:
                        changed_bytes=max(len(old[1]),len(new[1]))
                    else:
                        changed_bytes=sum(max(p2-p1,q2-q1)
                            for op,p1,p2,q1,q2 in difflib.SequenceMatcher(
                                None,old[1],new[1],autojunk=False).get_opcodes()
                            if op!="equal")
                    literal_edits+=changed_bytes
                    if changed_bytes>max(64,len(old[1])//3):
                        oversized_literal_change=True
                # Extra inserted or removed tokens count as full edits.
                for old in old_changed[len(new_changed):]:
                    modified_literal_bytes+=len(old[1])
                    literal_edits+=len(old[1])
                    if len(old[1])>64:
                        oversized_literal_change=True
                for new in new_changed[len(old_changed):]:
                    literal_edits+=len(new[1])
                    if len(new[1])>64:
                        oversized_literal_change=True
        if oversized_literal_change or literal_edits>max(64,modified_literal_bytes//3):
            fail["nonminimal_patch"]+=1
        if token_edits>max(6,len(old_tokens)//3):
            fail["nonminimal_patch"]+=1
        if changes>allowed_delta or len(after_lines)>len(before_lines)+allowed_delta:
            fail["nonminimal_patch"]+=1
    except (SyntaxError,ValueError,TypeError,RecursionError):
        fail["invalid_python_syntax"]+=1
    if witness.get("vulnerable_reproduced") is not True or witness.get("fix_verified") is not True:
        fail["missing_executable_witness"]+=1
    return {
        "causal_gate_pass":not bool(fail),
        "external_certification":"NOT_VERIFIED",
        "runtime_witness_self_declared":True,
        "failures":dict(sorted(fail.items())),
    }


def semantic_mutation_policy()->dict:
    """Govern four requested mutation axes; no fabricated million-record output."""
    return {
        "operator_families":["control_flow","data_flow","sanitization_order","boundary_conditions"],
        "required_proofs":[
            "verified_vulnerable_behavior","verified_fixed_behavior",
            "project_and_mechanism_holdout_no_leakage",
            "independent_appsec_adjudication","real_world_provenance",
        ],
        "unverified_target_lexical_patterns":200000,
        "status":"IMPLEMENTATION_AND_EVIDENCE_REQUIRED",
        "note":"Mutations may change behavior; never equate syntactic novelty with new causal roots.",
    }
