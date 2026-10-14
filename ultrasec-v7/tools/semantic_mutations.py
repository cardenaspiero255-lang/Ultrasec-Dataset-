#!/usr/bin/env python3
"""Candidate-only semantic mutation operators; never counted as independent findings.

Owner-side examples may be transformed along four requested axes, but generated
artifacts require real behavior witnesses and independent expert adjudication.
Do NOT export protected corpus code, and do NOT conflate variations with roots.
"""
from __future__ import annotations
import ast
import copy
import hashlib
import json
import re

OPERATORS=frozenset({
    "control_flow","data_flow","sanitization_order","boundary_conditions",
})


def _proposal_identity_digest(original_hash:str, transformed_hash:str, operator:str, family_id:str)->str:
    content=json.dumps([original_hash,transformed_hash,operator,family_id],separators=(",",":"),ensure_ascii=True)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def propose_mutation(source:str,operator:str,family_id:str)->dict:
    """Modify a narrow allowlisted AST pattern. Source is never executed."""
    if operator not in OPERATORS or not re.fullmatch(r"CWE-[1-9][0-9]*",family_id):
        raise ValueError("Unsupported operator or family")
    if not isinstance(source,str) or len(source)>100000:
        raise ValueError("Source is missing or too long")
    root=ast.parse(source)
    if not root.body:
        raise ValueError("No statements")
    transformed=copy.deepcopy(root)
    changed=False
    if operator in ("control_flow","data_flow"):
        for i,node in enumerate(transformed.body):
            if (isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)
                    and isinstance(node.value.func,ast.Name)
                    and node.value.func.id=="sink"
                    and node.value.args and isinstance(node.value.args[0],ast.Name)):
                arg=node.value.args[0]
                if operator=="control_flow":
                    guard=ast.Compare(left=ast.Name(id=arg.id,ctx=ast.Load()),
                                      ops=[ast.IsNot()],comparators=[ast.Constant(None)])
                    transformed.body[i]=ast.If(test=guard,body=[node],orelse=[])
                else:
                    local="_ultrasec_flow"
                    assignment=ast.Assign(targets=[ast.Name(id=local,ctx=ast.Store())],
                                          value=copy.deepcopy(arg))
                    node.value.args[0]=ast.Name(id=local,ctx=ast.Load())
                    transformed.body[i:i+1]=[assignment,node]
                changed=True
                break
    elif operator=="sanitization_order":
        for node in ast.walk(transformed):
            if not isinstance(node,ast.Call) or len(node.args)!=1:
                continue
            outer=node.args[0]
            if (not isinstance(outer,ast.Call) or len(outer.args)!=1
                    or not isinstance(outer.func,ast.Name) or outer.func.id!="sanitize"):
                continue
            inner=outer.args[0]
            if (not isinstance(inner,ast.Call) or len(inner.args)!=1
                    or not isinstance(inner.func,ast.Name) or inner.func.id!="decode"):
                continue
            node.args[0]=ast.Call(
                func=ast.Name(id="decode",ctx=ast.Load()),
                args=[ast.Call(func=ast.Name(id="sanitize",ctx=ast.Load()),
                               args=[copy.deepcopy(inner.args[0])],keywords=[])],
                keywords=[])
            changed=True
            break
    else:  # boundary_conditions
        for node in ast.walk(transformed):
            if (isinstance(node,ast.If) and isinstance(node.test,ast.Compare)
                    and len(node.test.ops)==1 and isinstance(node.test.ops[0],ast.Lt)):
                node.test.ops[0]=ast.LtE()
                changed=True
                break
    if not changed:
        raise ValueError("No matching controlled AST transformation pattern")
    fixed=ast.fix_missing_locations(transformed)
    candidate=ast.unparse(fixed)
    if ast.dump(root,include_attributes=False)==ast.dump(fixed,include_attributes=False):
        raise ValueError("No AST-level change")
    return {
        "source":candidate,
        "original_source":source,
        "source_sha256":hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "original_sha256":hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "operator":operator,
        "family_id":family_id,
        "validation_status":"UNVALIDATED_CANDIDATE",
        "independent_root_cause":"NOT_VERIFIED",
        "required_before_admission":[
            "executable_witness","fixed_behavior_witness",
            "independent_appsec_signed_adjudication","legal_provenance_clearance",
            "leakage_free_holdout",
        ],
    }


def mutation_admission(proposal:dict,evidence:dict)->dict:
    failures={}
    if (not isinstance(proposal,dict)
            or not isinstance(proposal.get("source"),str)
            or not proposal.get("source")
            or proposal.get("operator") not in OPERATORS
            or not isinstance(proposal.get("family_id"),str)
            or not re.fullmatch(r"CWE-[1-9][0-9]*",proposal["family_id"])
            or proposal.get("validation_status")!="UNVALIDATED_CANDIDATE"):
        failures["invalid_proposal_schema"]=1
    else:
        actual_digest=hashlib.sha256(proposal["source"].encode("utf-8")).hexdigest()
        original=proposal.get("original_source")
        if not isinstance(original,str) or not original.strip():
            failures["unverifiable_mutation_origin"]=1
        elif hashlib.sha256(original.encode("utf-8")).hexdigest()!=proposal.get("original_sha256"):
            failures["unverifiable_mutation_origin"]=1
        elif original:
            try:
                rebuilt=propose_mutation(original,proposal["operator"],proposal["family_id"])
                if rebuilt["source_sha256"]!=actual_digest:
                    failures["unverifiable_mutation_origin"]=1
            except (ValueError,TypeError,SyntaxError,RecursionError):
                failures["unverifiable_mutation_origin"]=1
        if proposal.get("source_sha256")!=actual_digest:
            failures["tampered_proposal_digest"]=1
        if evidence.get("original_sha256")!=proposal.get("original_sha256"):
            failures["missing_original_bound_witness"]=1
        if evidence.get("artifact_sha256")!=actual_digest:
            failures["missing_artifact_bound_witness"]=1
    if (evidence.get("vulnerable_reproduced") is not True
            or evidence.get("fix_verified") is not True):
        failures["missing_executable_witness"]=1
    if evidence.get("independent_appsec_signed") is not True:
        failures["no_independent_adjudication"]=1
    if evidence.get("real_world_provenance_confirmed") is not True:
        failures["no_real_world_provenance"]=1
    if evidence.get("legal_rights_cleared") is not True:
        failures["rights_not_cleared"]=1
    if evidence.get("holdout_no_leakage") is not True:
        failures["split_integrity_unverified"]=1
    return {"admitted":not bool(failures),
            "certification":"NOT_CERTIFIED",
            "failures":failures}
