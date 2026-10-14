#!/usr/bin/env python3
"""Explainable AppSec scan-result scoring; never fabricates a scanner invocation."""
from __future__ import annotations
from collections import defaultdict, Counter

TOOLS={"semgrep","codeql","slither"}
COVERAGE={"rule_applied","no_rule","not_applicable","tool_failed","unsupported_language"}
SLITHER_LANGUAGES={"solidity","vyper"}


def summarize_sast(gold:list[dict], results:list[dict], required_recall:float=0.20)->dict:
    """Count TP/FP/FN/TN per CWE and tool over explicit supplied gold labels.

    A missing detector/rule cannot be treated as a negative result proving safety.
    The calling environment must supply evidence of real invocation and pin
    tool versions, coverage rules, and holdout integrity independently.
    """
    if not 0<=required_recall<=1:
        raise ValueError("required_recall outside [0,1]")
    failures=Counter()
    limitations=Counter()
    truth={}
    for row in gold:
        if not isinstance(row,dict) or not all(k in row for k in ("case_id","cwe_id","language","vulnerable")):
            failures["invalid_gold"]+=1
            continue
        if type(row["vulnerable"]) is not bool or row["case_id"] in truth:
            failures["invalid_gold"]+=1
            continue
        truth[row["case_id"]]=row
    classified=defaultdict(lambda:defaultdict(Counter))
    seen=set()
    for row in results:
        if not isinstance(row,dict) or row.get("case_id") not in truth or row.get("tool") not in TOOLS:
            failures["invalid_tool_record"]+=1;continue
        if row.get("coverage") not in COVERAGE or type(row.get("detected")) is not bool:
            failures["invalid_tool_record"]+=1;continue
        key=(row["tool"],row["case_id"])
        if key in seen:
            failures["duplicate_tool_record"]+=1;continue
        seen.add(key)
        actual=truth[row["case_id"]]
        group=classified[row["tool"]][actual["cwe_id"]]
        coverage=row["coverage"]
        if row["tool"]=="slither" and actual["language"].lower() not in SLITHER_LANGUAGES:
            coverage="not_applicable"
        if coverage!="rule_applied":
            limitations[coverage]+=1
        if coverage=="not_applicable" or coverage=="unsupported_language":
            group["not_applicable"]+=1;continue
        if coverage=="tool_failed":
            group["tool_failed"]+=1;continue
        # A detection of another CWE cannot be counted as TP for the target CWE.
        # A rule_applied claim requires a concrete rule→CWE mapping, even if
        # the tool did not alert on this particular case.
        if coverage=="rule_applied":
            mapped=row.get("rule_cwe_id")
            rule=row.get("rule_id")
            if not isinstance(rule,str) or not rule or not isinstance(mapped,str):
                failures["unverifiable_rule_coverage"]+=1
                coverage="no_rule"
                limitations["no_rule"]+=1
            elif mapped!=actual["cwe_id"]:
                failures["mismatched_rule_cwe"]+=1
                coverage="no_rule"
                limitations["wrong_cwe_rule"]+=1
        # No rule is never treated as tool success. When the true label
        # is vulnerable, its absence also contributes a false negative.
        detected=row["detected"] if coverage=="rule_applied" else False
        group["tp" if detected and actual["vulnerable"] else
              "fp" if detected else
              "fn" if actual["vulnerable"] else "tn"]+=1
    # Required per-tool predictions: any applicable test sample missing fails.
    if truth and not results:
        failures["missing_tool_results"]+=1
    for id_, gold_row in truth.items():
        # Mandatory coverage is determined by language, NOT by which tool
        # happened to appear in a vendor-controlled result file.
        required={"semgrep","codeql"}
        if str(gold_row.get("language","")).lower() in SLITHER_LANGUAGES:
            required={"semgrep","slither"}
        for tool in required:
            if (tool,id_) not in seen:
                failures["missing_tool_results"]+=1
    if not gold:
        failures["missing_real_holdout"]+=1
    summary={}
    for tool,cwes in sorted(classified.items()):
        summary[tool]={}
        for cwe,counts in sorted(cwes.items()):
            tp,fp,tn,fn=[counts[x] for x in ("tp","fp","tn","fn")]
            if tp+fn==0 or tn+fp==0:
                failures["unmeasurable_cwe_class_balance"]+=1
            precision=tp/(tp+fp) if tp+fp else 0.0
            recall=tp/(tp+fn) if tp+fn else None
            if recall is not None and recall<required_recall:
                failures["low_recall"]+=1
            summary[tool][cwe]={
                "tp":tp,"fp":fp,"tn":tn,"fn":fn,
                "precision":round(precision,6),
                "recall":round(recall,6) if recall is not None else None,
                "false_positive_rate":round(fp/(fp+tn),6) if fp+tn else None,
                "no_applicable_rule_or_language":counts["not_applicable"],
                "tool_failed":counts["tool_failed"],
            }
    if limitations:
        failures["coverage_not_complete"]+=1
    return {
        "schema":"ultrasec.appsec-tool-comparison.v1",
        "certification":"NOT_CERTIFIED",
        "execution_status":"NO_REAL_EXECUTION" if not gold and not results else "INPUT_RECORDS_ONLY_NOT_VERIFIED_AS_REAL_TOOL_EXECUTION",
        "benchmark_pass":not bool(failures),
        "required_recall":required_recall,
        "by_tool_cwe":summary,
        "limitations":dict(sorted(limitations.items())),
        "failures":dict(sorted(failures.items())),
        "interpretation":"No-rule, unsupported tool or zero recall are never evidence of superiority. Independent gold needed.",
    }
