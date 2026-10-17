"""Negative security controls: public research must never be promoted to gold."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from verify_candidate_cohort import validate, report

REGISTRY = ROOT / "verification" / "research" / "COHORT_5_PRE_ADMISSION_PUBLIC.json"


def fixture():
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def test_documented_five_candidates_are_public_and_not_gold():
    registry = fixture()
    assert validate(registry) == []
    status = report(registry)
    assert status["candidate_count"] == 5
    assert status["native_red_green_count"] == 1
    assert status["confirmed_gold_count"] == 0
    assert status["certification"] == "NOT_CERTIFIED"


@pytest.mark.parametrize("tamper", [
    lambda d: d["candidates"][0].update(gold_status="ADMITTED"),
    lambda d: d["candidates"][0].update(independent_review="EXPERT_ADJUDICATED"),
    lambda d: d["candidates"][0].update(commercial_rights="CLEARED"),
    lambda d: d["candidates"][0].update(split="TEST"),
    lambda d: d["candidates"][0].update(provenance="PRIVATE_SOURCE"),
    lambda d: d.update(certification="CERTIFIED"),
    lambda d: d["candidates"][1].update(cve_id=d["candidates"][0]["cve_id"]),
    lambda d: d["candidates"][1].update(cwe_id="CWE-9999"),
    lambda d: d["candidates"][0].update(source_commit="deadbeef"),
    lambda d: d["candidates"][0].update(native_evidence="PASS"),
    lambda d: d["candidates"].pop(),
    lambda d: d["candidates"][0].update(training_import="YES"),
    lambda d: d["candidates"][0].update(vulnerable_reproduced="YES"),
    lambda d: d["candidates"][0].update(source_url="http://example.invalid"),
])
def test_invalid_claims_are_rejected(tamper):
    registry = copy.deepcopy(fixture())
    tamper(registry)
    assert validate(registry), "invalid or overclaiming registry was accepted"


def test_empty_manifest_is_rejected():
    assert validate({})


def test_ci_is_not_an_independent_adjudicator():
    registry = fixture()
    assert registry["candidates"][0]["native_evidence"] == "RED_GREEN_REPRODUCED"
    assert report(registry)["confirmed_gold_count"] == 0


def test_duplicate_original_patch_pair_is_rejected():
    registry = fixture()
    registry["candidates"][4]["source_commit"] = registry["candidates"][0]["source_commit"]
    registry["candidates"][4]["fix_commit"] = registry["candidates"][0]["fix_commit"]
    assert "duplicate_source_patch_pair" in validate(registry)
