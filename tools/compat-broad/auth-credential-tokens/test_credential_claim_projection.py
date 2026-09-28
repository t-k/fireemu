"""Claim-projection completeness at the actual comparison API.

All receipt pairs are explicitly synthetic. A 'production' side label is test
input, not acquired production evidence. The real collector/parser/comparator
are imported; no transport, native runtime or Gate/Ledger is exercised here.
"""
from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from credential_cases import SAME_SECOND_CASE_ID, observation_cases
from credential_collector import claim_set, claim_shape
from credential_comparator import compare, compare_claim_sets
from test_credential_assertion_contract import classes, select, synthetic_pair

REFRESH = "refresh-preserves-auth-time"
ABOVE = "revocation-newer-session-accepted"
CLAIM_CASES = [
    case["id"] for case in observation_cases()
    if {"idTokenReturned", "sessionCookieReturned"}.intersection(case["expectedLocal"]["assertions"])
    or case["group"] == "claim-precedence"
]


def projected(payload=None, *, signed=False):
    if payload is None:
        payload = {"aud": "demo-claims", "sub": "test-only-user", "auth_time": 100,
                   "iat": 102, "exp": 3702,
                   "firebase": {"identities": {}, "sign_in_provider": "password"}}
    def segment(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    token = segment({"alg": "RS256" if signed else "none"}) + "." + segment(payload) + "."
    if signed:
        token += "Zml4dHVyZS1ub3QtYS1yZWFsLXNpZ25hdHVyZQ"
    return claim_set(claim_shape(token))


def malformed_shapes():
    good = projected()
    result = [{}, {"claimNames": []}, {"claimNames": [], "claimTypes": {}}]
    def changed(mutate):
        value = copy.deepcopy(good)
        mutate(value)
        result.append(value)
    changed(lambda c: c.update(claimNames="sub"))
    changed(lambda c: c["claimNames"].append(0))
    changed(lambda c: c["claimNames"].append("sub"))
    changed(lambda c: c["claimNames"].append("missingType"))
    changed(lambda c: c["claimTypes"].update(extraName="string"))
    changed(lambda c: c.update(claimTypes=[]))
    changed(lambda c: c["claimTypes"].update(sub="not-a-json-kind"))
    changed(lambda c: c["claimTypes"].update(sub=True))
    changed(lambda c: c.update(firebase=None))
    changed(lambda c: c.update(firebase={}))
    changed(lambda c: c["firebase"]["claimNames"].append("identities"))
    changed(lambda c: c["firebase"]["claimTypes"].pop("identities"))
    changed(lambda c: c["firebase"]["claimTypes"].update(identities="str"))
    changed(lambda c: c["firebase"].update(extra={}))
    changed(lambda c: c.update(extra={}))
    # Checking only after stripping the epoch would conceal these inconsistencies.
    changed(lambda c: c["firebase"]["claimNames"].append("fireemu_session_epoch"))
    changed(lambda c: c["firebase"]["claimTypes"].update(fireemu_session_epoch="string"))
    return result


@pytest.mark.parametrize("bad", malformed_shapes())
def test_identically_malformed_claim_sets_never_match(bad):
    assert compare_claim_sets(bad, copy.deepcopy(bad)) == "SEMANTIC_MISMATCH"
    assert compare_claim_sets(bad, projected()) == "SEMANTIC_MISMATCH"
    assert compare_claim_sets(projected(), bad) == "SEMANTIC_MISMATCH"


@pytest.mark.parametrize("case_id", CLAIM_CASES)
@pytest.mark.parametrize("side", ["local", "production", "both"])
def test_returned_token_without_its_claim_projection_is_indeterminate(case_id, side):
    pair = synthetic_pair()
    for receipt in pair if side == "both" else (pair[0 if side == "local" else 1],):
        select(receipt, case_id).pop("claims")
    got = classes(pair)
    assert got[case_id] == "INDETERMINATE"
    affected = {case_id}
    if case_id == ABOVE:
        affected.add(SAME_SECOND_CASE_ID)
        assert got[SAME_SECOND_CASE_ID] == "INDETERMINATE"
    assert all(value == "MATCH" for key, value in got.items() if key not in affected)


@pytest.mark.parametrize("bad", [None, {}, [], {"claimNames": ["sub"]}])
def test_bad_projection_is_indeterminate_through_full_compare_not_just_helper(bad):
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, REFRESH)["claims"] = copy.deepcopy(bad)
    assert classes(pair)[REFRESH] == "INDETERMINATE"


def test_valid_shape_is_derived_by_the_real_collector():
    pair = synthetic_pair()
    select(pair[0], REFRESH)["claims"] = projected()
    select(pair[1], REFRESH)["claims"] = projected(signed=True)
    assert classes(pair)[REFRESH] == "MATCH"
    assert compare_claim_sets(projected(), projected(signed=True)) == "MATCH"


def test_complete_empty_claim_projection_is_not_missing():
    empty = projected({})
    assert empty == {"claimNames": [], "claimTypes": {}, "firebase": None}
    assert compare_claim_sets(empty, empty) == "MATCH"
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, REFRESH)["claims"] = copy.deepcopy(empty)
    # This is a comparison of recorded shapes, NOT a JWT-validity decision.
    assert classes(pair)[REFRESH] == "MATCH"


@pytest.mark.parametrize("value", [None, False, 3, 1.5, "nonobject", [], {}])
def test_actual_non_object_firebase_claim_is_data_not_broken_projection(value):
    claims = projected({"firebase": value})
    assert compare_claim_sets(claims, claims) == "MATCH"


def test_unicode_and_empty_claim_names_are_not_rejected_as_token_policy():
    claims = projected({"": "value", "役割": "test", "firebase": {"": None, "権限": []}})
    assert compare_claim_sets(claims, claims) == "MATCH"


def test_only_the_complete_nested_local_epoch_is_excluded():
    production = projected()
    local = copy.deepcopy(production)
    local["firebase"]["claimNames"].append("fireemu_session_epoch")
    local["firebase"]["claimTypes"]["fireemu_session_epoch"] = "string"
    assert compare_claim_sets(local, production) == "MATCH"
    local["claimNames"].append("fireemu_session_epoch")
    local["claimTypes"]["fireemu_session_epoch"] = "string"
    assert compare_claim_sets(local, production) == "SEMANTIC_MISMATCH"


def test_coherent_type_difference_remains_a_semantic_difference():
    pair = synthetic_pair()
    select(pair[0], REFRESH)["claims"] = projected({"sub": "test-only-user", "auth_time": 100})
    select(pair[1], REFRESH)["claims"] = projected({"sub": "test-only-user", "auth_time": "100"})
    assert classes(pair)[REFRESH] == "DIFFERENT"


def test_refusal_without_a_returned_token_does_not_require_claims():
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, REFRESH).update(status=400, errorCode="TOKEN_EXPIRED", assertions={}, claims=None)
    assert classes(pair)[REFRESH] == "MATCH"


def test_absent_token_measurement_can_be_false_without_a_claim_projection():
    pair = synthetic_pair()
    for receipt in pair:
        row = select(receipt, REFRESH)
        row["assertions"] = dict.fromkeys(row["assertions"], False)
        row["claims"] = None
    assert classes(pair)[REFRESH] == "MATCH"


def test_a_malformed_projection_is_not_rescued_by_a_refusal():
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, REFRESH).update(status=400, errorCode="TOKEN_EXPIRED", assertions={}, claims={})
    assert classes(pair)[REFRESH] == "INDETERMINATE"


def test_claim_projection_validation_does_not_modify_receipts():
    pair = synthetic_pair()
    for receipt in pair:
        select(receipt, REFRESH)["claims"] = {}
    before = copy.deepcopy(pair)
    report = compare(*pair)
    assert pair == before
    assert report["parityEstablished"] is False
    assert all(set(row) == {"caseId", "classification"} for row in report["rows"])


@pytest.mark.parametrize("field,value,reason", [
    ("recordingComplete", False, "incomplete-recording"),
    ("productionExecuted", False, "production-unobserved"),
    ("collectorBinding", {"fixture": "different"}, "collector-binding-mismatch"),
])
def test_outer_evidence_failures_still_fail_closed(field, value, reason):
    pair = synthetic_pair()
    pair[1][field] = value
    report = compare(*pair)
    assert report["reason"] == reason
    assert {r["classification"] for r in report["rows"]} == {"INDETERMINATE"}


def test_cyclic_and_nonfinite_shapes_are_rejected_without_exception():
    cyclic = projected()
    cyclic["firebase"] = cyclic
    for value in [cyclic, {"claimNames": float("nan")}, projected({"sub": "x"}) | {"extra": 1 << 15000}]:
        assert compare_claim_sets(value, value) == "SEMANTIC_MISMATCH"
