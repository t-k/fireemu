"""Tests the preparation corpus only; never reports the Rust handlers as executed."""
from __future__ import annotations

import copy
import importlib.util
import json
import random
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("account_federation_corpus", Path(__file__).with_name("corpus.py"))
assert SPEC and SPEC.loader
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)


def oracle(request, users):
    """Independent full-sort evaluator of production's query semantics as the Identity
    Platform sandbox answered them on 2026-09-23: only the first expression is evaluated, the
    first non-empty selector in email > phoneNumber > userId order applies, and an empty
    selector is no constraint. Every item is still type-checked."""
    expressions = request.get("expression")
    if expressions is None:
        expressions = []
    if not isinstance(expressions, list) or len(expressions) > 128:
        raise ValueError
    predicates = []
    for expression in expressions:
        if not isinstance(expression, dict) or set(expression) - {"email", "phoneNumber", "userId"}:
            raise ValueError
        for value in expression.values():
            if value is not None and (not isinstance(value, str) or len(value.encode()) > 4096 or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
                raise ValueError
        selected = None
        for name in ["email", "phoneNumber", "userId"]:
            if isinstance(expression.get(name), str) and expression[name]:
                selected = (name, expression[name]); break
        predicates.append(selected)
    predicates = [predicates[0]] if predicates and predicates[0] is not None else []
    def matches(user):
        if not predicates:
            return True
        for field, value in predicates:
            key = "localId" if field == "userId" else field
            current = user.get(key)
            if current is not None and ((current.lower() == value.lower()) if field == "email" else current == value):
                return True
        return False
    selected = [user for user in users if matches(user)]
    if request.get("returnUserInfo") is False:
        if any(request.get(field) is not None for field in ("offset", "limit")):
            raise ValueError
        return None, len(selected)
    key = "displayName" if request.get("sortBy") == "NAME" else "localId"
    selected.sort(key=lambda user: (user[key], user["localId"]), reverse=request.get("order") == "DESC")
    offset, limit = int(request.get("offset", 0)), int(request.get("limit", 500))
    selected = selected[offset:offset + limit]
    return [user["localId"] for user in selected], len(selected)


def test_generated_file_is_byte_stable_and_claims_no_execution():
    value = corpus.build()
    corpus.validate(value)
    assert corpus.encode(value) == corpus.OUTPUT.read_bytes()
    assert value["nativeExecuted"] is False
    assert value["productionExecuted"] is False
    assert value["productionAllowed"] is False
    assert len(value["account"]["cases"]) == 42
    assert len(value["federation"]["samlFixtureCases"]) == 11
    assert "signed-XML-SAML" in value["federation"]["unimplemented"]


@pytest.mark.parametrize("case", corpus.build()["account"]["cases"], ids=lambda case: case["id"])
def test_account_request_and_expectation_against_independent_local_evaluator(case):
    before = copy.deepcopy(case)
    users = corpus.build()["account"]["fixture"]
    if case["expected"]["status"] == 400:
        with pytest.raises(ValueError):
            oracle(case["request"], users)
    else:
        ids, count = oracle(case["request"], users)
        assert ids == case["expected"]["ids"]
        assert str(count) == case["expected"]["count"]
    assert before == case


@pytest.mark.parametrize("field", ["productionAllowed", "productionExecuted", "nativeExecuted"])
@pytest.mark.parametrize("value", [True, 0, "false", None])
def test_preparation_cannot_be_promoted_to_execution_or_authority(field, value):
    changed = corpus.build(); changed[field] = value
    with pytest.raises(ValueError):
        corpus.validate(changed)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "changed-status", "changed-local-policy", "missing-saml", "removed-gap"])
def test_coverage_or_semantics_drift_is_not_silently_accepted(mutation):
    value = corpus.build()
    if mutation == "missing": value["account"]["cases"].pop()
    elif mutation == "duplicate": value["account"]["cases"].append(value["account"]["cases"][0])
    elif mutation == "changed-status": value["account"]["cases"][-1]["expected"]["status"] = 200
    elif mutation == "changed-local-policy": value["account"]["policy"] = "production-verified"
    elif mutation == "missing-saml": value["federation"]["samlFixtureCases"].pop()
    else: value["federation"]["unimplemented"].remove("signed-XML-SAML")
    with pytest.raises(ValueError): corpus.validate(value)


def test_shuffling_user_insertion_order_does_not_change_local_query_results():
    value = corpus.build(); users = value["account"]["fixture"]
    rng = random.Random(109)
    for _ in range(30):
        rng.shuffle(users)
        for case in value["account"]["cases"]:
            if case["expected"]["status"] == 200:
                actual, count = oracle(case["request"], users)
                assert actual == case["expected"]["ids"]
                assert str(count) == case["expected"]["count"]


def test_native_tests_consume_the_checked_in_corpus_without_python_execution_claims():
    name = "auth-account-federation-local-v1.json"
    for target in ("identity_toolkit.rs", "auth_flows.rs"):
        source = (corpus.ROOT / "crates/fireemu-adapter-http/tests" / target).read_text()
        assert name in source and "include_str!" in source
    ids = [case["id"] for case in corpus.build()["account"]["cases"]]
    assert len(ids) == len(set(ids))
