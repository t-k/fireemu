"""The frozen transaction expiry/retry observation cases are complete and closed."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_cases as cases


def test_campaign_identity_is_frozen():
    assert cases.CAMPAIGN == "FS-TRANSACTION-EXPIRY-RETRY-04"
    assert cases.CONTRACT == "txn-expiry-retry-cases-v1"


def test_every_case_identifier_is_unique_and_grouped():
    identifiers = [case["id"] for case in cases.CASES]
    assert len(identifiers) == len(set(identifiers))
    for case in cases.CASES:
        assert case["group"] in cases.GROUPS
        assert case["id"].startswith(case["group"] + "/")


def test_every_observation_case_declares_a_control():
    controls = {case["id"] for case in cases.CASES if case["kind"] == "control"}
    observations = [case for case in cases.CASES if case["kind"] == "observation"]
    assert observations, "the campaign must observe something"
    for case in observations:
        assert case["controls"], f"{case['id']} has no control"
        for control in case["controls"]:
            assert control in controls, f"{case['id']} names unknown control {control}"


def test_every_control_is_referenced_by_an_observation():
    referenced = set()
    for case in cases.CASES:
        referenced.update(case["controls"])
    for case in cases.CASES:
        if case["kind"] == "control":
            assert case["id"] in referenced, f"{case['id']} is an unused control"


def test_every_case_declares_an_expected_local_result():
    for case in cases.CASES:
        expected = case["expectedLocal"]
        assert expected["rpc"] in cases.RPCS
        assert expected["code"] in cases.CODES
        assert cases.CODES[expected["code"]] == expected["status"]
        if expected["code"] == 0:
            assert expected["message"] is None
        else:
            assert isinstance(expected["message"], str) and expected["message"]


def test_expiry_cases_declare_elapsed_time_and_others_do_not():
    for case in cases.CASES:
        elapsed = case["requiresElapsedSeconds"]
        if case["group"] == "idle-expiry":
            assert isinstance(elapsed, int)
        else:
            assert elapsed == 0, f"{case['id']} must not depend on elapsed time"


def test_expiry_observations_wait_far_past_the_declared_idle_limit():
    limit = cases.DECLARED_IDLE_LIMIT_SECONDS
    assert limit == 60
    for case in cases.CASES:
        if case["requiresElapsedSeconds"] == 0:
            continue
        if case["kind"] == "observation":
            assert case["requiresElapsedSeconds"] >= limit + 30
        else:
            assert case["requiresElapsedSeconds"] <= limit - 30


def test_cases_only_touch_owned_documents():
    for case in cases.CASES:
        for role in case["resources"]:
            assert role in cases.RESOURCE_ROLES


def test_previously_observed_cases_are_controls_and_name_their_evidence():
    for case in cases.CASES:
        prior = case["previouslyObserved"]
        if prior is None:
            continue
        assert case["kind"] == "control", (
            f"{case['id']} re-observes {prior} as an observation"
        )
        assert prior.startswith(("conformance:", "broad-run:"))


def test_no_case_creates_accounts_indexes_rules_or_databases():
    for case in cases.CASES:
        assert case["mutatesConfiguration"] is False


def test_digest_is_stable_and_covers_the_whole_table():
    first = cases.cases_digest()
    assert first == cases.cases_digest()
    assert len(first) == 64


def test_validate_cases_rejects_a_mutated_table(monkeypatch):
    broken = list(cases.CASES)
    broken[0] = dict(broken[0], controls=("idle-expiry/does-not-exist",))
    monkeypatch.setattr(cases, "CASES", tuple(broken))
    with pytest.raises(ValueError):
        cases.validate_cases()


def test_validate_cases_accepts_the_checked_in_table():
    cases.validate_cases()


def test_declared_unprepared_conditions_are_recorded_not_silently_dropped():
    assert cases.NOT_PREPARED
    for entry in cases.NOT_PREPARED:
        assert entry["condition"]
        assert entry["reason"]


def test_every_control_declares_the_evidence_it_repeats_or_says_there_is_none():
    for case in cases.CASES:
        if case["kind"] != "control":
            continue
        prior = case["previouslyObserved"]
        assert prior is not None, (
            f"{case['id']} is a control but names no prior observation; "
            "cite the recorded step or mark it explicitly as unobserved"
        )
        assert prior == cases.NO_PRIOR_OBSERVATION or prior.startswith(
            ("conformance:", "broad-run:")
        )


def test_the_rolled_back_retry_control_cites_the_recorded_production_step():
    case = cases.CASE_BY_ID["retry-token/retry-with-rolled-back-previous"]
    assert case["previouslyObserved"] == (
        "conformance:transactions/lifecycle#begin-read-write-with-retry-transaction"
    )


def test_validate_cases_rejects_an_uncited_control(monkeypatch):
    broken = []
    for case in cases.CASES:
        if case["kind"] == "control" and case["previouslyObserved"] is not None:
            case = dict(case, previouslyObserved=None)
        broken.append(case)
    monkeypatch.setattr(cases, "CASES", tuple(broken))
    with pytest.raises(ValueError):
        cases.validate_cases()
