import pytest
import window_recorder
from rev3_projection import (
    CAMPAIGN_ID,
    CASES_SHA256,
    CORPUS_SHA256,
    MAX_ACCOUNTS,
    MAX_AUTH_REQUESTS,
    OBSERVATION_AUTH_LIMIT,
    RECORDER_BUDGET_SHA256,
    RECOVERY_AUTH_RESERVE,
    RECOVERY_SECONDS,
    SELECTOR,
    WALL_SECONDS,
    observation_auth_requests,
    recovery_auth_requests,
    validate_budget,
    validate_recorder_budget,
    validate_selection,
)
from window_contract import CASES


def test_revision_three_freezes_task_selector_corpus_and_budget():
    validate_selection(SELECTOR, CASES)
    validate_budget()

    assert CAMPAIGN_ID == "AUTH-MFA-AGE-TOTP-01"
    assert SELECTOR == "pending-lifetime-rev3-v1"
    assert len(CASES) == 17
    assert (
        CASES_SHA256
        == "f48a38ec71c1ce70d0ed140c298bf70bf4e4330592641d15d0c1f111b77e8d6f"
    )
    assert (
        CORPUS_SHA256
        == "f219caea7f12cc431f87994fe814f7d8cb393f39ad29562d42362897e92510a3"
    )
    assert (
        RECORDER_BUDGET_SHA256
        == "77484edd8094d03f1a0d035bddf5b797c8125b9262c1e1c41b5c97f3b1ece7c0"
    )
    assert (WALL_SECONDS, RECOVERY_SECONDS) == (1500, 300)
    assert (MAX_ACCOUNTS, MAX_AUTH_REQUESTS, RECOVERY_AUTH_RESERVE) == (5, 300, 60)


@pytest.mark.parametrize(
    "selector,cases",
    [
        ("pending-age-300-v1", CASES),
        (SELECTOR, CASES[:-1]),
        (SELECTOR, tuple(reversed(CASES))),
    ],
)
def test_revision_three_rejects_unbound_or_drifted_selection(selector, cases):
    with pytest.raises(ValueError):
        validate_selection(selector, cases)


def test_auth_request_projection_counts_conditional_wire_paths_not_result_rows():
    assert observation_auth_requests(("accepted",) * 3) == 45
    assert observation_auth_requests(("start-refused",) * 3) == 54
    assert observation_auth_requests(("finalize-refused",) * 3) == 57
    assert (
        observation_auth_requests(("accepted", "start-refused", "finalize-refused"))
        == 52
    )
    assert (
        observation_auth_requests(("start-refused",) * 3)
        <= OBSERVATION_AUTH_LIMIT
        == 240
    )
    assert recovery_auth_requests() == 25 <= RECOVERY_AUTH_RESERVE


@pytest.mark.parametrize("outcomes", [("accepted",), ("unexpected",) * 3])
def test_projection_rejects_incomplete_or_unknown_branch_set(outcomes):
    with pytest.raises(ValueError):
        observation_auth_requests(outcomes)


@pytest.mark.parametrize(
    "key",
    [
        "maxAccounts",
        "maxRequests",
        "recoveryRequestReserve",
        "totalBudgetSeconds",
        "configHoldMaxSeconds",
        "cleanupReserveSeconds",
        "adminTokenMaxAgeSeconds",
    ],
)
def test_complete_recorder_budget_is_digest_pinned(key, monkeypatch):
    validate_recorder_budget(window_recorder.BUDGET)
    changed = dict(window_recorder.BUDGET)
    changed[key] += 1

    with pytest.raises(ValueError):
        validate_recorder_budget(changed)

    monkeypatch.setitem(window_recorder.BUDGET, key, changed[key])
    with pytest.raises(ValueError):
        validate_budget()
