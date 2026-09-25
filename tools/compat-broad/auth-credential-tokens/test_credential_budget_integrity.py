"""Do not mint requests/time through malformed numbers or recovery re-entry."""
from __future__ import annotations

import copy
import json

import pytest
import credential_collector as c
import credential_shadow as shadow
import credential_comparator as comparator


def budget(**changes):
    args = dict(max_requests=10, max_wall_seconds=100, max_cost_usd=0.05,
                recovery_requests=3, recovery_wall_seconds=20, started_monotonic=1000)
    args.update(changes)
    return c.new_budget(**args)


@pytest.mark.parametrize("field,value", [
    ("max_requests", True), ("max_requests", 2.5), ("max_requests", -1),
    ("recovery_requests", True), ("recovery_requests", 0.5),
    ("max_wall_seconds", float("nan")), ("max_wall_seconds", float("inf")),
    ("max_wall_seconds", True), ("recovery_wall_seconds", float("nan")),
    ("recovery_wall_seconds", True), ("started_monotonic", float("inf")),
    ("started_monotonic", float("nan")), ("started_monotonic", -1),
    ("started_monotonic", "1000"), ("started_monotonic", 10**1000),
    ("max_cost_usd", -0.1), ("max_cost_usd", float("-inf")),
    ("max_cost_usd", False), ("max_cost_usd", float("nan")),
])
def test_invalid_budgets_are_not_declared_enforced(field, value):
    with pytest.raises(ValueError):
        budget(**{field:value})


def test_recovery_can_be_entered_once_without_refilling_deadline_or_requests():
    b = budget()
    c.enter_recovery(b, 1030)
    c.reserve_request(b, 1040)
    original = copy.deepcopy(b)
    c.enter_recovery(b, 1049)
    assert b["recoveryDeadlineMonotonic"] == original["recoveryDeadlineMonotonic"] == 1050
    assert b["recoveryEnteredSeconds"] == original["recoveryEnteredSeconds"] == 30
    assert b["requests"] == original["requests"] == 1
    c.enter_recovery(b, 1100)
    with pytest.raises(c.BudgetExceeded):
        c.reserve_request(b, 1100)
    assert b["requests"] == 1


@pytest.mark.parametrize("elapsed", [-1, float("nan"), float("inf"), True, "1", None, 10**1000])
def test_bad_elapsed_charge_never_discards_received_response_or_refunds_budget(elapsed):
    b = budget()
    c.charge_elapsed(b, 3)
    c.charge_elapsed(b, elapsed)  # must not throw after a received signup ACK
    assert b["wallSeconds"] == 3
    assert b["integrityFailure"] == "invalid-elapsed-charge"
    json.dumps(c.budget_record(b), allow_nan=False)
    for now in (1001, 1002):
        with pytest.raises(c.BudgetExceeded):
            c.reserve_request(b, now)
    c.enter_recovery(b, 1002)
    with pytest.raises(c.BudgetExceeded):
        c.reserve_request(b, 1003)
    assert b["requests"] == 0


@pytest.mark.parametrize("clock", [True, "1002", None, -1, 999, float("nan"), float("inf"), 10**1000])
def test_bad_clock_latches_refusal_including_later_valid_readings(clock):
    b = budget()
    c.reserve_request(b, 1001)
    with pytest.raises(c.BudgetExceeded):
        c.reserve_request(b, clock)
    c.enter_recovery(b, 1002)  # cannot clear fault; does not skip caller finally
    with pytest.raises(c.BudgetExceeded):
        c.reserve_request(b, 1003)
    assert b["requests"] == 1
    assert b["integrityFailure"] == "invalid-monotonic-clock"


def test_clock_cannot_return_to_an_earlier_valid_positive_time():
    b = budget()
    c.check_deadline(b, 1010)
    with pytest.raises(c.BudgetExceeded):
        c.check_deadline(b, 1009)
    assert b["requests"] == 0


def test_invalid_initial_recovery_clock_does_not_mint_a_deadline():
    b = budget()
    c.enter_recovery(b, float("nan"))
    assert b["recoveryDeadlineMonotonic"] is None
    with pytest.raises(c.BudgetExceeded):
        c.reserve_request(b, 1001)


def test_delayed_first_recovery_still_receives_the_declared_tail():
    b = budget()
    with pytest.raises(c.BudgetExceeded):
        c.reserve_request(b, 1200)
    c.enter_recovery(b, 1200)
    assert c.reserve_request(b, 1201) == 19
    with pytest.raises(c.BudgetExceeded):
        c.reserve_request(b, 1220)


def test_post_returns_received_signup_ack_when_elapsed_clock_moves_backward(monkeypatch):
    b = budget()
    ticks = iter([1001, 1000])
    monkeypatch.setattr(shadow.time, "monotonic", lambda: next(ticks))
    status, body = shadow.post(b, "http://127.0.0.1:9099", "/signup", {},
        sender=lambda *_args: (200, b'{"localId":"owned"}'))
    assert (status, body) == (200, {"localId":"owned"})
    assert b["integrityFailure"] == "invalid-elapsed-charge"
    with pytest.raises(c.BudgetExceeded):
        c.reserve_request(b, 1002)


def test_forced_recording_flag_cannot_hide_an_explicit_budget_fault():
    receipt = {"side":"local", "recordingComplete":True,
               "budget":{"integrityFailure":"invalid-monotonic-clock"}}
    assert comparator._receipt_reason(receipt, "local") == "budget-integrity-failure"
