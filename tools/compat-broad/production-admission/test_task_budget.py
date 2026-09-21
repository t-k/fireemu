# ruff: noqa: I001 -- reservations bootstraps the shared module path.
"""The owner's US$10 is per production observation task, never program-wide."""

import pytest
from reservations import (
    TASK_CAP_MICROUSD,
    Ledger,
    task_budget_check,
    task_spent_microusd,
)
from broad_contract import digest

from test_reservations import plan

# Two independent catalogued tasks; a fixture label would be refused.
A = "FS-LIMIT-API-REQUEST-BYTES"
B = "FS-DATA-WRITE-COMMIT-TRANSFORMS-03"

USD = 1_000_000


def envelope(label, cost):
    """One permission per attempt: a spent permission is never reused."""
    return {
        "permissionDigest": digest(f"permission-{label}"),
        "issuedAt": 1000,
        "expiresAt": 10000,
        "limits": {
            "requests": 100,
            "accounts": 10,
            "resources": 10,
            "costMicrousd": cost,
        },
        "concurrency": 4,
        "scopes": [{"key": "project/p", "mode": "EXCLUSIVE"}],
    }


def attempt(tmp_path, task, label, cost):
    """A claim of `cost` micro-USD for task `task`, under its own nonce and Gate."""
    frozen = plan(label)
    frozen["costMicrousd"] = cost
    return (
        {
            "campaignId": task,
            "manifestDigest": digest(task),
            "nonceDigest": digest(frozen["nonce"]),
            "gatePath": str((tmp_path / label / "gate").resolve()),
            "gatePlanDigest": digest(frozen),
            "locks": [
                {
                    "key": f"project/p/firestore/(default)/documents/owned/{label}",
                    "mode": "WRITE",
                }
            ],
            "budget": {
                "requests": 2,
                "accounts": 0,
                "resources": 1,
                "costMicrousd": cost,
            },
            "durationSeconds": 100,
        },
        frozen,
    )


def reserve(ledger, tmp_path, task, label, cost):
    claim, frozen = attempt(tmp_path, task, label, cost)
    return ledger.reserve(envelope(label, cost), claim, frozen, now=1100), claim


def test_independent_tasks_each_have_their_own_ten_dollars(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    reserve(ledger, tmp_path, A, "a1", 8 * USD)
    reserve(ledger, tmp_path, B, "b1", 8 * USD)
    state = ledger.snapshot()
    assert task_spent_microusd(state, A) == 8 * USD
    assert task_spent_microusd(state, B) == 8 * USD
    # The program-wide total is reported, never a stop condition.
    assert (
        sum(
            row["claim"]["budget"]["costMicrousd"]
            for row in state["reservations"].values()
        )
        == 16 * USD
    )


def test_a_retry_of_the_same_task_counts_against_the_same_ten_dollars(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ticket, claim = reserve(ledger, tmp_path, A, "a1", 8 * USD)
    # The first attempt failed and was retired; its allocation stays charged.
    _retire_as_no_data(ledger, ticket, claim, tmp_path)
    with pytest.raises(ValueError, match=rf"task-budget-exceeded:{A} \("):
        reserve(ledger, tmp_path, A, "a2", 3 * USD)
    assert len(ledger.snapshot()["reservations"]) == 1


def test_recovery_of_the_same_task_within_the_cap_is_admitted(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    ticket, claim = reserve(ledger, tmp_path, A, "a1", 8 * USD)
    _retire_as_no_data(ledger, ticket, claim, tmp_path)
    reserve(ledger, tmp_path, A, "a-recovery", 1 * USD)
    assert task_spent_microusd(ledger.snapshot(), A) == 9 * USD


def test_a_held_row_of_the_task_still_counts(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    reserve(ledger, tmp_path, A, "a1", 8 * USD)
    assert ledger.snapshot()["reservations"]
    with pytest.raises(ValueError, match=f"task-budget-exceeded:{A}"):
        reserve(ledger, tmp_path, A, "a2", 3 * USD)


def test_exactly_the_cap_is_admitted_and_one_micro_usd_over_is_not(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    reserve(ledger, tmp_path, A, "a1", 9 * USD)
    with pytest.raises(ValueError, match=f"task-budget-exceeded:{A}"):
        reserve(ledger, tmp_path, A, "a2", 1 * USD + 1)
    reserve(ledger, tmp_path, A, "a3", 1 * USD)
    assert task_spent_microusd(ledger.snapshot(), A) == TASK_CAP_MICROUSD


def test_the_check_reads_every_state_and_only_the_named_task():
    state = {
        "reservations": {
            "r1": {
                "claim": {"campaignId": A, "budget": {"costMicrousd": 4}},
                "state": "released",
            },
            "r2": {
                "claim": {"campaignId": A, "budget": {"costMicrousd": 3}},
                "state": "aborted-no-data",
            },
            "r3": {
                "claim": {"campaignId": A, "budget": {"costMicrousd": 2}},
                "state": "closed-after-escalation",
            },
            "r4": {
                "claim": {"campaignId": B, "budget": {"costMicrousd": 50}},
                "state": "held",
            },
        }
    }
    assert task_spent_microusd(state, A) == 9
    assert task_budget_check(state, A, 1, cap_microusd=10) == 10
    with pytest.raises(ValueError, match=f"task-budget-exceeded:{A}"):
        task_budget_check(state, A, 2, cap_microusd=10)
    with pytest.raises(ValueError, match=f"task-budget-exceeded:{B}"):
        task_budget_check(state, B, 0, cap_microusd=10)
    with pytest.raises(ValueError, match="closed integer"):
        task_budget_check(state, A, -1)
    with pytest.raises(ValueError, match="closed integer"):
        task_budget_check(state, A, 1, cap_microusd=0)


def test_a_refused_claim_leaves_the_ledger_unchanged(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    reserve(ledger, tmp_path, A, "a1", 8 * USD)
    before = (tmp_path / "ledger" / "state.json").read_bytes()
    with pytest.raises(ValueError, match="task-budget-exceeded"):
        reserve(ledger, tmp_path, A, "a2", 3 * USD)
    assert (tmp_path / "ledger" / "state.json").read_bytes() == before


def _retire_as_no_data(ledger, ticket, claim, tmp_path):
    """Mark a held row terminal so the retry is measured against a retired one.

    The allocation of a retired row stays charged exactly as a held row's
    does, which is what the check reads; the terminal transition itself is
    exercised in test_reservations, so the state is set directly here.
    """
    with ledger._locked() as state:
        row = ledger._row(state, ticket)
        row["state"] = "aborted-no-data"
        row["abortRecordDigest"] = digest("record")
        ledger._save(state)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == (
        "aborted-no-data"
    )
