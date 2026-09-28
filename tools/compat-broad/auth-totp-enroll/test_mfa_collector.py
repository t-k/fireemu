"""The collector must bound itself, own its resources, and resume from a checkpoint."""

from __future__ import annotations

import pytest
from mfa_cases import CASE_IDS, observation_cases
from mfa_collector import (
    BudgetError,
    CheckpointError,
    SensitiveMaterialError,
    checkpoint_bytes,
    cleanup_complete,
    digest,
    initial_state,
    load_checkpoint,
    mark_deleted,
    next_action,
    outstanding_cleanup,
    record_step,
    register_owned,
    run_complete,
    skip_step,
)
from mfa_manifest import compile_campaign

NONCE = "0123456789abcdef0123456789abcdef"
ORIGIN = 1_700_000_000.0


def fresh() -> dict:
    return initial_state(compile_campaign(NONCE), ORIGIN)


def test_selected_collector_denominator_is_frozen_to_the_three_case_closure() -> None:
    state = initial_state(
        compile_campaign(NONCE, selector="pending-age-300-v1"), ORIGIN
    )
    assert [step["id"] for step in state["steps"]] == [
        "age-300s-start",
        "age-300s-finalize",
        "age-300s-same-account-fresh-control",
    ]
    assert state["selectedCaseIds"] == [step["id"] for step in state["steps"]]
    with pytest.raises(CheckpointError, match="checkpoint state is invalid"):
        altered = dict(state, selectedCaseIds=["age-450s-start"])
        checkpoint_bytes(altered)


def drain(state: dict, now: float) -> None:
    for step in state["steps"]:
        if step["status"] == "pending":
            record_step(state, step["id"], {"status": 200}, now)


def test_a_new_run_starts_on_the_first_case_and_charges_nothing() -> None:
    state = fresh()
    assert [step["id"] for step in state["steps"]] == list(CASE_IDS)
    assert state["requests"] == 0 and state["aborted"] is False
    action = next_action(state, ORIGIN)
    assert action["action"] == "RUN" and action["stepId"] == CASE_IDS[0]


def test_a_scheduled_step_waits_without_sleeping_and_reports_its_due_time() -> None:
    state = fresh()
    record_step(
        state,
        CASE_IDS[0],
        {"status": 200},
        ORIGIN,
        schedule={"age-300s-start": ORIGIN + 300.0},
    )
    action = next_action(state, ORIGIN + 1)
    assert action["action"] == "WAIT"
    assert action["stepId"] == "age-300s-start"
    assert action["dueAt"] == ORIGIN + 300.0
    assert action["waitSeconds"] == pytest.approx(299.0)
    assert next_action(state, ORIGIN + 300.0)["action"] == "RUN"


def test_a_checkpoint_round_trip_reproduces_the_same_decision() -> None:
    state = fresh()
    record_step(
        state,
        CASE_IDS[0],
        {"status": 200},
        ORIGIN,
        schedule={"age-300s-start": ORIGIN + 300.0},
    )
    register_owned(state, "account", "uid-pending-control", ORIGIN)
    resumed = load_checkpoint(checkpoint_bytes(state))
    assert resumed == state
    assert next_action(resumed, ORIGIN + 10) == next_action(state, ORIGIN + 10)
    assert next_action(resumed, ORIGIN + 400)["action"] == "RUN"


def test_a_progressed_checkpoint_remains_bound_to_its_frozen_plan() -> None:
    plan = compile_campaign(NONCE)
    state = initial_state(plan, ORIGIN)
    record_step(state, CASE_IDS[0], {"status": 200}, ORIGIN + 1)

    resumed = load_checkpoint(checkpoint_bytes(state), plan=plan)

    assert resumed == state


@pytest.mark.parametrize(
    ("checkpoint_selector", "plan_selector"),
    [(None, "pending-age-300-v1"), ("pending-age-300-v1", None)],
)
def test_a_checkpoint_cannot_be_loaded_under_a_different_case_denominator(
    checkpoint_selector, plan_selector
):
    checkpoint_plan = compile_campaign(NONCE, selector=checkpoint_selector)
    expected_plan = compile_campaign(NONCE, selector=plan_selector)
    state = initial_state(checkpoint_plan, ORIGIN)
    expected = initial_state(expected_plan, ORIGIN)
    state["planDigest"] = digest(expected_plan)
    state["maxRequests"] = expected["maxRequests"]
    state["deadline"] = expected["deadline"]
    with pytest.raises(CheckpointError, match="expected plan"):
        load_checkpoint(checkpoint_bytes(state), plan=expected_plan)


def test_an_altered_or_malformed_checkpoint_is_refused() -> None:
    state = fresh()
    payload = checkpoint_bytes(state)
    tampered = payload.replace(b'"requests":0', b'"requests":5')
    assert tampered != payload
    with pytest.raises(CheckpointError, match="digest"):
        load_checkpoint(tampered)
    for bad in (b"", b"not json", b"[]", b'{"state":{}}'):
        with pytest.raises(CheckpointError):
            load_checkpoint(bad)


def test_observations_carrying_secret_material_are_refused_before_storage() -> None:
    state = fresh()
    for observation in (
        {"status": 200, "sharedSecretKey": "ABC"},
        {"status": 200, "body": {"verificationCode": "123456"}},
        {"status": 200, "body": {"nested": [{"idToken": "x"}]}},
        {"status": 200, "mfaPendingCredential": "x"},
        {"status": 200, "sessionInfo": "x"},
    ):
        with pytest.raises(SensitiveMaterialError):
            record_step(state, CASE_IDS[0], observation, ORIGIN)
    assert state["steps"][0]["status"] == "pending" and state["requests"] == 0
    # The error code is the field the whole comparison rests on and must survive.
    record_step(
        state, CASE_IDS[0], {"status": 400, "errorCode": "INVALID_CODE"}, ORIGIN
    )
    assert state["steps"][0]["observation"]["errorCode"] == "INVALID_CODE"


def test_the_request_budget_latches_an_abort_that_still_demands_cleanup() -> None:
    state = fresh()
    register_owned(state, "account", "uid-one", ORIGIN)
    record_step(
        state, CASE_IDS[0], {"status": 200}, ORIGIN, requests=state["maxRequests"] + 1
    )
    assert (
        state["aborted"] is True and state["abortReason"] == "request-budget-exhausted"
    )
    action = next_action(state, ORIGIN + 1)
    assert action["action"] == "CLEANUP" and action["outstanding"] == ["uid-one"]
    with pytest.raises(BudgetError):
        record_step(state, CASE_IDS[1], {"status": 200}, ORIGIN + 1)
    mark_deleted(state, "uid-one", absence_verified=True)
    assert next_action(state, ORIGIN + 2)["action"] == "DONE"
    assert run_complete(state) is False


def test_the_wall_budget_aborts_a_run_that_outlives_its_deadline() -> None:
    state = fresh()
    late = state["deadline"] + 1
    assert next_action(state, late)["action"] == "DONE"
    assert state["aborted"] is True and state["abortReason"] == "wall-budget-exhausted"


def test_cleanup_needs_deletion_and_a_separate_absence_proof() -> None:
    state = fresh()
    register_owned(state, "account", "uid-one", ORIGIN)
    register_owned(state, "account", "uid-one", ORIGIN)
    assert len(state["ownedResources"]) == 1
    drain(state, ORIGIN + 5)
    assert next_action(state, ORIGIN + 6)["action"] == "CLEANUP"
    mark_deleted(state, "uid-one", absence_verified=False)
    assert cleanup_complete(state) is False
    assert outstanding_cleanup(state)[0]["id"] == "uid-one"
    mark_deleted(state, "uid-one", absence_verified=True)
    assert next_action(state, ORIGIN + 7)["action"] == "DONE"
    assert run_complete(state) is True
    with pytest.raises(KeyError):
        mark_deleted(state, "uid-unknown", absence_verified=True)


def test_a_skipped_step_resolves_without_pretending_it_was_observed() -> None:
    state = fresh()
    record_step(state, CASE_IDS[0], {"status": 200}, ORIGIN)
    skip_step(state, CASE_IDS[1], "its start was refused", ORIGIN + 1)
    assert state["steps"][1]["status"] == "skipped"
    assert state["steps"][1]["observation"] == {
        "skippedReason": "its start was refused"
    }
    with pytest.raises(BudgetError):
        skip_step(state, CASE_IDS[1], "again", ORIGIN + 2)


def test_a_run_is_incomplete_until_every_step_and_the_cleanup_resolve() -> None:
    state = fresh()
    assert run_complete(state) is False
    drain(state, ORIGIN + 1)
    assert run_complete(state) is True
    register_owned(state, "account", "uid-late", ORIGIN + 2)
    assert run_complete(state) is False


def test_the_overlapped_schedule_completes_inside_the_wall_budget() -> None:
    """Acquiring every aged resource at one origin makes the ages elapse concurrently."""
    plan = compile_campaign(NONCE)
    state = initial_state(plan, ORIGIN)
    schedule = {
        row["case"]: ORIGIN + row["dueOffsetSeconds"]
        for row in plan["agingSchedule"]["dueOffsetsSeconds"]
    }
    # One early step acquires everything and schedules every aged row together.
    record_step(state, CASE_IDS[0], {"status": 200}, ORIGIN, schedule=schedule)
    now = ORIGIN
    for _ in range(len(CASE_IDS) * 2):
        action = next_action(state, now)
        if action["action"] == "DONE":
            break
        if action["action"] == "WAIT":
            now = action["dueAt"]
            continue
        if action["action"] == "CLEANUP":
            break
        record_step(state, action["stepId"], {"status": 200}, now)
    assert all(step["status"] == "done" for step in state["steps"])
    assert state["aborted"] is False
    elapsed = now - ORIGIN
    assert elapsed == plan["limits"]["criticalPathSeconds"] - 30
    assert elapsed < plan["limits"]["maxWallSeconds"]


def test_the_serial_schedule_would_exhaust_the_wall_budget() -> None:
    plan = compile_campaign(NONCE)
    state = initial_state(plan, ORIGIN)
    now = ORIGIN
    by_id = {case["id"]: case for case in observation_cases()}
    for identifier in CASE_IDS:
        offset = by_id[identifier]["dueOffsetSeconds"]
        # Charge each aged resource once, at the row that first reads it: the serial
        # reading acquires the resource there, so its whole age elapses from that moment.
        if offset and (
            identifier.endswith("-start")
            or identifier.startswith("totp-enroll-session-age")
        ):
            now += offset
        if next_action(state, now)["action"] != "RUN":
            break
        record_step(state, identifier, {"status": 200}, now)
    assert state["aborted"] is True
    assert state["abortReason"] == "wall-budget-exhausted"


def test_a_skipped_step_cannot_be_recorded_after_an_abort() -> None:
    state = fresh()
    record_step(
        state, CASE_IDS[0], {"status": 200}, ORIGIN, requests=state["maxRequests"] + 1
    )
    assert state["aborted"] is True
    with pytest.raises(BudgetError):
        skip_step(state, CASE_IDS[1], "its start was refused", ORIGIN + 1)
