"""Mid-sweep releases retain the observation clock and all dispatch gates."""

import importlib

import pytest


@pytest.fixture
def session(monkeypatch):
    program = importlib.import_module("txn_boundary_grpc_program")
    runner = importlib.import_module("txn_boundary_grpc_runner")
    clock = [100.0]
    monkeypatch.setattr(runner.time, "monotonic", lambda: clock[0])
    counts = []
    budget = runner.SessionBudget(program.compile_plan("a" * 32, "b" * 32), lambda: None, counts.append)
    return runner, program, clock, counts, budget


def test_six_candidate_releases_do_not_start_final_recovery(session):
    _, _, clock, counts, budget = session
    for index in range(6):
        clock[0] += 70
        budget.charge("observation")
        budget.charge("tokenCleanup")
        assert budget.recovery_deadline is None
    assert budget.observation_deadline == 1300
    assert budget.used["tokenCleanup"] == 6
    assert counts[-1]["kind"] == "txn-p10b-charged-count-v1"
    assert len(counts) == 12


def test_final_recovery_is_explicit_once_and_cannot_return_to_observation(session):
    _, _, clock, _, budget = session
    clock[0] = 505
    budget.begin_recovery()
    assert budget.recovery_deadline == 685
    clock[0] = 600
    budget.begin_recovery()
    assert budget.recovery_deadline == 685
    budget.charge("documentCleanup")
    budget.charge("management")
    with pytest.raises(ValueError, match="observation|recovery"):
        budget.charge("observation")


def test_document_cleanup_requires_explicit_final_transition(session):
    *_, budget = session
    with pytest.raises(ValueError, match="recovery"):
        budget.charge("documentCleanup")
    assert budget.total == 0


@pytest.mark.parametrize("phase", ["observation", "tokenCleanup", "management", "credential"])
def test_every_mid_observation_phase_checks_observation_deadline(session, phase):
    _, _, clock, counts, budget = session
    clock[0] = 1288
    with pytest.raises(TimeoutError, match="deadline"):
        budget.charge(phase)
    assert budget.recovery_deadline is None
    assert budget.total == 0
    assert counts == []


def test_recovery_deadline_is_checked_instead_of_remaining_observation_time(session):
    _, _, clock, _, budget = session
    budget.begin_recovery()
    clock[0] = 268
    with pytest.raises(TimeoutError, match="deadline"):
        budget.charge("documentCleanup")
    assert budget.total == 0


def test_journal_failure_permanently_blocks_later_dispatch(session):
    _, _, _, _, budget = session
    calls = []
    def fail(value):
        calls.append(value)
        raise OSError("synthetic journal failure")
    budget.save_count = fail
    with pytest.raises(OSError, match="journal"):
        budget.charge("observation")
    assert budget.failed
    assert budget.total == 1
    with pytest.raises(ValueError, match="journal"):
        budget.charge("tokenCleanup")
    assert len(calls) == 1


def test_time_spent_saving_charged_count_is_rechecked_before_dispatch(session):
    _, _, clock, counts, budget = session
    def delay(value):
        counts.append(value)
        clock[0] = 1288
    budget.save_count = delay
    with pytest.raises(TimeoutError, match="journal"):
        budget.charge("observation")
    assert budget.total == 1
    assert len(counts) == 1


def test_cancellation_is_rechecked_after_count_journal(session):
    _, _, _, counts, budget = session
    calls = []
    def check():
        calls.append(True)
        if len(calls) == 2: raise ValueError("REVOKED")
    budget.check = check
    with pytest.raises(ValueError, match="REVOKED"):
        budget.charge("observation")
    assert budget.total == 1
    assert len(counts) == 1


@pytest.mark.parametrize("clock_value", [99.0, float("nan"), float("inf")])
def test_invalid_or_backwards_monotonic_clock_blocks_dispatch(session, clock_value):
    _, _, clock, counts, budget = session
    clock[0] = clock_value
    with pytest.raises(ValueError, match="clock"):
        budget.charge("observation")
    assert budget.total == 0
    assert not counts
