"""Collector failures after setup cannot bypass its existing recovery reserve."""

from __future__ import annotations

import json
from pathlib import Path

import o5_user_token_collector as module
import pytest
from test_o5_user_token_collector import Transport, case
from test_o5_user_token_collector_bound import acquisition_for, bound_transport


def test_unreaped_worker_failure_blocks_recovery_and_preserves_evidence():
    plan = case()
    calls = []

    class UnreapedWorker(ValueError):
        worker_reaped = False

    def execute(request):
        calls.append(request)
        raise UnreapedWorker("worker reap unconfirmed")

    result = module.collect(
        plan,
        execute,
        role=module.ROLE_LOCAL_SHADOW,
        run_id="unreaped-worker",
    )

    assert result["transport"]["workerReaped"] is False
    assert result["cleanup"]["cleanupComplete"] is False
    assert result["cleanup"]["blockedReason"] == "worker-reap-unconfirmed"
    assert result["cleanup"]["outstandingResources"] == plan["ownedResources"]
    assert result["cleanup"]["outstandingAccounts"] == [
        entry["ref"] for entry in plan["ownedAccounts"]
    ]
    assert calls and all(request.get("phase") != "recovery" for request in calls)


@pytest.mark.parametrize(
    ("attribute", "allows_recovery"),
    [(None, False), (1, False), (False, False), (True, True)],
)
def test_worker_failure_status_requires_exact_true(attribute, allows_recovery):
    plan = case()
    calls = []

    class WorkerFailure(ValueError):
        pass

    if attribute is not None:
        WorkerFailure.worker_reaped = attribute

    def execute(request):
        calls.append(request)
        raise WorkerFailure("worker status is not proven")

    result = module.collect(
        plan,
        execute,
        role=module.ROLE_LOCAL_SHADOW,
        run_id="unknown-worker-status",
    )

    assert result["transport"]["workerReaped"] is (True if allows_recovery else False)
    if allows_recovery:
        assert len(calls) > 1
        assert "blockedReason" not in result["cleanup"]
    else:
        assert result["cleanup"]["blockedReason"] == "worker-reap-unconfirmed"
        assert len(calls) == 1


@pytest.mark.parametrize("failure_phase", ["ruleset", "principal", "recovery"])
def test_unreaped_worker_failure_is_sticky_across_collector_helpers(failure_phase):
    plan = case()
    transport = bound_transport(plan, module.ROLE_LOCAL_SHADOW)
    calls = []
    failed = False

    class UnreapedWorker(ValueError):
        worker_reaped = False

    def execute(request):
        nonlocal failed
        calls.append(request)
        if request.get("phase") == failure_phase and not failed:
            failed = True
            raise UnreapedWorker("worker reap unconfirmed")
        return transport(request)

    result = module.collect(
        plan,
        execute,
        role=module.ROLE_LOCAL_SHADOW,
        run_id="unreaped-helper-" + failure_phase,
        acquisition=acquisition_for(plan, module.ROLE_LOCAL_SHADOW),
    )

    assert failed
    assert result["transport"]["workerReaped"] is False
    assert result["cleanup"]["cleanupComplete"] is False
    assert result["cleanup"]["blockedReason"] == "worker-reap-unconfirmed"
    failure_index = next(
        index for index, request in enumerate(calls) if request.get("phase") == failure_phase
    )
    assert len(calls) == failure_index + 1


@pytest.mark.parametrize(
    "stage", ["run", "accounts", "attempt", "request", "outcome", "recovery", "close"]
)
def test_failed_journal_stops_observation_but_recovers_existing_resources(
    tmp_path, monkeypatch, stage
):
    plan = case()
    transport = Transport(plan)
    original = module._Journal.__init__
    hit = []
    observation_counts_at_failure = []

    class FailingHandle:
        def __init__(self, actual):
            self.actual = actual

        def write(self, line):
            if json.loads(line)["kind"] == stage:
                hit.append(stage)
                observation_counts_at_failure.append(
                    sum(
                        request.get("phase") != "recovery"
                        for request in transport.requests
                    )
                )
                raise OSError("private-detail-must-not-escape")
            return self.actual.write(line)

        def flush(self):
            return self.actual.flush()

        def fileno(self):
            return self.actual.fileno()

        def close(self):
            self.actual.close()
            if stage == "close":
                hit.append(stage)
                raise OSError("private-detail-must-not-escape")

    def init(self, path):
        original(self, path)
        self._handle = FailingHandle(self._handle)

    monkeypatch.setattr(module._Journal, "__init__", init)
    result = module.collect(
        plan,
        transport,
        role=module.ROLE_LOCAL_SHADOW,
        run_id="journal",
        journal_path=tmp_path / "journal.jsonl",
    )
    assert hit
    assert result["recordingComplete"] is False
    assert result["abort"] is not None
    assert result["infrastructureFailures"]
    assert result["cleanup"]["cleanupComplete"] is True
    assert not any(transport.present.values()) and not any(transport.accounts.values())
    assert result["budget"]["recoverySpent"] <= result["budget"]["recoveryCeiling"]
    if stage in {"run", "accounts", "attempt", "request"}:
        assert (
            sum(request.get("phase") != "recovery" for request in transport.requests)
            == observation_counts_at_failure[0]
        )
    if stage == "outcome":
        assert (
            sum(request.get("phase") != "recovery" for request in transport.requests)
            == 1
        )
    assert "private-detail" not in json.dumps(result)


def test_journal_open_failure_still_recovers_preexisting_setup_resources(
    tmp_path, monkeypatch
):
    path = tmp_path / "journal.jsonl"
    original = Path.open

    def failing(self, *args, **kwargs):
        if self == path:
            raise OSError("open-failed")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing)
    plan = case()
    transport = Transport(plan)
    result = module.collect(
        plan, transport, role=module.ROLE_LOCAL_SHADOW, run_id="open", journal_path=path
    )
    assert result["recordingComplete"] is False
    assert result["cleanup"]["cleanupComplete"] is True
    assert all(request.get("phase") == "recovery" for request in transport.requests)
    assert not any(transport.present.values()) and not any(transport.accounts.values())


@pytest.mark.parametrize("point", ["_request", "_row", "_accept"])
def test_observation_processing_exception_enters_recovery(tmp_path, monkeypatch, point):
    plan = case()
    transport = Transport(plan)
    original = getattr(module, point)
    triggered = []

    def failing(*args, **kwargs):
        if not triggered:
            triggered.append(True)
            raise ValueError("private-exception-detail")
        return original(*args, **kwargs)

    monkeypatch.setattr(module, point, failing)
    result = module.collect(
        plan,
        transport,
        role=module.ROLE_LOCAL_SHADOW,
        run_id="processing",
        journal_path=tmp_path / "journal.jsonl",
    )
    assert result["recordingComplete"] is False
    assert result["cleanup"]["cleanupComplete"] is True
    assert not any(transport.present.values()) and not any(transport.accounts.values())
    assert "private-exception-detail" not in json.dumps(result)


def test_recovery_processing_failure_retains_one_resource_and_continues(monkeypatch):
    plan = case()
    transport = Transport(plan)
    original = module._accept
    failed = []

    def fail_first_recovery(raw, allowed):
        if allowed == module.RECOVERY_RECEIPT_KEYS and not failed:
            failed.append(True)
            raise ValueError("invalid-recovery-normalization")
        return original(raw, allowed)

    monkeypatch.setattr(module, "_accept", fail_first_recovery)
    result = module.collect(
        plan, transport, role=module.ROLE_LOCAL_SHADOW, run_id="recovery"
    )
    assert result["recordingComplete"] is False
    assert result["cleanup"]["outstandingResources"] == [plan["ownedResources"][0]]
    assert sum(transport.present.values()) == 1
    assert not any(transport.accounts.values())


@pytest.mark.parametrize("method", ["flush", "fsync"])
def test_failed_journal_flush_or_sync_keeps_cleanup_but_not_completion(
    tmp_path, monkeypatch, method
):
    plan = case()
    transport = Transport(plan)
    original = module._Journal.__init__
    hits = []
    if method == "fsync":

        def failed_sync(_fd):
            hits.append(True)
            raise OSError("private-sync-error")

        monkeypatch.setattr(module.os, "fsync", failed_sync)
    else:

        class Handle:
            def __init__(self, handle):
                self.handle = handle

            def write(self, value):
                return self.handle.write(value)

            def flush(self):
                hits.append(True)
                raise OSError("private-flush-error")

            def close(self):
                self.handle.close()

        def init(self, path):
            original(self, path)
            self._handle = Handle(self._handle)

        monkeypatch.setattr(module._Journal, "__init__", init)
    result = module.collect(
        plan,
        transport,
        role=module.ROLE_LOCAL_SHADOW,
        run_id="durability",
        journal_path=tmp_path / "journal.jsonl",
    )
    assert hits
    assert not result["recordingComplete"]
    assert result["cleanup"]["cleanupComplete"] is True
    assert not any(transport.present.values()) and not any(transport.accounts.values())
    assert all(request.get("phase") == "recovery" for request in transport.requests)
    assert "private-" not in json.dumps(result)


@pytest.mark.parametrize("point", ["initial", "observation", "recovery"])
@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), -1.0, True, "1", None, "raise"],
    ids=["nan", "infinite", "negative", "bool", "string", "null", "exception"],
)
def test_invalid_clock_latches_both_phases_without_free_requests(point, value):
    plan = case()
    transport = Transport(plan)
    ticks = []
    invalid_at = {
        "initial": 0,
        "observation": 1,
        "recovery": 1 + len(plan["observation"]),
    }[point]

    def clock():
        index = len(ticks)
        ticks.append(index)
        if index == invalid_at:
            if value == "raise":
                raise OSError("private-clock-details")
            return value
        return 0.0

    result = module.collect(
        plan, transport, role=module.ROLE_LOCAL_SHADOW, run_id="clock", clock=clock
    )
    assert result["recordingComplete"] is False
    assert result["cleanup"]["cleanupComplete"] is False
    assert result["budget"]["recoverySpent"] == 0
    assert (
        len(ticks) == invalid_at + 1
    )  # a later healthy reading cannot refill authority
    assert len(transport.requests) == (
        len(plan["observation"]) if point == "recovery" else 0
    )
    assert all(transport.present.values()) and all(transport.accounts.values())
    assert "private-clock-details" not in json.dumps(result)


def test_clock_rollback_after_first_response_stops_all_later_dispatches():
    plan = case()
    transport = Transport(plan)
    ticks = iter([10.0, 11.0, 9.0])
    result = module.collect(
        plan,
        transport,
        role=module.ROLE_LOCAL_SHADOW,
        run_id="rollback",
        clock=lambda: next(ticks),
    )
    assert result["recordingComplete"] is False
    assert result["abort"] == "clock-regressed"
    assert len(transport.requests) == 1
    assert result["budget"]["observationSpent"] == 1
    assert result["budget"]["recoverySpent"] == 0
    assert result["cleanup"]["cleanupComplete"] is False
