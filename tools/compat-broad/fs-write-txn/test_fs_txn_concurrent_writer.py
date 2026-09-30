"""The concurrent outside-writer step: an outside writer sent while the holder's release (its anchor) is still to be sent, collected as
its own row after the anchor's, and replayed by the projection in the order the ledger took the two on."""

import copy
import threading
import time

import pytest

import fs_txn_table_p05 as p05
import fs_txn_table_p12 as p12
import txn_program_collector as collector_module
from txn_program_collector import Collector, Ledger, check_concurrent_order, projection
from txn_program_program import RequestBudget, compile_plan
from test_txn_program_collector import Clock, Service

TABLE = p05.TABLE
NONCE, OWNER = "a" * 32, "b" * 32


def with_step(step_id, **changes):
    steps = tuple({**step, **changes} if step["id"] == step_id else step for step in TABLE["steps"])
    return {**TABLE, "steps": steps}


def without_key(step_id, key):
    steps = tuple({k: v for k, v in step.items() if k != key} if step["id"] == step_id else step for step in TABLE["steps"])
    return {**TABLE, "steps": steps}


def refused(table):
    with pytest.raises(ValueError, match="txn-program table"):
        compile_plan(table, NONCE, OWNER)


def test_a_concurrent_writer_must_be_an_outside_commit_with_writes_right_after_its_anchor():
    refused(with_step("rest/c/writer-a", concurrentWith="rest/c/read-a"))
    refused(with_step("rest/c/writer-a", concurrentWith="rest/r/rollback"))
    refused(with_step("rest/c/writer-a", tokenInput="rest-c"))
    refused(with_step("rest/c/writer-a", role="observation"))
    refused(with_step("rest/c/writer-a", writes=()))
    refused(with_step("rest/c/writer-a", waitSeconds=3))
    refused(with_step("rest/c/writer-a", rpc="Rollback"))


def test_the_anchor_must_be_a_holders_release_with_a_wait_inside_the_writers_deadline():
    refused(without_key("rest/c/commit", "waitSeconds"))
    refused(with_step("rest/c/commit", waitSeconds=21))
    refused(with_step("rest/c/commit", waitSeconds=0))
    refused(with_step("rest/c/commit", tokenInput=None))
    steps = list(TABLE["steps"])
    index = next(i for i, step in enumerate(steps) if step["id"] == "rest/c/commit")
    steps[index] = {**steps[index], "rpc": "GetDocument", "document": "a", "writes": ()}
    refused({**TABLE, "steps": tuple(steps)})


def test_a_writer_cannot_be_concurrent_with_a_step_that_is_itself_concurrent():
    steps = list(TABLE["steps"])
    index = next(i for i, step in enumerate(steps) if step["id"] == "rest/c/writer-a")
    follower = {**steps[index + 1], "concurrentWith": "rest/c/writer-a", "waitSeconds": None}
    del follower["waitSeconds"]
    steps[index + 1] = follower
    refused({**TABLE, "steps": tuple(steps)})


def test_a_concurrent_plan_names_its_pending_writer_in_the_journal_and_a_sequential_plan_does_not():
    states = []
    clock = Clock()
    value = compile_plan(TABLE, NONCE, OWNER)
    collector = Collector(value, TABLE, RequestBudget(value, TABLE), Service(clock, locks=True, hold_writers=True), "owner", save=lambda state: states.append(copy.deepcopy(state)), monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)
    assert collector.run()["complete"] is True
    assert all("pendingConcurrent" in state for state in states)
    assert any(state["pendingConcurrent"] and state["pendingConcurrent"]["site"] == "rest/c/writer-a" for state in states)
    assert any(state["pending"] and state["pendingConcurrent"] for state in states), "both requests are in flight at once"
    assert states[-1]["pendingConcurrent"] is None
    states = []
    clock = Clock()
    value = compile_plan(p12.TABLE, NONCE, OWNER)
    Collector(value, p12.TABLE, RequestBudget(value, p12.TABLE), Service(clock, expiry=True), "owner", save=lambda state: states.append(state), monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()
    assert states and all("pendingConcurrent" not in state for state in states)


def recorded():
    clock = Clock()
    value = compile_plan(TABLE, NONCE, OWNER)
    return Collector(value, TABLE, RequestBudget(value, TABLE), Service(clock, locks=True, hold_writers=True), "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()


def swap_sequences(receipt, first, second):
    rows = {row["site"]: row for row in receipt["steps"]}
    rows[first]["sequence"], rows[second]["sequence"] = rows[second]["sequence"], rows[first]["sequence"]
    receipt["steps"].sort(key=lambda row: row["sequence"])


def test_the_projection_replays_the_pair_and_refuses_a_tampered_one():
    receipt = recorded()
    assert receipt["complete"] is True
    projection(receipt, TABLE)
    swapped = copy.deepcopy(receipt)
    swap_sequences(swapped, "rest/c/commit", "rest/c/writer-a")
    with pytest.raises(ValueError):
        projection(swapped, TABLE)
    changed = copy.deepcopy(receipt)
    row = next(row for row in changed["steps"] if row["site"] == "rest/c/writer-a")
    row["request"]["writes"][0]["update"]["fields"]["state"]["stringValue"] = "elsewhere"
    with pytest.raises(ValueError):
        projection(changed, TABLE)
    early = copy.deepcopy(receipt)
    row = next(row for row in early["steps"] if row["site"] == "rest/c/writer-a")
    before = next(row for row in early["steps"] if row["site"] == "rest/c/read-a")
    row["timing"] = {**row["timing"], "dispatchMonotonic": before["timing"]["responseMonotonic"] - 5.0}
    with pytest.raises(ValueError):
        projection(early, TABLE)


def test_the_concurrent_order_check_needs_a_start_after_the_earlier_answer_and_an_end_after_the_start():
    before = {"responseMonotonic": 10.0, "responseUtc": "2026-09-30T00:00:10.000000Z"}
    good = {"dispatchMonotonic": 10.0, "responseMonotonic": 12.0, "dispatchUtc": "2026-09-30T00:00:10.000000Z", "responseUtc": "2026-09-30T00:00:12.000000Z"}
    check_concurrent_order(before, good)
    for changes in ({"dispatchMonotonic": 9.9}, {"responseMonotonic": 9.0}, {"dispatchUtc": "2026-09-30T00:00:09.000000Z"}):
        with pytest.raises(ValueError):
            check_concurrent_order(before, {**good, **changes})


def concurrent_ledger():
    ledger = Ledger(compile_plan(TABLE, NONCE, OWNER))
    ledger.docs["a"].update(status="created", state="created", possible=["created"])
    ledger.history["a"].append("created")
    return ledger


def acknowledge(ledger, step, site, seconds):
    request = {"database": ledger.plan["database"], "writes": [{"update": {"name": ledger.plan["documents"]["a"]}}]}
    result = {"kind": "txn-program-receipt-v1", "transport": "rest", "complete": True, "code": 0, "details": "", "http": 200, "dispatchedRequests": 1, "childReaped": True,
              "response": {"writeResults": [{"updateTime": f"2026-09-30T00:00:{seconds:02d}.000000Z"}], "commitTime": f"2026-09-30T00:00:{seconds:02d}.000000Z"}}
    return request, result


def test_a_read_after_a_concurrent_pair_may_show_either_writers_state_until_a_later_write_settles_it():
    plan = compile_plan(TABLE, NONCE, OWNER)
    steps = {step["id"]: step for step in plan["steps"]}
    ledger = concurrent_ledger()
    ledger.docs["a"].update(state="rest-c-commit", possible=["rest-c-commit"])
    ledger.history["a"].append("rest-c-commit")
    request, result = acknowledge(ledger, steps["rest/c/writer-a"], "rest/c/writer-a", 5)
    timing = {"dispatchMonotonic": 1.0, "responseMonotonic": 2.0, "dispatchUtc": "2026-09-30T00:00:01.000000Z", "responseUtc": "2026-09-30T00:00:02.000000Z"}
    ledger.before("rest/c/writer-a", "rest", "Commit", request, steps["rest/c/writer-a"])
    ledger.after("rest/c/writer-a", "rest", "Commit", request, steps["rest/c/writer-a"], result, timing)
    read = {"name": plan["documents"]["a"]}
    assert ledger._visible("a", read) == {"rest-c-conflict", "rest-c-commit"}
    # a later plain write settles it
    request, result = acknowledge(ledger, steps["rest/c/writer-after-commit"], "rest/c/writer-after-commit", 6)
    ledger.before("rest/c/writer-after-commit", "rest", "Commit", request, steps["rest/c/writer-after-commit"])
    ledger.after("rest/c/writer-after-commit", "rest", "Commit", request, steps["rest/c/writer-after-commit"], result, timing)
    assert ledger._visible("a", read) == {"rest-c-after"}


def test_a_refused_concurrent_writer_leaves_the_holders_state_and_keeps_its_labels_known():
    plan = compile_plan(TABLE, NONCE, OWNER)
    step = next(step for step in plan["steps"] if step["id"] == "rest/c/writer-a")
    ledger = concurrent_ledger()
    request, _ = acknowledge(ledger, step, step["id"], 5)
    ledger.before(step["id"], "rest", "Commit", request, step)
    ledger.docs["a"].update(state="rest-c-commit", possible=["rest-c-commit"])   # the holder's commit landed meanwhile
    refusal = {"kind": "txn-program-receipt-v1", "transport": "rest", "complete": True, "code": 10, "details": "Too much contention on these documents. Please try again.", "http": 409, "dispatchedRequests": 1, "childReaped": True, "response": None}
    timing = {"dispatchMonotonic": 1.0, "responseMonotonic": 2.0, "dispatchUtc": "2026-09-30T00:00:01.000000Z", "responseUtc": "2026-09-30T00:00:02.000000Z"}
    ledger.after(step["id"], "rest", "Commit", request, step, refusal, timing)
    assert ledger.docs["a"]["state"] == "rest-c-commit", "a refusal must not roll the document back over the holder's commit"
    assert "rest-c-conflict" in ledger.tried["a"] and not ledger.unknown_commits


def test_a_writer_that_does_not_answer_within_its_deadline_stays_unknown_and_is_kept_for_the_recovery():
    clock = Clock()
    value = compile_plan(TABLE, NONCE, OWNER)
    collector = Collector(value, TABLE, RequestBudget(value, TABLE), Service(clock), "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)
    gate = threading.Event()
    thread = threading.Thread(target=gate.wait, daemon=True)
    thread.start()
    collector.started = {"context": {}, "thread": thread, "box": {}, "limit": 0.05}
    with pytest.raises(TimeoutError):
        collector._finish_concurrent()
    assert collector.started is not None, "the writer is still in flight, so it is kept"
    gate.set()
    thread.join(1)
    collector.started = {"context": {}, "thread": thread, "box": {"error": RuntimeError("wire failed")}, "limit": 1}
    with pytest.raises(RuntimeError):
        collector._finish_concurrent()
    assert collector.started is None


def test_a_recording_stopped_while_a_writer_is_in_flight_releases_the_holder_first_then_waits_for_the_writer_and_records_its_answer():
    # P06 recording 2's shape: the holder's release never went out, the writer stays held, and only the recovery's release frees it.
    clock = Clock()
    value = compile_plan(TABLE, NONCE, OWNER)
    service = Service(clock, locks=True, hold_writers=True)
    original = service.send
    def failing_anchor(transport, method, request, **kwargs):
        if method == "Commit" and request.get("transaction") and request.get("writes"):
            time.sleep(0.05)   # let the writer reach its wait
            raise ValueError("the wire failed before the holder's release")
        return original(transport, method, request, **kwargs)
    service.send = failing_anchor
    receipt = Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    assert receipt["cleanup"] == {"absent": True} and service.documents == {}
    assert receipt["tokens"]["rest-c"]["state"] == "rolled-back", "the recovery released the holder"
    writer = next(row for row in receipt["steps"] if row["site"] == "rest/c/writer-a")
    assert writer["result"]["code"] == 0, "the writer that waited for the release landed, and its answer is recorded"
    assert not receipt["unknownCommits"] or receipt["unknownCommits"] == ["rest/c/commit"]
