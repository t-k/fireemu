"""The concurrent outside-writer step: an outside writer sent while the holder's release (its anchor) is still to be sent, collected as
its own row after the anchor's, and replayed by the projection in the order the ledger took the two on."""

import copy
import datetime as dt
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


def test_the_anchor_must_carry_the_holders_token_not_be_another_outside_writer_with_a_wait():
    # an outside writer may wait and carries no token, so a writer concurrent with one is not beside a holder's release
    steps = list(TABLE["steps"])
    index = next(i for i, step in enumerate(steps) if step["id"] == "rest/c/commit")
    steps[index] = {**steps[index], "tokenInput": None, "role": "outside-writer", "deadlineMs": 30000, "allow": [0, 10], "caseId": "rest/c-commit"}
    with pytest.raises(ValueError, match="anchor that is not a holder release"):
        compile_plan({**TABLE, "steps": tuple(steps)}, NONCE, OWNER)


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


def tamper_consistently(receipt, site, change):
    """Change one row and its copy in `observations` the same way, so the final comparison of the two cannot be what refuses it: only the check
    under test can."""
    changed = copy.deepcopy(receipt)
    for row in changed["steps"]:
        if row["site"] == site:
            change(row)
    for row in changed["observations"]:
        if row["site"] == site:
            change(row)
    return changed


@pytest.mark.parametrize("label,change", [
    ("the writer's request carries a changed precondition", lambda row: row["request"]["writes"][0].update(currentDocument={"exists": False})),
    ("the writer's request carries an extra field", lambda row: row["request"].update(extra=1)),
    ("the writer's case id differs", lambda row: row.update(caseId="rest/c-elsewhere")),
    ("the writer's transport differs", lambda row: row.update(transport="grpc")),
    ("the writer's rpc differs", lambda row: row.update(rpc="Rollback")),
])
def test_the_projection_refuses_a_writer_row_that_differs_from_the_graph_even_when_its_copy_agrees(label, change):
    receipt = recorded()
    projection(receipt, TABLE)
    with pytest.raises(ValueError, match="concurrent request graph differs"):
        projection(tamper_consistently(receipt, "rest/c/writer-a", change), TABLE)


def test_the_projection_refuses_a_writer_that_started_before_the_request_that_precedes_its_anchor_even_when_its_copy_agrees():
    receipt = recorded()
    before = next(row for row in receipt["steps"] if row["site"] == "rest/c/read-a")
    early_utc = (dt.datetime.fromisoformat(before["timing"]["responseUtc"]) - dt.timedelta(seconds=5)).isoformat().replace("+00:00", "Z")
    def early(row):
        # both clocks move together, so the timing itself stays well formed and only the order against the earlier answer is wrong
        row["timing"] = {**row["timing"], "dispatchMonotonic": before["timing"]["responseMonotonic"] - 5.0, "dispatchUtc": early_utc}
    with pytest.raises(ValueError, match="starts before the request that precedes its anchor"):
        projection(tamper_consistently(receipt, "rest/c/writer-a", early), TABLE)


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
    writer_waiting = threading.Event()
    real_wait = service.released.wait
    def noting_wait(timeout=None):
        writer_waiting.set()
        return real_wait(timeout)
    service.released.wait = noting_wait
    def failing_anchor(transport, method, request, **kwargs):
        if method == "Commit" and request.get("transaction") and request.get("writes"):
            assert writer_waiting.wait(5), "the writer never reached its wait"
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


def test_a_refused_holder_commit_that_keeps_its_lock_is_released_before_the_writer_is_joined():
    # The stand-in of review finding D-S1: the holder's Commit is refused (10), so its token stays open and keeps the lock the writer waits
    # on. Joining the writer first would let it time out (answer 4) and stop the recording; the release has to go out first.
    clock = Clock()
    value = compile_plan(TABLE, NONCE, OWNER)
    service = Service(clock, locks=True, hold_writers=True, rw_commit_code=10)
    receipt = Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()
    assert receipt["complete"] is True, receipt.get("failureType")
    assert [row for row in receipt["steps"] if row["site"].endswith("/writer-a") and row["result"]["code"] == 4] == []
    order = [row["site"] for row in sorted(receipt["steps"] + receipt["cleanupSteps"], key=lambda row: row["sequence"])]
    commit = order.index("rest/c/commit")
    assert order[commit + 1].startswith("cleanup/token/"), "the holder is released right after its anchor"
    assert order.index("rest/c/writer-a") > commit + 1
    projection(receipt, TABLE)


@pytest.mark.parametrize("holder_code, writer_code, states", [(0, 0, {"a": "grpc-r-after", "b": "grpc-c-unrelated"}), (10, 0, {"a": "grpc-r-after", "b": "grpc-c-unrelated"}),
                                                              (0, 10, {"a": "grpc-c-commit", "b": "created"}), (10, 10, {"a": "created", "b": "created"})])
def test_the_projection_derives_the_states_whether_the_holder_commit_and_the_writer_are_accepted_or_refused(holder_code, writer_code, states):
    # The projection takes the writer on before its anchor, as the collector did: a refused writer then returns the state the anchor left, and the
    # completion claims derive from the native rows. (Dropping that step made every refused-writer recording unprojectable: Codex M3, 2026-10-01.)
    clock = Clock()
    value = compile_plan(TABLE, NONCE, OWNER)
    service = Service(clock, locks=True, hold_writers=True, rw_commit_code=holder_code, writer_code=writer_code)
    receipt = Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()
    assert receipt["complete"] is True, receipt.get("failureType")
    assert projection(receipt, TABLE)["expectedStates"] == states


def test_the_projection_refuses_a_receipt_whose_step_list_is_not_in_sequence_order_at_the_writer():
    # The writer row is compared with the next row of the receipt's own step list, not only by its site: a list whose order differs from the
    # native sequence is refused wherever the writer's row has been moved to (Codex M3 follow-up, 2026-10-01).
    receipt = recorded()
    sites = [row["site"] for row in receipt["steps"]]
    position = sites.index("rest/c/writer-a")
    for other in range(len(sites)):
        if other == position:
            continue
        moved = copy.deepcopy(receipt)
        moved["steps"][position], moved["steps"][other] = moved["steps"][other], moved["steps"][position]
        with pytest.raises(ValueError):
            projection(moved, TABLE)


def test_the_projection_refuses_a_writer_row_moved_into_the_cleanup_rows():
    # The writer row and a cleanup row change places between the two lists with their sequence numbers kept: the replay reads the observation
    # list by position (`wait_entry` and the graph comparison), so the receipt is refused.
    receipt = recorded()
    assert receipt["cleanupSteps"], "the recording releases its tokens in the cleanup rows"
    position = [row["site"] for row in receipt["steps"]].index("rest/c/writer-a")
    moved = copy.deepcopy(receipt)
    moved["steps"][position], moved["cleanupSteps"][0] = moved["cleanupSteps"][0], moved["steps"][position]
    with pytest.raises(ValueError):
        projection(moved, TABLE)


def test_the_projection_orders_the_next_request_after_the_later_of_the_anchors_and_the_writers_answer():
    # The next request follows the later of the two answers (the collector joins the writer first). The replay holds the same rule: a request that
    # starts after the anchor's answer but before the writer's is refused, even when the rest of the row agrees with its copy.
    receipt = recorded()
    rows = {row["site"]: row for row in receipt["steps"]}
    anchor, writer = rows["rest/c/commit"]["timing"], rows["rest/c/writer-a"]["timing"]
    assert writer["responseMonotonic"] > anchor["responseMonotonic"], "the held writer answers after its anchor"

    def starts_between(row):
        row["timing"] = {**row["timing"], "dispatchMonotonic": (anchor["responseMonotonic"] + writer["responseMonotonic"]) / 2, "dispatchUtc": anchor["responseUtc"]}

    projection(receipt, TABLE)
    with pytest.raises(ValueError, match="overlap or ran out of order"):
        projection(tamper_consistently(receipt, "rest/c/read-after-pair", starts_between), TABLE)
