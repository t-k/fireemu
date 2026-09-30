"""P02b's table: the shape it declares, and the recordings it produces against stand-in services."""

import pytest

import fs_txn_table_p02b as p02b
import txn_program_cli as cli
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest
from test_txn_program_collector import Clock, Service

TABLE = p02b.TABLE
NONCE, OWNER = "a" * 32, "b" * 32


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def names(transport, chain):
    return [step["id"].split("/", 2)[2] for step in plan()["steps"] if step["id"].startswith(f"{transport}/{chain}/")]


def record(**knobs):
    clock = Clock()
    value = plan()
    service = Service(clock, **knobs)
    return Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run(), service


def cases(receipt):
    return {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p02b-readonly-refused"] == "fs_txn_table_p02b" and cli.table_for("p02b-readonly-refused") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p02b.py" in cli.source_manifest("p02b-readonly-refused")


def test_the_requests_stay_inside_the_caps():
    value = plan()
    assert len(value["steps"]) == 42 and len(value["cases"]) == 24
    assert value["caps"] == {"observation": 42, "tokenCleanup": 6, "documentCleanup": 7, "management": 7, "credential": 2}
    assert value["maxRequests"] == 64 and value["maxTokens"] == 6
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p02b-readonly-refused-001"


def test_both_transports_meet_the_refused_token_in_both_orders():
    for transport in ("rest", "grpc"):
        assert names(transport, "x") == ["begin", "read-a", "ro-write", "get-after", "commit-empty", "rollback", "post-read-a"]
        assert names(transport, "y") == ["begin", "read-a", "ro-write", "commit-empty", "get-after", "rollback", "post-read-a"]


def test_the_read_write_chain_records_the_first_read_and_may_be_aborted_at_commit():
    for transport in ("rest", "grpc"):
        assert names(transport, "z") == ["begin", "writer", "first-read", "commit", "rollback", "post-read-a"]
    steps = {step["id"]: step for step in plan()["steps"]}
    for transport in ("rest", "grpc"):
        read, commit, writer = steps[f"{transport}/z/first-read"], steps[f"{transport}/z/commit"], steps[f"{transport}/z/writer"]
        assert read["sinceBegin"] is True and read["allow"] == [0, 10] and read["role"] == "observation"
        assert commit["allow"] == [0, 10] and commit["writes"] and commit["tokenInput"] == f"{transport}-z"
        assert writer["role"] == "outside-writer" and writer["tokenInput"] is None
        assert steps[f"{transport}/z/begin"].get("mode") is None, "the chain is read-write"


def test_every_chain_is_read_only_and_its_write_may_only_be_refused():
    steps = plan()["steps"]
    assert [step["mode"] for step in steps if step["rpc"] == "BeginTransaction" and "mode" in step] == ["readOnly"] * 4
    for step in steps:
        if step["id"].endswith("/ro-write"):
            assert step["allow"] == [3, 5, 9, 10] and step["writes"] and step["tokenInput"]
        if step["id"].endswith(("/get-after", "/commit-empty", "/rollback")):
            assert step["allow"] == [0, 3, 5, 9, 10] and step["role"] == "observation" and not step["writes"]


def test_every_state_label_is_declared_and_used():
    assert set(TABLE["states"]) == {write["state"] for step in plan()["steps"] for write in step["writes"]}


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "82609a7a852a5bcb93ec8efbda5040ecbc1ec3dd728d3ab49663b560ea656e2e"


@pytest.mark.parametrize("knobs,code_after", [({}, 0), ({"ro_write_ends_token": True}, 3)])
def test_a_recording_completes_whether_or_not_the_refused_write_ends_the_token(knobs, code_after):
    receipt, _service = record(**knobs)
    assert receipt["complete"] is True, receipt["failureType"]
    codes = cases(receipt)
    for transport in ("rest", "grpc"):
        assert codes[f"{transport}/x-ro-write"] == codes[f"{transport}/y-ro-write"] == 3
        for chain in ("x", "y"):
            assert [codes[f"{transport}/{chain}-{name}"] for name in ("get-after", "commit-empty")] == [code_after] * 2
        # An empty commit that succeeded finished the token, so a Rollback after it answers 10.
        assert codes[f"{transport}/x-rollback"] == codes[f"{transport}/y-rollback"] == (10 if code_after == 0 else 0)
    assert [case["caseId"] for case in projection(receipt, TABLE)["cases"]] == plan()["cases"]


@pytest.mark.parametrize("knobs,shown", [({}, "rest-z-w"), ({"rw_snapshot": "begin"}, "created")])
def test_a_read_write_first_read_may_show_the_writer_or_the_state_at_the_begin(knobs, shown):
    receipt, _service = record(**knobs)
    assert receipt["complete"] is True, receipt["failureType"]
    reads = {read["site"]: read["state"] for read in projection(receipt, TABLE)["reads"] if "state" in read}
    assert reads["rest/z/first-read"] == shown
    assert cases(receipt)["rest/z-commit"] == 0


def test_an_aborted_read_write_commit_is_recorded_not_fatal():
    receipt, _service = record(rw_commit_code=10)
    assert receipt["complete"] is True, receipt["failureType"]
    assert cases(receipt)["rest/z-commit"] == 10 and cases(receipt)["grpc/z-commit"] == 10


def test_a_write_that_production_accepts_on_a_read_only_token_stops_and_is_cleaned_up():
    clock = Clock()
    value = plan()
    service = Service(clock)
    original = service.send
    def send(transport, method, request, **kwargs):
        if method == "Commit" and request.get("transaction") in service.readonly and request.get("writes"):
            service.readonly.discard(request["transaction"])
        return original(transport, method, request, **kwargs)
    service.send = send
    receipt = Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    assert receipt["cleanup"] == {"absent": True} and service.documents == {}


def test_two_recordings_of_one_service_project_identically():
    assert projection(record(ro_write_ends_token=True)[0], TABLE) == projection(record(ro_write_ends_token=True)[0], TABLE)


def _table(steps):
    return {**TABLE, "steps": tuple(steps), "caps": {**TABLE["caps"], "observation": len(steps)}}


def _with(step_id, **changes):
    return _table([{**step, **changes} if step["id"] == step_id else step for step in TABLE["steps"]])


SINCE_BEGIN = "marks a read that is not the first observation read of a read-write transaction"


def _without(step_id):
    return _table([step for step in TABLE["steps"] if step["id"] != step_id])


def _refused(table_, message):
    with pytest.raises(ValueError, match=message):
        compile_plan(table_, NONCE, OWNER)


def test_since_begin_is_only_for_the_first_observation_read_of_a_read_write_transaction():
    steps = list(TABLE["steps"])
    index = next(i for i, step in enumerate(steps) if step["id"] == "rest/z/first-read")
    first = steps[index]
    # A read-only transaction's read: only the mode differs from the accepted table.
    _refused(_with("rest/z/begin", mode="readOnly"), SINCE_BEGIN)
    # A marker that is not `true`.
    _refused(_with("rest/z/first-read", sinceBegin=False), SINCE_BEGIN)
    # A control read: only the role differs.
    _refused(_with("rest/z/first-read", role="control", caseId=None, allow=(0,)), SINCE_BEGIN)
    # A commit: the read that would precede it is dropped, so the token has not read yet.
    dropped = _without("rest/z/first-read")
    _refused(_table([{**step, "sinceBegin": True} if step["id"] == "rest/z/commit" else step for step in dropped["steps"]]), SINCE_BEGIN)
    # A second marked read, and a marked read after an unmarked one.
    second = {**first, "id": "rest/z/second-read", "caseId": "rest/z-second-read"}
    _refused(_table(steps[:index + 1] + [second] + steps[index + 1:]), SINCE_BEGIN)
    unmarked = {key: value for key, value in first.items() if key != "sinceBegin"} | {"id": "rest/z/plain-read", "caseId": "rest/z-plain-read"}
    _refused(_table(steps[:index] + [unmarked, first] + steps[index + 1:]), SINCE_BEGIN)


def test_a_read_write_read_that_is_not_marked_may_only_show_the_latest_state():
    table_ = _with("rest/z/first-read", sinceBegin=None)
    steps = [{key: value for key, value in step.items() if not (key == "sinceBegin" and value is None)} for step in table_["steps"]]
    table_ = _table(steps)
    clock = Clock()
    value = compile_plan(table_, NONCE, OWNER)
    service = Service(clock, rw_snapshot="begin")
    receipt = Collector(value, table_, RequestBudget(value, table_), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    assert receipt["cleanup"] == {"absent": True} and service.documents == {}


def test_the_digest_of_an_earlier_table_does_not_move_for_the_new_key():
    from fs_txn_table_p02 import TABLE as older
    assert not [step for step in compile_plan(older, NONCE, OWNER)["steps"] if "sinceBegin" in step]
