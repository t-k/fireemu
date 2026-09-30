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
    assert len(value["steps"]) == 30 and len(value["cases"]) == 16
    assert value["caps"] == {"observation": 30, "tokenCleanup": 4, "documentCleanup": 7, "management": 7, "credential": 2}
    assert value["maxRequests"] == 50 and value["maxTokens"] == 4
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p02b-readonly-refused-001"


def test_both_transports_meet_the_refused_token_in_both_orders():
    for transport in ("rest", "grpc"):
        assert names(transport, "x") == ["begin", "read-a", "ro-write", "get-after", "commit-empty", "rollback", "post-read-a"]
        assert names(transport, "y") == ["begin", "read-a", "ro-write", "commit-empty", "get-after", "rollback", "post-read-a"]


def test_every_chain_is_read_only_and_its_write_may_only_be_refused():
    steps = plan()["steps"]
    assert [step["mode"] for step in steps if step["rpc"] == "BeginTransaction"] == ["readOnly"] * 4
    for step in steps:
        if step["id"].endswith("/ro-write"):
            assert step["allow"] == [3, 5, 9, 10] and step["writes"] and step["tokenInput"]
        if step["id"].endswith(("/get-after", "/commit-empty", "/rollback")):
            assert step["allow"] == [0, 3, 5, 9, 10] and step["role"] == "observation" and not step["writes"]


def test_every_state_label_is_declared_and_used():
    assert set(TABLE["states"]) == {write["state"] for step in plan()["steps"] for write in step["writes"]}


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "da84a559d66c299ad09d64d9b2108705c0cdbb01c4677d08c95ae239ca0033d9"


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
