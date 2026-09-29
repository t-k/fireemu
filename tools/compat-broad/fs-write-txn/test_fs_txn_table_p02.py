"""P02's table: the shape it declares, and the recordings it produces against stand-in services."""

import pytest

import fs_txn_table_p02 as p02
import txn_program_cli as cli
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest
from test_txn_program_collector import Clock, Service

TABLE = p02.TABLE
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


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p02-readonly"] == "fs_txn_table_p02" and cli.table_for("p02-readonly") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p02.py" in cli.source_manifest("p02-readonly")


def test_the_requests_stay_inside_the_corpus_cap():
    value = plan()
    assert len(value["steps"]) == 35 and len(value["cases"]) == 16
    assert value["caps"] == {"observation": 35, "tokenCleanup": 6, "documentCleanup": 14, "management": 7, "credential": 2}
    assert value["maxRequests"] == 64 <= 64
    assert value["maxTokens"] == 6 and value["observationSeconds"] == 300 and value["recoverySeconds"] == 180
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p02-readonly-001"


def test_rest_runs_every_chain_and_grpc_a_representative_subset():
    assert names("rest", "s1") == ["begin", "writer", "ro-read", "ro-batch", "ro-write", "rollback", "post-read-a"]
    assert names("rest", "s2") == ["begin", "read-a", "writer", "ro-read-again", "ro-empty", "post-read-a"]
    assert names("rest", "w") == ["begin", "read-a", "commit", "post-read-a"]
    assert names("grpc", "s1") == ["begin", "writer", "ro-read", "ro-write", "post-read-a"]
    assert names("grpc", "s2") == names("rest", "s2") and names("grpc", "w") == names("rest", "w")


def test_only_the_snapshot_chains_are_read_only_and_their_writes_may_only_be_refused():
    for step in plan()["steps"]:
        if step["rpc"] == "BeginTransaction":
            assert step.get("mode") == ("readOnly" if "/s" in step["id"] else None), step["id"]
        if step["id"].endswith("/ro-write"):
            assert step["allow"] == [3, 5, 9, 10] and step["writes"] and step["tokenInput"]
    control = [step for step in plan()["steps"] if step["id"].endswith("/w/commit")]
    assert len(control) == 2 and all(step["allow"] == [0] for step in control)
    reads = [step for step in plan()["steps"] if step["id"].endswith(("ro-read", "ro-batch", "ro-read-again"))]
    assert reads and all(step["allow"] == [0] for step in reads)


def test_every_state_label_is_declared_and_used():
    assert len(set(TABLE["states"])) == len(TABLE["states"]) == 8
    assert {write["state"] for step in plan()["steps"] for write in step["writes"]} == set(TABLE["states"])


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "1b38109181ba6120eca4e273587b4ed24dfa097c442abb2fc288ebe01f84ccc0"


@pytest.mark.parametrize("label,knobs,first,second", [
    ("the snapshot is taken at begin", {"ro_snapshot": "begin"}, "created", "created"),
    ("the snapshot is taken at the first read", {"ro_snapshot": "first-read"}, "rest-s1-w", "rest-s2-w"),
    ("a read-only transaction reads the latest", {"ro_snapshot": "latest"}, "rest-s1-w", "rest-s2-w"),
])
def test_a_full_recording_completes_whichever_snapshot_the_service_takes(label, knobs, first, second):
    receipt, _service = record(**knobs)
    assert receipt["complete"] is True, (label, receipt["failureType"])
    projected = projection(receipt, TABLE)
    reads = {read["site"]: read for read in projected["reads"]}
    assert reads["rest/s1/ro-read"]["state"] == first
    assert reads["rest/s1/ro-batch"]["documents"]["a"] == first
    assert [case["caseId"] for case in projected["cases"]] == plan()["cases"]


def test_the_second_read_shows_the_state_of_the_first_when_the_snapshot_is_pinned_by_it():
    receipt, _service = record(ro_snapshot="first-read")
    reads = {read["site"]: read["state"] for read in projection(receipt, TABLE)["reads"] if "state" in read}
    assert reads["rest/s2/ro-read-again"] == "rest-s1-w", "the first read pinned the state before the second writer"
    receipt, _service = record(ro_snapshot="latest")
    reads = {read["site"]: read["state"] for read in projection(receipt, TABLE)["reads"] if "state" in read}
    assert reads["rest/s2/ro-read-again"] == "rest-s2-w"


def test_a_refused_empty_commit_on_a_read_only_token_is_recorded_not_fatal():
    receipt, _service = record(ro_empty_refused=True)
    assert receipt["complete"] is True, receipt["failureType"]
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    assert cases["rest/s2-ro-empty"] == 3 and cases["grpc/s2-ro-empty"] == 3


def test_a_read_only_write_that_production_accepts_stops_and_is_cleaned_up():
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
    assert projection(record(ro_snapshot="begin")[0], TABLE) == projection(record(ro_snapshot="begin")[0], TABLE)


def test_a_writer_timeout_stops_and_is_never_resent():
    receipt, service = record(writer_code=4)
    assert receipt["complete"] is False and receipt["unknownCommits"] == ["rest/s1/writer"]
    assert receipt["cleanup"] == {"absent": True}


def test_a_read_only_transaction_that_shows_a_state_from_before_it_began_stops():
    receipt, service = record(ro_snapshot="ancient")
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    assert receipt["cleanup"] == {"absent": True} and service.documents == {}
    assert [row["site"] for row in receipt["steps"]][-1] == "rest/s2/read-a", "the first read older than its begin is where the recording stops"
