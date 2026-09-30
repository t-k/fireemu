"""P05's table: the shape it declares, and the recordings it produces against stand-in services."""

import pytest

import fs_txn_table_p05 as p05
import txn_program_cli as cli
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest
from test_txn_program_collector import Clock, Service

TABLE = p05.TABLE
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
    assert cli.TABLES["p05-readlock"] == "fs_txn_table_p05" and cli.table_for("p05-readlock") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p05.py" in cli.source_manifest("p05-readlock")


def test_the_requests_stay_inside_the_corpus_cap():
    value = plan()
    assert len(value["steps"]) == 31 and len(value["cases"]) == 14
    assert value["caps"] == {"observation": 31, "tokenCleanup": 4, "documentCleanup": 14, "management": 7, "credential": 2}
    assert value["maxRequests"] == 58 <= 72 and value["maxTokens"] == 4
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p05-readlock-001"


def test_each_transport_runs_both_chains():
    for transport in ["rest", "grpc"]:
        assert names(transport, "c") == ["begin", "read-a", "writer-a", "writer-b", "commit", "writer-after-commit", "post-read-a", "post-read-b"]
        assert names(transport, "r") == ["begin", "read-a", "writer-a", "rollback", "writer-after-rollback", "post-read-a"]
    assert [step["id"] for step in plan()["steps"][:3]] == ["setup/absence-a", "setup/absence-b", "setup/create-a-and-b"]


def test_the_writers_are_outside_the_transaction_and_only_the_commit_release_writes_are_required_to_be_visible():
    writers = [step for step in plan()["steps"] if step["role"] == "outside-writer"]
    assert len(writers) == 10 and all(step["tokenInput"] is None and step["deadlineMs"] == 30000 and step["allow"] == [0, 10] for step in writers)
    assert {step["id"].split("/")[-1] for step in writers} == {"writer-a", "writer-b", "writer-after-commit", "writer-after-rollback"}
    unrelated = [step for step in writers if step["id"].endswith("writer-b")]
    assert all([write["document"] for write in step["writes"]] == ["b"] for step in unrelated)
    conflicting = [step for step in writers if step["id"].endswith("writer-a")]
    assert all([write["document"] for write in step["writes"]] == ["a"] for step in conflicting)


def test_every_state_label_is_declared_and_used():
    assert len(set(TABLE["states"])) == len(TABLE["states"]) == 13
    assert {write["state"] for step in plan()["steps"] for write in step["writes"]} == set(TABLE["states"])


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "b5ff93dab2e14e0efb4a84ebeaac8b1afbb754b704b46ac4ca630fab6b8fc488"


@pytest.mark.parametrize("label,knobs", [
    ("no service refuses anything", {}),
    ("the read lock refuses the writer that touches a", {"locks": True}),
    ("every writer is contended", {"writer_code": 10}),
])
def test_a_full_recording_completes_and_projects(label, knobs):
    receipt, _service = record(**knobs)
    assert receipt["complete"] is True, (label, receipt["failureType"])
    assert receipt["phaseRequests"]["observation"] == 31
    projected = projection(receipt, TABLE)
    assert [case["caseId"] for case in projected["cases"]] == plan()["cases"]


def test_with_a_lock_model_only_the_writer_that_touches_the_locked_document_is_refused():
    receipt, _service = record(locks=True)
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    for transport in ["rest", "grpc"]:
        assert cases[f"{transport}/c-writer-a"] == 10 and cases[f"{transport}/c-writer-b"] == 0
        assert cases[f"{transport}/c-writer-after-commit"] == 0 and cases[f"{transport}/r-writer-a"] == 10 and cases[f"{transport}/r-writer-after-rollback"] == 0
        assert cases[f"{transport}/c-commit"] == 0 and cases[f"{transport}/r-rollback"] == 0
    reads = {read["site"]: read["state"] for read in projection(receipt, TABLE)["reads"]}
    assert reads["rest/c/post-read-b"] == "rest-c-unrelated" and reads["rest/c/post-read-a"] == "rest-c-after"


def test_a_writer_timeout_stops_and_is_never_resent():
    receipt, service = record(writer_code=4)
    assert receipt["complete"] is False and receipt["unknownCommits"] == ["rest/c/writer-a"]
    assert receipt["cleanup"] == {"absent": True}
    assert sum(1 for call in service.calls if call[1] == "Commit" and "transaction" not in call[2] and call[2]["writes"][0]["update"]["fields"]["state"]["stringValue"] == "rest-c-conflict") == 1


def test_two_recordings_of_one_service_project_identically():
    assert projection(record(locks=True)[0], TABLE) == projection(record(locks=True)[0], TABLE)
