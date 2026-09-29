"""P06's table: the shape it declares, and the recordings it produces against stand-in services."""

import pytest

import fs_txn_table_p06 as p06
import txn_program_cli as cli
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest
from test_txn_program_collector import Clock, Service

TABLE = p06.TABLE
NONCE, OWNER = "a" * 32, "b" * 32


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def record(**knobs):
    clock = Clock()
    value = plan()
    service = Service(clock, **knobs)
    return Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run(), service


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p06-multiwrite"] == "fs_txn_table_p06" and cli.table_for("p06-multiwrite") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p06.py" in cli.source_manifest("p06-multiwrite")


def test_the_requests_stay_inside_the_corpus_cap():
    value = plan()
    assert len(value["steps"]) == 25 and len(value["cases"]) == 12
    assert value["caps"] == {"observation": 25, "tokenCleanup": 2, "documentCleanup": 28, "management": 7, "credential": 2}
    assert value["maxRequests"] == 64 <= 80
    assert value["maxTokens"] == 2 and value["observationSeconds"] == 360 and value["recoverySeconds"] == 180
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p06-multiwrite-001"


def test_each_transport_runs_the_same_chain_over_its_own_new_document():
    ids = [step["id"] for step in plan()["steps"]]
    assert ids[:5] == ["setup/absence-a", "setup/absence-b", "setup/absence-c", "setup/absence-d", "setup/create-a-and-b"]
    for transport, spare in [("rest", "c"), ("grpc", "d")]:
        chain = [step for step in plan()["steps"] if step["id"].startswith(f"{transport}/")]
        assert [step["id"].split("/", 1)[1] for step in chain] == ["begin", "read-a", "multiwrite-with-holder", "plain-a-after-refusal", "plain-b-after-refusal", "multiwrite-without-holder-doc", "rollback", "multiwrite-after-rollback", "post-read-a", "post-read-b"]
        new = next(step for step in chain if step["id"].endswith("multiwrite-without-holder-doc"))
        assert [(write["document"], write["exists"]) for write in new["writes"]] == [("b", True), (spare, False)]
        assert not any(write["document"] == spare for step in chain for write in step["writes"] if step is not new)


def test_the_writers_are_outside_the_transaction_and_may_be_contended():
    writers = [step for step in plan()["steps"] if step["role"] == "outside-writer"]
    assert len(writers) == 6
    for step in writers:
        assert step["tokenInput"] is None and step["deadlineMs"] == 30000 and step["allow"] == [0, 10] and len(step["writes"]) == 2
    held = [step for step in writers if step["id"].endswith("multiwrite-with-holder")]
    assert all([write["document"] for write in step["writes"]] == ["a", "b"] for step in held)


def test_the_plain_reads_after_the_refusal_are_required_to_succeed():
    for step in plan()["steps"]:
        if "after-refusal" in step["id"]:
            assert step["allow"] == [0] and step["tokenInput"] is None and step["role"] == "observation"


def test_every_state_label_is_declared_and_used():
    assert len(set(TABLE["states"])) == len(TABLE["states"]) == 7
    assert {write["state"] for step in plan()["steps"] for write in step["writes"]} == set(TABLE["states"])


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "8850f80eb152b73e51b9e1241ffad2fa9f0807a16a0a7b489549fd2d489efb66"


@pytest.mark.parametrize("label,knobs", [
    ("no service refuses", {}),
    ("the holder's read lock refuses the multi-write", {"locks": True}),
    ("every writer is contended", {"writer_code": 10}),
])
def test_a_full_recording_completes_and_projects(label, knobs):
    receipt, _service = record(**knobs)
    assert receipt["complete"] is True, (label, receipt["failureType"])
    assert receipt["phaseRequests"]["observation"] == 25
    projected = projection(receipt, TABLE)
    assert [case["caseId"] for case in projected["cases"]] == plan()["cases"]
    assert {entry["state"] for entry in projected["tokens"].values()} == {"rolled-back"}


def test_with_a_lock_model_the_holder_refuses_only_the_multiwrite_that_touches_a():
    receipt, service = record(locks=True)
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    for transport in ["rest", "grpc"]:
        assert cases[f"{transport}/multiwrite-with-holder"] == 10 and cases[f"{transport}/multiwrite-without-holder-doc"] == 0 and cases[f"{transport}/multiwrite-after-rollback"] == 0
    reads = {read["site"]: read["state"] for read in projection(receipt, TABLE)["reads"]}
    assert reads["rest/plain-a-after-refusal"] == "created" and reads["rest/plain-b-after-refusal"] == "created", "nothing of the refused multi-write is visible"
    assert reads["rest/post-read-a"] == "rest-ab-after" and reads["rest/post-read-b"] == "rest-ab-after"
    assert reads["grpc/plain-b-after-refusal"] == "rest-ab-after"


def test_a_partly_published_refusal_stops_the_recording_and_the_documents_are_still_deleted():
    receipt, service = record(locks=True, partial_publish=True)
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    assert receipt["cleanup"] == {"absent": True} and service.documents == {}, "recovery deletes what the refused commit partly wrote"


def test_two_recordings_of_one_service_project_identically():
    assert projection(record(locks=True)[0], TABLE) == projection(record(locks=True)[0], TABLE)


def test_a_writer_timeout_stops_and_is_never_resent():
    receipt, service = record(writer_code=4)
    assert receipt["complete"] is False and receipt["unknownCommits"] == ["rest/multiwrite-with-holder"]
    two_writes = [call for call in service.calls if call[1] == "Commit" and "transaction" not in call[2] and len(call[2]["writes"]) == 2 and call[2]["writes"][0]["currentDocument"]["exists"] and call[2]["writes"][1]["currentDocument"]["exists"]]
    assert len(two_writes) == 1 and receipt["failureType"] == "ValueError"
    assert receipt["cleanup"] == {"absent": True}
