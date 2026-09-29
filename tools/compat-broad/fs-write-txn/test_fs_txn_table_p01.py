"""P01's table: the shape it declares, and the recordings it produces against stand-in services."""

import pytest

import fs_txn_table_p01 as p01
import txn_program_cli as cli
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest
from test_txn_program_collector import Clock, Service

TABLE = p01.TABLE
NONCE, OWNER = "a" * 32, "b" * 32


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def steps(transport, chain):
    return [step["id"].split("/", 2)[2] for step in plan()["steps"] if step["id"].startswith(f"{transport}/{chain}/")]


def record(**knobs):
    clock = Clock()
    value = plan()
    return Collector(value, TABLE, RequestBudget(value, TABLE), Service(clock, **knobs), "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p01-lifecycle"] == "fs_txn_table_p01" and cli.table_for("p01-lifecycle") is TABLE
    manifest = cli.source_manifest("p01-lifecycle")
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p01.py" in manifest
    assert not [path for path in manifest if "fs_txn_table_p08" in path and not path.endswith("test_fs_txn_table_p08.py")]


def test_the_requests_stay_inside_the_corpus_cap():
    value = plan()
    assert len(value["steps"]) == 39 and len(value["cases"]) == 21
    assert value["caps"] == {"observation": 39, "tokenCleanup": 6, "documentCleanup": 14, "management": 7, "credential": 2}
    assert value["maxRequests"] == 68 <= 72
    assert value["maxTokens"] == 6 and value["observationSeconds"] == 180 and value["recoverySeconds"] == 180
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p01-lifecycle-001"
    assert not [step for step in value["steps"] if step["role"] == "outside-writer"], "P01 has no outside writer"


def test_rest_runs_every_chain_and_grpc_a_representative_subset():
    assert steps("rest", "l") == ["begin", "read-a", "batch", "commit", "commit-again", "get-after-commit", "batch-after-commit", "rollback-after-commit", "post-read-a"]
    assert steps("rest", "e") == ["begin", "read-a", "empty-commit", "commit-after-empty", "get-after-empty", "post-read-a"]
    assert steps("rest", "r") == ["begin", "read-a", "rollback", "commit-after-rollback", "get-after-rollback", "batch-after-rollback", "post-read-a"]
    assert steps("grpc", "l") == ["begin", "batch", "commit", "commit-again", "get-after-commit", "post-read-a"]
    assert steps("grpc", "e") == ["begin", "empty-commit", "commit-after-empty", "post-read-a"]
    assert steps("grpc", "r") == ["begin", "rollback", "commit-after-rollback", "post-read-a"]
    ids = [step["id"] for step in plan()["steps"]]
    assert ids[:3] == ["setup/absence-a", "setup/absence-m", "setup/create-a"] and [i.split("/")[0] for i in ids[3:]] == ["rest"] * 22 + ["grpc"] * 14


def test_a_commit_on_an_ended_token_may_only_be_refused_and_the_writing_ends_are_required_to_succeed():
    for step in plan()["steps"]:
        name = step["id"].split("/")[-1]
        if name in ("commit-again", "commit-after-empty", "commit-after-rollback"):
            assert step["allow"] == [3, 5, 9, 10] and step["writes"] and step["tokenInput"], step["id"]
        if name in ("commit", "empty-commit", "rollback") and step["id"].split("/")[0] != "setup":
            assert step["allow"] == [0], step["id"]
    empties = [step for step in plan()["steps"] if step["id"].endswith("/empty-commit")]
    assert len(empties) == 2 and all(step["writes"] == [] and step["tokenInput"] for step in empties)


def test_the_batch_reads_name_the_owned_documents():
    batches = {step["id"]: step["documents"] for step in plan()["steps"] if step["rpc"] == "BatchGetDocuments"}
    assert batches["rest/l/batch"] == ["a", "m"] and batches["grpc/l/batch"] == ["a", "m"] and batches["rest/l/batch-after-commit"] == ["a"] and batches["rest/r/batch-after-rollback"] == ["a", "m"]
    assert len(batches) == 4


def test_every_state_label_is_declared_and_used():
    assert len(set(TABLE["states"])) == len(TABLE["states"]) == 9
    assert {write["state"] for step in plan()["steps"] for write in step["writes"]} == set(TABLE["states"])


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "fd2f32cffc300d46b697dcc359ec76d9e1759e522b17f3fefa3d8506dfab7889"


@pytest.mark.parametrize("label,knobs", [
    ("the ended token's reads are refused", {"finished_reads_refused": True}),
    ("the ended token's plain get still answers", {}),
])
def test_a_full_recording_completes_and_projects(label, knobs):
    receipt = record(**knobs)
    assert receipt["complete"] is True, (label, receipt["failureType"])
    assert receipt["phaseRequests"] == {"observation": 39, "tokenCleanup": 0, "documentCleanup": 3, "management": 0, "credential": 0}
    projected = projection(receipt, TABLE)
    assert [case["caseId"] for case in projected["cases"]] == plan()["cases"]
    assert {entry["state"] for entry in projected["tokens"].values()} == {"committed", "rolled-back"}
    assert projected["expectedStates"] == {"a": "grpc-l-commit"}
    batches = {read["site"]: read["documents"] for read in projected["reads"] if "documents" in read}
    assert batches["rest/l/batch"] == {"a": "created", "m": None}
    assert batches["grpc/l/batch"] == {"a": "rest-l-commit", "m": None}


def test_two_recordings_of_one_service_project_identically():
    assert projection(record(), TABLE) == projection(record(), TABLE)


def test_the_refused_commits_publish_nothing():
    receipt = record()
    projected = projection(receipt, TABLE)
    reads = {read["site"]: read["state"] for read in projected["reads"] if "state" in read}
    assert reads["rest/l/post-read-a"] == "rest-l-commit" and reads["rest/e/post-read-a"] == "rest-l-commit" and reads["rest/r/post-read-a"] == "rest-l-commit"
    assert reads["grpc/l/post-read-a"] == "grpc-l-commit" and reads["grpc/e/post-read-a"] == "grpc-l-commit" and reads["grpc/r/post-read-a"] == "grpc-l-commit"


@pytest.mark.parametrize("site,stop", [("rest/l/commit-again", "accepted"), ("rest/e/commit-after-empty", "accepted"), ("grpc/r/commit-after-rollback", "accepted")])
def test_a_commit_on_an_ended_token_that_production_accepts_stops_and_is_cleaned_up(site, stop):
    clock = Clock()
    value = plan()
    service = Service(clock)
    original = service.send
    def send(transport, method, request, **kwargs):
        name = request.get("writes", [{}])[0].get("update", {}).get("fields", {}).get("state", {}).get("stringValue") if method == "Commit" and request.get("writes") else None
        if method == "Commit" and request.get("transaction") and name == site_state[site]:
            # An ended token accepts the write, as if production allowed it.
            service.tokens[request["transaction"]] = "open"
        return original(transport, method, request, **kwargs)
    site_state = {"rest/l/commit-again": "rest-l-again", "rest/e/commit-after-empty": "rest-e-after", "grpc/r/commit-after-rollback": "grpc-r-after"}
    service.send = send
    receipt = Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    assert receipt["cleanup"] == {"absent": True} and service.documents == {}, "the owned document is deleted whatever the answer was"
