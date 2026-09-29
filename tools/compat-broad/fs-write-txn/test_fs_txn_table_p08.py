"""P08's table: the shape it declares, and the recordings it produces against stand-in services."""

import copy
import importlib

import pytest

import fs_txn_table_p08 as p08
import txn_program_cli as cli
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest, source_digest
from test_txn_program_collector import Clock, Service

TABLE = p08.TABLE
NONCE, OWNER = "a" * 32, "b" * 32


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def steps(transport, chain):
    return [step for step in plan()["steps"] if step["id"].startswith(f"{transport}/{chain}/")]


def record(**knobs):
    clock = Clock()
    value = plan()
    receipt = Collector(value, TABLE, RequestBudget(value, TABLE), Service(clock, **knobs), "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()
    return receipt


def test_the_table_is_registered_under_its_own_name():
    assert cli.TABLES["p08-failed-commit"] == "fs_txn_table_p08"
    assert cli.table_for("p08-failed-commit") is TABLE


def test_the_manifest_binds_this_table_and_no_other_program_table():
    manifest = cli.source_manifest("p08-failed-commit")
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p08.py" in manifest
    assert "tools/compat-broad/fs-write-txn/txn_program_support_for_tests.py" in manifest, "the framework's own test table is bound with the framework"
    assert not [path for path in manifest if "fs_txn_table_" in path and not path.endswith("fs_txn_table_p08.py") and not path.endswith("test_fs_txn_table_p08.py")]


def test_the_requests_match_the_corpus_plus_the_one_absence_probe_for_m():
    value = plan()
    assert len(value["steps"]) == 45, "the corpus proposal counted 44 with no probe that m is absent"
    assert value["caps"] == {"observation": 45, "tokenCleanup": 6, "documentCleanup": 14, "management": 7, "credential": 2}
    assert value["maxRequests"] == 74 <= 80
    assert value["maxTokens"] == 6 and value["observationSeconds"] == 180 and value["recoverySeconds"] == 180
    assert len(value["cases"]) == 26
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p08-failed-commit-001"


def test_setup_and_both_transports_run_the_same_three_chains():
    value = plan()
    assert [step["id"] for step in value["steps"][:3]] == ["setup/absence-a", "setup/absence-m", "setup/create-a"]
    assert {step["transport"] for step in value["steps"][:3]} == {"grpc"}
    for transport in ["rest", "grpc"]:
        names = lambda chain: [step["id"].split("/", 2)[2] for step in steps(transport, chain)]
        assert names("a") == ["begin", "read-a", "fail-commit", "plain-read-a", "same-token-read-a", "writer", "corrected-commit", "rollback", "rollback-again", "post-read-a"]
        assert names("b") == ["begin", "read-a", "fail-commit", "rollback", "writer", "rollback-again", "post-read-a"]
        assert names("c") == ["begin", "read-a", "commit", "rollback-after-commit"]
        assert {step["transport"] for chain in "abc" for step in steps(transport, chain)} == {transport}
    order = [step["id"].split("/")[0] for step in value["steps"][3:]]
    assert order == ["rest"] * 21 + ["grpc"] * 21


def test_the_failed_commit_writes_a_and_the_absent_m_and_may_only_be_refused():
    for step in [s for s in plan()["steps"] if s["id"].endswith("/fail-commit")]:
        assert [(write["document"], write["exists"]) for write in step["writes"]] == [("a", True), ("m", True)]
        assert step["allow"] == [3, 5, 9, 10] and step["role"] == "observation" and step["tokenInput"]


def test_only_the_control_commit_and_the_setup_may_succeed_and_only_reads_may_be_plain():
    for step in plan()["steps"]:
        if step["rpc"] == "Commit" and step["role"] != "outside-writer" and not step["id"].endswith("/corrected-commit"):
            assert step["allow"] in ([0], [3, 5, 9, 10]), step["id"]
    for step in plan()["steps"]:
        if step["id"].endswith("/plain-read-a") or step["role"] == "post-state":
            assert step["allow"] == [0] and step["tokenInput"] is None


def test_outside_writers_carry_no_token_and_wait_at_most_thirty_seconds():
    writers = [step for step in plan()["steps"] if step["role"] == "outside-writer"]
    assert [step["id"] for step in writers] == ["rest/a/writer", "rest/b/writer", "grpc/a/writer", "grpc/b/writer"]
    for step in writers:
        assert step["tokenInput"] is None and step["deadlineMs"] == 30000 and step["allow"] == [0, 10]
        assert [(write["document"], write["exists"]) for write in step["writes"]] == [("a", True)]


def test_the_rollback_after_a_successful_commit_is_the_aborted_control():
    for transport in ["rest", "grpc"]:
        control = steps(transport, "c")[-1]
        assert control["rpc"] == "Rollback" and control["allow"] == [0, 10]


def test_every_state_label_is_declared_and_unique():
    assert len(set(TABLE["states"])) == len(TABLE["states"]) == 10
    used = {write["state"] for step in plan()["steps"] for write in step["writes"]}
    assert used == set(TABLE["states"])


def test_the_digests_bind_the_table_and_do_not_move_by_accident():
    assert corpus_digest(TABLE) == plan()["corpusDigest"] and source_digest(TABLE) == plan()["sourceDigest"]
    assert corpus_digest(TABLE) == "1dc1d44eca4b99a23d8f3b480eb9b8d71aec4ef0894509b149fa12354c9d92bc"


# --- Recordings against stand-in services. The services differ in what a refused commit leaves alive. ---

@pytest.mark.parametrize("label,knobs", [
    ("the token dies with the refused commit", {"dead_on_failure": True}),
    ("the token survives the refused commit", {}),
    ("the token survives and the writer is contended", {"writer_code": 10}),
    ("the dead token also refuses its rollback with code 5", {"dead_on_failure": True, "dead_rollback_code": 5}),
    ("the failed commit is answered FAILED_PRECONDITION and the dead token's rollback is accepted", {"dead_on_failure": True, "fail_code": 5, "dead_rollback_code": 0}),
])
def test_a_full_recording_completes_and_projects_for_every_allowed_behaviour(label, knobs):
    receipt = record(**knobs)
    assert receipt["complete"] is True, (label, receipt["failureType"])
    assert receipt["phaseRequests"]["observation"] == 45
    assert receipt["phaseRequests"]["documentCleanup"] == 3
    projected = projection(receipt, TABLE)
    assert [case["caseId"] for case in projected["cases"]] == plan()["cases"]
    assert set(projected["tokens"]) == {f"{t}-{c}" for t in ["rest", "grpc"] for c in "abc"}
    assert all(entry["state"] in ("committed", "rolled-back", "released-refused") for entry in projected["tokens"].values())


def test_two_recordings_of_the_same_service_project_identically():
    assert projection(record(dead_on_failure=True), TABLE) == projection(record(dead_on_failure=True), TABLE)


def test_the_refused_commit_publishes_nothing_and_the_final_state_follows_the_last_acknowledged_write():
    projected = projection(record(dead_on_failure=True), TABLE)
    reads = {read["site"]: read["state"] for read in projected["reads"]}
    assert reads["rest/a/plain-read-a"] == "created", "the refused commit staged nothing publicly"
    assert reads["grpc/a/plain-read-a"] == "rest-c-commit", "and the last acknowledged write is what a plain read sees"
    assert reads["rest/a/post-read-a"] == "rest-a-writer" and reads["rest/b/post-read-a"] == "rest-b-writer"
    assert projected["expectedStates"] == {"a": "grpc-c-commit"}
    contended = projection(record(writer_code=10), TABLE)
    assert contended["expectedStates"] == {"a": "grpc-c-commit"}


def test_a_refused_commit_that_is_accepted_stops_and_cleans_up_both_documents():
    receipt = record(fail_code=0)
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    assert receipt["cleanup"] == {"absent": True} and receipt["phaseRequests"]["documentCleanup"] == 6


def test_an_outside_writer_timeout_stops_the_recording_and_is_never_resent():
    for applies in [True, False]:
        clock = Clock()
        value = plan()
        service = Service(clock, writer_code=4, writer_applies=applies)
        receipt = Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()
        assert receipt["complete"] is False and receipt["unknownCommits"] == ["rest/a/writer"]
        writes = [call for call in service.calls if call[1] == "Commit" and "transaction" not in call[2] and call[2]["writes"][0]["currentDocument"]["exists"]]
        assert len(writes) == 1
        assert receipt["cleanup"] == {"absent": True}, "the owned document is deleted whether or not the write landed"


def test_the_absence_of_m_is_proved_before_the_first_write():
    service = Service(Clock())
    value = plan()
    clock = service.clock
    Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()
    first_write = next(index for index, call in enumerate(service.calls) if call[1] == "Commit")
    probed = [call[2]["name"].rsplit("/", 1)[1] for call in service.calls[:first_write] if call[1] == "GetDocument"]
    assert probed == ["a", "m"]
