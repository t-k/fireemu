"""P05's table: the shape it declares, and the recordings it produces against stand-in services that hold an outside writer while a
holder's read lock lasts."""

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


def collector(service, clock):
    value = plan()
    return Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)


def record(**knobs):
    clock = Clock()
    service = Service(clock, **knobs)
    return collector(service, clock).run(), service, clock


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p05-readlock"] == "fs_txn_table_p05" and cli.table_for("p05-readlock") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p05.py" in cli.source_manifest("p05-readlock")


def test_the_requests_and_the_clock_stay_inside_the_corpus_cap():
    value = plan()
    assert len(value["steps"]) == 33 and len(value["cases"]) == 14
    assert value["caps"] == {"observation": 33, "tokenCleanup": 4, "documentCleanup": 14, "management": 7, "credential": 2}
    assert value["maxRequests"] == 60 <= 72 and value["maxTokens"] == 4
    assert sum(value["waits"].values()) == 4 * p05.HOLD_SECONDS == 20
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p05-readlock-001"
    # ten outside writers at their full 30 s, 33 requests at up to 2 s, the four holds, and room for the last request
    assert 10 * 30 + 33 * 2 + 20 + 13 <= TABLE["observationSeconds"] == 420


def test_each_transport_runs_both_chains_with_the_writer_beside_its_holder_release():
    for transport in ["rest", "grpc"]:
        assert names(transport, "c") == ["begin", "read-a", "writer-b", "commit", "writer-a", "read-after-pair", "writer-after-commit", "post-read-a", "post-read-b"]
        assert names(transport, "r") == ["begin", "read-a", "rollback", "writer-a", "writer-after-rollback", "post-read-a"]
    assert [step["id"] for step in plan()["steps"][:3]] == ["setup/absence-a", "setup/absence-b", "setup/create-a-and-b"]


def test_the_concurrent_writers_follow_their_anchor_and_the_anchor_waits_inside_the_writers_deadline():
    steps = {step["id"]: step for step in plan()["steps"]}
    concurrent = [step for step in plan()["steps"] if "concurrentWith" in step]
    assert len(concurrent) == 4 and {step["id"].split("/", 1)[1] for step in concurrent} == {"c/writer-a", "r/writer-a"}
    for step in concurrent:
        anchor = steps[step["concurrentWith"]]
        assert anchor["tokenInput"] and anchor["waitSeconds"] == 5 and anchor["rpc"] in ("Commit", "Rollback")
        assert anchor["waitSeconds"] <= step["deadlineMs"] / 1000 - 10
        assert step["tokenInput"] is None and step["role"] == "outside-writer" and step["allow"] == [0, 10]
        assert [write["document"] for write in step["writes"]] == ["a"]


def test_the_writers_are_outside_the_transaction_and_only_the_holder_steps_may_be_refused_beyond_ten():
    writers = [step for step in plan()["steps"] if step["role"] == "outside-writer"]
    assert len(writers) == 10 and all(step["tokenInput"] is None and step["deadlineMs"] == 30000 and step["allow"] == [0, 10] for step in writers)
    assert {step["id"].split("/")[-1] for step in writers} == {"writer-a", "writer-b", "writer-after-commit", "writer-after-rollback"}
    assert all([write["document"] for write in step["writes"]] == ["b"] for step in writers if step["id"].endswith("writer-b"))


def test_every_state_label_is_declared_and_used():
    assert len(set(TABLE["states"])) == len(TABLE["states"]) == 13
    assert {write["state"] for step in plan()["steps"] for write in step["writes"]} == set(TABLE["states"])


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "97e0a0dbe4089029fdecc9483b67102bd5f445bed4112a96d171657176a76f3d"


@pytest.mark.parametrize("label,knobs", [
    ("no service refuses anything", {}),
    ("the read lock holds the writer until the holder lets go", {"locks": True, "hold_writers": True}),
    ("the read lock refuses the writer at once", {"locks": True, "hold_writers": True, "contention_refusal": True}),
])
def test_a_full_recording_completes_and_projects(label, knobs):
    receipt, _service, _clock = record(**knobs)
    assert receipt["complete"] is True, (label, receipt["failureType"], receipt["unknownCommits"])
    assert receipt["phaseRequests"]["observation"] == 33
    projected = projection(receipt, TABLE)
    assert [case["caseId"] for case in projected["cases"]] == plan()["cases"]


def test_a_writer_held_until_the_release_commits_after_the_holder_and_both_answers_are_recorded():
    receipt, _service, _clock = record(locks=True, hold_writers=True)
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    for transport in ["rest", "grpc"]:
        assert cases[f"{transport}/c-writer-a"] == 0 and cases[f"{transport}/c-commit"] == 0
        assert cases[f"{transport}/r-writer-a"] == 0 and cases[f"{transport}/r-rollback"] == 0
        assert cases[f"{transport}/c-writer-b"] == 0 and cases[f"{transport}/c-writer-after-commit"] == 0
    rows = [row["site"] for row in receipt["steps"]]
    assert rows.index("rest/c/commit") + 1 == rows.index("rest/c/writer-a") and rows.index("rest/r/rollback") + 1 == rows.index("rest/r/writer-a")
    by_site = {row["site"]: row for row in receipt["steps"]}
    assert by_site["rest/c/writer-a"]["timing"]["dispatchMonotonic"] < by_site["rest/c/commit"]["timing"]["dispatchMonotonic"], "the writer was sent first"
    reads = {read["site"]: read["state"] for read in projection(receipt, TABLE)["reads"]}
    assert reads["rest/c/post-read-a"] == "rest-c-after" and reads["rest/c/post-read-b"] == "rest-c-unrelated"


def test_a_contended_writer_refused_at_once_is_recorded_beside_the_holders_answers():
    receipt, _service, _clock = record(locks=True, hold_writers=True, contention_refusal=True)
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    for transport in ["rest", "grpc"]:
        assert cases[f"{transport}/c-writer-a"] == 10 and cases[f"{transport}/r-writer-a"] == 10
        assert cases[f"{transport}/c-commit"] == 0 and cases[f"{transport}/r-rollback"] == 0


def test_a_writer_that_is_never_released_stops_the_recording_without_a_resend_and_cleanup_waits_for_it():
    receipt, service, clock = record(locks=True, hold_writers=True, never_release=True, hold_timeout=0.2)
    assert receipt["complete"] is False and receipt["unknownCommits"] == ["rest/c/writer-a"]
    assert receipt["cleanup"] == {"absent": True} and service.documents == {}
    writers = [call for call in service.calls if call[1] == "Commit" and "transaction" not in call[2] and call[2]["writes"][0]["update"]["fields"]["state"]["stringValue"] == "rest-c-conflict"]
    assert len(writers) == 1, "an unknown outcome is never resent"
    assert receipt["tokens"]["rest-c"]["state"] == "committed", "the holder's release had been sent beside the writer"
    last = receipt["steps"][-1]
    assert (last["site"], last["result"]["code"]) == ("rest/c/writer-a", 4), "the writer's timeout is recorded as its row, after the holder's"


def test_a_writer_that_lands_late_is_seen_by_the_cleanup_read_after_the_settle_wait():
    receipt, service, clock = record(writer_code=4, writer_applies=True)
    assert receipt["complete"] is False and receipt["unknownCommits"]
    assert receipt["cleanup"] == {"absent": True} and service.documents == {}
    assert clock.now() - 100.0 >= 5, "the settle wait passed on the recovery clock"


def test_two_recordings_of_one_service_project_identically():
    assert projection(record(locks=True, hold_writers=True)[0], TABLE) == projection(record(locks=True, hold_writers=True)[0], TABLE)


def test_the_read_right_after_a_pair_records_which_write_landed_last():
    # held writer: it commits after the holder's release, so it is the last write to `a`; a refused writer leaves the holder's commit
    for knobs, state in (({"locks": True, "hold_writers": True}, "rest-c-conflict"), ({"locks": True, "hold_writers": True, "contention_refusal": True}, "rest-c-commit")):
        receipt, _service, _clock = record(**knobs)
        assert receipt["complete"] is True
        reads = {entry["site"]: entry for entry in projection(receipt, TABLE)["reads"]}
        assert reads["rest/c/read-after-pair"] == {"site": "rest/c/read-after-pair", "code": 0, "state": state}
        assert reads["grpc/c/read-after-pair"]["state"] == state.replace("rest", "grpc")
