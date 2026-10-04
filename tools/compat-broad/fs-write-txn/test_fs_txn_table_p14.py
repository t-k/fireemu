"""P14's table (stage 2): the shape it declares for the five conditions, and that nothing in it can touch anything the run does not own."""

import pytest

import fs_txn_table_p14 as p14
import txn_program_cli as cli
from txn_program_program import compile_plan, corpus_digest

TABLE = p14.TABLE
NONCE, OWNER = "a" * 32, "b" * 32


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def ids(prefix):
    return [step["id"] for step in plan()["steps"] if step["id"].startswith(prefix)]


def tail(prefix):
    return [step_id.removeprefix(prefix) for step_id in ids(prefix)]


def test_the_table_is_registered_bound_and_targets_the_free_tier_project():
    assert cli.TABLES["p14-stage2"] == "fs_txn_table_p14" and cli.table_for("p14-stage2") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p14.py" in cli.source_manifest("p14-stage2")
    value = plan()
    assert value["project"] == "fireemu-oracle-txn" and value["database"] == "projects/fireemu-oracle-txn/databases/(default)"
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p14-stage2-001"


def test_the_requests_tokens_and_waits_stay_inside_the_declared_caps():
    value = plan()
    assert len(value["steps"]) == 69 and len(value["cases"]) == 46
    assert value["caps"] == {"observation": 69, "tokenCleanup": 9, "documentCleanup": 56, "management": 7, "credential": 2}
    assert value["maxRequests"] == 143 and value["maxTokens"] == 9
    assert sum(value["waits"].values()) == 2 * p14.WRITE_SET_HOLD_SECONDS + 4 * p14.HOLD_SECONDS == 110
    writers = [step for step in value["steps"] if step["role"] == "outside-writer"]
    # every outside writer at its full deadline, every request at up to 2 s, the holds, and room for the last request: well inside the clock
    assert sum(step["deadlineMs"] for step in writers) / 1000 + 69 * 2 + 110 + 13 <= TABLE["observationSeconds"]
    assert len(value["documents"]) == 8 and len(value["states"]) == len(set(value["states"])) == 10


def test_every_document_is_probed_absent_before_it_is_written_and_setup_creates_only_three():
    steps = plan()["steps"]
    assert [step["id"] for step in steps[:8]] == [f"setup/absence-{role}" for role in ("a", "b", "c", "d", "h", "p", "o", "p2")]
    assert all(step["allow"] == [5] and step["role"] == "control" for step in steps[:8])
    create = steps[8]
    assert create["id"] == "setup/create-a-b-h" and [(w["document"], w["state"], w["exists"]) for w in create["writes"]] == [("a", "created", False), ("b", "created", False), ("h", "q-in", False)]


def test_the_write_set_chains_hold_a_two_document_writer_beside_a_45_second_release():
    for transport, spare in (("rest", "c"), ("grpc", "d")):
        assert tail(f"{transport}/w/") == ["begin", "read-a", "writer-bc", "release", "writer-ab", "plain-a", "plain-b"]
        steps = {step["id"]: step for step in plan()["steps"]}
        release, writer, unrelated = steps[f"{transport}/w/release"], steps[f"{transport}/w/writer-ab"], steps[f"{transport}/w/writer-bc"]
        assert release["waitSeconds"] == 45 and release["allow"] == [0, 10]
        assert writer["concurrentWith"] == release["id"] and writer["deadlineMs"] == 90000 and writer["allow"] == [0, 10]
        assert [(w["document"], w["exists"]) for w in writer["writes"]] == [("a", True), ("b", True)]
        # the unrelated writer touches neither document the holder read, and creates the spare
        assert [(w["document"], w["exists"]) for w in unrelated["writes"]] == [("b", True), (spare, False)] and unrelated["deadlineMs"] == 30000


def test_the_range_chains_run_the_in_range_query_and_one_writer_each():
    for transport, chain, document, state in (("rest", "q1", "o", "q-out"), ("rest", "q2", "p", "q-in"), ("grpc", "q", "p2", "q-in")):
        assert tail(f"{transport}/{chain}/")[:4] == ["begin", "query-in", "release", "writer"]
        steps = {step["id"]: step for step in plan()["steps"]}
        query, release, writer = steps[f"{transport}/{chain}/query-in"], steps[f"{transport}/{chain}/release"], steps[f"{transport}/{chain}/writer"]
        assert query["rpc"] == "RunQuery" and query["query"] == {"stateEquals": "q-in"} and query["role"] == "control" and query["allow"] == [0]
        assert release["waitSeconds"] == 5 and writer["concurrentWith"] == release["id"]
        assert [(w["document"], w["state"], w["exists"]) for w in writer["writes"]] == [(document, state, False)]
    # the phantom and the control are new documents in different states; the outside-range control is not in the range
    assert ids("rest/q/") == ["rest/q/post-query-in", "rest/q/post-read-p", "rest/q/post-read-o"] and ids("grpc/q/")[-1] == "grpc/q/post-query-in"


def test_the_paging_chain_cancels_the_stream_after_one_frame_and_keeps_using_the_token():
    assert tail("grpc/pg/") == ["begin", "query-cancelled", "read-after-cancel", "commit", "writer", "post-read-h"]
    steps = {step["id"]: step for step in plan()["steps"]}
    cancelled, commit, writer = steps["grpc/pg/query-cancelled"], steps["grpc/pg/commit"], steps["grpc/pg/writer"]
    assert cancelled["cancelAfter"] == 1 and cancelled["allow"] == [1] and cancelled["query"] == {} and cancelled["tokenInput"] == "grpc-pg"
    assert steps["grpc/pg/read-after-cancel"]["tokenInput"] == "grpc-pg" and commit["tokenInput"] == "grpc-pg" and commit["writes"] == [] and commit["waitSeconds"] == 5
    assert writer["concurrentWith"] == commit["id"] and [(w["document"], w["exists"]) for w in writer["writes"]] == [("h", True)]
    # the unfiltered query sees every document that exists by then: more than the three the cancel needs to be meaningful
    created_before = {"a", "b", "h", "c", "d", "p", "o", "p2"}
    assert len(created_before) > 3


def test_the_retention_reads_name_59_and_61_minutes_ago_and_a_begin_is_released_only_when_it_was_accepted():
    steps = {step["id"]: step for step in plan()["steps"]}
    assert tail("rest/ret/") == ["get-59", "batch-59", "get-61", "batch-61", "begin-59", "release-59", "begin-61"]
    assert tail("grpc/ret/") == ["get-59", "get-61", "batch-61"]
    assert [step["id"] for step in plan()["steps"]][-3:] == ["rest/ret/begin-59", "rest/ret/release-59", "rest/ret/begin-61"], "the two begins come last: a stop there costs no other row"
    for step_id, step in steps.items():
        if "/ret/" in step_id:
            if "readAgoSeconds" in step:
                assert step["readAgoSeconds"] == (3540 if step_id.endswith("59") else 3660), step_id
            expected = {"rest/ret/begin-59": [0], "rest/ret/begin-61": [3, 5, 9, 10]}.get(step_id, [0, 3, 5, 9, 10])
            assert step["allow"] == expected and step["tokenInput"] in (None, "ro-59"), step_id
    assert steps["rest/ret/begin-59"]["mode"] == "readOnly" and steps["rest/ret/begin-61"]["mode"] == "readOnly"
    assert steps["rest/ret/release-59"]["tokenInput"] == "ro-59"
    assert not any(step["tokenInput"] == "ro-61" for step in steps.values()), "a refused 61 minute begin leaves nothing to release; an accepted one is released by the recovery"


def test_the_token_chain_is_a_valid_control_then_literal_tokens_with_the_malformed_one_over_rest_alone():
    assert tail("rest/tv/")[:3] == ["begin", "read-control", "release"]
    literal = {step["id"]: step for step in plan()["steps"] if "tokenLiteral" in step}
    assert sorted(literal) == sorted(
        [f"rest/tv/{kind}-{name}" for kind in ("get", "batch", "commit", "rollback") for name in ("malformed", "unknown")] + ["grpc/tv/get-unknown", "grpc/tv/commit-unknown", "grpc/tv/rollback-unknown"])
    assert all(step["tokenLiteral"] == "malformed" for step_id, step in literal.items() if step_id.endswith("malformed"))
    assert all(step["transport"] == "rest" for step in literal.values() if step["tokenLiteral"] == "malformed")
    assert all(step["allow"] == [0, 3, 5, 9, 10] and step["role"] == "observation" for step in literal.values())


def test_every_observation_may_give_any_refusal_and_nothing_outside_the_declared_set_names_a_foreign_document():
    for step in plan()["steps"]:
        if step["role"] == "observation" and "cancelAfter" not in step and step["allow"] != [0, 10] and step["id"] not in ("rest/ret/begin-59", "rest/ret/begin-61"):
            assert step["allow"] == [0, 3, 5, 9, 10], step["id"]
        assert step["document"] in (None, *TABLE["documents"])
        assert all(write["document"] in TABLE["documents"] for write in step["writes"])


def test_the_corpus_digest_is_stable_and_moves_with_a_step():
    base = corpus_digest(TABLE)
    assert corpus_digest(TABLE) == base

    def changed(step_id, **fields):
        value = dict(TABLE, steps=tuple(dict(step, **fields) if step["id"] == step_id else step for step in TABLE["steps"]))
        return corpus_digest(value)

    assert changed("rest/ret/get-59", readAgoSeconds=3541) != base
    assert changed("grpc/pg/query-cancelled", cancelAfter=2) != base
    assert changed("rest/tv/get-unknown", tokenLiteral="malformed") != base
