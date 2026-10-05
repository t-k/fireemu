"""The comparison tool's pure parts: commit-time relations and the row comparison."""

import fs_txn_compare_local as tool


def step(site, transport, code=0, response=None, request=None, case=None):
    return {"site": site, "rpc": "Commit", "transport": transport, "caseId": case, "request": request or {}, "result": {"code": code, "response": response}}


def rest(stamp):
    return {"commitTime": stamp}


def test_an_empty_commit_before_the_outside_writer_is_related_to_it():
    steps = [
        step("s/writer", "rest", response=rest("2026-09-30T01:17:23.183416Z"), request={"writes": [{}]}, case="rest/s-writer"),
        step("s/ro-empty", "rest", response=rest("2026-09-30T01:17:19.219755Z"), request={"transaction": "t", "writes": []}),
    ]
    assert tool.commit_relations(steps)["s/ro-empty"] == {"commitTime": True, "relation": "before-writer"}
    steps[1]["result"]["response"] = rest("2026-09-30T01:17:29.000000Z")
    assert tool.commit_relations(steps)["s/ro-empty"]["relation"] == "after-writer"


def test_an_empty_commit_without_an_earlier_writer_or_a_time_has_no_relation():
    only = [step("s/ro-empty", "rest", response=rest("2026-09-30T01:17:19Z"), request={"transaction": "t", "writes": []})]
    assert tool.commit_relations(only)["s/ro-empty"] == {"commitTime": True, "relation": None}
    bare = [step("s/ro-empty", "grpc", response={}, request={"transaction": "t", "writes": []})]
    assert tool.commit_relations(bare)["s/ro-empty"] == {"commitTime": False, "relation": None}


def test_refused_commits_and_other_rpcs_are_not_related():
    refused = step("s/x", "rest", code=3, response=None)
    read = {**step("s/y", "rest", response=rest("2026-09-30T01:17:19Z")), "rpc": "GetDocument"}
    assert tool.commit_relations([refused, read]) == {}


def test_grpc_commit_times_compare_like_rest_ones():
    writer = step("g/writer", "grpc", response={"commitTime": {"seconds": "1790731101", "nanos": 314215000}}, request={"writes": [{}]}, case="grpc/s-writer")
    empty = step("g/ro-empty", "grpc", response={"commitTime": {"seconds": "1790731098", "nanos": 607751000}}, request={"transaction": "t", "writes": []})
    assert tool.commit_relations([writer, empty])["g/ro-empty"]["relation"] == "before-writer"


def projection(code=0, details="", state="v1", documents=None):
    return {"cases": [{"caseId": "c", "code": code, "details": details}], "reads": [{"site": "r", "code": 0, "state": state, "documents": documents}]}


def test_matching_rows_have_no_mismatch():
    cases, reads, times = tool.compare(projection(), projection(), {"s": {"commitTime": True, "relation": None}}, {"s": {"commitTime": True, "relation": None}})
    assert all(row["match"] for row in cases + reads + times)


def test_a_different_code_state_document_or_commit_time_is_a_mismatch():
    for local, relations in [
        (projection(code=3), {"s": {"commitTime": True, "relation": None}}),
        (projection(state="v2"), {"s": {"commitTime": True, "relation": None}}),
        (projection(documents={"a": "v1"}), {"s": {"commitTime": True, "relation": None}}),
        (projection(), {"s": {"commitTime": False, "relation": None}}),
        (projection(), {"s": {"commitTime": True, "relation": "after-writer"}}),
    ]:
        cases, reads, times = tool.compare(projection(), local, {"s": {"commitTime": True, "relation": None}}, relations)
        assert not all(row["match"] for row in cases + reads + times)


def test_the_first_line_of_a_diagnostic_decides_and_the_project_id_is_normalised():
    production = projection(code=5, details='Document "projects/fireemu-oracle-sbx/x" not found\nmore')
    local = projection(code=5, details='Document "projects/demo-program/x" not found\nother')
    cases, _reads, _times = tool.compare(production, local, None, {})
    assert cases[0]["match"] is True


def test_a_missing_local_row_is_a_mismatch():
    cases, reads, times = tool.compare(projection(), {"cases": [], "reads": []}, {"s": {"commitTime": True, "relation": None}}, {})
    assert not cases[0]["match"] and not reads[0]["match"] and not times[0]["match"]


def test_a_table_for_the_free_tier_project_is_replayed_and_normalised_under_that_project():
    assert tool.table_project({"project": "fireemu-oracle-txn"}) == "fireemu-oracle-txn"
    assert tool.table_project({}) == "fireemu-oracle-sbx"
    production = projection(code=5, details='Document "projects/fireemu-oracle-txn/x" not found')
    local = projection(code=5, details='Document "projects/demo-program/x" not found')
    cases, _reads, _times = tool.compare(production, local, None, {}, project="fireemu-oracle-txn")
    assert cases[0]["match"] is True
    # under the default project name the same pair differs
    cases, _reads, _times = tool.compare(production, local, None, {})
    assert cases[0]["match"] is False


def test_the_published_local_diagnostic_is_the_normalised_one():
    production = projection(code=5, details='Document "projects/fireemu-oracle-txn/x" not found')
    local = projection(code=5, details='Document "projects/demo-program/x" not found')
    cases, _reads, _times = tool.compare(production, local, None, {}, project="fireemu-oracle-txn")
    assert cases[0]["local"]["details"] == 'Document "projects/fireemu-oracle-txn/x" not found'
