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


def timed(site, dispatch, response):
    return {"site": site, "timing": {"dispatchMonotonic": dispatch, "responseMonotonic": response}}


PLAN = {"steps": [{"id": "w/release"}, {"id": "w/writer", "concurrentWith": "w/release"}, {"id": "q/release"}, {"id": "q/writer", "concurrentWith": "q/release"}, {"id": "plain"}]}


def test_a_writer_that_answered_before_its_anchor_was_sent_is_not_held_and_one_that_answered_after_was():
    steps = [timed("w/writer", 10.0, 11.0), timed("w/release", 55.0, 56.0), timed("q/writer", 100.0, 160.0), timed("q/release", 105.0, 106.0)]
    assert tool.writer_orders(steps, PLAN) == {"w/writer": "before-anchor", "q/writer": "after-anchor"}


def test_a_writer_that_answered_at_the_instant_its_anchor_was_sent_was_held():
    # a frozen virtual clock stamps a writer released by its anchor with the anchor's own dispatch time
    assert tool.writer_orders([timed("w/writer", 10.0, 55.0), timed("w/release", 55.0, 55.0)], PLAN) == {"w/writer": "after-anchor"}


def test_a_pair_with_a_missing_row_and_a_step_that_is_nobodys_writer_have_no_order():
    assert tool.writer_orders([timed("w/writer", 1.0, 2.0)], PLAN) == {}
    assert tool.writer_orders([timed("w/release", 1.0, 2.0), timed("plain", 3.0, 4.0)], PLAN) == {}


def test_the_orders_of_production_and_the_local_replay_are_compared_site_by_site():
    rows = tool.compare_orders({"w/writer": "after-anchor", "q/writer": "before-anchor"}, {"w/writer": "after-anchor", "q/writer": "after-anchor"})
    assert rows == [{"site": "q/writer", "production": "before-anchor", "local": "after-anchor", "match": False}, {"site": "w/writer", "production": "after-anchor", "local": "after-anchor", "match": True}]
    # a writer the local replay never answered is a mismatch, and so is one only the local replay has
    rows = tool.compare_orders({"w/writer": "after-anchor"}, {"q/writer": "after-anchor"})
    assert [(row["site"], row["match"]) for row in rows] == [("q/writer", False), ("w/writer", False)]
    assert tool.compare_orders({}, {}) == []


def test_a_writer_that_answered_while_its_anchor_was_in_flight_was_held():
    # between the anchor's dispatch and its answer: the writer was released by it, so it was held
    assert tool.writer_orders([timed("w/writer", 10.0, 105.5), timed("w/release", 105.0, 106.0)], PLAN) == {"w/writer": "after-anchor"}


def test_a_step_with_no_anchor_has_no_order():
    assert tool.writer_orders([timed("plain", 1.0, 2.0), timed("w/release", 3.0, 4.0)], {"steps": [{"id": "plain"}, {"id": "w/release"}]}) == {}
