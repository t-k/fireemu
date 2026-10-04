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


# --- the read-time retention rows are judged by class, and the host clock the 59/61-minute boundary depends on is checked against the server's own clock ---

def retention_plan():
    return {"steps": [{"id": "rest/ret/get-59", "caseId": "rest/ret/get-59", "readAgoSeconds": 3540}, {"id": "rest/ret/get-61", "caseId": "rest/ret/get-61", "readAgoSeconds": 3660},
                      {"id": "rest/ret/release-59", "caseId": "rest/ret/release-59"}, {"id": "plain", "caseId": "plain"}, {"id": "setup", "caseId": None}]}


def test_the_retention_cases_are_the_steps_that_name_a_time_ago():
    assert tool.retention_cases(retention_plan()) == frozenset({"rest/ret/get-59", "rest/ret/get-61"})
    # a step with no case is nobody's case
    assert tool.retention_cases({"steps": [{"id": "x", "caseId": None, "readAgoSeconds": 3540}]}) == frozenset()
    assert tool.retention_cases({"steps": []}) == frozenset()


def test_a_read_at_a_time_ago_is_accepted_or_refused_and_any_other_answer_has_its_own_class():
    assert [tool.outcome_class(code) for code in (0, 5)] == ["accepted", "accepted"]
    assert [tool.outcome_class(code) for code in (3, 9)] == ["refused", "refused"]
    assert [tool.outcome_class(code) for code in (10, 1, 13)] == ["other:10", "other:1", "other:13"]


def case_projection(code, details="x"):
    return {"cases": [{"caseId": "rest/ret/get-61", "code": code, "details": details}], "reads": []}


def test_a_retention_case_matches_when_both_sides_are_in_the_same_class_whatever_the_code_and_text():
    # 9 (too old) against 3 (before the database existed): both refuse the read time
    cases, _reads, _times = tool.compare(case_projection(9, "too old"), case_projection(3, "before creation"), None, {}, retention=frozenset({"rest/ret/get-61"}))
    assert cases[0]["match"] is True
    # the rows still carry both exact answers
    assert cases[0]["production"]["code"] == 9 and cases[0]["local"]["code"] == 3
    assert cases[0]["class"] == {"production": "refused", "local": "refused"}


def test_a_retention_case_refused_on_one_side_and_accepted_on_the_other_is_a_mismatch():
    cases, _reads, _times = tool.compare(case_projection(9), case_projection(0), None, {}, retention=frozenset({"rest/ret/get-61"}))
    assert cases[0]["match"] is False
    cases, _reads, _times = tool.compare(case_projection(0), case_projection(5), None, {}, retention=frozenset({"rest/ret/get-61"}))
    assert cases[0]["match"] is True   # found and not found are both accepted: the document may not have existed that long ago
    # an answer of another kind (10) never matches a different one, and matches itself
    assert tool.compare(case_projection(10), case_projection(9), None, {}, retention=frozenset({"rest/ret/get-61"}))[0][0]["match"] is False
    assert tool.compare(case_projection(10), case_projection(10), None, {}, retention=frozenset({"rest/ret/get-61"}))[0][0]["match"] is True


def test_a_case_that_is_not_a_retention_case_still_compares_code_and_text():
    cases, _reads, _times = tool.compare(case_projection(9, "too old"), case_projection(3, "before creation"), None, {}, retention=frozenset({"other"}))
    assert cases[0]["match"] is False
    assert "class" not in cases[0]


def rest_commit(site, dispatch, response, update):
    return {"site": site, "rpc": "Commit", "transport": "rest", "request": {}, "result": {"code": 0, "response": {"commitTime": update, "writeResults": [{"updateTime": update}]}},
            "timing": {"dispatchUtc": dispatch, "responseUtc": response}}


def test_every_update_time_of_an_acknowledged_commit_is_checked_against_the_window_around_the_request():
    steps = [rest_commit("a", "2026-10-05T10:00:00.000000Z", "2026-10-05T10:00:01.000000Z", "2026-10-05T10:00:00.500000Z"),
             rest_commit("b", "2026-10-05T10:00:10.000000Z", "2026-10-05T10:00:11.000000Z", "2026-10-05T10:00:12.900000Z"),
             rest_commit("c", "2026-10-05T10:00:20.000000Z", "2026-10-05T10:00:21.000000Z", "2026-10-05T10:00:23.100000Z"),
             rest_commit("d", "2026-10-05T10:00:30.000000Z", "2026-10-05T10:00:31.000000Z", "2026-10-05T10:00:28.100000Z"),
             rest_commit("e", "2026-10-05T10:00:40.000000Z", "2026-10-05T10:00:41.000000Z", "2026-10-05T10:00:37.900000Z")]
    assert tool.clock_evidence(steps) == {"a": True, "b": True, "c": False, "d": True, "e": False}


def test_the_window_is_two_seconds_either_side_inclusive_and_covers_native_stamps_too():
    exactly = [rest_commit("lo", "2026-10-05T10:00:10.000000Z", "2026-10-05T10:00:11.000000Z", "2026-10-05T10:00:08.000000Z"),
               rest_commit("hi", "2026-10-05T10:00:10.000000Z", "2026-10-05T10:00:11.000000Z", "2026-10-05T10:00:13.000000Z")]
    assert tool.clock_evidence(exactly) == {"lo": True, "hi": True}
    native = {"site": "g", "rpc": "Commit", "transport": "grpc", "request": {}, "timing": {"dispatchUtc": "2026-10-05T10:00:10.000000Z", "responseUtc": "2026-10-05T10:00:11.000000Z"},
              "result": {"code": 0, "response": {"commitTime": {"seconds": "1", "nanos": 0}, "writeResults": [{"updateTime": {"seconds": "1791194413", "nanos": 500000000}}]}}}
    # 2026-10-05T10:00:13.5Z is 2.5 s after the response
    assert tool.clock_evidence([native]) == {"g": False}
    native["result"]["response"]["writeResults"][0]["updateTime"] = {"seconds": "1791194412", "nanos": 0}
    assert tool.clock_evidence([native]) == {"g": True}


def test_a_commit_with_several_write_results_is_in_the_window_only_if_every_update_time_is():
    step = rest_commit("m", "2026-10-05T10:00:10.000000Z", "2026-10-05T10:00:11.000000Z", "2026-10-05T10:00:10.500000Z")
    step["result"]["response"]["writeResults"].append({"updateTime": "2026-10-05T10:00:20.000000Z"})
    assert tool.clock_evidence([step]) == {"m": False}


def test_only_acknowledged_commits_with_an_update_time_are_checked():
    refused = rest_commit("r", "2026-10-05T10:00:10.000000Z", "2026-10-05T10:00:11.000000Z", "2026-10-05T11:00:00.000000Z")
    refused["result"]["code"] = 10
    empty = rest_commit("e", "2026-10-05T10:00:10.000000Z", "2026-10-05T10:00:11.000000Z", "2026-10-05T09:00:00.000000Z")
    empty["result"]["response"]["writeResults"] = []   # an empty commit's commitTime is a snapshot time, not the server's clock
    read = {**rest_commit("g", "2026-10-05T10:00:10.000000Z", "2026-10-05T10:00:11.000000Z", "2026-10-05T11:00:00.000000Z"), "rpc": "GetDocument"}
    assert tool.clock_evidence([refused, empty, read]) == {}


def test_the_clock_evidence_rows_match_when_both_the_recording_and_the_replay_keep_the_server_clock_inside_the_window():
    rows = tool.compare_clock({"a": True, "b": True}, {"a": True, "b": True})
    assert [(row["site"], row["match"]) for row in rows] == [("a", True), ("b", True)]
    # a recording whose host clock was off is a mismatch: its retention rows are not evidence of the boundary
    rows = tool.compare_clock({"a": False}, {"a": True})
    assert rows == [{"site": "a", "production": False, "local": True, "match": False}]
    # a replay whose clock drifted is one too, and so is a row only one side has
    assert tool.compare_clock({"a": True}, {"a": False})[0]["match"] is False
    assert [row["match"] for row in tool.compare_clock({"a": True}, {"b": True})] == [False, False]
    # both sides out of the window is no evidence either
    assert tool.compare_clock({"a": False}, {"a": False})[0]["match"] is False
    assert tool.compare_clock({}, {}) == []


def test_a_retention_case_the_local_replay_never_answered_is_a_mismatch_whatever_the_production_class():
    local = {"cases": [], "reads": []}
    for code in (0, 9, 10):
        cases, _reads, _times = tool.compare(case_projection(code), local, None, {}, retention=frozenset({"rest/ret/get-61"}))
        assert cases[0]["match"] is False and cases[0]["local"] is None and cases[0]["class"]["local"] is None


def test_the_clock_rows_check_the_recording_and_the_replay_each_by_its_own_steps():
    inside = rest_commit("a", "2026-10-05T10:00:00.000000Z", "2026-10-05T10:00:01.000000Z", "2026-10-05T10:00:00.500000Z")
    outside = rest_commit("a", "2026-10-05T10:00:00.000000Z", "2026-10-05T10:00:01.000000Z", "2026-10-05T10:05:00.000000Z")
    assert [row["match"] for row in tool.clock_rows([inside], [inside])] == [True]
    assert tool.clock_rows([outside], [inside]) == [{"site": "a", "production": False, "local": True, "match": False}]
    assert tool.clock_rows([inside], [outside]) == [{"site": "a", "production": True, "local": False, "match": False}]


def read_projection(code, state=None, documents=None):
    return {"cases": [], "reads": [{"site": "rest/ret/get-59", "code": code, "state": state, "documents": documents}]}


def test_a_retention_read_row_is_judged_by_class_and_by_state_only_when_both_sides_found_the_document():
    sites = frozenset({"rest/ret/get-59"})
    judge = lambda production, local: tool.compare(production, local, None, {}, retention=sites)[1][0]   # noqa: E731
    # not found against found: both accepted, the document may not have existed that long ago
    assert judge(read_projection(5), read_projection(0, "v1"))["match"] is True
    assert judge(read_projection(3), read_projection(9))["match"] is True
    assert judge(read_projection(9), read_projection(0, "v1"))["match"] is False
    assert judge(read_projection(0, "v1"), read_projection(9))["match"] is False
    # both found: the state still has to agree
    assert judge(read_projection(0, "v1"), read_projection(0, "v1"))["match"] is True
    assert judge(read_projection(0, "v1"), read_projection(0, "v2"))["match"] is False
    assert judge(read_projection(0, "v1", {"a": "v1"}), read_projection(0, "v1", {"a": "v2"}))["match"] is False
    # the row keeps both exact answers
    row = judge(read_projection(3), read_projection(9))
    assert row["production"]["code"] == 3 and row["local"]["code"] == 9 and row["class"] == {"production": "refused", "local": "refused"}


def test_a_read_that_is_not_a_retention_read_still_compares_code_and_state():
    row = tool.compare(read_projection(3), read_projection(9), None, {}, retention=frozenset({"x"}))[1][0]
    assert row["match"] is False and "class" not in row


def test_a_retention_read_the_local_replay_never_answered_is_a_mismatch():
    row = tool.compare(read_projection(5), {"cases": [], "reads": []}, None, {}, retention=frozenset({"rest/ret/get-59"}))[1][0]
    assert row["match"] is False and row["local"] is None


def test_the_retention_steps_of_the_p14_table_carry_the_same_name_as_their_case():
    import fs_txn_table_p14 as p14

    plan = tool.compile_plan(p14.TABLE, "a" * 32, "b" * 32)
    steps = [step for step in plan["steps"] if "readAgoSeconds" in step]
    assert len(steps) == 9 and all(step["id"] == step["caseId"] for step in steps)
    assert tool.retention_cases(plan) == frozenset(step["id"] for step in steps)
