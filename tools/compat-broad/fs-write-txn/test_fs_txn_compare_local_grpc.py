"""The row comparison of the native gRPC programs' replay driver."""

import pytest

import fs_txn_compare_local_grpc as tool


def case(case_id="c", code=0, details="", rpc="Commit", token=False):
    return {"caseId": case_id, "rpc": rpc, "code": code, "details": details, "issuedToken": token}


def projection(cases=None, reads=None, skipped=None, idle=None):
    value = {"cases": cases if cases is not None else [case()], "reads": reads if reads is not None else [{"site": "r", "code": 0, "state": "created", "details": ""}], "skipped": skipped or []}
    if idle is not None:
        value["idleCandidates"] = idle
    return value


def test_equal_projections_have_no_mismatch():
    rows = tool.compare(projection(), projection())
    assert all(row["match"] for section in rows for row in section)


def test_the_project_identifier_in_a_diagnostic_is_a_role_on_both_sides():
    production = projection(cases=[case(code=5, details='Document "projects/fireemu-oracle-sbx/databases/(default)/documents/x" not found.')])
    local = projection(cases=[case(code=5, details='Document "projects/demo-program/databases/(default)/documents/x" not found.')])
    cases, *_ = tool.compare(production, local)
    assert cases[0]["match"] is True


@pytest.mark.parametrize("field,value", [("code", 10), ("rpc", "Rollback"), ("token", True), ("details", "other")])
def test_any_difference_in_a_case_is_a_mismatch(field, value):
    other = case(**({"token": value} if field == "token" else {field: value}))
    cases, *_ = tool.compare(projection(), projection(cases=[other]))
    assert cases[0]["match"] is False


def test_a_read_state_difference_is_a_mismatch():
    local = projection(reads=[{"site": "r", "code": 0, "state": "committed", "details": ""}])
    _cases, reads, *_ = tool.compare(projection(), local)
    assert reads[0]["match"] is False


def test_a_different_inventory_is_refused_not_compared():
    with pytest.raises(ValueError):
        tool.compare(projection(), projection(cases=[case("other")]))
    with pytest.raises(ValueError):
        tool.compare(projection(), projection(reads=[{"site": "x", "code": 0, "state": None, "details": ""}]))
    with pytest.raises(ValueError):
        tool.compare(projection(), projection(skipped=[{"site": "s", "basis": "b", "tokenRole": "t"}]))


def test_idle_candidates_match_by_classification_and_wait():
    wait = {"site": "w", "seconds": 65, "classification": "after", "thresholdSeconds": 60}
    rows = tool.compare(projection(idle=[wait]), projection(idle=[dict(wait)]))
    assert rows[3][0]["match"] is True
    rows = tool.compare(projection(idle=[wait]), projection(idle=[{**wait, "classification": "before"}]))
    assert rows[3][0]["match"] is False
    with pytest.raises(ValueError):
        tool.compare(projection(idle=[wait]), projection(idle=[]))


def test_a_projection_without_conditional_steps_has_no_skipped_list():
    bare = {"cases": [case()], "reads": []}
    cases, reads, skipped, idle = tool.compare(bare, dict(bare))
    assert cases[0]["match"] is True and reads == [] and skipped == [] and idle == []
