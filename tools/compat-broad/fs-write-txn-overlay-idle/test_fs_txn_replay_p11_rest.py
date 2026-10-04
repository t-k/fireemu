"""The P11 REST replay's pure parts: the compared production rows and the row comparison."""

import fs_txn_replay_p11_rest as replay

GONE = "The referenced transaction has expired or is no longer valid."


def step(site, code, details=""):
    return {"site": site, "result": {"code": code, "details": details}}


RECORDING = {"steps": [step("rest/live-read", 0), step("rest/expiry-read", 10, GONE), step("rest/expiry-commit", 3, "Invalid transaction.")],
             "cleanupSteps": [step("cleanup/token/rest-k", 3, "Invalid transaction."), step("cleanup/read/a", 0)]}


def local(**changes):
    rows = {"rest/live-read": {"code": 0, "details": ""}, "rest/expiry-read": {"code": 10, "details": GONE},
            "rest/expiry-commit": {"code": 3, "details": "Invalid transaction."}, "rest/release": {"code": 3, "details": "Invalid transaction."}}
    rows.update(changes)
    return rows


def test_the_recorded_rows_are_the_four_compared_ones():
    assert list(replay.recorded_rows(RECORDING)) == ["rest/live-read", "rest/expiry-read", "rest/expiry-commit", "rest/release"]


def test_matching_answers_have_no_mismatch():
    assert all(row["match"] for row in replay.compare_rows(replay.recorded_rows(RECORDING), local()))


def test_a_different_code_or_diagnostic_or_a_missing_row_is_a_mismatch():
    production = replay.recorded_rows(RECORDING)
    for changed in [{"rest/expiry-read": {"code": 3, "details": "Invalid transaction."}},
                    {"rest/expiry-commit": {"code": 10, "details": GONE}},
                    {"rest/release": {"code": 3, "details": "other"}}]:
        assert not all(row["match"] for row in replay.compare_rows(production, local(**changed)))
    partial = local()
    del partial["rest/release"]
    assert not all(row["match"] for row in replay.compare_rows(production, partial))


def test_the_replay_table_ends_with_a_release_and_holds_one_token():
    table = replay.table()
    ids = [step["id"] for step in table["steps"]]
    assert ids[-3:] == ["rest/expiry-commit", "rest/release", "rest/post-read-a"] and table["maxTokens"] == 1
    assert table["caps"]["observation"] == len(ids)
