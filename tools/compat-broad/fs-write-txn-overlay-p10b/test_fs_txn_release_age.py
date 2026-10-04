"""A table that declares `releaseAfterAgeSeconds` treats a definitive refusal of a Rollback as the token's release once the token is
certainly older than that age (P11: a request was refused as expired at a token age of 298.7 to 301.0 s; the age is a lower bound)."""

import datetime as dt
import importlib

import pytest

collector_module = importlib.import_module("txn_program_collector")
program = importlib.import_module("txn_program_program")
p11 = importlib.import_module("fs_txn_table_p11")
p12 = importlib.import_module("fs_txn_table_p12")

NONCE, OWNER = "a" * 32, "b" * 32
TOKEN = "dG9rZW4="
BASE = dt.datetime(2026, 9, 30, 3, 0, 0, tzinfo=dt.timezone.utc)
GONE = "The referenced transaction has expired or is no longer valid."


def moment(seconds):
    return (BASE + dt.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def timing(dispatch, response):
    return {"dispatchMonotonic": float(dispatch), "responseMonotonic": float(response), "dispatchUtc": moment(dispatch), "responseUtc": moment(response)}


def ledger_for(table):
    ledger = collector_module.Ledger(program.compile_plan(table, NONCE, OWNER))
    ledger.docs["a"].update(status="created", state="created")
    ledger.tokens["rest-c"] = {"value": TOKEN, "state": "open", "transport": "rest", "start": timing(1.0, 2.0), "lastUse": timing(1.0, 2.0)}
    ledger.modes["rest-c"] = "readWrite"
    return ledger


def release(ledger, code, details, dispatch, step=None):
    result = {"code": code, "details": details, "response": None, "http": 400}
    ledger._apply("release", "rest", "Rollback", {"transaction": TOKEN}, step, result, timing(dispatch, dispatch + 1.0), code)
    return ledger.tokens["rest-c"]["state"]


def test_the_release_age_is_declared_by_the_tables_that_need_it():
    assert p12.TABLE["thresholds"] == {"totalAgeSeconds": 270, "releaseAfterAgeSeconds": 315}
    assert "releaseAfterAgeSeconds" not in p11.TABLE["thresholds"]


@pytest.mark.parametrize("code,details", [(3, "Invalid transaction."), (10, "Too much contention"), (3, GONE), (5, "not found"), (9, "failed precondition")])
def test_a_definitive_refusal_of_a_release_of_a_token_certainly_past_the_age_releases_it(code, details):
    # begin answered at 2.0 s; the Rollback is dispatched at 320.0 s, so the token is at least 318.0 s old
    assert release(ledger_for(p12.TABLE), code, details, 320.0) == "released-expired"


def test_it_also_finishes_a_declared_release_step_and_not_only_a_chain_end_release():
    declared = {"id": "rest/c/rollback-last"}
    assert release(ledger_for(p12.TABLE), 3, "Invalid transaction.", 320.0, step=declared) == "released-expired"


@pytest.mark.parametrize("dispatch,expected", [(317.0, "unconfirmed-release"), (317.01, "released-expired"), (303.0, "unconfirmed-release"), (250.0, "unconfirmed-release")])
def test_the_age_bound_is_strict_and_a_lower_one(dispatch, expected):
    # begin answered at 2.0 s: at a dispatch of 317.0 the lower bound is exactly 315.0 s, which is not past it; 303.0 (301 s) is inside the margin
    assert release(ledger_for(p12.TABLE), 3, "Invalid transaction.", dispatch) == expected


@pytest.mark.parametrize("code", [1, 2, 4, 6, 7, 8, 13, 14])
def test_an_unknown_outcome_never_releases_a_token(code):
    assert release(ledger_for(p12.TABLE), code, "unknown", 400.0) == "unconfirmed-release"


def test_an_accepted_release_is_a_rollback_whatever_the_age():
    assert release(ledger_for(p12.TABLE), 0, "", 400.0) == "rolled-back"


def test_a_table_without_the_declaration_keeps_the_narrow_rule():
    assert release(ledger_for(p11.TABLE), 3, "Invalid transaction.", 400.0) == "unconfirmed-release"
    assert release(ledger_for(p11.TABLE), 10, "Too much contention", 400.0) == "unconfirmed-release"


def test_the_narrow_answers_still_release_a_token_at_any_age_and_stay_distinct():
    assert release(ledger_for(p12.TABLE), 10, GONE, 100.0) == "released-refused"
    assert release(ledger_for(p12.TABLE), 10, GONE, 400.0) == "released-refused"


def test_a_release_age_below_the_total_age_threshold_never_compiles():
    for changes in ({"releaseAfterAgeSeconds": 100}, {"releaseAfterAgeSeconds": "315"}, {"releaseAfterAgeSeconds": 315, "other": 1}):
        table = {**p12.TABLE, "thresholds": {"totalAgeSeconds": 270, **changes}}
        with pytest.raises(ValueError, match="txn-program table"):
            program.compile_plan(table, NONCE, OWNER)


def test_no_table_with_a_grpc_transaction_may_declare_the_release_age_until_the_grpc_lifetime_is_recorded():
    # P12's setup steps are gRPC and stay allowed; a gRPC token step (Begin, or a step that uses or issues a token) is what the REST-only premise excludes.
    program.compile_plan(p12.TABLE, NONCE, OWNER)
    for change in ({"transport": "grpc"},):
        steps = tuple({**step, **change} if step["id"] == "rest/c/begin" else step for step in p12.TABLE["steps"])
        with pytest.raises(ValueError, match="no table with a gRPC transaction"):
            program.compile_plan({**p12.TABLE, "steps": steps}, NONCE, OWNER)
    steps = tuple({**step, "transport": "grpc"} if step["id"] == "rest/c/read-a" else step for step in p12.TABLE["steps"])
    with pytest.raises(ValueError, match="no table with a gRPC transaction"):
        program.compile_plan({**p12.TABLE, "steps": steps}, NONCE, OWNER)
    grpc_table = {**p11.TABLE, "thresholds": {"totalAgeSeconds": 270, "releaseAfterAgeSeconds": 315}}
    with pytest.raises(ValueError, match="no table with a gRPC transaction"):
        program.compile_plan(grpc_table, NONCE, OWNER)
