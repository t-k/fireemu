"""P12's table (REST): the shape it declares, its timing against the recorded values, and the recordings it produces against stand-in
services that answer an expired transaction by each model P11 leaves open."""

import pytest

import fs_txn_table_p12 as p12
import txn_program_cli as cli
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest
from test_txn_program_collector import Clock, Service

TABLE = p12.TABLE
NONCE, OWNER = "a" * 32, "b" * 32
GONE = "The referenced transaction has expired or is no longer valid."
# P11 recording 1 (docs.local/runs/fs-transaction-p11-lifetime-0478164e4f3b1948, REST): a request was live at a token age of 246.8 to 249.2 s
# and refused at 298.7 to 301.0 s; an RPC took about 1.1 to 1.3 s and each wait ran about 0.6 s long. P10-C accepted requests after an idle of
# 75 to 110 s.
LIVE_AGE, REFUSED_AGE, ACCEPTED_IDLE = 246.8, 301.0, 110.0


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def names(chain):
    return [step["id"].split("/", 2)[2] for step in plan()["steps"] if step["id"].startswith(f"rest/{chain}/")]


def collector(service, clock):
    value = plan()
    return Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)


def record(**knobs):
    clock = Clock()
    service = Service(clock, **knobs)
    return collector(service, clock).run(), service, clock


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p12-first-request"] == "fs_txn_table_p12" and cli.table_for("p12-first-request") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p12.py" in cli.source_manifest("p12-first-request")


def test_the_requests_and_waits_stay_inside_their_clock():
    value = plan()
    assert len(value["steps"]) == 33 and len(value["cases"]) == 7
    assert value["caps"] == {"observation": 33, "tokenCleanup": 2, "documentCleanup": 7, "management": 7, "credential": 2}
    assert value["maxRequests"] == 51 and value["maxTokens"] == 2
    assert sum(value["waits"].values()) == 2 * (9 * 24 + 90) == 612
    assert value["thresholds"] == {"totalAgeSeconds": 270, "releaseAfterAgeSeconds": 301}
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p12-first-request-001"
    assert all(step["transport"] in ("rest", "grpc") for step in value["steps"]) and {step["transport"] for step in value["steps"] if step["id"].startswith("rest/")} == {"rest"}


def test_each_chain_meets_an_expiry_first_and_the_rest_in_the_declared_order():
    keep = [f"keepalive-{index}" for index in range(1, 10)]
    assert names("c") == ["begin", "read-a", *keep, "commit-first", "read-after", "read-again", "rollback-last", "post-read-a"]
    assert names("r") == ["begin", "read-a", *keep, "rollback-first", "read-after", "commit-last", "post-read-a"]


def test_the_timing_is_tied_to_the_recorded_lifetime_bracket_and_idle():
    steps = plan()["steps"]
    for chain, first in (("c", "commit-first"), ("r", "rollback-first")):
        waits = [step["waitSeconds"] for step in steps if step["id"].startswith(f"rest/{chain}/") and "waitSeconds" in step]
        assert waits == [24] * 9 + [90]
        # from waits alone, with no request time at all, the first request is past the age a request was refused at
        assert sum(waits) >= REFUSED_AGE + 1
        # the last keepalive stays below the age a request was live at (with the recorded pace: 11 requests at 1.3 s and 10 waits 0.6 s long)
        assert sum(waits[:9]) + 11 * 1.3 + 9 * 0.6 < LIVE_AGE + 50
        assert waits[-1] <= ACCEPTED_IDLE - 10 and max(waits[:9]) < 60
        assert next(step for step in steps if step["id"] == f"rest/{chain}/{first}")["waitSeconds"] == 90
        assert not any("waitSeconds" in step for step in steps if step["id"].startswith(f"rest/{chain}/") and step["id"].endswith(("read-after", "read-again", "rollback-last", "commit-last")))
    assert TABLE["thresholds"]["releaseAfterAgeSeconds"] >= REFUSED_AGE


def test_the_observation_clock_fits_all_the_chains_at_the_worst_recorded_pace():
    # 33 requests at 1.6 s and a 1 s gap, plus the waits, with room for the last request and the admission margin
    need = sum(plan()["waits"].values()) + 33 * (1.6 + 1.0) + 13
    assert need <= TABLE["observationSeconds"] == 900


def test_every_request_after_the_wait_may_answer_anything_and_only_the_controls_are_strict():
    for step in plan()["steps"]:
        if step["id"].split("/")[-1].startswith(("keepalive", "commit-first", "read-after", "read-again", "rollback-", "commit-last")):
            assert step["allow"] == [0, 3, 5, 9, 10], step["id"]
        if step["id"].endswith(("/begin", "/read-a")):
            assert step["allow"] == [0] and step["role"] == "control"
        if step["id"].endswith("post-read-a"):
            assert step["role"] == "post-state" and step["allow"] == [0]
    assert [step["caseId"] for step in plan()["steps"] if step["caseId"] and "keepalive" in step["id"]] == []


def test_every_state_label_is_declared_and_used():
    assert set(TABLE["states"]) == {write["state"] for step in plan()["steps"] for write in step["writes"]} | {"created"}


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "268cbd9caae672e7b0b14f72920c24c230850be49361f0ca96e88037f817e110"


def answering(model):
    """A service answering an expired transaction by one of the models P11 leaves open (A, B, C, or P08-like answers with 3 and the expired text)."""
    def wrap(service):
        original, seen = service.send, {}
        def send(transport, method, request, **kwargs):
            answer = original(transport, method, request, **kwargs)
            token = request.get("transaction")
            if not token or answer["code"] not in (10, 0) or service.tokens.get(token) != "dead":
                return answer
            first = token not in seen
            seen[token] = True
            http = lambda code: {"rest": 409 if code == 10 else 400}.get(transport)  # noqa: E731
            def as_(code, details):
                return {**answer, "code": code, "details": details, "response": None, "http": http(code)}
            gone, invalid = as_(10, GONE), as_(3, "Invalid transaction.")
            if model == "A":
                return gone if first else invalid
            if model == "B":
                return gone if method == "GetDocument" else invalid
            if model == "C":
                if first:
                    return gone if method == "GetDocument" else invalid
                return invalid
            if model == "P08":
                return as_(3, GONE)
            if model == "rollback-zero":
                return {**answer, "code": 0, "details": "", "response": {}, "http": 200} if method == "Rollback" and first else gone
            raise AssertionError(model)
        service.send = send
        return service
    return wrap


@pytest.mark.parametrize("model", ["A", "B", "C", "P08", "rollback-zero"])
def test_a_recording_completes_under_every_model_and_records_all_seven_cases(model):
    clock = Clock()
    service = answering(model)(Service(clock, expiry=True, lifetime=270, idle=120))
    receipt = collector(service, clock).run()
    assert receipt["complete"] is True, (model, receipt["failureType"], receipt["openTokens"])
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    assert set(cases) == set(plan()["cases"]) and len(cases) == 7
    assert all(entry["state"] in ("released-refused", "released-expired", "rolled-back", "committed") for entry in receipt["tokens"].values())
    if model == "A":
        assert cases["rest/c-commit-first"] == 10 and cases["rest/c-read-after"] == 3 and cases["rest/c-read-again"] == 3
    if model == "B":
        assert cases["rest/c-commit-first"] == 3 and cases["rest/c-read-after"] == 10 and cases["rest/c-read-again"] == 10
    if model == "C":
        assert (cases["rest/c-commit-first"], cases["rest/c-read-after"], cases["rest/r-rollback-first"], cases["rest/r-read-after"]) == (3, 3, 3, 3)


def test_a_release_the_narrow_rule_would_not_accept_is_released_by_age_and_shown():
    # model C: nothing on chain C ever answers 10 with the expired text, so only the age rule can release the token
    clock = Clock()
    service = answering("C")(Service(clock, expiry=True, lifetime=270, idle=120))
    receipt = collector(service, clock).run()
    assert receipt["complete"] is True
    assert receipt["tokens"]["rest-c"]["state"] == "released-expired"


def test_a_service_whose_lifetime_is_not_reached_lets_the_first_request_through_and_the_recording_still_completes():
    # stand-in lifetime beyond the first request's age: the Commit is accepted and writes; nothing is frozen as an expiry answer
    receipt, service, clock = record(expiry=True, lifetime=400, idle=120)
    assert receipt["complete"] is True, receipt["failureType"]
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    assert cases["rest/c-commit-first"] == 0
    ages = {wait["site"]: wait["ageClass"] for wait in projection(receipt, TABLE)["waits"]}
    assert ages["rest/c/commit-first"] == "AFTER", "the age class follows the table's 270 s, not the service's real lifetime"


def test_a_recording_with_the_documented_lifetime_completes_with_the_first_request_after_it():
    receipt, service, clock = record(expiry=True, lifetime=270, idle=120)
    assert receipt["complete"] is True, receipt["failureType"]
    projected = projection(receipt, TABLE)
    cases = {case["caseId"]: case["code"] for case in projected["cases"]}
    assert cases["rest/c-commit-first"] == 10 and cases["rest/r-rollback-first"] == 10
    ages = {wait["site"]: wait["ageClass"] for wait in projected["waits"]}
    assert ages["rest/c/commit-first"] == "AFTER" and ages["rest/r/rollback-first"] == "AFTER" and ages["rest/c/keepalive-9"] == "BEFORE"


def test_two_recordings_of_one_service_project_identically():
    assert projection(record(expiry=True)[0], TABLE) == projection(record(expiry=True)[0], TABLE)
