"""P12's table: the shape it declares, and the recordings it produces against stand-in services."""

import pytest

import fs_txn_table_p12 as p12
import txn_program_cli as cli
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest
from test_txn_program_collector import Clock, Service

TABLE = p12.TABLE
NONCE, OWNER = "a" * 32, "b" * 32
GONE = "The referenced transaction has expired or is no longer valid."


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def names(transport, chain):
    return [step["id"].split("/", 2)[2] for step in plan()["steps"] if step["id"].startswith(f"{transport}/{chain}/")]


def record(**knobs):
    clock = Clock()
    value = plan()
    service = Service(clock, **knobs)
    collector = Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)
    return collector.run(), service


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p12-first-request"] == "fs_txn_table_p12" and cli.table_for("p12-first-request") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p12.py" in cli.source_manifest("p12-first-request")


def test_the_requests_and_waits_stay_inside_their_clock():
    value = plan()
    assert len(value["steps"]) == 64 and len(value["cases"]) == 14
    assert value["caps"] == {"observation": 64, "tokenCleanup": 4, "documentCleanup": 7, "management": 7, "credential": 2}
    assert value["maxRequests"] == 84 and value["maxTokens"] == 4
    assert sum(value["waits"].values()) == 4 * (9 * 24 + 62) == 1112
    assert value["observationSeconds"] == 1500 and value["thresholds"] == {"totalAgeSeconds": 270}
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p12-first-request-001"


def test_each_chain_meets_an_expiry_first_and_the_rest_in_the_declared_order():
    for transport in ("rest", "grpc"):
        keep = [f"keepalive-{index}" for index in range(1, 10)]
        assert names(transport, "c") == ["begin", "read-a", *keep, "commit-first", "read-after", "read-again", "rollback-last", "post-read-a"]
        assert names(transport, "r") == ["begin", "read-a", *keep, "rollback-first", "read-after", "commit-last", "post-read-a"]


def test_the_chains_grow_old_by_keepalive_and_the_first_request_after_the_lifetime_follows_the_last_wait():
    steps = {step["id"]: step for step in plan()["steps"]}
    for transport in ("rest", "grpc"):
        for chain, first in (("c", "commit-first"), ("r", "rollback-first")):
            waits = [step["waitSeconds"] for step in plan()["steps"] if step["id"].startswith(f"{transport}/{chain}/") and "waitSeconds" in step]
            assert waits == [24] * 9 + [62] and max(waits) < 120 and sum(waits) > 270
            assert steps[f"{transport}/{chain}/{first}"]["waitSeconds"] == 62
            assert not any("waitSeconds" in step for step in plan()["steps"] if step["id"].startswith(f"{transport}/{chain}/") and step["id"].endswith(("read-after", "read-again", "rollback-last", "commit-last")))


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
    assert corpus_digest(TABLE) == "3f4891160d31a1268e900b570d0c6e2db86e9454b8c23c9eaa533c8dda103e76"


def test_a_recording_with_the_documented_lifetime_completes():
    receipt, service = record(expiry=True, lifetime=270, idle=120)
    assert receipt["complete"] is True, receipt["failureType"]
    projected = projection(receipt, TABLE)
    cases = {case["caseId"]: case["code"] for case in projected["cases"]}
    assert cases["rest/c-commit-first"] == 10 and cases["rest/r-rollback-first"] == 10
    assert cases["grpc/c-read-after"] == 10 and cases["grpc/r-commit-last"] == 10
    ages = {wait["site"]: wait["ageClass"] for wait in projected["waits"]}
    assert ages["rest/c/commit-first"] == "AFTER" and ages["rest/r/rollback-first"] == "AFTER" and ages["grpc/c/keepalive-9"] == "BEFORE"


def _answers_as(model):
    """A service answering an expired transaction by one of the two models P11 leaves open."""
    def wrap(service):
        original, seen = service.send, {}
        def send(transport, method, request, **kwargs):
            answer = original(transport, method, request, **kwargs)
            token = request.get("transaction")
            if not token or answer["code"] not in (10, 0) or service.tokens.get(token) != "dead":
                return answer
            first = token not in seen
            seen[token] = True
            gone = {**answer, "code": 10, "details": GONE, "response": None, "http": 409 if transport == "rest" else None}
            invalid = {**answer, "code": 3, "details": "Invalid transaction.", "response": None, "http": 400 if transport == "rest" else None}
            if model == "A":  # the first refused request answers 10, everything after 3
                return gone if first else invalid
            return gone if method == "GetDocument" else invalid  # model B: reads 10, Commit and Rollback 3
        service.send = send
        return service
    return wrap


@pytest.mark.parametrize("model", ["A", "B"])
def test_a_recording_completes_under_either_model_p11_leaves_open(model):
    clock = Clock()
    value = plan()
    service = _answers_as(model)(Service(clock, expiry=True, lifetime=270, idle=120))
    receipt = Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()
    assert receipt["complete"] is True, (model, receipt["failureType"])
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    if model == "A":
        assert cases["rest/c-commit-first"] == 10 and cases["rest/c-read-after"] == 3 and cases["rest/c-read-again"] == 3
    else:
        assert cases["rest/c-commit-first"] == 3 and cases["rest/c-read-after"] == 10 and cases["rest/c-read-again"] == 10
    assert all(step["state"] in ("released-refused", "rolled-back", "committed") for step in receipt["tokens"].values())


def test_two_recordings_of_one_service_project_identically():
    assert projection(record(expiry=True)[0], TABLE) == projection(record(expiry=True)[0], TABLE)
