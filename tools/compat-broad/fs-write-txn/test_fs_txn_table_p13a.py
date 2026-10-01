"""P13a's table (REST): the shape it declares, its timing against the recorded values, and the recordings it produces against stand-in
services that answer an expired or idle-expired transaction by each model the table leaves open."""

import pytest

import fs_txn_table_p13a as p13a
import txn_program_cli as cli
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest
from test_txn_program_collector import Clock, Service

TABLE = p13a.TABLE
NONCE, OWNER = "a" * 32, "b" * 32
GONE = "The referenced transaction has expired or is no longer valid."
RECORDED_PACE = 2.0   # seconds per step in the stand-in; P11 v4 recorded the keepalive chain at about 2.26 to 2.6 s a step including the wait overhead
# P11 v4 (REST) token ages of the expiry read: 284.8 to 287.9 s after waits that total 260 s over 11 steps (about 2.26 to 2.6 s of overhead a step);
# P11 REST recording 1: a request refused at 298.7 to 301.0 s and the Commit after it forgotten at about 302.2 s; P10-C: idle 110 s accepted, 120 s refused.
STEP_OVERHEAD = (2.26, 2.6)
REMEMBERED_UNTIL, FORGOTTEN_BY, IDLE_REFUSED = 298.7, 302.2, 120.54


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def names(chain):
    return [step["id"].split("/", 2)[2] for step in plan()["steps"] if step["id"].startswith(f"rest/{chain}/")]


def collector(service, clock):
    value = plan()
    return Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)


def record(**knobs):
    clock = Clock()
    knobs.setdefault("rpc_seconds", RECORDED_PACE)
    service = Service(clock, **knobs)
    return collector(service, clock).run(), service, clock


def age_bounds(chain, step_name):
    """The token age at a step's dispatch at the recorded overhead per step: the waits up to and including it plus the steps before it."""
    chain_steps = [step for step in plan()["steps"] if step["id"].startswith(f"rest/{chain}/")]
    index = next(i for i, step in enumerate(chain_steps) if step["id"].endswith("/" + step_name))
    waits = sum(step.get("waitSeconds", 0) for step in chain_steps[: index + 1])
    return tuple(waits + index * overhead for overhead in STEP_OVERHEAD)


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p13a-inferred-answers"] == "fs_txn_table_p13a" and cli.table_for("p13a-inferred-answers") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p13a.py" in cli.source_manifest("p13a-inferred-answers")


def test_the_requests_and_waits_stay_inside_their_clock():
    value = plan()
    assert len(value["steps"]) == 41 and len(value["cases"]) == 9
    assert value["caps"] == {"observation": 41, "tokenCleanup": 4, "documentCleanup": 7, "management": 7, "credential": 2}
    assert value["maxRequests"] == 61 and value["maxTokens"] == 4
    assert sum(value["waits"].values()) == 2 * (9 * 24 + 12 + 32) + (130 + 100 + 50) + (130 + 175) == 1105
    assert value["thresholds"] == {"totalAgeSeconds": 270, "releaseAfterAgeSeconds": 275}
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p13a-inferred-answers-001"
    assert {step["transport"] for step in value["steps"] if not step["id"].startswith("setup/")} == {"rest"}
    # 41 requests at up to 1.6 s with a 1 s gap, plus the waits, with room for the last request and the admission margin
    need = 1105 + 41 * (1.6 + 1.0) + 13
    assert need <= TABLE["observationSeconds"] == 1320


def test_each_chain_runs_in_the_declared_order():
    keep = [f"keepalive-{index}" for index in range(1, 10)]
    assert names("uc") == ["begin", "read-a", *keep, "live-read", "first-commit", "post-read-a"]
    assert names("ur") == ["begin", "read-a", *keep, "live-read", "first-rollback", "read-after"]
    assert names("i1") == ["begin", "read-a", "idle-read", "memory-read", "late-rollback", "read-after"]
    assert names("i2") == ["begin", "read-a", "idle-read", "late-read"]
    assert [step["id"] for step in plan()["steps"]][-1] == "final/post-read-a"


def test_the_first_requests_land_between_the_lifetime_and_the_forgetting_age():
    for chain, name in (("uc", "first-commit"), ("ur", "first-rollback")):
        low, high = age_bounds(chain, name)
        # past the 270 s lifetime with a margin and before the age a request was still answered 10 (298.7 s)
        assert 275 < low and high < REMEMBERED_UNTIL, (chain, low, high)
    # the idle chain's Rollback and the read after it are still inside the remembered window
    low, high = age_bounds("i1", "late-rollback")
    assert 275 < low and high < REMEMBERED_UNTIL
    low, high = age_bounds("i1", "read-after")
    assert 275 < low and high < REMEMBERED_UNTIL
    # the first idle read is well past the idle limit and well before the lifetime
    assert p13a.IDLE_WAIT >= IDLE_REFUSED + 5
    low, high = age_bounds("i1", "idle-read")
    assert high < 270 and age_bounds("i1", "memory-read")[1] < 270
    # the idle chain's last read is past the forgetting age at the smallest overhead
    assert age_bounds("i2", "late-read")[0] > FORGOTTEN_BY


def test_the_release_rule_applies_at_every_release_site():
    # the age rule needs the token certainly older than 275 s where a refused Rollback releases it
    for chain, name in (("uc", "first-commit"), ("ur", "first-rollback"), ("i1", "late-rollback"), ("i2", "late-read")):
        assert age_bounds(chain, name)[0] > 275 + 1, (chain, name)
    # the idle chains reach the chain-end release (the cleanup Rollback) after their last read
    assert age_bounds("i2", "late-read")[0] + 1 > 275


def test_every_answer_after_a_wait_may_be_anything_and_only_the_controls_are_strict():
    steps = plan()["steps"]
    for step in steps:
        if step["id"].startswith("setup/") or step["id"].endswith(("/begin", "/read-a")):
            assert step["role"] == "control" and step["allow"] in ([0], [5]), step["id"]
        elif step["role"] == "post-state":
            assert step["allow"] == [0], step["id"]
        else:
            assert step["allow"] == [0, 3, 5, 9, 10], step["id"]
    cased = [step["id"] for step in steps if step["caseId"]]
    assert cased == ["rest/uc/first-commit", "rest/ur/first-rollback", "rest/ur/read-after", "rest/i1/idle-read", "rest/i1/memory-read", "rest/i1/late-rollback",
                     "rest/i1/read-after", "rest/i2/idle-read", "rest/i2/late-read"]
    assert [step["caseId"] for step in steps if step["id"].split("/")[-1].startswith("keepalive") or step["id"].endswith("live-read")] == [None] * 20


def test_every_state_label_is_declared_and_used():
    assert set(TABLE["states"]) == {write["state"] for step in plan()["steps"] for write in step["writes"]} | {"created"}


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "8ef5cfc17df36c81844790b92d1439654d12e084f8b9323342eec3a6273be77e"


def answering(model):
    """A service that answers a dead (expired or idle-expired) token by one of the models this table leaves open."""
    def wrap(service):
        original = service.send
        def send(transport, method, request, **kwargs):
            answer = original(transport, method, request, **kwargs)
            token = request.get("transaction")
            if not token or answer["code"] not in (10, 0) or service.tokens.get(token) != "dead":
                return answer
            age = service.clock.now() - service.tstart[token]
            def as_(code, details):
                return {**answer, "code": code, "details": details, "response": None, "http": 409 if code == 10 else 400}
            gone, invalid = as_(10, GONE), as_(3, "Invalid transaction.")
            if model == "remembered-then-forgotten":
                return gone if age < 300 else invalid
            if model == "forgotten-at-once":
                return invalid
            if model == "rollback-zero":
                return {**answer, "code": 0, "details": "", "response": {}, "http": 200} if method == "Rollback" else gone
            if model == "P08":
                return as_(3, GONE)
            raise AssertionError(model)
        service.send = send
        return service
    return wrap


@pytest.mark.parametrize("model", ["remembered-then-forgotten", "forgotten-at-once", "rollback-zero", "P08"])
def test_a_recording_completes_under_every_model_and_records_all_nine_cases(model):
    clock = Clock()
    service = answering(model)(Service(clock, expiry=True, lifetime=270, idle=120, rpc_seconds=RECORDED_PACE))
    receipt = collector(service, clock).run()
    assert receipt["complete"] is True, (model, receipt["failureType"], receipt["openTokens"])
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    assert set(cases) == set(plan()["cases"]) and len(cases) == 9
    assert all(entry["state"] in ("released-refused", "released-expired", "rolled-back", "committed") for entry in receipt["tokens"].values())
    if model == "remembered-then-forgotten":
        assert cases["rest/uc-first-commit"] == 10 and cases["rest/ur-first-rollback"] == 10
        assert cases["rest/i1-idle-read"] == 10 and cases["rest/i1-memory-read"] == 10 and cases["rest/i1-read-after"] == 10
        assert cases["rest/i2-idle-read"] == 10 and cases["rest/i2-late-read"] == 3
    if model == "forgotten-at-once":
        assert cases["rest/uc-first-commit"] == 3 and cases["rest/i1-memory-read"] == 3 and cases["rest/i2-idle-read"] == 3


def test_a_service_whose_limits_are_not_reached_lets_everything_through_and_the_recording_still_completes():
    # stand-in limits beyond every wait: the first requests are accepted, nothing is frozen as an expiry answer
    receipt, service, clock = record(expiry=True, lifetime=2000, idle=2000)
    assert receipt["complete"] is True, receipt["failureType"]
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    assert set(cases.values()) == {0}
    assert receipt["cleanup"] == {"absent": True} and service.documents == {}


def test_two_recordings_of_one_service_project_identically():
    def run():
        clock = Clock()
        service = answering("remembered-then-forgotten")(Service(clock, expiry=True, lifetime=270, idle=120, rpc_seconds=RECORDED_PACE))
        receipt = collector(service, clock).run()
        return projection(receipt, TABLE)
    assert run() == run()
