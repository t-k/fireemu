"""P13b's table (REST): the shape it declares, its timing against the recorded values, and the recordings it produces against stand-in services
that accept or refuse a retry."""

import copy

import pytest

import fs_txn_table_p13b as p13b
import txn_program_cli as cli
from txn_program_collector import Collector, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest
from test_txn_program_collector import Clock, Service

TABLE = p13b.TABLE
NONCE, OWNER = "a" * 32, "b" * 32
RECORDED_PACE = 2.0   # seconds per step in the stand-in
# P13a (REST, two recordings): the first request after the same waits (260 s over 11 requests) landed at a token age of 280.4 to 284.5 s, so each
# request cost 1.85 to 2.23 s beyond its wait; an idle of 130 s was past the idle limit (P10-C and later: refused from 122.97 s); P11 REST
# recording 1: a request still answered 10 at 298.7 s.
STEP_OVERHEAD = (1.85, 2.23)
REMEMBERED_UNTIL, IDLE_REFUSED = 298.7, 122.97
P13A_FIRST_REQUEST_AGE = (280.4, 284.5)   # P13a, run 2 recordings: the token age of the first request after 260 s of waits


def plan():
    return compile_plan(TABLE, NONCE, OWNER)


def names(chain):
    return [step["id"].split("/", 2)[2] for step in plan()["steps"] if step["id"].startswith(f"rest/{chain}/")]


def collector(service, clock):
    value = plan()
    return Collector(value, TABLE, RequestBudget(value, TABLE), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)


def test_the_table_is_registered_and_bound():
    assert cli.TABLES["p13b-retry-answers"] == "fs_txn_table_p13b" and cli.table_for("p13b-retry-answers") is TABLE
    assert "tools/compat-broad/fs-write-txn/fs_txn_table_p13b.py" in cli.source_manifest("p13b-retry-answers")


def test_the_requests_tokens_and_waits_stay_inside_their_clock():
    value = plan()
    assert len(value["steps"]) == 30 and len(value["cases"]) == 8
    assert value["caps"] == {"observation": 30, "tokenCleanup": 8, "documentCleanup": 7, "management": 6, "credential": 2}
    assert value["maxRequests"] == 53 and value["maxTokens"] == 8 and value["project"] == "fireemu-oracle-txn"
    assert sum(value["waits"].values()) == 130 + 130 + 9 * 24 + 12 + 32 == 520
    assert value["thresholds"] == {"totalAgeSeconds": 270, "releaseAfterAgeSeconds": 275}
    assert TABLE["envelopeId"] == "FS-TRANSACTION-p13b-retry-answers-001"
    assert {step["transport"] for step in value["steps"] if not step["id"].startswith("setup/")} == {"rest"}
    assert 520 + 30 * (1.6 + 1.0) + 13 <= TABLE["observationSeconds"] == 780


def test_each_chain_runs_in_the_declared_order():
    assert names("rt1") == ["begin", "read-a", "rollback", "retry-begin", "writer", "first-read", "commit"]
    assert names("rt2") == ["begin", "read-a", "retry-idle"]
    assert names("rt3") == ["begin", "read-a", "rollback-idle", "retry-after-rollback"]
    keep = [f"keepalive-{index}" for index in range(1, 10)]
    assert names("rt4") == ["begin", "read-a", *keep, "live-read", "retry-lifetime"]
    assert [step["id"] for step in plan()["steps"]][-1] == "final/post-read-a"


def test_every_retry_names_the_right_token_and_only_the_first_is_a_control():
    retries = {step["id"]: step for step in plan()["steps"] if "retryOf" in step}
    assert {key: (step["retryOf"], step["tokenOutput"], step["role"]) for key, step in retries.items()} == {
        "rest/rt1/retry-begin": ("t1", "t1r", "control"), "rest/rt2/retry-idle": ("t2", "t2r", "observation"),
        "rest/rt3/retry-after-rollback": ("t3", "t3r", "observation"), "rest/rt4/retry-lifetime": ("t4", "t4r", "observation")}
    # RT-2 to RT-4 end their chains, so a refused retry strands no step
    for chain in ("rt2", "rt3", "rt4"):
        assert names(chain)[-1].startswith("retry")
    assert retries["rest/rt1/retry-begin"]["allow"] == [0]
    assert all(step["allow"] == [0, 3, 5, 9, 10] for key, step in retries.items() if key != "rest/rt1/retry-begin")


def age(chain, step_name):
    """The token age at a step's dispatch: the waits up to and including it, plus the overhead of each request between the begin and it (the begin's
    own answer starts the age, so a step at position n follows n - 1 requests)."""
    chain_steps = [step for step in plan()["steps"] if step["id"].startswith(f"rest/{chain}/")]
    index = next(i for i, step in enumerate(chain_steps) if step["id"].endswith("/" + step_name))
    waits = sum(step.get("waitSeconds", 0) for step in chain_steps[: index + 1])
    return tuple(waits + (index - 1) * overhead for overhead in STEP_OVERHEAD)


def test_the_timing_is_tied_to_the_recorded_idle_and_lifetime_values():
    assert p13b.IDLE_WAIT >= IDLE_REFUSED + 5   # 130 s against 122.97 s
    # the idle chains reach their retry well before the lifetime
    for chain, name in (("rt2", "retry-idle"), ("rt3", "rollback-idle")):
        assert age(chain, name)[1] < 270
    # the lifetime chain's retry lands past the lifetime with a margin and inside the remembered window
    low, high = age("rt4", "retry-lifetime")
    assert 275 < low and high < REMEMBERED_UNTIL
    # the release rule's age holds at the chain-end release (the retried token is certainly older than 275 s)
    assert age("rt4", "retry-lifetime")[0] > 275 + 1
    # the window equals what P13a recorded for the same waits (the first request after 260 s of waits came at 280.4 to 284.5 s of token age): the
    # earlier model (an overhead of 2.26 to 2.6 s and one more request) put it at 287.1 to 291.2 s and no longer matches the recordings
    assert abs(low - P13A_FIRST_REQUEST_AGE[0]) <= 0.5 and abs(high - P13A_FIRST_REQUEST_AGE[1]) <= 0.5, (low, high)


def test_every_answer_after_a_wait_may_be_anything_and_the_controls_are_strict():
    for step in plan()["steps"]:
        if step["id"].startswith("setup/") or step["id"].endswith(("/begin", "/read-a", "/retry-begin")):
            assert step["role"] == "control" and step["allow"] in ([0], [5]), step["id"]
        elif step["role"] == "post-state":
            assert step["allow"] == [0], step["id"]
        elif step["role"] == "outside-writer":
            assert step["allow"] == [0, 10] and step["deadlineMs"] == 30000
        elif step["id"] == "rest/rt1/rollback":
            assert step["allow"] == [0, 10]
        else:
            assert step["allow"] == [0, 3, 5, 9, 10], step["id"]


def test_every_state_label_is_declared_and_used():
    assert set(TABLE["states"]) == {write["state"] for step in plan()["steps"] for write in step["writes"]} | {"created"}


def test_the_digest_binds_the_table():
    assert corpus_digest(TABLE) == plan()["corpusDigest"]
    assert corpus_digest(TABLE) == "3c91e4695ace7cccb5089f3c8fc88425f1393ee40a13c28f97bf15ac05a63751"


def refusing(service, only_expired=False):
    """A service that refuses a retry (3 Invalid retry transaction.) naming a token it has finished or that idled or aged out."""
    original = service.send
    def send(transport, method, request, **kwargs):
        retried = ((request.get("options") or {}).get("readWrite") or {}).get("retryTransaction") if method == "BeginTransaction" else None
        if retried is not None:
            now = service.clock.now()
            state = service.tokens.get(retried)
            out = state in ("open", "dead") and retried in service.tlast and (now - service.tlast[retried] > service.idle or now - service.tstart[retried] > service.lifetime)
            done = state in ("rolled-back", "committed")
            if out or state == "dead" or (done and not only_expired):
                service.calls.append((transport, method, copy.deepcopy(request)))
                return service._receipt(transport, 3, details="Invalid retry transaction.")
        return original(transport, method, request, **kwargs)
    service.send = send
    return service


@pytest.mark.parametrize("model", ["accept-all", "refuse-expired"])
def test_a_recording_completes_under_every_retry_model_and_records_all_cases(model):
    clock = Clock()
    service = Service(clock, expiry=True, lifetime=270, idle=120, rpc_seconds=RECORDED_PACE)
    if model == "refuse-expired":
        refusing(service, only_expired=True)
    receipt = collector(service, clock).run()
    assert receipt["complete"] is True, (model, receipt["failureType"], receipt["openTokens"])
    cases = {case["caseId"]: case["code"] for case in projection(receipt, TABLE)["cases"]}
    assert set(cases) == set(plan()["cases"]) and len(cases) == 8
    assert all(entry["state"] in ("released-refused", "released-expired", "rolled-back", "committed") for entry in receipt["tokens"].values())
    if model == "accept-all":
        assert cases["rest/rt2-retry-idle"] == 0 and cases["rest/rt4-retry-lifetime"] == 0 and {"t2r", "t3r", "t4r"} <= set(receipt["tokens"])
    if model == "refuse-expired":
        assert cases["rest/rt2-retry-idle"] == 3 and cases["rest/rt4-retry-lifetime"] == 3
        assert not {"t2r", "t4r"} & set(receipt["tokens"])


def test_a_refused_control_retry_stops_the_run_and_the_recovery_releases_what_it_holds():
    # the retry after a Rollback was recorded as accepted for REST, so it is a control: a refusal is not what this table expects
    clock = Clock()
    service = refusing(Service(clock, expiry=True, lifetime=270, idle=120, rpc_seconds=RECORDED_PACE))
    receipt = collector(service, clock).run()
    assert receipt["complete"] is False and receipt["failureType"] == "ValueError"
    assert receipt["cleanup"] == {"absent": True} and receipt["openTokens"] == []


def test_two_recordings_of_one_service_project_identically():
    def run():
        clock = Clock()
        service = refusing(Service(clock, expiry=True, lifetime=270, idle=120, rpc_seconds=RECORDED_PACE), only_expired=True)
        return projection(collector(service, clock).run(), TABLE)
    assert run() == run()
