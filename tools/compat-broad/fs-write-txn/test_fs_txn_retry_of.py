"""The `retryOf` step key: a REST read-write begin that names one earlier token as the attempt it retries. Validation, the request it builds,
the ledger's release order and a recording against stand-in services that accept or refuse the retry."""

import copy
from pathlib import Path

import pytest

from txn_program_collector import Collector, Ledger, projection
from txn_program_program import RequestBudget, compile_plan, corpus_digest, request_for_step
from test_txn_program_collector import Clock, Service

NONCE, OWNER = "a" * 32, "b" * 32
ANY = (0, 3, 5, 9, 10)


def step(step_id, transport, rpc, role, *, document=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,), wait=None, retry_of=None, mode=None):
    row = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
           "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
           "caseId": case, "role": role, "allow": allow}
    if wait:
        row["waitSeconds"] = wait
    if retry_of:
        row["retryOf"] = retry_of
    if mode:
        row["mode"] = mode
    return row


SETUP = [step("setup/absence-a", "grpc", "GetDocument", "control", document="a", allow=(5,)),
         step("setup/create-a", "grpc", "Commit", "control", writes=(("a", "created", False),))]
# RT-1: a retry after a Rollback keeps its later steps; RT-2: a retry naming an idle token ends its chain.
RT1 = [step("rest/t1/begin", "rest", "BeginTransaction", "control", token_out="t1"),
       step("rest/t1/read-a", "rest", "GetDocument", "control", document="a", token_in="t1"),
       step("rest/t1/rollback", "rest", "Rollback", "observation", token_in="t1", case="rest/t1-rollback", allow=(0, 10)),
       step("rest/t2/retry-begin", "rest", "BeginTransaction", "control", token_out="t2", retry_of="t1"),
       step("rest/t2/read-a", "rest", "GetDocument", "observation", document="a", token_in="t2", case="rest/t2-read", allow=ANY),
       step("rest/t2/rollback", "rest", "Rollback", "observation", token_in="t2", case="rest/t2-rollback", allow=(0, 10))]
RT2 = [step("rest/t3/begin", "rest", "BeginTransaction", "control", token_out="t3"),
       step("rest/t3/read-a", "rest", "GetDocument", "control", document="a", token_in="t3"),
       step("rest/t3r/retry-idle", "rest", "BeginTransaction", "observation", token_out="t3r", retry_of="t3", case="rest/t3r-retry", allow=ANY, wait=130)]


def table(steps=None, **changes):
    steps = tuple(steps if steps is not None else SETUP + RT1 + RT2)
    value = {"name": "toy-retry-of", "program": "FS-TRANSACTION-TOY-RETRY-OF", "envelopeId": "FS-TRANSACTION-toy-retry-of-001", "slug": "txn-retry", "documents": ("a",),
             "states": ("created",), "steps": steps, "thresholds": {"totalAgeSeconds": 270, "releaseAfterAgeSeconds": 275},
             "caps": {"observation": len(steps), "tokenCleanup": 4, "documentCleanup": 7, "management": 7, "credential": 2},
             "observationSeconds": 600, "recoverySeconds": 180, "maxTokens": 4, "sourceFile": Path(__file__)}
    value.update(changes)
    return value


def refused(steps):
    with pytest.raises(ValueError, match="txn-program table"):
        compile_plan(table(steps), NONCE, OWNER)


def replace(steps, step_id, **changes):
    return [{**row, **changes} if row["id"] == step_id else row for row in steps]


def test_the_toy_table_compiles_and_the_key_is_bound_into_the_digest():
    base = table()
    assert compile_plan(base, NONCE, OWNER)["maxTokens"] == 4
    plain = [{key: value for key, value in row.items() if key != "retryOf"} if row["id"] == "rest/t2/retry-begin" else row for row in SETUP + RT1 + RT2]
    assert corpus_digest(base) != corpus_digest(table(plain))


@pytest.mark.parametrize("changes,why", [
    ({"rpc": "Commit", "writes": (), "tokenInput": "t1"}, "not a begin"),
    ({"transport": "grpc"}, "gRPC"),
    ({"mode": "readOnly"}, "read-only"),
    ({"retryOf": "nothing"}, "unknown role"),
    ({"retryOf": "t2"}, "its own token"),
    ({"retryOf": 7}, "not a string"),
])
def test_a_retry_that_is_not_a_rest_read_write_begin_of_an_earlier_token_never_compiles(changes, why):
    refused(replace(SETUP + RT1 + RT2, "rest/t2/retry-begin", **changes))


def test_a_retry_cannot_name_a_token_issued_later_or_over_grpc_or_read_only():
    steps = SETUP + RT1 + RT2
    # the retry of t3 placed before t3 begins
    reordered = replace(steps, "rest/t2/retry-begin", retryOf="t3")
    refused(reordered)
    # a read-only token is not retried
    readonly = replace(steps, "rest/t1/begin", mode="readOnly")
    refused(readonly)


def test_a_retry_key_on_a_step_that_is_not_a_begin_never_compiles():
    steps = SETUP + RT1 + RT2
    refused(replace(steps, "rest/t1/read-a", retryOf="t1"))
    refused(replace(steps, "rest/t1/rollback", retryOf="t1"))


def test_the_request_names_the_retried_token_only_for_a_retry_step():
    plan = compile_plan(table(), NONCE, OWNER)
    issued = {"t1": "aXNzdWVkLXRva2Vu", "t2": "b3RoZXI="}
    retry = next(row for row in plan["steps"] if row["id"] == "rest/t2/retry-begin")
    assert request_for_step(plan, retry, issued, table()) == {"database": plan["database"], "options": {"readWrite": {"retryTransaction": "aXNzdWVkLXRva2Vu"}}}
    plain = next(row for row in plan["steps"] if row["id"] == "rest/t1/begin")
    assert request_for_step(plan, plain, issued, table()) == {"database": plan["database"], "options": {"readWrite": {}}}
    with pytest.raises(ValueError, match="never issued"):
        request_for_step(plan, retry, {}, table())


def test_the_retry_is_the_last_use_of_both_tokens():
    plan = compile_plan(table(), NONCE, OWNER)
    ledger = Ledger(plan)
    assert ledger.last_use["t3"] == "rest/t3r/retry-idle" and ledger.last_use["t3r"] == "rest/t3r/retry-idle"
    # t1 is last used by its own Rollback and then by the retry that names it; t2 by its Rollback
    assert ledger.last_use["t1"] == "rest/t2/retry-begin" and ledger.last_use["t2"] == "rest/t2/rollback"


def collector(service, clock, steps=None, **changes):
    tbl = table(steps, **changes)
    value = compile_plan(tbl, NONCE, OWNER)
    return Collector(value, tbl, RequestBudget(value, tbl), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep), tbl


def retry_refusing(service):
    """A service that refuses a retry naming a token it has finished or that idled out."""
    original = service.send
    def send(transport, method, request, **kwargs):
        retried = ((request.get("options") or {}).get("readWrite") or {}).get("retryTransaction") if method == "BeginTransaction" else None
        idle_out = retried in service.tlast and service.clock.now() - service.tlast[retried] > service.idle
        if retried is not None and (idle_out or service.tokens.get(retried) in ("dead", "rolled-back", "committed")):
            service.calls.append((transport, method, copy.deepcopy(request)))
            return service._receipt(transport, 3, details="Invalid retry transaction.")
        return original(transport, method, request, **kwargs)
    service.send = send
    return service


def test_a_recording_with_an_accepted_retry_completes_and_releases_every_token():
    clock = Clock()
    service = Service(clock, expiry=True, lifetime=270, idle=120, rpc_seconds=2.0)
    run, tbl = collector(service, clock)
    receipt = run.run()
    assert receipt["complete"] is True, (receipt["failureType"], receipt["openTokens"])
    assert set(receipt["tokens"]) == {"t1", "t2", "t3", "t3r"}
    assert all(entry["state"] in ("rolled-back", "released-refused", "released-expired") for entry in receipt["tokens"].values())
    retry_calls = [call for call in service.calls if call[1] == "BeginTransaction" and call[2]["options"]["readWrite"].get("retryTransaction")]
    assert len(retry_calls) == 2
    cases = {case["caseId"]: case["code"] for case in projection(receipt, tbl)["cases"]}
    assert cases["rest/t3r-retry"] == 0
    # the wait before a retry begin ages the token it names
    waits = {wait["site"]: wait for wait in receipt["waits"]}
    assert waits["rest/t3r/retry-idle"]["tokenRole"] == "t3" and "totalAgeInterval" in waits["rest/t3r/retry-idle"]


def test_a_recording_with_a_refused_retry_still_completes_because_the_retry_ends_its_chain():
    clock = Clock()
    service = retry_refusing(Service(clock, expiry=True, lifetime=270, idle=120, rpc_seconds=2.0))
    run, tbl = collector(service, clock, SETUP + RT2, maxTokens=2)
    receipt = run.run()
    assert receipt["complete"] is True, (receipt["failureType"], receipt["openTokens"])
    assert "t3r" not in receipt["tokens"], "a refused retry issues no token"
    assert receipt["tokens"]["t3"]["state"] in ("released-refused", "released-expired", "rolled-back")
    cases = {case["caseId"]: case["code"] for case in projection(receipt, tbl)["cases"]}
    assert cases == {"rest/t3r-retry": 3}
    row = next(row for row in receipt["steps"] if row["site"] == "rest/t3r/retry-idle")
    assert row["result"]["code"] == 3 and row["result"]["details"] == "Invalid retry transaction."


def test_a_retry_begin_may_name_the_one_open_token_but_no_other_open_token_may_remain():
    clock = Clock()
    service = Service(clock, expiry=True, lifetime=270, idle=120, rpc_seconds=2.0)
    run, tbl = collector(service, clock)
    plan = run.plan
    ledger = Ledger(plan)
    ledger.tokens["t1"] = {"value": "dG9rZW4x", "state": "open", "transport": "rest", "start": {}, "lastUse": {}}
    ledger.tokens["tx"] = {"value": "dG9rZW4y", "state": "open", "transport": "rest", "start": {}, "lastUse": {}}
    request = {"database": plan["database"], "options": {"readWrite": {"retryTransaction": "dG9rZW4x"}}}
    with pytest.raises(ValueError, match="unresolved"):
        ledger.guard("BeginTransaction", request, None)
    ledger.tokens["tx"]["state"] = "rolled-back"
    ledger.guard("BeginTransaction", request, None)
    plain = {"database": plan["database"], "options": {"readWrite": {}}}
    with pytest.raises(ValueError, match="unresolved"):
        ledger.guard("BeginTransaction", plain, None)
