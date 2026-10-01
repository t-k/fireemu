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


SHAPE = "retries on something other than a REST read-write begin"
TARGET = "retries a token that is not an earlier read-write token of this table over REST"


def refused_with(steps, message, **changes):
    # no release age here: a table that declares one is refused for any gRPC transaction step first, which would mask the retry checks
    changes.setdefault("thresholds", {"totalAgeSeconds": 270})
    with pytest.raises(ValueError, match=message):
        compile_plan(table(steps, **changes), NONCE, OWNER)


@pytest.mark.parametrize("changes,message", [
    ({"transport": "grpc"}, SHAPE),
    ({"mode": "readOnly"}, SHAPE),
    ({"readAt": {"document": "a", "commit": "setup/create-a"}}, SHAPE),
    ({"retryOf": "nothing"}, TARGET),
    ({"retryOf": "t2"}, TARGET),
    ({"retryOf": 7}, TARGET),
])
def test_a_retry_that_is_not_a_rest_read_write_begin_of_an_earlier_token_never_compiles(changes, message):
    refused_with(replace(SETUP + RT1 + RT2, "rest/t2/retry-begin", **changes), message)


def test_a_retry_cannot_name_a_token_issued_later_or_over_grpc_or_read_only():
    steps = SETUP + RT1 + RT2
    refused_with(replace(steps, "rest/t2/retry-begin", retryOf="t3"), TARGET)   # t3 is issued after the retry
    refused_with(replace(steps, "rest/t1/begin", mode="readOnly"), TARGET)      # a read-only token is not retried
    # a token issued over gRPC is not retried over REST
    grpc_first = replace(steps, "rest/t1/begin", transport="grpc")
    grpc_first = replace(grpc_first, "rest/t1/read-a", transport="grpc")
    grpc_first = replace(grpc_first, "rest/t1/rollback", transport="grpc")
    refused_with(grpc_first, TARGET)


def test_a_retry_of_an_earlier_chain_after_another_chain_began_never_compiles():
    # t1's chain, then a new chain (t3), then a retry that names t1: the retry would be t1's last use after another chain began
    steps = SETUP + RT1[:3] + RT2[:2] + [step("rest/t1b/retry-late", "rest", "BeginTransaction", "observation", token_out="t1r", retry_of="t1", case="rest/t1b-retry", allow=ANY)]
    refused_with(steps, "begins while an earlier chain still uses its token", maxTokens=3)


def test_only_a_retry_may_wait_on_a_begin():
    steps = SETUP + RT1 + RT2
    refused_with(replace(steps, "rest/t1/begin", waitSeconds=5), "waits outside a transaction")
    refused_with(replace(steps, "rest/t3/begin", waitSeconds=5), "waits outside a transaction")


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


def test_a_retry_refused_as_expired_marks_the_named_token_gone_so_its_release_may_answer_invalid_transaction():
    from txn_program_collector import GONE_CODE, GONE_DETAILS
    plan = compile_plan(table(), NONCE, OWNER)
    ledger = Ledger(plan)
    ledger.tokens["t3"] = {"value": "dG9rZW4z", "state": "open", "transport": "rest", "start": {}, "lastUse": {}}
    retry = next(row for row in plan["steps"] if row["id"] == "rest/t3r/retry-idle")
    request = {"database": plan["database"], "options": {"readWrite": {"retryTransaction": "dG9rZW4z"}}}
    timing = {"dispatchMonotonic": 1.0, "responseMonotonic": 2.0, "dispatchUtc": "2026-09-30T00:00:01.000000Z", "responseUtc": "2026-09-30T00:00:02.000000Z"}
    refusal = {"kind": "txn-program-receipt-v1", "transport": "rest", "complete": True, "code": GONE_CODE, "details": GONE_DETAILS, "response": None, "http": 409, "dispatchedRequests": 1, "childReaped": True}
    ledger.before("rest/t3r/retry-idle", "rest", "BeginTransaction", request, retry)
    ledger.after("rest/t3r/retry-idle", "rest", "BeginTransaction", request, retry, refusal, timing)
    assert "t3" in ledger.gone_seen


def test_the_guard_exemption_covers_only_an_open_token_not_one_in_unconfirmed_release():
    plan = compile_plan(table(), NONCE, OWNER)
    ledger = Ledger(plan)
    ledger.tokens["t1"] = {"value": "dG9rZW4x", "state": "unconfirmed-release", "transport": "rest", "start": {}, "lastUse": {}}
    request = {"database": plan["database"], "options": {"readWrite": {"retryTransaction": "dG9rZW4x"}}}
    with pytest.raises(ValueError, match="unresolved"):
        ledger.guard("BeginTransaction", request, None)
    ledger.tokens["t1"]["state"] = "open"
    ledger.guard("BeginTransaction", request, None)


def test_the_token_a_retry_issued_is_released_before_the_next_chain_begins():
    # RT-2 first, then RT-1: the retry's own token (t3r) stays open until its release, which must precede the next chain's begin
    clock = Clock()
    service = Service(clock, expiry=True, lifetime=270, idle=120, rpc_seconds=2.0)
    run, tbl = collector(service, clock, SETUP + RT2 + RT1)
    receipt = run.run()
    assert receipt["complete"] is True, (receipt["failureType"], receipt["openTokens"])
    order = [row["site"] for row in sorted(receipt["steps"] + receipt["cleanupSteps"], key=lambda row: row["sequence"])]
    release = order.index("cleanup/token/t3r")
    assert release < order.index("rest/t1/begin"), "the retry's token is released before the next chain begins"
    assert receipt["tokens"]["t3r"]["state"] in ("rolled-back", "released-refused", "released-expired")


def _retry_ledger():
    plan = compile_plan(table(), NONCE, OWNER)
    ledger = Ledger(plan)
    ledger.tokens["t3"] = {"value": "dG9rZW4z", "state": "open", "transport": "rest", "start": {}, "lastUse": {}}
    retry = next(row for row in plan["steps"] if row["id"] == "rest/t3r/retry-idle")
    request = {"database": plan["database"], "options": {"readWrite": {"retryTransaction": "dG9rZW4z"}}}
    timing = {"dispatchMonotonic": 1.0, "responseMonotonic": 2.0, "dispatchUtc": "2026-09-30T00:00:01.000000Z", "responseUtc": "2026-09-30T00:00:02.000000Z"}
    return plan, ledger, retry, request, timing


def test_a_retry_refused_as_expired_lets_the_later_invalid_transaction_release_count_as_released_and_the_recording_finish():
    from txn_program_collector import GONE_CODE, GONE_DETAILS, INVALID_DETAILS
    plan, ledger, retry, request, timing = _retry_ledger()
    refusal = {"kind": "txn-program-receipt-v1", "transport": "rest", "complete": True, "code": GONE_CODE, "details": GONE_DETAILS, "response": None, "http": 409, "dispatchedRequests": 1, "childReaped": True}
    ledger.before("rest/t3r/retry-idle", "rest", "BeginTransaction", request, retry)
    ledger.after("rest/t3r/retry-idle", "rest", "BeginTransaction", request, retry, refusal, timing)
    release = {"database": plan["database"], "transaction": "dG9rZW4z"}
    ledger.before("cleanup/token/t3", "rest", "Rollback", release, None)
    later = {**timing, "dispatchMonotonic": 3.0, "responseMonotonic": 4.0, "dispatchUtc": "2026-09-30T00:00:03.000000Z", "responseUtc": "2026-09-30T00:00:04.000000Z"}
    forgotten = {"kind": "txn-program-receipt-v1", "transport": "rest", "complete": True, "code": 3, "details": INVALID_DETAILS, "response": None, "http": 400, "dispatchedRequests": 1, "childReaped": True}
    ledger.after("cleanup/token/t3", "rest", "Rollback", release, None, forgotten, later)
    assert ledger.tokens["t3"]["state"] == "released-refused"
    assert not ledger.unknown_rollbacks


def test_a_rest_retry_answered_with_the_named_tokens_own_bytes_stops_as_an_unknown_start():
    # Every recorded accepted retry minted a different token, over gRPC (P09, P10); a REST retry that returned the named token's own bytes is
    # unrecorded, so the ledger refuses it and keeps the start unknown for the recovery rather than guessing which token the service means.
    plan, ledger, retry, request, timing = _retry_ledger()
    same = {"kind": "txn-program-receipt-v1", "transport": "rest", "complete": True, "code": 0, "details": "", "response": {"transaction": "dG9rZW4z"}, "http": 200, "dispatchedRequests": 1, "childReaped": True}
    ledger.before("rest/t3r/retry-idle", "rest", "BeginTransaction", request, retry)
    with pytest.raises(ValueError, match="not fresh"):
        ledger.after("rest/t3r/retry-idle", "rest", "BeginTransaction", request, retry, same, timing)
    assert "rest/t3r/retry-idle" in ledger.unknown_starts
    assert "t3r" not in ledger.tokens
