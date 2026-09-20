"""Recovery/timing invariants at the real collector's normalized RPC boundary.

Endpoints here are controlled Python fixtures, never production/native evidence.
"""
from __future__ import annotations

import copy
import math
import sys
from pathlib import Path

import pytest

sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parents[1])]
import txn_expiry_collector as c
import txn_expiry_comparison as comparison
import txn_expiry_plan as plan
import test_txn_expiry_collector as fixtures
import test_txn_expiry_comparison as compared


def make(transport, *, now=lambda: 0.0, advance=None):
    options = fixtures.options()
    compiled = plan.compile_plan(options["nonce"], options["ownerId"], project=options["projectId"])
    return c.Collection(options, compiled, transport,
                        monotonic=now, advance=advance or fixtures.advances([]))


def error(code, **extras):
    return {"code": code, "status": c.CANONICAL_STATUS[code], "complete": True, **extras}


@pytest.mark.parametrize("code", [1, 2, 4, 8, 10, 13, 14, 15])
def test_ambiguous_create_error_does_not_forget_applied_write(code):
    class Applied(fixtures.StatefulEndpoint):
        def __call__(self, request):
            result = super().__call__(request)
            writes = (request.get("body") or {}).get("writes", [])
            if (request["rpc"] == "Commit" and writes
                    and writes[0].get("currentDocument", {}).get("exists") is False):
                return error(code)
            return result
    endpoint = Applied()
    receipt, _ = fixtures.run_against(endpoint)
    assert receipt["complete"] is False  # the failed observation is never repaired
    assert receipt["responsibility"][0]["role"] == "control"
    assert receipt["responsibility"][0]["resolved"] is True  # exact owned readback then delete
    assert endpoint.documents == {}
    assert receipt["requestCount"] == len(endpoint.calls)


@pytest.mark.parametrize("code", [1, 2, 4, 8, 10, 13, 14, 15])
def test_ambiguous_create_then_absence_keeps_late_apply_responsibility(code):
    class Pending(fixtures.StatefulEndpoint):
        def __call__(self, request):
            writes = (request.get("body") or {}).get("writes", [])
            if (request["rpc"] == "Commit" and writes
                    and writes[0].get("currentDocument", {}).get("exists") is False):
                self.calls.append(copy.deepcopy(request))
                self.pending = request
                return error(code)
            return super().__call__(request)
    endpoint = Pending()
    receipt, collection = fixtures.run_against(endpoint)
    assert receipt["responsibility"] == [{"role": "control", "state": c.SENT_UNKNOWN, "resolved": False}]
    assert receipt["unrecovered"] == ["control"]
    assert endpoint.deletes == []
    # Demonstrate the race the absence read cannot exclude.
    write = endpoint.pending["body"]["writes"][0]
    endpoint.documents[write["update"]["name"]] = write["update"]["fields"]
    assert collection._name("control") in endpoint.documents


@pytest.mark.parametrize("code", [3, 6, 7, 9, 16])
def test_definitive_create_refusal_gives_no_delete_authority(code):
    requests = []
    def send(req):
        requests.append(req)
        return error(5 if req["rpc"] == "GetDocument" else code)
    col = make(send); receipt = col.run()
    # Authority refusals stop before the precondition recorder; no sends follow.
    if code in c.AUTHORITY_REFUSALS:
        assert receipt["authorityRefusal"]
    else:
        assert receipt["resourceStates"]["control"] == c.ABSENCE_CONFIRMED
        assert receipt["responsibility"] == []
    assert not any(w.get("delete") for q in requests for w in (q.get("body") or {}).get("writes", []))


@pytest.mark.parametrize("bad", [
    {"complete": False}, {"complete": 1}, {"complete": "true"},
    {"code": False}, {"code": 0.0}, {"status": "ABORTED"},
    {"body": {"error": {"status": "INTERNAL"}}}, {"body": {"ignored": True}},
    {"failure": "interrupted"}, {"incomplete": "body-cut"},
])
def test_incomplete_or_contradictory_rollback_never_releases(bad):
    response = {"code": 0, "status": "OK", "complete": True, "body": {}, **bad}
    col = make(lambda _q: response); col.open_tokens["live"] = b"token"
    releases = col._release_transactions(c._Deadline(180, lambda: 0))
    assert releases[0]["released"] is False
    assert col.open_tokens == {"live": b"token"}


@pytest.mark.parametrize("bad", [
    {"complete": False}, {"complete": 1}, {"code": 5.0},
    {"status": "PERMISSION_DENIED"},
    {"body": {"error": {"status": "NOT_FOUND", "code": 404}, "name": "present"}},
    {"body": {"error": {"status": "NOT_FOUND", "code": 404.0}}},
    {"body": {}},
])
def test_incomplete_absence_never_completes_cleanup(bad):
    response = error(5, **bad) if "code" not in bad else {**error(5), **bad}
    col = make(lambda _q: response)
    col.established["control"] = {"updateTime": "2026-09-18T00:00:00Z"}
    col.resource_state["control"] = c.CREATION_CONFIRMED
    entry = col._recover_one("control", c._Deadline(180, lambda: 0))
    assert entry["complete"] is False
    assert entry["absent"] is False


@pytest.mark.parametrize("body", [
    {}, {"writeResults": []}, {"writeResults": [{}]},
    {"writeResults": [{"updateTime": "not-a-time"}]},
    {"writeResults": [{"updateTime": "2026-02-30T00:00:00Z"}]},
    {"writeResults": [{"updateTime": "2026-09-18T00:00:00Z"}], "error": {}},
    {"writeResults": [{"updateTime": "2026-09-18T00:00:00Z", "error": {}}]},
])
def test_malformed_successful_create_never_grants_ownership(body):
    calls = []
    def transport(q):
        calls.append(q)
        if q["rpc"] == "GetDocument": return error(5)
        return {"code": 0, "status": "OK", "complete": True, "body": body}
    col = make(transport); receipt = col.run()
    assert col.established == {}
    assert receipt["unrecovered"] == ["control"]
    assert receipt["resourceStates"]["control"] == c.SENT_UNKNOWN
    assert len(calls) == len(col.plan["resources"]) + 2  # all preflights, one create, recovery read
    assert [q["rpc"] for q in calls].count("Commit") == 1


@pytest.mark.parametrize("value", [None, True, "90", -1, math.nan, math.inf, 10**400])
def test_unmeasured_virtual_time_does_not_invent_expiry(value):
    endpoint = fixtures.Endpoint()
    col = make(endpoint, advance=lambda _seconds: value)
    receipt = col.run()
    assert receipt["failure"] == "clock-advance-unconfirmed"
    assert receipt["complete"] is False
    assert receipt["virtualClockConfirmed"] is False
    assert col.virtual_elapsed == 0
    # Valid rollback acknowledgements still permit recovery under valid wall time.
    assert receipt["openTransactions"] == []
    assert receipt["unrecovered"] == []


@pytest.mark.parametrize("value", [True, None, -1, math.nan, math.inf, 10**400])
def test_bad_monotonic_clock_never_sends(value):
    calls = []
    col = make(lambda q: calls.append(q), now=lambda: value)
    receipt = col.run()
    assert calls == []
    assert receipt["clockIntegrityFailure"]
    assert receipt["complete"] is False


def test_wait_consuming_wall_deadline_sends_no_next_observation():
    clock = {"now": 0.0}
    endpoint = fixtures.Endpoint()
    def advance(_seconds):
        clock["now"] = 301.0
        return 20
    col = make(endpoint, now=lambda: clock["now"], advance=advance)
    receipt = col.run()
    assert receipt["failure"] == "deadline-reached"
    assert not any(row["slot"] == "idle/commit-before" for row in receipt["rows"])
    assert receipt["openTransactions"] == []
    assert receipt["unrecovered"] == []  # independent recovery tail remains


def test_recovery_each_request_gets_remaining_time_and_stops_when_spent():
    clock = {"now": 0.0}; seen = []
    def transport(req):
        seen.append(req)
        clock["now"] += 4
        return {"complete": True, "code": 0, "status": "OK", "body": {}}
    col = make(transport, now=lambda: clock["now"])
    col.open_tokens.update(a=b"a", b=b"b", c=b"c")
    deadline = c._Deadline(5, col.monotonic); col.active_deadline = deadline
    releases = col._release_transactions(deadline)
    assert [q["timeoutSeconds"] for q in seen] == [5, 1]
    assert list(col.open_tokens) == ["c"]
    assert releases[-1]["failure"] == "recovery-deadline-reached"


def test_partial_commit_response_does_not_close_live_transaction():
    class Partial(fixtures.Endpoint):
        def __call__(self, q):
            r = super().__call__(q)
            if q["rpc"] == "Commit" and (q.get("body") or {}).get("transaction"):
                return {**r, "complete": False}
            return r
    endpoint = Partial(); receipt = make(endpoint).run()
    assert receipt["complete"] is False
    assert any(r["transaction"] == "d" for r in receipt["transactionReleases"])


@pytest.mark.parametrize("field", ["idleSeconds", "measuredSeconds", "requestedSeconds"])
@pytest.mark.parametrize("value", [math.nan, math.inf, -1, True, "90"])
def test_comparator_refuses_bad_time_instead_of_semantic_match(field, value):
    prod, local = compared.production(), compared.local()
    for receipt in (prod, local):
        for row in receipt["rows"]:
            if field == "idleSeconds" and field in row: row[field] = value
            elif field != "idleSeconds" and row.get("waited"): row["waited"][field] = value
    report = comparison.compare(prod, local)
    assert report["classification"] == comparison.INDETERMINATE


@pytest.mark.parametrize("value", [False, 1, None, "true"])
def test_comparator_requires_real_completion(value):
    local = compared.local();local["complete"] = value
    assert comparison.compare(compared.production(), local)["classification"] == comparison.INDETERMINATE


@pytest.mark.parametrize("reply", [
    {"code": 0, "status": "OK", "body": {}},
    {"code": 0, "status": "OK", "body": {"transaction": "not base64!"}},
    {"code": 4, "status": "DEADLINE_EXCEEDED", "complete": True},
    {"code": None, "complete": False},
])
def test_begin_without_confirmed_token_keeps_unknown_transaction_responsibility(reply):
    class BeginUnknown(fixtures.Endpoint):
        def __call__(self,q):
            if q["rpc"] == "BeginTransaction":
                self.calls.append(q);return copy.deepcopy(reply)
            return super().__call__(q)
    endpoint=BeginUnknown();receipt=make(endpoint).run()
    assert receipt["unconfirmedTransactionStarts"] == ["a"]
    assert receipt["complete"] is False
    # Known documents can be cleaned even when an unnamed transaction stays unknown.
    assert receipt["unrecovered"] == []


def test_monotonic_integrity_latches_even_when_clock_recovers():
    clock={"now":1.0}; calls=[]
    col=make(lambda req:calls.append(req),now=lambda:clock["now"])
    assert col.monotonic()==1.0
    clock["now"]=0.0
    with pytest.raises(c._Stopped):col.monotonic()
    clock["now"]=2.0
    assert col._rollback(b"known")["complete"] is False
    assert calls==[]
