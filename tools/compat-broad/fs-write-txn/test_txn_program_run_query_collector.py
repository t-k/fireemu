"""A recording with queries: frames are checked for ownership only, a client cancel is a recorded outcome, and the replay of the rows accepts them."""

import copy
import importlib

import pytest

NONCE, OWNER = "a" * 32, "b" * 32
WIDE = (0, 3, 5, 9, 10)
CANCEL_TEXT = "cancelled by the client after 1 frame(s)"

program = importlib.import_module("txn_program_program")
collector_module = importlib.import_module("txn_program_collector")
support = importlib.import_module("txn_program_support_for_tests")
collector_tests = importlib.import_module("test_txn_program_collector")


def step(step_id, transport, rpc, **fields):
    row = {"id": step_id, "transport": transport, "rpc": rpc, "document": None, "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": None, "role": "observation", "allow": WIDE}
    row.update(fields)
    return row


def chain(transport):
    token = f"{transport}-q"
    steps = [step(f"{transport}/q-begin", transport, "BeginTransaction", tokenOutput=token, role="control", allow=(0,)),
             step(f"{transport}/q-all", transport, "RunQuery", tokenInput=token, caseId=f"{transport}/q-all", query={}),
             step(f"{transport}/q-held", transport, "RunQuery", tokenInput=token, caseId=f"{transport}/q-held", query={"stateEquals": "held"})]
    if transport == "grpc":
        steps.append(step("grpc/q-cancel", "grpc", "RunQuery", tokenInput=token, caseId="grpc/q-cancel", query={}, cancelAfter=1, allow=(1,)))
    steps.append(step(f"{transport}/q-rollback", transport, "Rollback", tokenInput=token, caseId=f"{transport}/q-rollback"))
    return steps


def table():
    value = copy.deepcopy(support.TABLE)
    value["steps"] = tuple(value["steps"]) + tuple(chain("rest")) + tuple(chain("grpc"))
    value["caps"] = {**value["caps"], "observation": len(value["steps"]), "tokenCleanup": 6}
    value["maxTokens"] = 4
    return value


class QueryWire:
    """Answers every RunQuery from the documents the toy service holds; everything else is the toy service's."""

    def __init__(self, inner, *, plan, foreign=None, stray_transaction=False, held_state="held"):
        self.inner, self.plan, self.foreign, self.stray, self.held_state = inner, plan, foreign, stray_transaction, held_state
        self.queries = []

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def frame(self, role, state, transport):
        name = self.plan["documents"][role]
        fields = {"owner": {"stringValue": OWNER}, "nonce": {"stringValue": NONCE}, "role": {"stringValue": role}, "state": {"stringValue": state}}
        stamp = "2026-09-30T00:00:00.000000001Z" if transport == "rest" else {"seconds": "1788004860", "nanos": 1}
        return {"document": {"name": name, "fields": fields, "createTime": stamp, "updateTime": stamp}, "readTime": stamp}

    def send(self, transport, method, request, **kwargs):
        if method != "RunQuery":
            return self.inner.send(transport, method, request, **kwargs)
        self.queries.append((transport, request, kwargs))
        token = request.get("transaction")
        if token is not None and self.inner.tokens.get(token) != "open":
            return {"kind": "txn-program-receipt-v1", "transport": transport, "complete": True, "code": 10, "details": "gone", "response": None, "http": None if transport == "grpc" else 409, "dispatchedRequests": 1, "childReaped": True}
        frames = [self.frame("a", "created", transport)]
        if "where" in request["structuredQuery"]:
            frames = [self.frame("a", self.held_state, transport)] if self.held_state == "held" else []
        if self.foreign:
            frames.append({"document": {"name": self.plan["documents"]["a"].replace("/a", "/zz"), "fields": {}, "updateTime": "2026-09-30T00:00:00.000000001Z"}})
        if self.stray:
            frames.append({"transaction": "dG9rZW4=", "readTime": "2026-09-30T00:00:00.000000001Z"})
        frames.append({"readTime": "2026-09-30T00:00:00.000000001Z"})
        cancel = kwargs.get("cancel_after")
        if cancel is not None:
            return {"kind": "txn-program-receipt-v1", "transport": transport, "complete": True, "code": 1, "details": f"cancelled by the client after {cancel} frame(s)", "response": {"responses": frames[:cancel]}, "http": None, "dispatchedRequests": 1, "childReaped": True}
        return {"kind": "txn-program-receipt-v1", "transport": transport, "complete": True, "code": 0, "details": "", "response": {"responses": frames}, "http": None if transport == "grpc" else 200, "dispatchedRequests": 1, "childReaped": True}


def run(**knobs):
    value = table()
    collector, service, budget, journal, clock, plan = collector_tests.fixture(value)
    # the toy service holds `a` after the setup commit; the query wire answers from the plan's own names
    wire = QueryWire(service, plan=plan, **knobs)
    collector.wire = wire
    return collector.run(), wire, value


def test_a_recording_with_queries_completes_and_replays(program=program):
    receipt, wire, value = run()
    assert receipt["complete"] is True and receipt["graphComplete"] is True and receipt["unrecovered"] is False
    cancel = [row for row in receipt["steps"] if row["site"] == "grpc/q-cancel"][0]
    assert cancel["result"]["code"] == 1 and cancel["outcomeClass"] == "CLIENT_CANCEL"
    # the cancel was asked of the wire, with the declared frame count
    assert [kwargs.get("cancel_after") for _t, _r, kwargs in wire.queries] == [None, None, None, None, 1]
    projected = collector_module.projection(receipt, value)
    reads = {row["site"]: row for row in projected["reads"]}
    assert reads["rest/q-all"]["documents"] == {"a": "created"} and reads["rest/q-all"]["code"] == 0
    assert reads["rest/q-held"]["documents"] == {"a": "held"}   # a state the toy chain tried on `a`: shown, not judged
    assert reads["grpc/q-cancel"] == {"site": "grpc/q-cancel", "code": 1, "documents": {"a": "created"}}
    cases = {row["caseId"]: row for row in projected["cases"]}
    assert cases["grpc/q-cancel"]["outcomeClass"] == "CLIENT_CANCEL" and cases["rest/q-all"]["outcomeClass"] == "OK"


def test_a_frame_for_a_document_the_run_does_not_own_stops_the_recording():
    receipt, _wire, _value = run(foreign=True)
    assert receipt["complete"] is False


def test_a_frame_that_carries_a_transaction_nobody_asked_for_stops_the_recording():
    receipt, _wire, _value = run(stray_transaction=True)
    assert receipt["complete"] is False


def test_a_query_that_shows_a_state_the_run_never_wrote_stops_the_recording():
    class Wrong(QueryWire):
        def frame(self, role, state, transport):
            return super().frame(role, "elsewhere", transport)
    value = table()
    collector, service, _budget, _journal, _clock, plan = collector_tests.fixture(value)
    collector.wire = Wrong(service, plan=plan)
    assert collector.run()["complete"] is False


def test_a_client_cancel_is_only_recorded_for_a_step_that_cancels():
    # code 1 on a step that did not ask for a cancel is an unknown outcome, never a recorded one
    value = table()
    collector, service, _budget, _journal, _clock, plan = collector_tests.fixture(value)

    class Rogue(QueryWire):
        def send(self, transport, method, request, **kwargs):
            if method == "RunQuery" and kwargs.get("cancel_after") is None and request["structuredQuery"].get("where") is None and not self.queries:
                self.queries.append(1)
                return {"kind": "txn-program-receipt-v1", "transport": transport, "complete": True, "code": 1, "details": CANCEL_TEXT, "response": {"responses": []}, "http": None if transport == "grpc" else 499, "dispatchedRequests": 1, "childReaped": True}
            return super().send(transport, method, request, **kwargs)
    collector.wire = Rogue(service, plan=plan)
    assert collector.run()["complete"] is False
