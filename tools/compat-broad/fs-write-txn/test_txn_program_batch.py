"""Batch reads and empty commits on the shared graph, through a small table of their own."""

import copy

import pytest

from test_txn_program_collector import Clock, NONCE, OWNER, Service, collector_module, program, support
from test_txn_program_hardening import receipt, timing

GONE = "The referenced transaction has expired or is no longer valid."


def rows(transport):
    def step(step_id, rpc, role, **kwargs):
        base = {"id": f"{transport}/{step_id}", "transport": transport, "rpc": rpc, "document": None, "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": None, "role": role, "allow": (0,)}
        return {**base, **kwargs}
    token = f"{transport}-t"
    write = ({"document": "a", "state": f"{transport}-empty", "exists": True},)
    return [
        step("begin", "BeginTransaction", "control", tokenOutput=token),
        step("batch", "BatchGetDocuments", "observation", documents=("a", "m"), tokenInput=token, caseId=f"{transport}/batch"),
        step("empty-commit", "Commit", "observation", tokenInput=token, caseId=f"{transport}/empty-commit"),
        step("commit-after-empty", "Commit", "observation", tokenInput=token, writes=write, caseId=f"{transport}/commit-after-empty", allow=(3, 5, 9, 10)),
        step("batch-after-empty", "BatchGetDocuments", "observation", documents=("a",), tokenInput=token, caseId=f"{transport}/batch-after-empty", allow=(0, 3, 5, 9, 10)),
        step("plain-batch", "BatchGetDocuments", "post-state", documents=("a", "m")),
    ]


def probes():
    return [
        {"id": "setup/absence-a", "transport": "grpc", "rpc": "GetDocument", "document": "a", "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": None, "role": "control", "allow": (5,)},
        {"id": "setup/absence-m", "transport": "grpc", "rpc": "GetDocument", "document": "m", "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": None, "role": "control", "allow": (5,)},
        {"id": "setup/create-a", "transport": "grpc", "rpc": "Commit", "document": None, "tokenInput": None, "tokenOutput": None, "writes": ({"document": "a", "state": "created", "exists": False},), "caseId": None, "role": "control", "allow": (0,)},
    ]


def table():
    steps = tuple(probes() + rows("rest") + rows("grpc"))
    return {**support.TABLE, "name": "toy-failed-commit", "steps": steps, "states": ("created", "held", "moved", "rest-empty", "grpc-empty"), "maxTokens": 2, "caps": {"observation": len(steps), "tokenCleanup": 4, "documentCleanup": 14, "management": 7, "credential": 2}}


def record(**knobs):
    value = table()
    clock = Clock()
    plan = program.compile_plan(value, NONCE, OWNER)
    service = Service(clock, **knobs)
    return value, service, collector_module.Collector(plan, value, program.RequestBudget(plan, value), service, "owner", save=lambda _s: None, monotonic=clock.now, utc=clock.utc).run()


def test_a_batch_read_and_an_empty_commit_complete_on_both_transports():
    value, service, result = record()
    assert result["complete"] is True, result["failureType"]
    projected = collector_module.projection(result, value)
    cases = {case["caseId"]: case for case in projected["cases"]}
    assert cases["rest/empty-commit"]["code"] == 0 and cases["grpc/batch"]["code"] == 0
    assert cases["rest/commit-after-empty"]["code"] == 10 and cases["grpc/batch-after-empty"]["code"] == 10
    reads = {read["site"]: read for read in projected["reads"] if "documents" in read}
    assert reads["rest/batch"]["documents"] == {"a": "created", "m": None}
    assert reads["grpc/plain-batch"]["documents"] == {"a": "created", "m": None}
    assert {call[0] for call in service.calls if call[1] == "BatchGetDocuments"} == {"rest", "grpc"}


def test_the_batch_request_names_the_planned_documents_and_the_token():
    value, service, result = record()
    plan = program.compile_plan(value, NONCE, OWNER)
    batches = [call for call in service.calls if call[1] == "BatchGetDocuments"]
    assert batches[0][2]["documents"] == [plan["documents"]["a"], plan["documents"]["m"]] and "transaction" in batches[0][2]
    assert "transaction" not in batches[2][2] and batches[2][2]["documents"] == [plan["documents"]["a"], plan["documents"]["m"]]
    assert [call[2]["writes"] for call in service.calls if call[1] == "Commit" and not call[2]["writes"]] == [[], []]


@pytest.mark.parametrize("mutation", ["missing-for-found", "found-for-missing", "count", "repeat", "foreign-name", "both", "neither", "extra-key", "foreign-owner", "not-a-list"])
def test_a_batch_answer_that_disagrees_with_what_was_written_stops(mutation):
    value = table()
    ledger = collector_module.Ledger(program.compile_plan(value, NONCE, OWNER))
    names = ledger.plan["documents"]
    ledger.docs["a"].update(status="created", state="created")
    ledger.docs["m"].update(status="confirmed-absent")
    found = {"name": names["a"], "fields": {"owner": {"stringValue": OWNER}, "nonce": {"stringValue": NONCE}, "role": {"stringValue": "a"}, "state": {"stringValue": "created"}}, "updateTime": {"seconds": "1", "nanos": 1}}
    frames = [{"found": found}, {"missing": names["m"]}]
    if mutation == "missing-for-found": frames[0] = {"missing": names["a"]}
    elif mutation == "found-for-missing": frames[1] = {"found": {**found, "name": names["m"], "fields": {**found["fields"], "role": {"stringValue": "m"}}}}
    elif mutation == "count": frames = frames[:1]
    elif mutation == "repeat": frames[1] = {"found": found}
    elif mutation == "foreign-name": frames[1] = {"missing": names["m"].replace("/m", "/z")}
    elif mutation == "both": frames[0] = {"found": found, "missing": names["a"]}
    elif mutation == "neither": frames[0] = {}
    elif mutation == "extra-key": frames[0] = {"found": found, "extra": 1}
    elif mutation == "foreign-owner": frames[0] = {"found": {**found, "fields": {**found["fields"], "owner": {"stringValue": "c" * 32}}}}
    response = {"responses": "x"} if mutation == "not-a-list" else {"responses": frames}
    step = next(step for step in ledger.plan["steps"] if step["id"] == "grpc/plain-batch")
    request = {"database": ledger.plan["database"], "documents": [names["a"], names["m"]]}
    with pytest.raises(ValueError):
        ledger.after("x", "grpc", "BatchGetDocuments", request, step, receipt(response=response), timing())


def test_a_correct_batch_answer_is_accepted_in_either_order():
    ledger = collector_module.Ledger(program.compile_plan(table(), NONCE, OWNER))
    names = ledger.plan["documents"]
    ledger.docs["a"].update(status="created", state="created"); ledger.docs["m"].update(status="confirmed-absent")
    found = {"name": names["a"], "fields": {"owner": {"stringValue": OWNER}, "nonce": {"stringValue": NONCE}, "role": {"stringValue": "a"}, "state": {"stringValue": "created"}}, "updateTime": {"seconds": "1", "nanos": 1}}
    step = next(step for step in ledger.plan["steps"] if step["id"] == "grpc/plain-batch")
    request = {"database": ledger.plan["database"], "documents": [names["a"], names["m"]]}
    ledger.after("x", "grpc", "BatchGetDocuments", request, step, receipt(response={"responses": [{"missing": names["m"]}, {"found": found}]}), timing())


def test_a_refused_empty_commit_never_finishes_the_token():
    value, service, result = record()
    assert {entry["state"] for entry in result["tokens"].values()} == {"committed"}


@pytest.mark.parametrize("label,change", [
    ("a batch before its documents are probed", lambda t: {**t, "steps": tuple(t["steps"][8:9] + t["steps"][:8] + t["steps"][9:])}),
    ("an empty commit outside a transaction", lambda t: {**t, "steps": tuple(dict(s, tokenInput=None) if s["id"] == "rest/empty-commit" else s for s in t["steps"])}),
    ("a batch naming one document twice", lambda t: {**t, "steps": tuple(dict(s, documents=("a", "a")) if s["id"] == "rest/batch" else s for s in t["steps"])}),
    ("a batch of an unknown document", lambda t: {**t, "steps": tuple(dict(s, documents=("a", "z")) if s["id"] == "rest/batch" else s for s in t["steps"])}),
    ("a batch with no documents", lambda t: {**t, "steps": tuple(dict(s, documents=()) if s["id"] == "rest/batch" else s for s in t["steps"])}),
    ("a batch that also names a document", lambda t: {**t, "steps": tuple(dict(s, document="a") if s["id"] == "rest/batch" else s for s in t["steps"])}),
    ("documents on a plain read", lambda t: {**t, "steps": tuple(dict(s, documents=("a",)) if s["id"] == "setup/absence-a" else s for s in t["steps"])}),
    ("an outside writer with an empty commit", lambda t: {**t, "steps": tuple(dict(s, role="outside-writer", tokenInput=None) if s["id"] == "rest/empty-commit" else s for s in t["steps"])}),
])
def test_a_malformed_batch_table_never_compiles(label, change):
    with pytest.raises(ValueError, match="table"):
        program.compile_plan(change(table()), NONCE, OWNER)


def test_a_table_without_batches_keeps_its_digest():
    assert program.corpus_digest(support.TABLE) == "624ee4410100a3a30d90bdc80ad2133bd4c68dadde18978b7c425749bd957099", "adding batch reads must not move any earlier table's digest"
    import fs_txn_table_p08
    assert program.corpus_digest(fs_txn_table_p08.TABLE) == "1dc1d44eca4b99a23d8f3b480eb9b8d71aec4ef0894509b149fa12354c9d92bc"
