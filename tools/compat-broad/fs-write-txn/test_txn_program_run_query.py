"""A step may run a query over the table's own collection, optionally inside a transaction, and over gRPC may cancel the stream after N frames."""

import copy
import importlib

import pytest

NONCE, OWNER = "a" * 32, "b" * 32
WIDE = (0, 3, 5, 9, 10)


@pytest.fixture
def program():
    return importlib.import_module("txn_program_program")


@pytest.fixture
def toy():
    return importlib.import_module("txn_program_support_for_tests")


def query_step(step_id, transport="rest", query=None, **fields):
    row = {"id": step_id, "transport": transport, "rpc": "RunQuery", "document": None, "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": step_id,
           "role": "observation", "allow": WIDE, "query": {} if query is None else query}
    row.update(fields)
    return row


def table_with(toy, *extra):
    table = copy.deepcopy(toy.TABLE)
    table["steps"] = tuple(table["steps"]) + extra
    table["caps"] = {**table["caps"], "observation": len(table["steps"])}
    return table


def test_a_query_request_names_the_runs_own_collection_and_may_filter_on_a_declared_state(program, toy):
    steps = (query_step("q/all"), query_step("q/held", query={"stateEquals": "held"}), query_step("q/grpc", "grpc"))
    table = table_with(toy, *steps)
    plan = program.compile_plan(table, NONCE, OWNER)
    parent = f"{plan['database']}/documents/oracle/{NONCE}"
    everything, held, native = (program.request_for_step(plan, step, {}, table) for step in plan["steps"][-3:])
    assert everything == {"parent": parent, "structuredQuery": {"from": [{"collectionId": "txn-toy"}]}}
    assert held["structuredQuery"]["where"] == {"fieldFilter": {"field": {"fieldPath": "state"}, "op": "EQUAL", "value": {"stringValue": "held"}}}
    assert native["parent"] == parent


def test_a_query_inside_a_transaction_carries_its_token(program, toy):
    begin = {"id": "q/begin", "transport": "rest", "rpc": "BeginTransaction", "document": None, "tokenInput": None, "tokenOutput": "rest-q", "writes": (), "caseId": None, "role": "control", "allow": (0,)}
    rollback = {"id": "q/rollback", "transport": "rest", "rpc": "Rollback", "document": None, "tokenInput": "rest-q", "tokenOutput": None, "writes": (), "caseId": "q/rollback", "role": "observation", "allow": WIDE}
    table = table_with(toy, begin, query_step("q/in", tokenInput="rest-q"), rollback)
    table["maxTokens"] = 3
    plan = program.compile_plan(table, NONCE, OWNER)
    request = program.request_for_step(plan, plan["steps"][-2], {"rest-q": "dG9rZW4="}, table)
    assert request["transaction"] == "dG9rZW4="


@pytest.mark.parametrize("label,step", [
    ("an unknown query key", query_step("q/k", query={"limit": 3})),
    ("a state that is not declared", query_step("q/s", query={"stateEquals": "elsewhere"})),
    ("a query that is not a mapping", query_step("q/m", query=[])),
    ("a query on another rpc", {"id": "q/rpc", "transport": "rest", "rpc": "GetDocument", "document": "a", "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": "q/rpc", "role": "observation", "allow": WIDE, "query": {}}),
    ("a document on a query", query_step("q/d", document="a")),
    ("writes on a query", query_step("q/w", writes=({"document": "a", "state": "held", "exists": True},))),
    ("an output token", query_step("q/t", tokenOutput="rest-new")),
    ("a literal token on a query", query_step("q/l", tokenLiteral="unknown")),
    ("a read time on a query", query_step("q/rt", readAgoSeconds=60)),
    ("a query that is an outside writer", query_step("q/ow", role="outside-writer", deadlineMs=30000)),
    ("a token that was never issued on that transport", query_step("q/g", "grpc", tokenInput="rest-r")),
])
def test_a_misplaced_query_never_compiles(program, toy, label, step):
    with pytest.raises(ValueError):
        program.compile_plan(table_with(toy, step), NONCE, OWNER)


def test_a_cancelled_stream_is_a_grpc_query_that_allows_only_the_client_cancel(program, toy):
    ok = query_step("q/cancel", "grpc", cancelAfter=1, allow=(1,))
    program.compile_plan(table_with(toy, ok), NONCE, OWNER)
    for label, step in [
        ("over REST", query_step("q/c1", "rest", cancelAfter=1, allow=(1,))),
        ("allowing another code", query_step("q/c2", "grpc", cancelAfter=1, allow=(1, 0))),
        ("allowing nothing but success", query_step("q/c3", "grpc", cancelAfter=1, allow=(0,))),
        ("cancelling after no frame", query_step("q/c4", "grpc", cancelAfter=0, allow=(1,))),
        ("cancelling after too many frames", query_step("q/c5", "grpc", cancelAfter=17, allow=(1,))),
        ("a cancel that is not an int", query_step("q/c6", "grpc", cancelAfter="1", allow=(1,))),
        ("a cancel on a plain read", {"id": "q/c7", "transport": "grpc", "rpc": "GetDocument", "document": "a", "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": "q/c7", "role": "observation", "allow": (1,), "cancelAfter": 1}),
    ]:
        with pytest.raises(ValueError):
            program.compile_plan(table_with(toy, step), NONCE, OWNER)


def test_a_client_cancel_is_its_own_outcome_class_and_every_other_use_of_code_1_stays_unknown(program):
    assert program.outcome_class(1) == "UNKNOWN"
    assert program.step_outcome_class({"cancelAfter": 1}, 1) == "CLIENT_CANCEL"
    assert program.step_outcome_class({"cancelAfter": 1}, 0) == "OK"
    assert program.step_outcome_class({}, 1) == "UNKNOWN"


def test_the_corpus_digest_moves_with_the_query_and_the_cancel(program, toy):
    base = program.corpus_digest(table_with(toy, query_step("q/a", "grpc", cancelAfter=1, allow=(1,))))
    assert program.corpus_digest(table_with(toy, query_step("q/a", "grpc", cancelAfter=2, allow=(1,)))) != base
    assert program.corpus_digest(table_with(toy, query_step("q/a", "grpc", query={"stateEquals": "held"}, cancelAfter=1, allow=(1,)))) != base
    assert program.corpus_digest(toy.TABLE) == program.corpus_digest(copy.deepcopy(toy.TABLE))
