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


def token_chain(step_factory):
    """The step inside a transaction of its own: a begin before it and a release after it, so that nothing but the rule under test can refuse the table."""
    begin = {"id": "z/begin", "transport": "rest", "rpc": "BeginTransaction", "document": None, "tokenInput": None, "tokenOutput": "rest-z", "writes": (), "caseId": None, "role": "control", "allow": (0,)}
    rollback = {"id": "z/rollback", "transport": "rest", "rpc": "Rollback", "document": None, "tokenInput": "rest-z", "tokenOutput": None, "writes": (), "caseId": "z/rollback", "role": "observation", "allow": WIDE}
    return (begin, step_factory("rest-z"), rollback)


def with_tokens(toy, *steps):
    table = table_with(toy, *steps)
    table["maxTokens"] = 3
    return table


@pytest.mark.parametrize("label,steps,message", [
    ("an unknown query key", (query_step("q/k", query={"limit": 3}),), "is a query that is malformed"),
    ("a state that is not declared", (query_step("q/s", query={"stateEquals": "elsewhere"}),), "is a query that is malformed"),
    ("a query that is not a mapping", (query_step("q/m", query=[]),), "is a query that is malformed"),
    ("a query on another rpc", ({"id": "q/rpc", "transport": "rest", "rpc": "GetDocument", "document": "a", "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": "q/rpc", "role": "observation", "allow": WIDE, "query": {}},), "is a query that is malformed"),
    ("a document on a query", (query_step("q/d", document="a"),), "names a document, writes"),
    ("writes on a query", (query_step("q/w", writes=({"document": "a", "state": "held", "exists": True},)),), "names a document, writes"),
    ("an output token", (query_step("q/t", tokenOutput="rest-new"),), "names a document, writes"),
    ("a literal token on a query", (query_step("q/l", tokenLiteral="unknown"),), "literal token that is not allowed"),
    ("a read time on a query", (query_step("q/rt", readAgoSeconds=60),), "names a document, writes"),
    ("a new transaction on a query", (query_step("q/nt", newTransaction="readOnly"),), "names a document, writes"),
    ("a query that is an outside writer", (query_step("q/ow", role="outside-writer", deadlineMs=30000),), "names a document, writes"),
    ("a token that was never issued on that transport", token_chain(lambda token: query_step("q/g", "grpc", tokenInput=token)), "not issued earlier on its transport"),
])
def test_a_misplaced_query_never_compiles(program, toy, label, steps, message):
    # the message names the query rule that refused it: another rule refusing the table would not show this one works
    with pytest.raises(ValueError, match=message):
        program.compile_plan(with_tokens(toy, *steps) if len(steps) == 3 else table_with(toy, *steps), NONCE, OWNER)


def test_a_cancelled_stream_is_a_grpc_query_that_allows_only_the_client_cancel(program, toy):
    for frames in (1, program.MAX_CANCEL_FRAMES):
        program.compile_plan(table_with(toy, query_step("q/cancel", "grpc", cancelAfter=frames, allow=(1,))), NONCE, OWNER)
    assert program.MAX_CANCEL_FRAMES == 16
    for label, step in [
        ("over REST", query_step("q/c1", "rest", cancelAfter=1, allow=(1,))),
        ("allowing another code", query_step("q/c2", "grpc", cancelAfter=1, allow=(1, 0))),
        ("allowing nothing but success", query_step("q/c3", "grpc", cancelAfter=1, allow=(0,))),
        ("cancelling after no frame", query_step("q/c4", "grpc", cancelAfter=0, allow=(1,))),
        ("cancelling after too many frames", query_step("q/c5", "grpc", cancelAfter=17, allow=(1,))),
        ("a cancel that is not an int", query_step("q/c6", "grpc", cancelAfter="1", allow=(1,))),
        ("a cancel on a plain read", {"id": "q/c7", "transport": "grpc", "rpc": "GetDocument", "document": "a", "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": "q/c7", "role": "observation", "allow": (1,), "cancelAfter": 1}),
    ]:
        with pytest.raises(ValueError, match="cancels something other than"):
            program.compile_plan(table_with(toy, step), NONCE, OWNER)
    # code 1 stays an unknown outcome on a step that does not cancel, whatever else it allows
    with pytest.raises(ValueError, match="unknown-outcome code"):
        program.compile_plan(table_with(toy, query_step("q/c8", "grpc", allow=(1,))), NONCE, OWNER)


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
