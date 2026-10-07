"""A step may name a token the table never issued: one that does not decode (REST only) or one that decodes and was never issued."""

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


def literal(step_id, transport, rpc, name, **fields):
    row = {"id": step_id, "transport": transport, "rpc": rpc, "document": "a" if rpc == "GetDocument" else None, "tokenInput": None, "tokenOutput": None,
           "writes": (), "caseId": step_id, "role": "observation", "allow": WIDE, "tokenLiteral": name}
    if rpc == "BatchGetDocuments":
        row["documents"] = ["a"]
    if rpc == "Commit":
        row["writes"] = ({"document": "a", "state": "held", "exists": True},)
    row.update(fields)
    return row


def table_with(toy, *extra):
    table = copy.deepcopy(toy.TABLE)
    table["steps"] = tuple(table["steps"]) + extra
    table["caps"] = {**table["caps"], "observation": len(table["steps"])}
    return table


def test_a_literal_token_resolves_to_the_closed_constant_and_never_to_an_issued_one(program, toy):
    steps = (
        literal("lit/rest-malformed-get", "rest", "GetDocument", "malformed"),
        literal("lit/rest-unknown-batch", "rest", "BatchGetDocuments", "unknown"),
        literal("lit/grpc-unknown-get", "grpc", "GetDocument", "unknown"),
        literal("lit/rest-malformed-rollback", "rest", "Rollback", "malformed"),
        literal("lit/grpc-unknown-commit", "grpc", "Commit", "unknown"),
    )
    table = table_with(toy, *steps)
    plan = program.compile_plan(table, NONCE, OWNER)
    for declared in plan["steps"][-5:]:
        request = program.request_for_step(plan, declared, {}, table)
        assert request["transaction"] == program.LITERAL_TOKENS[declared["tokenLiteral"]]
    assert program.LITERAL_TOKENS["malformed"] == "not base64!"
    program.canonical_token(program.LITERAL_TOKENS["unknown"])
    with pytest.raises(ValueError):
        program.canonical_token(program.LITERAL_TOKENS["malformed"])


@pytest.mark.parametrize("label,step,message", [
    ("malformed over gRPC", literal("lit/g", "grpc", "GetDocument", "malformed"), "malformed token over gRPC"),
    ("a literal that is not in the closed set", literal("lit/x", "rest", "GetDocument", "forged"), "literal token that is not allowed"),
    ("a literal beside an issued token", "chain", "literal token that is not allowed"),
    ("a literal on a begin", literal("lit/begin", "rest", "BeginTransaction", "unknown", tokenOutput="rest-z", document=None), "literal token that is not allowed"),
    ("a literal on a control step", literal("lit/c", "rest", "GetDocument", "unknown", role="control", allow=(0,), caseId=None), "literal token that is not allowed"),
    ("a literal on a post-state read", literal("lit/p", "rest", "GetDocument", "unknown", role="post-state", allow=(0,), caseId=None), "literal token that is not allowed"),
    ("a literal on an outside writer", literal("lit/w", "rest", "Commit", "unknown", role="outside-writer", deadlineMs=30000), "literal token that is not allowed"),
    ("a literal that is not a string", literal("lit/n", "rest", "GetDocument", 7), "literal token that is not allowed"),
])
def test_a_misplaced_literal_token_never_compiles(program, toy, label, step, message):
    # the message names the literal rule: another rule refusing the table would not show that the literal rule works
    table = table_with(toy, step) if step != "chain" else None
    if table is None:
        # a literal beside an issued token, inside a transaction of its own so that nothing else refuses the table
        begin = {"id": "z/begin", "transport": "rest", "rpc": "BeginTransaction", "document": None, "tokenInput": None, "tokenOutput": "rest-z", "writes": (), "caseId": None, "role": "control", "allow": (0,)}
        rollback = {"id": "z/rollback", "transport": "rest", "rpc": "Rollback", "document": None, "tokenInput": "rest-z", "tokenOutput": None, "writes": (), "caseId": "z/rollback", "role": "observation", "allow": WIDE}
        table = table_with(toy, begin, literal("lit/b", "rest", "GetDocument", "unknown", tokenInput="rest-z"), rollback)
        table["maxTokens"] = 3
    with pytest.raises(ValueError, match=message):
        program.compile_plan(table, NONCE, OWNER)


def test_a_literal_step_moves_the_corpus_digest_and_an_absent_key_keeps_every_earlier_one(program, toy):
    base = program.corpus_digest(toy.TABLE)
    assert program.corpus_digest(table_with(toy, literal("lit/a", "rest", "GetDocument", "unknown"))) != base
    assert program.corpus_digest(table_with(toy, literal("lit/a", "rest", "GetDocument", "unknown"))) != program.corpus_digest(table_with(toy, literal("lit/a", "rest", "GetDocument", "malformed")))
    assert program.corpus_digest(toy.TABLE) == base


class Wire:
    """A Firestore stand-in that refuses every literal token the way production refuses an unknown one."""

    def __init__(self, inner, literals):
        self.inner, self.literals, self.literal_calls = inner, literals, []

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def send(self, transport, method, request, **kwargs):
        if request.get("transaction") in self.literals:
            self.literal_calls.append((transport, method, request["transaction"]))
            code, text = (3, "Invalid transaction.")
            return {"kind": "txn-program-receipt-v1", "transport": transport, "complete": True, "code": code, "details": text, "response": None,
                    "http": None if transport == "grpc" else 400, "dispatchedRequests": 1, "childReaped": True}
        return self.inner.send(transport, method, request, **kwargs)


def run(toy, program, steps):
    collector_tests = importlib.import_module("test_txn_program_collector")
    table = table_with(toy, *steps)
    collector, service, budget, journal, _clock, plan = collector_tests.fixture(table)
    wire = Wire(service, set(program.LITERAL_TOKENS.values()))
    collector.wire = wire
    return collector.run(), wire, table


def test_a_recording_with_literal_tokens_completes_and_owns_nothing_they_touched(program, toy):
    steps = (
        literal("lit/rest-malformed-get", "rest", "GetDocument", "malformed"),
        literal("lit/rest-unknown-batch", "rest", "BatchGetDocuments", "unknown"),
        literal("lit/grpc-unknown-get", "grpc", "GetDocument", "unknown"),
        literal("lit/rest-malformed-rollback", "rest", "Rollback", "malformed"),
        literal("lit/grpc-unknown-rollback", "grpc", "Rollback", "unknown"),
        literal("lit/grpc-unknown-commit", "grpc", "Commit", "unknown"),
    )
    receipt, wire, table = run(toy, program, steps)
    assert receipt["complete"] is True and receipt["graphComplete"] is True and receipt["unrecovered"] is False
    assert [call[1] for call in wire.literal_calls] == ["GetDocument", "BatchGetDocuments", "GetDocument", "Rollback", "Rollback", "Commit"]
    # a refused literal Rollback is a probe: no token of ours was released by it, and none was left owed
    assert receipt["unknownRollbacks"] == [] and receipt["unknownCommits"] == [] and receipt["openTokens"] == []
    cases = {row["caseId"]: row for row in receipt["observations"]}
    assert all(cases[step["id"]]["result"]["code"] == 3 for step in steps)
    # the refused commit left the document as it was
    assert all(state["status"] == "confirmed-absent" for state in receipt["documents"].values())
    collector_module = importlib.import_module("txn_program_collector")
    projected = collector_module.projection(receipt, table)
    assert {row["caseId"] for row in projected["cases"]} >= {step["id"] for step in steps}
