"""The shared closed-graph table type: one plan per table, a fixed request for every declared step."""

import copy
import importlib

import pytest

TOKEN = "dG9rZW4="
NONCE, OWNER = "a" * 32, "b" * 32


@pytest.fixture
def program():
    return importlib.import_module("txn_program_program")


@pytest.fixture
def table():
    return importlib.import_module("txn_program_support_for_tests").TABLE


def plan(program, table):
    return program.compile_plan(table, NONCE, OWNER)


def tokens_for(value):
    return {step["tokenOutput"]: TOKEN for step in value["steps"] if step["tokenOutput"]}


def test_plan_is_built_from_the_table_alone(program, table):
    value = plan(program, table)
    assert value["kind"] == "txn-program-plan-v1"
    assert value["program"] == "FS-TRANSACTION-TOY"
    assert value["documents"] == {
        "a": f"projects/fireemu-oracle-sbx/databases/(default)/documents/oracle/{NONCE}/txn-toy/a",
        "m": f"projects/fireemu-oracle-sbx/databases/(default)/documents/oracle/{NONCE}/txn-toy/m",
    }
    assert [step["id"] for step in value["steps"]] == [step["id"] for step in table["steps"]]
    assert value["cases"] == [step["caseId"] for step in table["steps"] if step["caseId"]]
    assert value["caps"]["observation"] == len(value["steps"]) == 19
    assert value["maxRequests"] == sum(value["caps"].values())
    assert value["waits"] == {}
    assert value["retries"] == "none" and value["iamConfig"] == "none"
    assert value["sourceDigest"] == program.source_digest(table)
    assert value["corpusDigest"] == program.corpus_digest(table)


def test_step_defaults_are_filled_and_the_writer_keeps_its_own_deadline(program, table):
    value = plan(program, table)
    by_id = {step["id"]: step for step in value["steps"]}
    assert by_id["r/begin"]["deadlineMs"] == 10000
    assert by_id["r/writer"]["deadlineMs"] == 30000
    assert "finished" not in by_id["r/rollback"]


@pytest.mark.parametrize(
    "mutation",
    ["omit", "repeat", "allow", "transport", "state", "caps", "clock", "document", "program", "corpus", "source", "waits", "retries", "case", "deadline", "token"],
)
def test_plan_rejects_authority_and_graph_changes(program, table, mutation):
    changed = copy.deepcopy(plan(program, table))
    if mutation == "omit": changed["steps"].pop()
    elif mutation == "repeat": changed["steps"].append(changed["steps"][-1])
    elif mutation == "allow": changed["steps"][5]["allow"] = [0, 5, 9, 10]
    elif mutation == "transport": changed["steps"][4]["transport"] = "grpc"
    elif mutation == "state": changed["steps"][5]["writes"][0]["state"] = "moved"
    elif mutation == "caps": changed["caps"]["observation"] = 20
    elif mutation == "clock": changed["observationSeconds"] = 900
    elif mutation == "document": changed["documents"]["m"] = changed["documents"]["a"]
    elif mutation == "program": changed["program"] = "FS-TRANSACTION-P10-A-GRPC-IDLE"
    elif mutation == "corpus": changed["corpusDigest"] = "c" * 64
    elif mutation == "source": changed["sourceDigest"] = "c" * 64
    elif mutation == "waits": changed["waits"] = {"r/read": 60}
    elif mutation == "retries": changed["retries"] = "sdk"
    elif mutation == "case": changed["cases"].reverse()
    elif mutation == "deadline": changed["steps"][8]["deadlineMs"] = 60000
    else: changed["steps"][4]["tokenInput"] = "grpc-g"
    with pytest.raises(ValueError, match="closed|graph|plan"):
        program.validate_plan(changed, table)


def test_a_plan_that_is_not_a_dict_is_refused(program, table):
    with pytest.raises(ValueError, match="plan"):
        program.validate_plan(None, table)


def test_nonce_and_owner_must_be_canonical(program, table):
    for nonce, owner in [("A" * 32, OWNER), (NONCE, "b" * 31), (1, OWNER), (NONCE, None)]:
        with pytest.raises(ValueError, match="canonical"):
            program.compile_plan(table, nonce, owner)


def _broken(table, **changes):
    value = copy.deepcopy(table)
    for key, change in changes.items():
        value[key] = change(value[key]) if callable(change) else change
    return value


def _step_change(index, **fields):
    def apply(steps):
        steps = [dict(step) for step in steps]
        steps[index] = {**steps[index], **fields}
        return tuple(steps)
    return apply


@pytest.mark.parametrize(
    "label,broken",
    [
        ("duplicate id", lambda t: _broken(t, steps=_step_change(1, id="setup/absence-a"))),
        ("unknown rpc", lambda t: _broken(t, steps=_step_change(1, rpc="DeleteDocument"))),
        ("unknown transport", lambda t: _broken(t, steps=_step_change(1, transport="http"))),
        ("unknown document", lambda t: _broken(t, steps=_step_change(1, document="z"))),
        ("token before begin", lambda t: _broken(t, steps=_step_change(4, tokenInput="rest-late"))),
        ("token across transports", lambda t: _broken(t, steps=_step_change(13, tokenInput="rest-r"))),
        ("reused token output", lambda t: _broken(t, steps=_step_change(11, tokenOutput="rest-r"))),
        ("unknown state", lambda t: _broken(t, steps=_step_change(5, writes=({"document": "a", "state": "gone", "exists": True},)))),
        ("allowed unknown code", lambda t: _broken(t, steps=_step_change(5, allow=(5, 14)))),
        ("empty allow", lambda t: _broken(t, steps=_step_change(5, allow=()))),
        ("commit without writes", lambda t: _broken(t, steps=_step_change(5, writes=()))),
        ("writer with token", lambda t: _broken(t, steps=_step_change(7, tokenInput="rest-r"))),
        ("writer over deadline", lambda t: _broken(t, steps=_step_change(7, deadlineMs=30001))),
        ("case on control", lambda t: _broken(t, steps=_step_change(4, caseId="x"))),
        ("duplicate case", lambda t: _broken(t, steps=_step_change(6, caseId="rest/fail-commit"))),
        ("caps not the step count", lambda t: _broken(t, caps={**t["caps"], "observation": 18})),
        ("too many tokens", lambda t: _broken(t, maxTokens=1)),
        ("undeclared key", lambda t: _broken(t, steps=_step_change(4, finished=True))),
        ("read with writes", lambda t: _broken(t, steps=_step_change(4, writes=({"document": "a", "state": "held", "exists": True},)))),
        ("envelope of another program", lambda t: _broken(t, envelopeId="FS-TRANSACTION-p10-grpc-boundary-002")),
        ("unnumbered envelope", lambda t: _broken(t, envelopeId="FS-TRANSACTION-toy-failed-commit")),
        ("missing key", lambda t: _broken(t, steps=lambda steps: tuple({k: v for k, v in step.items() if k != "allow"} for step in steps))),
    ],
)
def test_a_malformed_table_never_compiles(program, table, label, broken):
    with pytest.raises(ValueError, match="table"):
        program.compile_plan(broken(table), NONCE, OWNER)


def test_digests_move_with_every_recorded_fact(program, table):
    base = program.corpus_digest(table)
    for label, changed in [
        ("allow", _broken(table, steps=_step_change(5, allow=(5, 9)))),
        ("transport", _broken(table, steps=_step_change(1, transport="rest"))),
        ("document", _broken(table, steps=lambda steps: (dict(steps[0], document="m"), dict(steps[1], document="a")) + tuple(steps[2:]))),
        ("case", _broken(table, steps=_step_change(5, caseId="renamed"))),
        ("states", _broken(table, states=("created", "held", "moved", "extra"))),
        ("deadline", _broken(table, steps=_step_change(7, deadlineMs=20000))),
    ]:
        assert program.corpus_digest(changed) != base, label
    assert program.corpus_digest(copy.deepcopy(table)) == base


def test_requests_for_every_declared_step_are_fixed(program, table):
    value = plan(program, table)
    tokens = tokens_for(value)
    seen = set()
    for step in value["steps"]:
        request = program.request_for_step(value, step, tokens, table)
        seen.add(step["rpc"])
        if step["rpc"] == "BeginTransaction":
            assert request == {"database": "projects/fireemu-oracle-sbx/databases/(default)", "options": {"readWrite": {}}}
        elif step["rpc"] == "GetDocument":
            assert request["name"] == value["documents"][step["document"]]
            assert request.get("transaction") == (TOKEN if step["tokenInput"] else None)
        elif step["rpc"] == "Rollback":
            assert request == {"database": "projects/fireemu-oracle-sbx/databases/(default)", "transaction": TOKEN}
        else:
            assert len(request["writes"]) == len(step["writes"])
            assert request.get("transaction") == (TOKEN if step["tokenInput"] else None)
            for write, declared in zip(request["writes"], step["writes"], strict=True):
                assert write["update"]["name"] == value["documents"][declared["document"]]
                assert write["currentDocument"] == {"exists": declared["exists"]}
                fields = {key: field["stringValue"] for key, field in write["update"]["fields"].items()}
                assert fields == {"owner": OWNER, "nonce": NONCE, "role": declared["document"], "state": declared["state"]}
    assert seen == {"BeginTransaction", "GetDocument", "Commit", "Rollback"}


def test_a_step_needs_an_earlier_issued_token_and_canonical_bytes(program, table):
    value = plan(program, table)
    step = next(step for step in value["steps"] if step["id"] == "r/read")
    with pytest.raises(ValueError, match="token"):
        program.request_for_step(value, step, {}, table)
    for bad in ["", "not base64!", "dG9rZW4", "A" * 3000, "dG9rZW4=\n"]:
        with pytest.raises(ValueError, match="canonical|bounded"):
            program.request_for_step(value, step, {"rest-r": bad}, table)
    with pytest.raises(ValueError, match="declared"):
        program.request_for_step(value, {**step, "id": "r/other"}, {"rest-r": TOKEN}, table)


def test_a_begin_cannot_carry_a_token(program, table):
    value = plan(program, table)
    step = copy.deepcopy(value["steps"][3])
    assert step["rpc"] == "BeginTransaction"
    with pytest.raises(ValueError, match="declared"):
        program.request_for_step(value, {**step, "tokenInput": "rest-r"}, {"rest-r": TOKEN}, table)


def test_slots_cannot_repeat_or_skip(program, table):
    value = plan(program, table)
    cursor = program.GraphCursor(value, table)
    with pytest.raises(ValueError, match="order"):
        cursor.claim(value["steps"][1]["id"])
    for step in value["steps"]:
        assert cursor.claim(step["id"]) == step
    assert cursor.complete
    with pytest.raises(ValueError, match="order"):
        cursor.claim(value["steps"][-1]["id"])


def test_observation_never_borrows_reserved_cleanup_requests(program, table):
    value = plan(program, table)
    budget = program.RequestBudget(value, table)
    for _ in range(value["caps"]["observation"]): budget.charge("observation")
    with pytest.raises(ValueError, match="exhausted"):
        budget.charge("observation")
    for phase in ["tokenCleanup", "documentCleanup", "management", "credential"]:
        for _ in range(value["caps"][phase]): budget.charge(phase)
        with pytest.raises(ValueError, match="exhausted"):
            budget.charge(phase)
    assert budget.total == value["maxRequests"]
    with pytest.raises(ValueError, match="exhausted"):
        budget.charge("nowhere")


def test_outcome_classes_follow_the_code(program):
    assert [program.outcome_class(code) for code in [0, 3, 5, 9, 10, 1, 2, 4, 13, 14, 7, 16]] == [
        "OK", "REFUSED", "REFUSED", "REFUSED", "REFUSED", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "OTHER", "OTHER",
    ]
    for bad in [-1, 17, True, None, "0"]:
        with pytest.raises(ValueError, match="code"):
            program.outcome_class(bad)
