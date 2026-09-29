"""The boundary sweep has six fresh samples and an immutable request graph (P10-C: 75 to 120 s)."""

import copy
import importlib

import pytest


@pytest.fixture
def program():
    return importlib.import_module("txn_boundary_grpc_program")


def plan(program):
    return program.compile_plan("a" * 32, "b" * 32)


def test_sweep_has_six_fixed_fresh_transactions_and_one_owned_marker(program):
    value = plan(program)
    assert value["program"] == "FS-TRANSACTION-P10-C-GRPC-BOUNDARY"
    assert value["document"].endswith("/oracle/" + "a" * 32 + "/txn-p10b/control")
    assert value["candidates"] == [75, 80, 90, 100, 110, 120] == list(program.CANDIDATES)
    assert len(value["steps"]) == 26
    assert value["conditionalSkips"] == []
    assert value["maxTokens"] == 6
    assert value["maxUnresolvedTokens"] == 1
    assert value["observationSeconds"] == 1200
    assert value["recoverySeconds"] == 180
    assert value["maxRequests"] == sum(value["caps"].values()) == 48
    assert sum(value["waits"].values()) == 575
    tokens = {f"idle-{seconds}": f"token-{seconds}".encode().hex() for seconds in program.CANDIDATES}
    for index, seconds in enumerate(program.CANDIDATES):
        sample = value["steps"][2 + index * 4:6 + index * 4]
        assert [step["rpc"] for step in sample] == ["BeginTransaction", "GetDocument", "Commit", "GetDocument"]
        assert sample[0]["tokenInput"] is None
        assert sample[0]["tokenOutput"] == f"idle-{seconds}"
        assert program.request_for_step(value, sample[0], tokens)["options"] == {"readWrite": {}}
        assert sample[2]["caseId"] == f"grpc/commit-idle-{seconds}"
        assert sample[2]["state"] == f"accepted-idle-{seconds}"
        assert value["waits"][sample[2]["id"]] == seconds
        assert sample[3]["tokenInput"] is None


@pytest.mark.parametrize("mutation", ["wait", "candidate", "omit", "repeat", "state", "skip", "tokens", "concurrent", "phase", "clock", "document", "program", "corpus"])
def test_plan_rejects_authority_and_graph_changes(program, mutation):
    value = plan(program)
    changed = copy.deepcopy(value)
    if mutation == "wait": changed["waits"]["idle-75/commit"] = 74
    elif mutation == "candidate": changed["candidates"][0] = 74
    elif mutation == "omit": changed["steps"].pop()
    elif mutation == "repeat": changed["steps"].append(changed["steps"][-1])
    elif mutation == "state": changed["steps"][4]["state"] = "accepted-idle-120"
    elif mutation == "skip": changed["conditionalSkips"].append("idle-75/read")
    elif mutation == "tokens": changed["maxTokens"] = 7
    elif mutation == "concurrent": changed["maxUnresolvedTokens"] = 2
    elif mutation == "phase": changed["caps"]["observation"] = 27
    elif mutation == "clock": changed["observationSeconds"] = 900
    elif mutation == "document": changed["document"] = changed["document"].replace("txn-p10b", "txn-p10")
    elif mutation == "program": changed["program"] = "FS-TRANSACTION-P10-A-GRPC-IDLE"
    else: changed["corpusDigest"] = "c" * 64
    with pytest.raises(ValueError, match="closed|graph|plan"):
        program.validate_plan(changed)


def test_slots_cannot_repeat_or_skip_and_requests_keep_owned_preconditions(program):
    value = plan(program)
    cursor = program.GraphCursor(value)
    with pytest.raises(ValueError, match="order"):
        cursor.claim(value["steps"][1]["id"])
    token = "dG9rZW4="
    tokens = {f"idle-{seconds}": token for seconds in program.CANDIDATES}
    for step in value["steps"]:
        assert cursor.claim(step["id"]) == step
        request = program.request_for_step(value, step, tokens)
        if step["rpc"] == "Commit":
            write = request["writes"][0]
            assert write["update"]["name"] == value["document"]
            assert write["update"]["fields"]["owner"]["stringValue"] == value["ownerId"]
            assert write["currentDocument"] == {"exists": step["id"] != "setup/create"}
            if step["tokenInput"]: assert request["transaction"] == token
    assert cursor.complete
    with pytest.raises(ValueError, match="order"):
        cursor.claim(value["steps"][-1]["id"])


def test_observation_never_borrows_reserved_cleanup_requests(program):
    budget = program.RequestBudget(plan(program))
    for _ in range(26): budget.charge("observation")
    with pytest.raises(ValueError, match="exhausted"):
        budget.charge("observation")
    assert budget.total == 26
    for phase, count in [("tokenCleanup", 6), ("documentCleanup", 7), ("management", 7), ("credential", 2)]:
        for _ in range(count): budget.charge(phase)
        with pytest.raises(ValueError, match="exhausted"):
            budget.charge(phase)
    assert budget.total == 48


def test_missing_prior_token_cannot_dispatch_a_sample_read(program):
    value = plan(program)
    with pytest.raises(ValueError, match="token"):
        program.request_for_step(value, value["steps"][3], {})
