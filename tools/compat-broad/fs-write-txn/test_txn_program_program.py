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
        ("commit without writes outside a transaction", lambda t: _broken(t, steps=_step_change(7, writes=()))),
        ("writer with token", lambda t: _broken(t, steps=_step_change(7, tokenInput="rest-r"))),
        ("writer over deadline", lambda t: _broken(t, steps=_step_change(7, deadlineMs=90001))),
        ("case on control", lambda t: _broken(t, steps=_step_change(4, caseId="x"))),
        ("duplicate case", lambda t: _broken(t, steps=_step_change(6, caseId="rest/fail-commit"))),
        ("caps not the step count", lambda t: _broken(t, caps={**t["caps"], "observation": 18})),
        ("too many tokens", lambda t: _broken(t, maxTokens=1)),
        ("undeclared key", lambda t: _broken(t, steps=_step_change(4, finished=True))),
        ("read with writes", lambda t: _broken(t, steps=_step_change(4, writes=({"document": "a", "state": "held", "exists": True},)))),
        ("non-writer with the writer deadline", lambda t: _broken(t, steps=_step_change(4, deadlineMs=30000))),
        ("fewer tokens than declared", lambda t: _broken(t, maxTokens=3)),
        ("exists is not a bool", lambda t: _broken(t, steps=_step_change(5, writes=({"document": "a", "state": "held", "exists": "yes"}, {"document": "m", "state": "held", "exists": True})))),
        ("write to an undeclared document", lambda t: _broken(t, steps=_step_change(5, writes=({"document": "a", "state": "held", "exists": True}, {"document": "z", "state": "held", "exists": True})))),
        ("more documents than the worker admits", lambda t: _broken(t, documents=("a", "m") + tuple(f"d{n}" for n in range(7)), caps={**t["caps"], "documentCleanup": 27})),
        ("more states than the worker admits", lambda t: _broken(t, states=t["states"] + tuple(f"s{n}" for n in range(30)))),
        ("token cleanup reserve short", lambda t: _broken(t, caps={**t["caps"], "tokenCleanup": 1})),
        ("document cleanup reserve short", lambda t: _broken(t, caps={**t["caps"], "documentCleanup": 5})),
        ("write before the absence probe", lambda t: _broken(t, steps=lambda steps: (steps[2], steps[0], steps[1]) + tuple(steps[3:]))),
        ("token read of an unprobed document", lambda t: _broken(t, caps={**t["caps"], "observation": 18}, steps=lambda steps: tuple(dict(step, document="m") if step["id"] == "r/read" else step for step in steps if step["id"] != "setup/absence-m"))),
        ("absence probe that allows a document", lambda t: _broken(t, steps=_step_change(0, allow=(0, 5)))),
        ("absence probe in a transaction", lambda t: _broken(t, steps=_step_change(1, tokenInput="rest-r"))),
        ("absence probe that is an observation", lambda t: _broken(t, steps=_step_change(0, role="observation"))),
        ("control step that may be refused", lambda t: _broken(t, steps=_step_change(2, allow=(0, 9)))),
        ("post-state read that may be refused", lambda t: _broken(t, steps=_step_change(10, allow=(0, 5)))),
        ("a chain that begins before the last one is done", lambda t: _broken(t, steps=lambda steps: tuple(steps[:6]) + (steps[11],) + tuple(steps[6:11]) + tuple(steps[12:]))),
        ("a probe inside a transaction", lambda t: _broken(t, caps={**t["caps"], "observation": 18}, steps=lambda steps: tuple(dict(step, document="m", allow=(5,)) if step["id"] == "r/read" else step for step in steps if step["id"] != "setup/absence-m"))),
        ("a token used across transports", lambda t: _broken(t, steps=_step_change(8, transport="grpc"))),
        ("a control commit that expects absence", lambda t: _broken(t, steps=_step_change(2, allow=(5,)))),
        ("a first read that expects presence", lambda t: _broken(t, steps=_step_change(0, allow=(0,)))),
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


def test_transaction_bytes_are_capped_at_1024_decoded_bytes():
    import base64
    program = importlib.import_module("txn_program_program")
    assert program.canonical_token(base64.b64encode(b"x" * 1024).decode())
    with pytest.raises(ValueError, match="bounded"):
        program.canonical_token(base64.b64encode(b"x" * 1025).decode())


def test_an_outside_writer_may_declare_a_deadline_up_to_90_seconds_and_a_reader_may_not(program, table):
    program.compile_plan(_broken(table, steps=_step_change(7, deadlineMs=90000)), NONCE, OWNER)
    with pytest.raises(ValueError, match="deadline"):
        program.compile_plan(_broken(table, steps=_step_change(4, deadlineMs=30000)), NONCE, OWNER)


# Frozen before adding database declarations; absent extension keys must not enter the digest.
LEGACY_DIGESTS = {'fs_txn_table_p01': 'fd2f32cffc300d46b697dcc359ec76d9e1759e522b17f3fefa3d8506dfab7889', 'fs_txn_table_p02': '1b38109181ba6120eca4e273587b4ed24dfa097c442abb2fc288ebe01f84ccc0', 'fs_txn_table_p02b': '82609a7a852a5bcb93ec8efbda5040ecbc1ec3dd728d3ab49663b560ea656e2e', 'fs_txn_table_p03': '68f373dcbef6da967eba9cca9d34b2c1a7b5c420f9eafaded84453abe968f290', 'fs_txn_table_p05': '97e0a0dbe4089029fdecc9483b67102bd5f445bed4112a96d171657176a76f3d', 'fs_txn_table_p06': '5843dd8c1d0a4ba841e9d96e4da5f6b6987310fc4017f05d301c66ccebda925c', 'fs_txn_table_p08': '1dc1d44eca4b99a23d8f3b480eb9b8d71aec4ef0894509b149fa12354c9d92bc', 'fs_txn_table_p11': 'c0a0857c152271b104dd6ae30b81cff924b855bc29753a28f9519b465e676b97', 'fs_txn_table_p12': '6b95437d01903a57ba6a15ef3a9294f6816596c532f6e92cda2c344a379aa61a', 'fs_txn_table_p13a': '8ef5cfc17df36c81844790b92d1439654d12e084f8b9323342eec3a6273be77e', 'fs_txn_table_p13b': '3c91e4695ace7cccb5089f3c8fc88425f1393ee40a13c28f97bf15ac05a63751', 'fs_txn_table_p14': '2ffcbddb8531442ac0d2c44acd21beeb70eb098dfbe8dfa04cdecb19849c9ca5'}


@pytest.mark.parametrize("module,digest", LEGACY_DIGESTS.items())
def test_earlier_tables_keep_their_exact_corpus_digest(program, module, digest):
    assert program.corpus_digest(importlib.import_module(module).TABLE) == digest


def test_declared_databases_place_roles_and_route_steps(program, table):
    changed = copy.deepcopy(table)
    changed["project"] = "fireemu-oracle-query"
    changed["databases"] = {"named": "projects/fireemu-oracle-query/databases/txn-{nonce}", "foreign": "projects/fireemu-oracle-txn/databases/(default)"}
    changed["placements"] = {"a": "named", "m": "foreign"}
    for row in changed["steps"]:
        row["onDatabase"] = "named" if row["document"] == "a" or row["rpc"] != "GetDocument" else "foreign"
    # The toy's refused multi-write commit must not mix databases.
    for row in changed["steps"]:
        row["writes"] = tuple(write for write in row["writes"] if write["document"] == "a")
    value = plan(program, changed)
    named = f"projects/fireemu-oracle-query/databases/txn-{NONCE}"
    assert value["databases"]["named"] == named
    assert value["placements"] == changed["placements"]
    assert value["documents"]["a"].startswith(named + "/documents/")
    assert value["documents"]["m"].startswith(changed["databases"]["foreign"] + "/documents/")
    for row in value["steps"]:
        request = program.request_for_step(value, row, tokens_for(value), changed)
        if "database" in request:
            assert request["database"] == named
    digest = program.corpus_digest(changed)
    other = copy.deepcopy(changed)
    other["databases"]["named"] = other["databases"]["named"].replace("txn-", "other-")
    assert program.corpus_digest(other) != digest
    other = copy.deepcopy(changed)
    other["steps"][3]["onDatabase"] = "foreign"
    assert program.corpus_digest(other) != digest


@pytest.mark.parametrize("changes", [
    {"databases": {"other": "projects/fireemu-oracle-idp/databases/(default)"}},
    {"databases": {"other": "projects/fireemu-oracle-query/databases/txn-{owner}"}},
    {"databases": {"other": "projects/fireemu-oracle-query/databases/../escape"}},
    {"databases": {"default": "projects/fireemu-oracle-query/databases/(default)"}},
    {"databases": {"x": "projects/fireemu-oracle-sbx/databases/(default)"}},
    {"databases": None},
    {"placements": None},
    {"placements": {"a": "undeclared"}},
    {"placements": {"unknown-role": "named"}, "databases": {"named": "projects/fireemu-oracle-query/databases/txn-{nonce}"}},
])
def test_database_declarations_and_placements_refuse_near_misses(program, table, changes):
    with pytest.raises(ValueError):
        plan(program, {**table, **changes})


def test_steps_refuse_undeclared_databases_and_documents_in_another_database(program, table):
    changed = copy.deepcopy(table)
    changed["steps"][3]["onDatabase"] = "undeclared"
    with pytest.raises(ValueError):
        plan(program, changed)
    changed = copy.deepcopy(table)
    changed["databases"] = {"named": "projects/fireemu-oracle-query/databases/txn-{nonce}"}
    changed["placements"] = {"a": "named"}
    with pytest.raises(ValueError):
        plan(program, changed)


def test_database_declaration_and_placement_keys_bind_the_digest_only_when_present(program, table):
    base = program.corpus_digest(table)
    assert program.corpus_digest({**table, "databases": {}}) != base
    assert program.corpus_digest({**table, "placements": {}}) != base
    assert program.corpus_digest({**table, "databases": {}}) != program.corpus_digest({**table, "databases": {}, "placements": {}})


def test_nonce_resolution_cannot_alias_two_declared_databases(program, table):
    changed = {**table, "project": "fireemu-oracle-query", "databases": {"x": "projects/fireemu-oracle-query/databases/txn-{nonce}", "y": f"projects/fireemu-oracle-query/databases/txn-{NONCE}"}}
    with pytest.raises(ValueError, match="repeat"):
        plan(program, changed)


def test_billed_secondary_projects_are_refused_before_a_plan_can_be_budgeted(program, table):
    changed = {**table, "project": "fireemu-oracle-txn", "databases": {"named": "projects/fireemu-oracle-query/databases/txn-{nonce}"}}
    with pytest.raises(ValueError, match="billed secondary"):
        plan(program, changed)


def test_budget_refuses_an_unregistered_project(program):
    with pytest.raises(ValueError, match="project differs"):
        program.budget_for("fireemu-oracle-idp")


@pytest.mark.parametrize("change", ["duplicate", "default-alias", "unknown-role", "wrong-step-database"])
def test_database_extensions_refuse_invalid_declarations_and_placements(program, change):
    changed = copy.deepcopy(importlib.import_module("fs_txn_table_p16").TABLE)
    if change == "duplicate":
        changed["databases"]["duplicate"] = changed["databases"]["named"]
    elif change == "default-alias":
        changed["databases"]["default"] = "projects/fireemu-oracle-query/databases/other"
    elif change == "unknown-role":
        changed["placements"]["unknown"] = "named"
    else:
        changed["steps"][0]["onDatabase"] = "named"
    with pytest.raises(ValueError, match="table"):
        program.corpus_digest(changed)
    with pytest.raises(ValueError, match="table"):
        plan(program, changed)


def test_s5b_has_six_writable_names_two_absent_probes_and_exact_63_cap():
    from txn_program_cli import table_for
    from txn_program_program import compile_plan
    table = table_for('s5b-web-sdk-retry')
    plan = compile_plan(table, 'a' * 32, 'b' * 32)
    assert plan['project'] == 'fireemu-oracle-query'
    assert plan['caps'] == {'observation': 34, 'tokenCleanup': 0, 'documentCleanup': 18, 'management': 10, 'credential': 1}
    assert plan['maxRequests'] == 63
    assert len(plan['documents']) == 8
    assert sum(name.endswith('_probe') for name in plan['documents'].values()) == 2
    assert all(name.startswith('projects/fireemu-oracle-query/databases/(default)/documents/conf_txn/s5b_' + 'a' * 32 + '_') for name in plan['documents'].values())
    assert plan['cases'] == ['control', 'conflict']
    assert plan['maxTokens'] == 0
