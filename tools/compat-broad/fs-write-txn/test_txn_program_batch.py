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
    # Loaded by name so a framework test does not bind a program table into every other program's manifest.
    p08 = __import__("importlib").import_module("fs_txn_table_p08")
    assert program.corpus_digest(p08.TABLE) == "1dc1d44eca4b99a23d8f3b480eb9b8d71aec4ef0894509b149fa12354c9d92bc"


def test_an_empty_commit_may_answer_without_write_results_but_a_write_may_not():
    value = table()
    ledger = collector_module.Ledger(program.compile_plan(value, NONCE, OWNER))
    ledger.docs["a"].update(status="created", state="created"); ledger.docs["m"].update(status="confirmed-absent")
    ledger.tokens["rest-t"] = {"value": "dG9rZW4=", "state": "open", "transport": "rest", "start": timing(), "lastUse": timing()}
    empty = next(step for step in ledger.plan["steps"] if step["id"] == "rest/empty-commit")
    request = {"database": ledger.plan["database"], "writes": [], "transaction": "dG9rZW4="}
    ledger.before("rest/empty-commit", "rest", "Commit", request, empty)
    ledger.after("rest/empty-commit", "rest", "Commit", request, empty, receipt("rest", response={"commitTime": "2026-09-30T00:00:00Z"}), timing())
    assert ledger.tokens["rest-t"]["state"] == "committed"
    write = next(step for step in ledger.plan["steps"] if step["id"] == "setup/create-a")
    request = program.request_for_step(ledger.plan, write, {}, value)
    ledger2 = collector_module.Ledger(program.compile_plan(value, NONCE, OWNER))
    ledger2.before("setup/create-a", "grpc", "Commit", request, write)
    with pytest.raises(ValueError, match="acknowledgement"):
        ledger2.after("setup/create-a", "grpc", "Commit", request, write, receipt("grpc", response={"commitTime": {"seconds": "1", "nanos": 0}}), timing())


@pytest.mark.parametrize("change", [{"transaction": "AAAA"}, {"result": "missing"}])
def test_a_grpc_batch_entry_with_a_stray_transaction_or_a_disagreeing_discriminator_stops(change):
    ledger = collector_module.Ledger(program.compile_plan(table(), NONCE, OWNER))
    names = ledger.plan["documents"]
    ledger.docs["a"].update(status="created", state="created"); ledger.docs["m"].update(status="confirmed-absent")
    found = {"name": names["a"], "fields": {"owner": {"stringValue": OWNER, "valueType": "stringValue"}, "nonce": {"stringValue": NONCE, "valueType": "stringValue"}, "role": {"stringValue": "a", "valueType": "stringValue"}, "state": {"stringValue": "created", "valueType": "stringValue"}}, "updateTime": {"seconds": "1", "nanos": 1}}
    step = next(step for step in ledger.plan["steps"] if step["id"] == "grpc/plain-batch")
    request = {"database": ledger.plan["database"], "documents": [names["a"], names["m"]]}
    good = [{"found": found, "transaction": "", "result": "found"}, {"missing": names["m"], "transaction": "", "result": "missing"}]
    ledger.after("x", "grpc", "BatchGetDocuments", request, step, receipt(response={"responses": copy.deepcopy(good)}), timing())
    good[0] = {**good[0], **change}
    with pytest.raises(ValueError, match="unrequested|discriminator"):
        ledger.after("x", "grpc", "BatchGetDocuments", request, step, receipt(response={"responses": good}), timing())


# --- read-only transactions ---

def ro_rows(transport, mode="readOnly"):
    def step(step_id, rpc, role, **kwargs):
        base = {"id": f"{transport}/{step_id}", "transport": transport, "rpc": rpc, "document": None, "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": None, "role": role, "allow": (0,)}
        return {**base, **kwargs}
    token = f"{transport}-s"
    return [
        step("begin", "BeginTransaction", "control", tokenOutput=token, mode=mode),
        step("writer", "Commit", "outside-writer", writes=({"document": "a", "state": f"{transport}-empty", "exists": True},), caseId=f"{transport}/writer", allow=(0, 10), deadlineMs=30000),
        step("ro-read", "GetDocument", "observation", document="a", tokenInput=token, caseId=f"{transport}/ro-read"),
        step("ro-batch", "BatchGetDocuments", "observation", documents=("a", "m"), tokenInput=token, caseId=f"{transport}/ro-batch"),
        step("ro-write", "Commit", "observation", tokenInput=token, writes=({"document": "a", "state": "held", "exists": True},), caseId=f"{transport}/ro-write", allow=(3, 5, 9, 10)),
        step("ro-empty", "Commit", "observation", tokenInput=token, caseId=f"{transport}/ro-empty"),
        step("post", "GetDocument", "post-state", document="a"),
    ]


def ro_table(mode="readOnly", transports=("rest",)):
    steps = tuple(probes() + [row for transport in transports for row in ro_rows(transport, mode)])
    return {**support.TABLE, "steps": steps, "states": ("created", "held", "moved", "rest-empty", "grpc-empty"), "maxTokens": len(transports), "caps": {"observation": len(steps), "tokenCleanup": 4, "documentCleanup": 14, "management": 7, "credential": 2}}


def record_ro(table_, **knobs):
    clock = Clock()
    plan = program.compile_plan(table_, NONCE, OWNER)
    service = Service(clock, **knobs)
    return collector_module.Collector(plan, table_, program.RequestBudget(plan, table_), service, "owner", save=lambda _s: None, monotonic=clock.now, utc=clock.utc).run(), service


@pytest.mark.parametrize("snapshot,shown", [("begin", "created"), ("first-read", "rest-empty"), ("latest", "rest-empty")])
def test_a_read_only_transaction_may_show_any_state_since_it_began(snapshot, shown):
    table_ = ro_table()
    result, service = record_ro(table_, ro_snapshot=snapshot)
    assert result["complete"] is True, result["failureType"]
    projected = collector_module.projection(result, table_)
    reads = {read["site"]: read for read in projected["reads"]}
    assert reads["rest/ro-read"]["state"] == shown
    assert reads["rest/ro-batch"]["documents"]["a"] == shown
    assert {c["caseId"]: c["code"] for c in projected["cases"]}["rest/ro-write"] == 3
    assert any(call[2].get("options") == {"readOnly": {}} for call in service.calls if call[1] == "BeginTransaction")


def test_a_read_only_transaction_cannot_show_a_state_from_before_it_began():
    table_ = ro_table()
    ledger = collector_module.Ledger(program.compile_plan(table_, NONCE, OWNER))
    names = ledger.plan["documents"]
    ledger.history["a"].extend(["created", "rest-empty", "moved"])
    ledger.docs["a"].update(status="created", state="moved"); ledger.docs["m"].update(status="confirmed-absent")
    ledger.tokens["rest-s"] = {"value": "dG9rZW4=", "state": "open", "transport": "rest", "start": timing(), "lastUse": timing()}
    # The token began when two states had been acknowledged ("rest-empty" was current); "moved" came after.
    ledger.modes["rest-s"] = "readOnly"; ledger.since["rest-s"] = {"a": 2, "m": 0}
    step = next(step for step in ledger.plan["steps"] if step["id"] == "rest/ro-read")
    def answer(state):
        return receipt("rest", response={"name": names["a"], "fields": {"owner": {"stringValue": OWNER}, "nonce": {"stringValue": NONCE}, "role": {"stringValue": "a"}, "state": {"stringValue": state}}, "updateTime": "2026-09-30T00:00:00.000000001Z"})
    request = {"name": names["a"], "transaction": "dG9rZW4="}
    for shown in ("rest-empty", "moved"):
        ledger.after("x", "rest", "GetDocument", request, step, answer(shown), timing())
    for shown in ("created", "held"):
        with pytest.raises(ValueError, match="state differs"):
            ledger.after("x", "rest", "GetDocument", request, step, answer(shown), timing())
    ledger.modes["rest-s"] = "readWrite"
    with pytest.raises(ValueError, match="state differs"):
        ledger.after("x", "rest", "GetDocument", request, step, answer("rest-empty"), timing())
    ledger.after("x", "rest", "GetDocument", request, step, answer("moved"), timing())


def test_a_read_write_transaction_still_shows_only_the_latest_state():
    table_ = ro_table(mode="readWrite")
    table_["steps"] = tuple(dict(step, allow=(3, 5, 9, 10)) if step["id"] == "rest/ro-write" else step for step in table_["steps"])
    result, _service = record_ro(table_, ro_snapshot="begin")
    assert result["complete"] is False, "a read-write transaction that sees the old state is not an allowed answer"


@pytest.mark.parametrize("label,change", [
    ("an unknown mode", lambda t: {**t, "steps": tuple(dict(s, mode="readSometimes") if s["id"] == "rest/begin" else s for s in t["steps"])}),
    ("a mode on a read", lambda t: {**t, "steps": tuple(dict(s, mode="readOnly") if s["id"] == "rest/ro-read" else s for s in t["steps"])}),
    ("a write that may succeed on a read-only token", lambda t: {**t, "steps": tuple(dict(s, allow=(0, 3)) if s["id"] == "rest/ro-write" else s for s in t["steps"])}),
])
def test_a_malformed_mode_never_compiles(label, change):
    with pytest.raises(ValueError, match="table"):
        program.compile_plan(change(ro_table()), NONCE, OWNER)


def test_the_begin_request_names_its_mode():
    table_ = ro_table()
    plan = program.compile_plan(table_, NONCE, OWNER)
    begin = next(step for step in plan["steps"] if step["id"] == "rest/begin")
    assert program.request_for_step(plan, begin, {}, table_)["options"] == {"readOnly": {}}
    plain = program.compile_plan(support.TABLE, NONCE, OWNER)
    assert program.request_for_step(plain, next(step for step in plain["steps"] if step["id"] == "r/begin"), {}, support.TABLE)["options"] == {"readWrite": {}}
    assert "mode" not in next(step for step in plain["steps"] if step["id"] == "r/begin"), "a table that names no mode keeps its digest"


# --- read times and embedded transactions in a table ---

def time_table():
    # Loaded by name so a framework test does not bind a program table into every other program's manifest.
    return copy.deepcopy(__import__("importlib").import_module("fs_txn_table_p03").TABLE)


def edit(table_, step_id, **changes):
    table_["steps"] = tuple({**step, **changes} if step["id"] == step_id else step for step in table_["steps"])
    return table_


def drop(table_, step_id, key):
    table_["steps"] = tuple({k: v for k, v in step.items() if k != key} if step["id"] == step_id else step for step in table_["steps"])
    return table_


@pytest.mark.parametrize("label,change", [
    ("a version no earlier step acknowledged", lambda t: edit(t, "rest/get-at-v1", readAt={"document": "a", "version": 3})),
    ("a negative version", lambda t: edit(t, "rest/get-at-v1", readAt={"document": "a", "version": -1})),
    ("a boolean version", lambda t: edit(t, "rest/get-at-v1", readAt={"document": "a", "version": True})),
    ("a document nothing ever wrote", lambda t: edit(t, "rest/get-at-v1", readAt={"document": "m", "version": 0})),
    ("an unknown document", lambda t: edit(t, "rest/get-at-v1", readAt={"document": "z", "version": 0})),
    ("extra keys", lambda t: edit(t, "rest/get-at-v1", readAt={"document": "a", "version": 1, "extra": 1})),
    ("a missing key", lambda t: edit(t, "rest/get-at-v1", readAt={"document": "a"})),
    ("a read time on a commit", lambda t: edit(t, "rest/emb/commit", readAt={"document": "a", "version": 1})),
    ("a read time on a rollback-less read inside a transaction", lambda t: edit(t, "rest/ro/read-a", readAt={"document": "a", "version": 1})),
    ("a read time on a read-write begin", lambda t: drop(t, "rest/ro/begin", "mode")),
    ("a read time beside an embedded transaction", lambda t: edit(t, "rest/emb/batch-new", readAt={"document": "a", "version": 1})),
    ("a read time before the version exists", lambda t: edit(t, "setup/create-a", readAt={"document": "a", "version": 0})),
    ("an embedded transaction on a plain read", lambda t: edit(t, "rest/current-a", newTransaction="readWrite")),
    ("an unknown embedded mode", lambda t: edit(t, "rest/emb/batch-new", newTransaction="readSometimes")),
    ("an embedded transaction with no token output", lambda t: edit(t, "rest/emb/batch-new", tokenOutput=None)),
    ("an embedded transaction inside a transaction", lambda t: edit(t, "rest/emb/batch-new", tokenInput="rest-ro")),
    ("an embedded transaction that reuses a token", lambda t: edit(t, "grpc/emb/batch-new", tokenOutput="rest-emb")),
    ("a token output on a batch that begins nothing", lambda t: edit(t, "rest/batch-at-v1", tokenOutput="rest-x")),
])
def test_a_malformed_read_time_or_embedded_transaction_never_compiles(label, change):
    with pytest.raises(ValueError, match="table"):
        program.compile_plan(change(time_table()), NONCE, OWNER)


def test_an_embedded_transaction_may_not_start_while_an_earlier_token_is_still_used():
    table_ = time_table()
    steps = list(table_["steps"])
    ro_index = next(i for i, step in enumerate(steps) if step["id"] == "rest/ro/read-a")
    emb_index = next(i for i, step in enumerate(steps) if step["id"] == "rest/emb/batch-new")
    steps.insert(ro_index, steps.pop(emb_index))
    table_["steps"] = tuple(steps)
    with pytest.raises(ValueError, match="table"):
        program.compile_plan(table_, NONCE, OWNER)


def test_read_times_and_embedded_transactions_do_not_move_an_earlier_tables_digest():
    plain = program.compile_plan(support.TABLE, NONCE, OWNER)
    assert not [step for step in plain["steps"] if "readAt" in step or "newTransaction" in step]
    assert program.corpus_digest(support.TABLE) == "624ee4410100a3a30d90bdc80ad2133bd4c68dadde18978b7c425749bd957099"
