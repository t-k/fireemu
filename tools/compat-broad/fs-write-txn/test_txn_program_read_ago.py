"""A read may name a time N seconds before it is sent (the one-hour retention boundary); the recorded request must be that one."""

import copy
import importlib

import pytest

NONCE, OWNER = "a" * 32, "b" * 32
WIDE = (0, 3, 5, 9, 10)
NOW = 1_788_000_000.25


@pytest.fixture
def program():
    return importlib.import_module("txn_program_program")


@pytest.fixture
def toy():
    return importlib.import_module("txn_program_support_for_tests")


def ago(step_id, transport, rpc, seconds, **fields):
    row = {"id": step_id, "transport": transport, "rpc": rpc, "document": "a" if rpc == "GetDocument" else None, "tokenInput": None, "tokenOutput": None,
           "writes": (), "caseId": step_id, "role": "observation", "allow": WIDE, "readAgoSeconds": seconds}
    if rpc == "BatchGetDocuments":
        row["documents"] = ["a"]
    if rpc == "BeginTransaction":
        row.update(mode="readOnly", tokenOutput="ro-token")
    row.update(fields)
    return row


def table_with(toy, *extra, max_tokens=None):
    table = copy.deepcopy(toy.TABLE)
    table["steps"] = tuple(table["steps"]) + extra
    table["caps"] = {**table["caps"], "observation": len(table["steps"])}
    if max_tokens:
        table["maxTokens"] = max_tokens
        table["caps"]["tokenCleanup"] = max_tokens
    return table


def test_a_read_ago_request_names_now_less_the_seconds(program, toy):
    steps = (ago("ago/get", "rest", "GetDocument", 3540), ago("ago/batch", "grpc", "BatchGetDocuments", 3660))
    table = table_with(toy, *steps)
    plan = program.compile_plan(table, NONCE, OWNER)
    get, batch = plan["steps"][-2:]
    assert program.request_for_step(plan, get, {}, table, now=NOW)["readTime"] == {"seconds": str(1_788_000_000 - 3540), "nanos": 250_000_000}
    assert program.request_for_step(plan, batch, {}, table, now=NOW)["readTime"] == {"seconds": str(1_788_000_000 - 3660), "nanos": 250_000_000}
    with pytest.raises(ValueError, match="now"):
        program.request_for_step(plan, get, {}, table)


def test_a_read_only_begin_may_read_at_a_time_ago(program, toy):
    begin = ago("ago/begin", "rest", "BeginTransaction", 3540)
    table = table_with(toy, begin, max_tokens=3)
    plan = program.compile_plan(table, NONCE, OWNER)
    request = program.request_for_step(plan, plan["steps"][-1], {}, table, now=NOW)
    assert request["options"] == {"readOnly": {"readTime": {"seconds": str(1_788_000_000 - 3540), "nanos": 250_000_000}}}


@pytest.mark.parametrize("label,step", [
    ("zero seconds", ago("ago/z", "rest", "GetDocument", 0)),
    ("negative seconds", ago("ago/n", "rest", "GetDocument", -5)),
    ("not an int", ago("ago/f", "rest", "GetDocument", 3.5)),
    ("over two hours", ago("ago/big", "rest", "GetDocument", 7201)),
    ("inside a transaction", ago("ago/t", "rest", "GetDocument", 60, tokenInput="rest-r")),
    ("beside readAt", ago("ago/a", "rest", "GetDocument", 60, readAt={"document": "a", "commit": "setup/create-a"})),
    ("on a commit", ago("ago/c", "rest", "Commit", 60, writes=({"document": "a", "state": "held", "exists": True},))),
    ("on a rollback", ago("ago/r", "rest", "Rollback", 60, tokenInput="rest-r")),
    ("on a read-write begin", ago("ago/rw", "rest", "BeginTransaction", 60, mode="readWrite")),
    ("with a new transaction", ago("ago/nt", "rest", "BatchGetDocuments", 60, newTransaction="readOnly", tokenOutput="ro-new")),
])
def test_a_misplaced_read_ago_never_compiles(program, toy, label, step):
    with pytest.raises(ValueError):
        program.compile_plan(table_with(toy, step, max_tokens=3), NONCE, OWNER)


def test_the_recorded_read_time_must_be_the_dispatch_time_less_the_seconds_within_a_short_build_delay(program):
    step = {"readAgoSeconds": 3540}
    expected = {"name": "n", "readTime": {"seconds": str(1_788_000_000 - 3540), "nanos": 250_000_000}}
    def recorded(offset):
        total = (1_788_000_000 - 3540 + 0.25) - offset
        whole = int(total // 1)
        return {"name": "n", "readTime": {"seconds": str(whole), "nanos": int(round((total - whole) * 1e9))}}
    assert program.same_request(step, recorded(0.0), expected)
    assert program.same_request(step, recorded(4.9), expected)
    assert not program.same_request(step, recorded(5.5), expected)      # built far too early
    assert not program.same_request(step, recorded(-1.0), expected)     # built after its own dispatch
    assert not program.same_request(step, {**recorded(0.0), "name": "other"}, expected)
    # a step without readAgoSeconds compares exactly
    assert program.same_request({}, expected, expected)
    assert not program.same_request({}, recorded(1.0), expected)


class AgoWire:
    """A Firestore stand-in that answers a read at a time ago the way a project with one hour of retention does: refused beyond it, not found within it."""

    def __init__(self, inner):
        self.inner, self.sent = inner, []

    def __getattr__(self, name):
        return getattr(self.inner, name)

    TOKEN = "dG9rZW4tYWdv"

    def send(self, transport, method, request, **kwargs):
        read_time = request.get("readTime") or request.get("options", {}).get("readOnly", {}).get("readTime")
        if method == "Rollback" and request.get("transaction") == self.TOKEN:
            return {"kind": "txn-program-receipt-v1", "transport": transport, "complete": True, "code": 0, "details": "", "response": {}, "http": None if transport == "grpc" else 200, "dispatchedRequests": 1, "childReaped": True}
        if read_time is None:
            return self.inner.send(transport, method, request, **kwargs)
        self.sent.append((transport, method, request))
        refused = method in ("GetDocument", "BatchGetDocuments", "BeginTransaction") and self.refuse(request)
        code = 3 if refused else (5 if method == "GetDocument" else 0)
        response = None
        if code == 0 and method == "BatchGetDocuments":
            response = {"responses": [{"missing": request["documents"][0], "readTime": "2026-09-30T00:00:00.000000001Z"}]} if transport == "rest" else {"responses": [{"missing": request["documents"][0], "result": "missing"}]}
        if code == 0 and method == "BeginTransaction":
            response = {"transaction": self.TOKEN}
        return {"kind": "txn-program-receipt-v1", "transport": transport, "complete": True, "code": code, "details": "" if code == 0 else ("The read time is too old" if code == 3 else "Document not found"),
                "response": response, "http": None if transport == "grpc" else {0: 200, 3: 400, 5: 404}[code], "dispatchedRequests": 1, "childReaped": True}

    refuse = staticmethod(lambda request: False)


def ago_old(request):
    """Refused when the named time is more than an hour before the dispatch (the test clock stands at 2026-09-30T00:01:40Z)."""
    read_time = request.get("readTime") or request.get("options", {}).get("readOnly", {}).get("readTime")
    clock_now = 1_790_726_500  # 2026-09-30T00:01:40Z
    return int(read_time["seconds"]) < clock_now - 3600


def run_ago(toy, program, steps, refuse):
    collector_tests = importlib.import_module("test_txn_program_collector")
    table = table_with(toy, *steps, max_tokens=2 + sum(step["rpc"] == "BeginTransaction" for step in steps) or None)
    collector, service, budget, journal, clock, plan = collector_tests.fixture(table)
    wire = AgoWire(service)
    wire.refuse = refuse
    collector.wire = wire
    return collector.run(), wire, table, clock


def test_a_recording_with_reads_at_a_time_ago_completes_and_each_request_names_its_dispatch_time_less_the_seconds(program, toy):
    rollback = {"id": "ago/rollback-59", "transport": "rest", "rpc": "Rollback", "document": None, "tokenInput": "ro-59", "tokenOutput": None, "writes": (), "caseId": "ago/rollback-59",
                "role": "observation", "allow": WIDE}
    steps = (ago("ago/get-59", "rest", "GetDocument", 3540), ago("ago/get-61", "rest", "GetDocument", 3660), ago("ago/batch-61", "grpc", "BatchGetDocuments", 3660),
             ago("ago/begin-59", "rest", "BeginTransaction", 3540, tokenOutput="ro-59"), rollback, ago("ago/begin-61", "rest", "BeginTransaction", 3660, tokenOutput="ro-61"))
    receipt, wire, table, clock = run_ago(toy, program, steps, refuse=ago_old)
    assert receipt["complete"] is True and receipt["graphComplete"] is True and receipt["unrecovered"] is False
    collector_module = importlib.import_module("txn_program_collector")
    rows = {row["site"]: row for row in receipt["steps"]}
    for step in (step for step in steps if "readAgoSeconds" in step):
        row = rows[step["id"]]
        request = row["request"]
        read_time = request.get("readTime") or request["options"]["readOnly"]["readTime"]
        dispatched = collector_module._utc_seconds(row["timing"]["dispatchUtc"])
        assert 0 <= dispatched - step["readAgoSeconds"] - (int(read_time["seconds"]) + read_time["nanos"] / 1e9) <= 5
    # the replay of the rows accepts them
    assert collector_module.projection(receipt, table)["cases"]


def test_a_recorded_read_time_that_moved_is_not_the_declared_request(program, toy):
    steps = (ago("ago/get-59", "rest", "GetDocument", 3540),)
    receipt, _wire, table, _clock = run_ago(toy, program, steps, refuse=lambda read_time: False)
    collector_module = importlib.import_module("txn_program_collector")
    tampered = copy.deepcopy(receipt)
    for row in tampered["steps"]:
        if row["site"] == "ago/get-59":
            row["request"]["readTime"]["seconds"] = str(int(row["request"]["readTime"]["seconds"]) - 30)
    with pytest.raises(ValueError):
        collector_module.projection(tampered, table)


def test_a_document_found_at_a_time_before_it_existed_is_recorded_not_judged(program, toy):
    """Production's answer to a time ago is the observation: even a found document (which this recording could not have written yet) is not a reason to stop."""
    steps = (ago("ago/get-59", "rest", "GetDocument", 3540),)
    collector_tests = importlib.import_module("test_txn_program_collector")
    table = table_with(toy, *steps)
    collector, service, _budget, _journal, _clock, _plan = collector_tests.fixture(table)
    inner = service

    class Found:
        def __getattr__(self, name):
            return getattr(inner, name)

        def send(self, transport, method, request, **kwargs):
            if request.get("readTime") is None:
                return inner.send(transport, method, request, **kwargs)
            name = request["name"]
            document = {"name": name, "fields": {"owner": {"stringValue": OWNER}, "nonce": {"stringValue": NONCE}, "role": {"stringValue": "a"}, "state": {"stringValue": "created"}}, "createTime": "2026-09-30T00:00:00.000000001Z", "updateTime": "2026-09-30T00:00:00.000000001Z"}
            return {"kind": "txn-program-receipt-v1", "transport": transport, "complete": True, "code": 0, "details": "", "response": document, "http": 200, "dispatchedRequests": 1, "childReaped": True}

    collector.wire = Found()
    receipt = collector.run()
    assert receipt["complete"] is True
