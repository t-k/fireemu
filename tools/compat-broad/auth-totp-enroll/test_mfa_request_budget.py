"""Pre-dispatch aggregate limits on real local runner objects; no production I/O."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from unittest.mock import patch

import pytest
import mfa_local_shadow as shadow
from mfa_collector import load_checkpoint
from mfa_manifest import compile_campaign
from mfa_request_budget import RequestBudget, RequestBudgetError, valid_summary


def instance():
    return shadow.Instance("http://127.0.0.1:9099", "http://127.0.0.1:9100", "CONTROL")


def charge(budget, count):
    for _ in range(count):
        with budget.attempt():
            pass


def send_recovery(client, uid, operation):
    return client.admin(f"/v1/projects/{shadow.PROJECT}/accounts:{operation}",
                        {"localId": uid if operation == "delete" else [uid]})


@pytest.mark.parametrize("maximum,accounts", [
    (True, 1), (1.0, 1), ("10", 1), (-1, 1), (401, 1), (0, 1), (8, True),
    (8, 1.0), (8, "1"), (8, 0), (8, -1), (400, 15), (4, 2), (3, 2),
])
def test_budget_rejects_untyped_or_expanded_bounds(maximum, accounts):
    with pytest.raises(ValueError):
        RequestBudget(maximum, accounts)


def test_all_400_slots_are_bounded_and_observation_cannot_spend_recovery(monkeypatch):
    client = instance()
    calls = []
    monkeypatch.setattr(shadow, "_call", lambda *args: (calls.append(args) or (200, {})))
    plan = compile_campaign("a" * 32)
    client.bind_plan(plan)
    for _ in range(372):
        client.emulator("/verificationCodes")
    for _ in range(3):
        with pytest.raises(RequestBudgetError):
            client.public("/v1/accounts:signUp", {})
    assert len(calls) == client.requests == 372
    uids = tuple(f"owned-{i}" for i in range(14))
    client.begin_recovery(uids)
    for uid in uids:
        send_recovery(client, uid, "delete")
        send_recovery(client, uid, "lookup")
    assert len(calls) == client.requests == 400
    client.begin_recovery(tuple(reversed(uids)))
    with pytest.raises(RequestBudgetError):
        send_recovery(client, uids[0], "delete")
    summary = client.finish_requests()
    assert summary["observationRequests"] == 372 and summary["recoveryRequests"] == 28
    assert summary["requestsCharged"] == 400
    assert valid_summary(summary, plan, 400, successful=False)
    assert not valid_summary(summary, plan, 400)
    assert len(calls) == 400


@pytest.mark.parametrize("route", ["public", "admin", "inspection", "clock-read", "clock-advance"])
def test_every_http_entry_uses_the_same_pre_dispatch_reservation(monkeypatch, route):
    client = instance()
    calls = []
    def sender(*args):
        calls.append(args)
        return 200, {"clock": "2026-09-20T00:00:00Z"}
    monkeypatch.setattr(shadow, "_call", sender)
    request = {
        "public": lambda: client.public("/v1/accounts:lookup", {}),
        "admin": lambda: client.admin("/v1/x", {}),
        "inspection": lambda: client.emulator("/verificationCodes"),
        "clock-read": client.now, "clock-advance": lambda: client.advance(1),
    }[route]
    for _ in range(372):
        request()
    with pytest.raises(RequestBudgetError):
        request()
    assert len(calls) == client.requests == 372


@pytest.mark.parametrize("failure", [OSError, TimeoutError, ValueError, KeyboardInterrupt])
def test_failed_calls_remain_charged_and_recovery_has_no_retry(failure, monkeypatch):
    client = instance()
    calls = []
    def fail(*args):
        calls.append(args)
        raise failure("PRIVATE")
    monkeypatch.setattr(shadow, "_call", fail)
    with pytest.raises(failure):
        client.public("/v1/accounts:lookup", {})
    assert client.requests == 1
    client.begin_recovery(("owned",))
    with pytest.raises(failure):
        send_recovery(client, "owned", "delete")
    with pytest.raises(RequestBudgetError):
        send_recovery(client, "owned", "delete")
    assert client.requests == len(calls) == 2
    assert client.finish_requests()["inFlight"] is False


@pytest.mark.parametrize("mode", ["signup", "control", "inspection", "other-uid", "array-delete", "string-lookup",
                                  "extra-field", "query-alias", "no-owner", "lookup-before-delete", "reentry-observation"])
def test_recovery_slots_cannot_be_used_for_unrelated_requests(monkeypatch, mode):
    client = instance()
    client.begin_recovery(("owned",))
    calls = []
    monkeypatch.setattr(shadow, "_call", lambda *args: (calls.append(args) or (200, {})))
    prefix = f"{client.identity}/v1/projects/{shadow.PROJECT}/accounts:"
    attempts = {
        "signup": lambda: client.public("/v1/accounts:signUp", {}),
        "control": client.now,
        "inspection": lambda: client.emulator("/verificationCodes"),
        "other-uid": lambda: send_recovery(client, "other", "delete"),
        "array-delete": lambda: client.admin(f"/v1/projects/{shadow.PROJECT}/accounts:delete", {"localId": ["owned"]}),
        "string-lookup": lambda: client.admin(f"/v1/projects/{shadow.PROJECT}/accounts:lookup", {"localId": "owned"}),
        "extra-field": lambda: client.send(prefix + "delete", {"localId": "owned", "x": 1}, "owner"),
        "query-alias": lambda: client.send(prefix + "delete?x=1", {"localId": "owned"}, "owner"),
        "no-owner": lambda: client.send(prefix + "delete", {"localId": "owned"}),
        "lookup-before-delete": lambda: send_recovery(client, "owned", "lookup"),
        "reentry-observation": lambda: client.public("/v1/accounts:lookup", {}),
    }
    with pytest.raises(ValueError):
        attempts[mode]()
    assert not calls and client.requests == 0
    # A rejected unrelated call grants no authority, consumes no actual HTTP
    # attempt and does not prevent the original, still-authorized pair.
    send_recovery(client, "owned", "delete")
    send_recovery(client, "owned", "lookup")
    assert len(calls) == 2


@pytest.mark.parametrize("scope", [["a"], ("a", "a"), (True,), ("",), ("\ud800",), ("bad\n",), tuple(str(i) for i in range(15))])
def test_invalid_recovery_scope_is_atomic(scope):
    b = RequestBudget()
    before = b.snapshot()
    with pytest.raises(ValueError):
        b.begin_recovery(scope)
    assert b.snapshot() == before


def test_scope_retry_and_snapshot_mutation_never_replenish_slots():
    b = RequestBudget(8, 2)
    charge(b, 4)
    b.begin_recovery(("one", "two"))
    with b.attempt(operation="delete", uid="one"):
        pass
    snapshot = b.snapshot()
    snapshot.update(requestsCharged=0, phase="observation", maxRequests=10000)
    with pytest.raises(ValueError):
        b.begin_recovery(("new",))
    b.begin_recovery(("two", "one"))
    with pytest.raises(ValueError):
        with b.attempt(operation="delete", uid="one"):
            pytest.fail("replayed delete")
    assert b.requests == 5
    b.close()
    with pytest.raises(ValueError):
        b.begin_recovery(("one", "two"))
    with pytest.raises(ValueError):
        with b.attempt(operation="lookup", uid="one"):
            pytest.fail("closed budget")
    assert b.requests == 5


def test_plan_is_bound_once_and_never_after_requests():
    plan = compile_campaign("b" * 32)
    b = RequestBudget()
    b.bind(plan)
    for other in (plan, compile_campaign("c" * 32)):
        with pytest.raises(ValueError):
            b.bind(other)
    used = RequestBudget()
    charge(used, 1)
    with pytest.raises(ValueError):
        used.bind(plan)
    assert used.requests == 1


@pytest.mark.parametrize("field,value", [("maxRequests", 401), ("maxRequests", 400.0), ("maxOwnedAccounts", 15), ("maxConcurrency", 2)])
def test_invalid_plan_cannot_change_runtime_allowances(field, value):
    b = RequestBudget()
    plan = compile_campaign("d" * 32)
    plan["limits"][field] = value
    with pytest.raises(ValueError):
        b.bind(plan)
    assert b.requests == 0 and b.snapshot()["maxRequests"] == 400


def test_nested_or_concurrent_calls_cannot_switch_phase_or_close_in_flight():
    b = RequestBudget()
    entered, release = threading.Event(), threading.Event()
    def active():
        with b.attempt():
            entered.set()
            assert release.wait(3)
    t = threading.Thread(target=active)
    t.start()
    try:
        assert entered.wait(3)
        with pytest.raises(ValueError):
            with b.attempt():
                pytest.fail("concurrent send")
        with pytest.raises(ValueError):
            b.begin_recovery(())
        with pytest.raises(ValueError):
            b.close()
        assert b.requests == 1
    finally:
        release.set()
        t.join(3)
    assert not t.is_alive()
    b.begin_recovery(())
    b.close()


def test_sequence_exhaustion_preserves_ownership_and_uses_only_reserved_tail(tmp_path, monkeypatch):
    calls, present = [], set()
    client = instance()
    def sender(url, body, token):
        calls.append(url)
        if ":signUp" in url:
            present.add("owned")
            return 200, {"localId": "owned", "email": body["email"], "idToken": "PRIVATE"}
        if url.endswith(":delete"):
            present.remove(body["localId"])
            return 200, {}
        return 200, {"users": []}
    monkeypatch.setattr(shadow, "_call", sender)
    def walk(client, state, checkpoint, rows, accounts, *, journal):
        shadow._create_owned_account(client, state, accounts, journal, "pending-control", False)
        for _ in range(372):
            client.emulator("/verificationCodes")
    monkeypatch.setattr(shadow, "_walk", walk)
    with pytest.raises(RequestBudgetError, match="observation allowance"):
        shadow.run_sequence(client, tmp_path)
    assert not present and len(calls) == client.requests == 374
    assert calls[-2].endswith(":delete") and calls[-1].endswith(":lookup")
    state = load_checkpoint((tmp_path / "checkpoint.json").read_bytes())
    assert state["aborted"] is True and state["requests"] == 374
    assert state["ownedResources"][0]["absenceVerified"] is True
    records = [json.loads(p.read_bytes()) for p in sorted((tmp_path / "responsibility").glob("*.json"))]
    final = records[-1]["body"]
    assert final["requestBudget"]["requestsCharged"] == 374
    assert final["requestBudget"]["observationLimitHit"] is True
    assert final["summary"]["resourceCleanupComplete"] is True
    assert final["observationAborted"] is True
    assert "PRIVATE" not in json.dumps(records)


def test_fresh_run_cannot_reuse_closed_instance(tmp_path, monkeypatch):
    client = instance()
    monkeypatch.setattr(shadow, "_walk", lambda *a, **k: (_ for _ in ()).throw(ValueError("stop")))
    with pytest.raises(ValueError, match="stop"):
        shadow.run_sequence(client, tmp_path)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="fresh local plan"):
        shadow.run_sequence(client, other)
    assert list(other.iterdir()) == []


def summary():
    p = compile_campaign("e" * 32)
    b = RequestBudget()
    b.bind(p)
    charge(b, 2)
    b.begin_recovery(("u",))
    for op in ("delete", "lookup"):
        with b.attempt(operation=op, uid="u"):
            pass
    b.close()
    return p, b.snapshot()


@pytest.mark.parametrize("field,value", [
    ("requestsCharged", 4.0), ("maxRequests", 401), ("observationRequests", 373),
    ("recoveryRequests", 3), ("recoveryAccounts", 0), ("phase", "observation"),
    ("inFlight", True), ("recoveryEntered", 1), ("observationLimitHit", True),
    ("reservedRecoveryRequests", 0), ("observationLimit", 400), ("planDigest", "0" * 64),
    ("authorizesCleanup", True), ("schema", "other"),
])
def test_explicit_receipt_cannot_override_accounting_with_complete_flags(field, value):
    from mfa_comparator import _receipt_problems
    from mfa_provenance import repository_root
    plan, value0 = summary()
    assert valid_summary(value0, plan, 4)
    value0[field] = value
    assert not valid_summary(value0, plan, 4)
    receipt = {"recordingComplete": True, "campaign": plan, "requestsCharged": 4, "requestBudget": value0}
    assert "transport request budget is incomplete or inconsistent" in _receipt_problems(receipt, "local", repository_root())


def test_real_local_wire_is_never_opened_for_denied_attempts(monkeypatch):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((self.path, body))
            payload = b'{}' if self.path.endswith(":delete") else b'{"users":[]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def log_message(self, *args):
            pass
    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{http.server_port}"
    client = shadow.Instance(origin, origin, "CONTROL")
    try:
        # Fill observation slots using an injected sender; only the two cleanup
        # requests below use the real TCP/worker path, not 374 real API requests.
        with patch.object(shadow, "_call", return_value=(200, {})):
            for _ in range(372):
                client.emulator("/verificationCodes")
        with pytest.raises(RequestBudgetError):
            client.public("/v1/accounts:signUp", {})
        assert not seen
        client.begin_recovery(("owned",))
        assert send_recovery(client, "owned", "delete") == (200, {})
        assert send_recovery(client, "owned", "lookup") == (200, {"users": []})
        assert len(seen) == 2 and client.requests == 374
    finally:
        http.shutdown()
        http.server_close()
        thread.join(3)
    assert not thread.is_alive()


@pytest.mark.parametrize("operation", ["delete", "lookup"])
def test_caller_body_mutation_cannot_retarget_an_admitted_recovery(operation, monkeypatch):
    client = instance()
    client.begin_recovery(("owned",))
    monkeypatch.setattr(shadow, "_call", lambda *a: (200, {}))
    if operation == "lookup":
        send_recovery(client, "owned", "delete")
    original = {"localId": "owned" if operation == "delete" else ["owned"]}
    observed = []
    def sender(url, admitted, token):
        if operation == "delete":
            original["localId"] = "foreign"
        else:
            original["localId"][0] = "foreign"
        observed.append(admitted)
        return 200, {}
    monkeypatch.setattr(shadow, "_call", sender)
    client.admin(f"/v1/projects/{shadow.PROJECT}/accounts:{operation}", original)
    assert observed == [{"localId": "owned" if operation == "delete" else ["owned"]}]
    assert original == {"localId": "foreign" if operation == "delete" else ["foreign"]}
