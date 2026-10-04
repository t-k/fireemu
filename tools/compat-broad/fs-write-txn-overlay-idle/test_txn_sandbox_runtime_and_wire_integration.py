"""Offline regression obligations for the reviewed runtime and real JSON wire."""

import datetime as dt
import importlib
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_expiry_collector as collector
import txn_expiry_offline_backend as offline
import txn_expiry_plan as plan
import txn_sandbox_admission as admission
import txn_sandbox_cli as cli
import txn_sandbox_contract as contract
import txn_sandbox_recovery as recovery
import txn_sandbox_run as runner
import txn_sandbox_session as session
import txn_sandbox_wire as wire
from test_txn_sandbox_admission import DELEGATED, ENVELOPE, LAST, NOW, PINS
from test_txn_sandbox_recovery import document, fixture_context, snapshot

NONCE = "0123456789abcdef0123456789abcdef"
OWNER = "11111111222233334444555566667777"
ACTOR = "Claude（委任。オーナーの裁量の委任 2026-09-28）"
from test_txn_delegation_fixtures import AUTHORITY


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("This regression suite must never open a socket")
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


@pytest.mark.parametrize("module", [cli, recovery])
@pytest.mark.parametrize("version", [(3, 9, 6), (3, 11, 14)])
def test_main_refuses_old_runtime_before_admission_or_credentials(monkeypatch, module, version):
    touched = []
    monkeypatch.setattr(sys, "version_info", version)
    monkeypatch.setattr(cli, "_main_root", lambda: touched.append("root"))
    monkeypatch.setattr(session, "_access_token", lambda: touched.append("credential"))
    monkeypatch.setattr(runner, "record_twice", lambda **_kwargs: touched.append("send"))
    monkeypatch.setattr(recovery, "record_recovery", lambda **_kwargs: touched.append("recovery"))
    with pytest.raises(ValueError, match="Python 3.12"):
        module.main([])
    assert touched == []


def test_launcher_uses_only_the_pinned_uv_runtime(monkeypatch):
    launcher = importlib.import_module("txn_sandbox_launcher")
    seen = []
    monkeypatch.setattr(launcher.subprocess, "run", lambda command, **kwargs: seen.append((command, kwargs)) or subprocess.CompletedProcess(command, 0))
    assert launcher.main(["record", "plan-local"]) == 0
    assert seen[0][0] == ["uv", "run", "--python", "3.12.13", "python", str(cli.HERE / "txn_sandbox_cli.py"), "plan-local"]
    assert seen[0][1]["check"] is False


def test_runtime_pin_and_evidence_are_exact(monkeypatch):
    runtime = importlib.import_module("txn_sandbox_runtime")
    runtime.require_packet_runtime("3.12.13")
    evidence = runtime.evidence()
    assert evidence == {"pythonVersion": "3.12.13", "pythonSysVersion": sys.version, "pythonExecutable": sys.executable}
    for wrong in (None, "3.12", "3.12.12", "3.14.3"):
        with pytest.raises(ValueError, match="runtime"):
            runtime.require_packet_runtime(wrong)
    monkeypatch.setattr(sys, "version_info", (3, 12, 14))
    with pytest.raises(ValueError, match="runtime"):
        runtime.require_packet_runtime("3.12.13")


def test_session_old_runtime_never_charges_or_acquires_credentials(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(sys, "version_info", (3, 9, 6))
    with pytest.raises(ValueError, match="Python 3.12"):
        session.run_once(NONCE, OWNER, tmp_path, {}, credential_fn=lambda: seen.append("credential"))
    assert seen == [] and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("digits", range(10))
def test_fractional_instant_property_covers_every_supported_precision(digits):
    fraction = "." + "123456789"[:digits] if digits else ""
    value = "2024-02-29T23:59:59" + fraction + "Z"
    assert collector.valid_instant(value)
    assert admission._instant(value) == dt.datetime(2024, 2, 29, 23, 59, 59, int(("123456789"[:digits] + "000000")[:6]), tzinfo=dt.timezone.utc)


@pytest.mark.parametrize("value", ["2023-02-29T00:00:00Z", "2024-13-01T00:00:00Z", "2024-02-29T24:00:00Z", "2024-02-29T23:59:60Z", "2024-02-29T00:00:00.1234567890Z"])
def test_instant_property_rejects_invalid_calendar_and_precision(value):
    assert not collector.valid_instant(value)
    with pytest.raises(ValueError, match="timestamp"):
        admission._instant(value)


def install_exchange(monkeypatch, backend, *, failure_site=None, malformed_site=None, budget=None):
    """Only the IPC boundary is replaced; JSON and response validation stay real."""
    active = {"request": None}
    def exchange(**kwargs):
        request = active["request"]
        header_raw, body_raw = kwargs["request_payload"].split(b"\n", 1)
        header = json.loads(header_raw)
        assert header["project"] == "fireemu-oracle-sbx"
        assert header["bodyBytes"] == len(body_raw)
        assert (json.loads(body_raw) if body_raw else None) == request["body"]
        backend.calls.append(request)
        if request["site"] == failure_site:
            raise TimeoutError("exchange failed")
        status, body = backend.answer(request)
        if request["site"] == malformed_site:
            body = {"writeResults": []}
        return status, "application/json; charset=UTF-8", json.dumps(body).encode(), None
    monkeypatch.setattr(wire, "_run_process_exchange", exchange)
    budget = budget or contract.RequestBudget(plan.compile_plan(NONCE, OWNER))
    fixed = wire.FixedDataWire("offline-test-token", budget)
    def send(request):
        active["request"] = request
        return fixed(request)
    return send, budget


def collection(send, *, responsibility=None):
    seconds = [0.0]
    def sleep(value):
        seconds[0] += value
    return collector.Collection({"target": "production", "host": collector.PRODUCTION_HOST, "projectId": "fireemu-oracle-sbx", "database": "(default)", "nonce": NONCE, "ownerId": OWNER, "timing": collector.WALL_CLOCK, "deadlineSeconds": plan.WALL_SECONDS}, plan.compile_plan(NONCE, OWNER), send, monotonic=lambda: seconds[0], sleeper=sleep, responsibility=responsibility)


def test_real_wire_json_collection_setup_through_typed_cleanup(monkeypatch):
    backend = offline.Backend()
    send, budget = install_exchange(monkeypatch, backend)
    result = collection(send).run()
    assert result["complete"] is True and result["unrecovered"] == []
    assert result["requestCount"] == budget.total == len(backend.calls)
    assert result["requestCount"] > 30
    assert backend.documents == {}
    assert any(request["rpc"] == "Rollback" for request in backend.calls)
    assert all(entry["absent"] is True for entry in result["cleanup"])


class Metadata:
    """The five preflight and two postflight management reads, without credentials."""
    def __init__(self, _token, _baseline, budget):
        self.budget = budget

    def preflight(self):
        for _ in range(5):
            self.budget.charge("management")
        return {"project": "fixed", "database": "fixed"}

    def postflight(self):
        for _ in range(2):
            self.budget.charge("management")
        return {"project": "fixed", "database": "fixed"}


def test_session_real_wire_receipt_records_runtime_and_entire_request_budget(tmp_path, monkeypatch):
    backend = offline.Backend()
    result = session.run_once(NONCE, OWNER, tmp_path, {}, credential_fn=lambda: "offline-test-token", metadata_factory=Metadata,
                              wire_factory=lambda _token, budget: install_exchange(monkeypatch, backend, budget=budget)[0],
                              collector_factory=lambda _options, _plan, send, responsibility: collection(send, responsibility=responsibility))
    assert result["complete"] is True
    assert result["sandboxRequests"] == result["requestCount"] + 8
    assert result["pythonVersion"] == "3.12.13"
    assert result["pythonSysVersion"] == sys.version and result["pythonExecutable"] == sys.executable


def test_real_wire_validation_exception_recovers_applied_create(monkeypatch):
    backend = offline.Backend()
    send, budget = install_exchange(monkeypatch, backend)
    original = wire.remote.normalize
    def normalize(status, raw, request):
        if request["site"] == "setup/create/control":
            raise TypeError("injected validation error")
        return original(status, raw, request)
    monkeypatch.setattr(wire.remote, "normalize", normalize)
    snapshots = []
    result = collection(send, responsibility=snapshots.append).run()
    assert result["complete"] is False and result["unrecovered"] == []
    assert any(value["resourceStates"]["control"] == "sent-unknown" for value in snapshots)
    assert backend.documents == {}
    assert result["requestCount"] == budget.total == 9
    failed = next(row for row in result["rows"] if row["slot"] == "setup/create/control")
    assert failed["observed"]["httpStatus"] == 200
    assert failed["observed"]["message"] == "response-validation-TypeError"


def test_real_wire_create_requires_an_update_timestamp_and_recovers_unknown_write(monkeypatch):
    backend = offline.Backend()
    original = backend.answer
    def answer(request):
        status, body = original(request)
        if request["site"] == "setup/create/control":
            body["writeResults"][0].pop("updateTime")
        return status, body
    backend.answer = answer
    send, budget = install_exchange(monkeypatch, backend)
    snapshots = []
    result = collection(send, responsibility=snapshots.append).run()
    assert result["complete"] is False and result["unrecovered"] == []
    assert result["requestCount"] == budget.total == 9
    assert any(value["resourceStates"]["control"] == "sent-unknown" for value in snapshots)
    assert backend.documents == {}


@pytest.mark.parametrize("status", [200, 400])
def test_wire_validation_failure_preserves_actual_http_status(monkeypatch, status):
    from test_txn_sandbox_wire import request
    raw = b'{}' if status == 200 else b'{"error":{"code":400,"status":["INVALID_ARGUMENT"]}}'
    monkeypatch.setattr(wire, "_run_process_exchange", lambda **_kwargs: (status, "application/json", raw, None))
    if status == 200:
        monkeypatch.setattr(wire.remote, "normalize", lambda *_args: (_ for _ in ()).throw(TypeError()))
    budget = contract.RequestBudget(plan.compile_plan(NONCE, OWNER))
    answer = wire.FixedDataWire("offline-token", budget)(request())
    assert answer["complete"] is False and answer["httpStatus"] == status
    assert answer["message"] == "response-validation-TypeError"
    assert budget.total == 1


def test_observation_exception_records_its_actual_site(monkeypatch):
    backend = offline.Backend()
    send, _budget = install_exchange(monkeypatch, backend)
    def broken(request):
        if request["site"] == "setup/create/control":
            raise RuntimeError("injected observation failure")
        return send(request)
    result = collection(broken).run()
    assert {"site": "setup/create/control", "reason": "RuntimeError"} in result["failureSites"]


@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("digits", [6, 9])
def test_real_wire_recovery_cases_a_and_b(monkeypatch, present, digits):
    backend = offline.Backend()
    name = recovery.targets(snapshot())[0]["name"]
    if present:
        body = document(name)
        body["updateTime"] = "2026-09-27T00:00:00." + "123456789"[:digits] + "Z"
        backend.documents[name] = body
    send, budget = install_exchange(monkeypatch, backend)
    result = recovery.recover(snapshot(), send)
    assert result == {"complete": True, "requests": 7 if present else 5, "recovered": list(recovery.ROLES)}
    assert budget.total == result["requests"]
    assert backend.documents == {}
    commits = [request for request in backend.calls if request["rpc"] == "Commit"]
    assert len(commits) == int(present)
    if present:
        assert commits[0]["body"]["writes"][0]["currentDocument"]["updateTime"] == body["updateTime"]


@pytest.mark.parametrize("branch,expected", [("foreign", 1), ("refused", 2), ("still-present", 3), ("exchange", 2), ("invalid-write-results", 2)])
def test_real_wire_recovery_failure_branches_stop_without_further_requests(monkeypatch, branch, expected):
    backend = offline.Backend()
    name = recovery.targets(snapshot())[0]["name"]
    backend.documents[name] = document(name, owner="0" * 32 if branch == "foreign" else OWNER)
    original = backend.answer
    def answer(request):
        if request["rpc"] == "Commit" and branch == "refused":
            return 400, {"error": {"code": 400, "status": "FAILED_PRECONDITION", "message": "stale"}}
        if request["rpc"] == "Commit" and branch == "still-present":
            return 200, {"writeResults": [{}], "commitTime": offline.VERSION}
        return original(request)
    backend.answer = answer
    site = "cleanup/conditional-delete/control"
    send, budget = install_exchange(monkeypatch, backend, failure_site=site if branch == "exchange" else None, malformed_site=site if branch == "invalid-write-results" else None)
    result = recovery.recover(snapshot(), send)
    assert result["complete"] is False
    assert result["requests"] == budget.total == expected


def test_canonical_delegation_needs_exact_owner_authority_and_scope():
    delegated = DELEGATED.replace("Claude（委任。枠の内の承認し直し）", ACTOR)
    envelope = ENVELOPE.replace("オーナー（直接の承認）", ACTOR)
    assert admission.verify_send_gates([LAST], NOW, AUTHORITY + envelope + delegated, PINS) == LAST["ts"]
    for authority in ("", AUTHORITY.replace("US$10", "US$100"), AUTHORITY.replace("オーナー（このセッションへの直接の返答）", ACTOR), AUTHORITY.replace("fireemu-oracle-sbx", "fireemu-35fe6")):
        with pytest.raises(ValueError, match="owner|delegat"):
            admission.verify_send_gates([LAST], NOW, authority + envelope + delegated, PINS)


def recovery_common(value, decisions):
    return {"packet_sha": value["packet_sha"], "snapshot_raw": value["snapshot_raw"], "baseline_raw": value["baseline_raw"], "lock_path": value["lock_path"], "ledger_rows": [value["original"]], "now": value["now"], "decisions": decisions, "review": value["review"], "packet_path": value["packet_path"]}


def test_recovery_canonical_delegation_and_packet_scoped_revocation(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)
    delegated = value["decisions"].replace("オーナー（直接）", ACTOR)
    assert recovery.verify_packet(value["packet"], **recovery_common(value, AUTHORITY + delegated))
    with pytest.raises(ValueError, match="owner"):
        recovery.verify_packet(value["packet"], **recovery_common(value, delegated))
    old = f'- 2026-09-28 | FS-TRANSACTION recovery | REVOKED packetSha256={"d" * 64}（already used） | {ACTOR} | old.json\n'
    assert recovery.verify_packet(value["packet"], **recovery_common(value, value["decisions"] + old))
    revoked = old.replace("d" * 64, value["packet_sha"])
    with pytest.raises(ValueError, match="revoked"):
        recovery.verify_packet(value["packet"], **recovery_common(value, value["decisions"] + revoked))


@pytest.mark.parametrize("decision", ["REVOKED packetSha256=malformed", "REVOKED packetSha256=" + "d" * 64 + "; packetSha256=" + "c" * 64])
def test_ambiguous_or_invalid_revocation_scope_cannot_bypass_current_packet(tmp_path, monkeypatch, decision):
    value = fixture_context(tmp_path, monkeypatch)
    revoked = f"- 2026-09-28 | FS-TRANSACTION recovery | {decision} | {ACTOR} | revoked.json\n"
    with pytest.raises(ValueError, match="revoked"):
        recovery.verify_packet(value["packet"], **recovery_common(value, value["decisions"] + revoked))


def test_recovery_preserves_completed_delete_http_status_after_validation_failure(monkeypatch):
    backend = offline.Backend()
    name = recovery.targets(snapshot())[0]["name"]
    backend.documents[name] = document(name)
    send, _budget = install_exchange(monkeypatch, backend)
    original = wire.remote.normalize
    def normalize(status, raw, request):
        if request["rpc"] == "Commit":
            raise TypeError("injected post-send validation failure")
        return original(status, raw, request)
    monkeypatch.setattr(wire.remote, "normalize", normalize)
    result = recovery.recover(snapshot(), send)
    assert result["complete"] is False and result["failure"] == "delete-unconfirmed"
    assert result["failureSite"] == "cleanup/conditional-delete/control"
    assert result["httpStatus"] == 200 and result["requests"] == 2
    assert backend.documents == {}


@pytest.mark.parametrize("present,expected", [(False, 13), (True, 15)])
def test_record_recovery_real_wire_records_runtime_then_releases_lock(tmp_path, monkeypatch, present, expected):
    value = fixture_context(tmp_path, monkeypatch)
    backend = offline.Backend()
    name = recovery.targets(snapshot())[0]["name"]
    if present:
        backend.documents[name] = document(name)
    result = recovery.record_recovery(packet=value["packet"], packet_sha=value["packet_sha"], packet_path=value["packet_path"], snapshot_raw=value["snapshot_raw"], baseline_raw=value["baseline_raw"],
                                      lock_path=value["lock_path"], ledger_path=value["ledger_path"], private_dir=value["root"] / "docs.local/runs", now=value["now"], decisions=value["decisions"], review=value["review"],
                                      credential_fn=lambda: "offline-test-token", metadata_factory=Metadata,
                                      wire_factory=lambda _token, budget: install_exchange(monkeypatch, backend, budget=budget)[0])
    assert result["complete"] is True and result["totalRequests"] == expected
    assert not value["lock_path"].exists()
    rows = [json.loads(line) for line in value["ledger_path"].read_text().splitlines()][1:]
    assert [row["outcome"] for row in rows] == ["reserved", "recovered-exact-name"]
    for evidence in [result, *rows]:
        assert evidence["pythonVersion"] == "3.12.13"
        assert evidence["pythonSysVersion"] == sys.version
        assert evidence["pythonExecutable"] == sys.executable


@pytest.mark.parametrize("fails", [False, True])
def test_recovery_terminal_ledger_timestamp_is_measured_after_requests(tmp_path, monkeypatch, fails):
    value = fixture_context(tmp_path, monkeypatch)
    clock = [value["now"]]
    backend = offline.Backend()
    def wire_factory(_token, budget):
        send, _budget = install_exchange(monkeypatch, backend, budget=budget)
        def advancing(request):
            result = send(request)
            clock[0] += dt.timedelta(seconds=1)
            return {**result, "complete": False} if fails else result
        return advancing
    arguments = dict(packet=value["packet"], packet_sha=value["packet_sha"], packet_path=value["packet_path"], snapshot_raw=value["snapshot_raw"], baseline_raw=value["baseline_raw"], lock_path=value["lock_path"], ledger_path=value["ledger_path"], private_dir=value["root"] / "docs.local/runs", now=lambda: clock[0], decisions=value["decisions"], review=value["review"], credential_fn=lambda: "offline-test-token", metadata_factory=Metadata, wire_factory=wire_factory)
    if fails:
        with pytest.raises(ValueError, match="incomplete"):
            recovery.record_recovery(**arguments)
    else:
        recovery.record_recovery(**arguments)
    rows = [json.loads(line) for line in value["ledger_path"].read_text().splitlines()][1:]
    assert admission._instant(rows[0]["ts"]) == value["now"]
    assert admission._instant(rows[-1]["ts"]) == clock[0]
    assert admission._instant(rows[-1]["ts"]) > admission._instant(rows[0]["ts"])


@pytest.mark.parametrize("entry", ["txn_sandbox_cli", "txn_sandbox_recovery"])
def test_runtime_guard_is_active_under_optimized_python(entry):
    source = f"import sys; sys.path.insert(0, {str(cli.HERE)!r}); import {entry} as entry; sys.version_info = (3, 9, 6); entry.main([])"
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-O", "-c", source], capture_output=True, text=True, timeout=5)
    assert result.returncode != 0
    assert "ValueError: Python 3.12" in result.stderr


def test_fraction_parsing_does_not_depend_on_interpreter_precision(monkeypatch):
    original = dt.datetime
    class LegacyDatetime(original):
        @classmethod
        def fromisoformat(cls, value):
            fraction = value.split(".", 1)[1].split("+", 1)[0] if "." in value else ""
            if fraction and len(fraction) not in (3, 6):
                raise ValueError("legacy parser precision")
            return original.fromisoformat(value)
    monkeypatch.setattr(dt, "datetime", LegacyDatetime)
    for digits in range(10):
        value = "2024-02-29T00:00:00" + ("." + "123456789"[:digits] if digits else "") + "Z"
        assert collector.valid_instant(value)
        assert admission._instant(value).year == 2024


def test_commit_validation_never_depends_on_zip_keyword_arguments(monkeypatch):
    original = zip
    def legacy_zip(*values, **kwargs):
        assert not kwargs
        return original(*values)
    monkeypatch.setattr(collector, "zip", legacy_zip, raising=False)
    request = {"rpc": "Commit", "body": {"writes": [{"delete": "owned"}]}}
    answer = {"code": 0, "status": "OK", "body": {"writeResults": [{}]}}
    assert collector._checked_response(answer, request)["complete"] is True
    for results in (None, [], [{}, {}], ["invalid"]):
        assert collector._checked_response({**answer, "body": {"writeResults": results}}, request)["complete"] is False


def test_minimum_runtime_compiles_imports_and_runs_isolated_worker(tmp_path):
    assert sys.version_info[:3] == (3, 12, 13)
    sources = sorted(Path(__file__).parent.glob("*.py"))
    for source in sources:
        compile(source.read_bytes(), str(source), "exec")
    command = [sys.executable, "-I", "-S", "-B", "-c", "import sys; print(sys.version); print(sys.executable)"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    assert "3.12.13" in result.stdout and sys.executable in result.stdout
    worker = subprocess.run([sys.executable, "-I", "-S", "-B", str(cli.HERE / "txn_expiry_https_worker.py")], input=b"", capture_output=True, timeout=5)
    assert worker.returncode == 0


def test_shadow_source_closure_pins_the_python_runtime_guard():
    assert "txn_sandbox_runtime.py" in plan.source_inputs()


def test_shadow_cannot_complete_with_a_child_python_runtime_mismatch():
    from test_txn_expiry_shadow import synthetic_document
    value = synthetic_document()
    assert value["complete"] is True
    receipt = {**value["receipt"], "pythonRuntime": {**value["receipt"]["pythonRuntime"], "pythonVersion": "3.14.3"}}
    assert synthetic_document(receipt=receipt)["complete"] is False
