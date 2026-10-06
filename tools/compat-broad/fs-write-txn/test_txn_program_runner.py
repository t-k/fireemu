"""One reserved session, two fresh recordings, retained locks on every stop; the session clock is the observation clock."""

import copy
import importlib
import json

import pytest

import txn_program_runner as runner
from txn_program_collector import Collector
from txn_program_program import RequestBudget, compile_plan
from test_txn_program_authority import DECISIONS, LAST, NOW, PINS
from test_txn_program_collector import Clock, Service

support = importlib.import_module("txn_program_support_for_tests")
TABLE = support.TABLE


def record(_index, nonce, owner, _directory, **knobs):
    plan = compile_plan(TABLE, nonce, owner)
    clock = Clock()
    receipt = Collector(plan, TABLE, RequestBudget(plan, TABLE), Service(clock, **knobs), "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()
    receipt["metadata"] = {"rulesSourceSha256": "d" * 64, "rulesetName": "projects/fireemu-oracle-sbx/rulesets/fixed"}
    return receipt


def fixture(tmp_path):
    tmp_path.chmod(0o700)
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(LAST) + "\n"); ledger.chmod(0o600)
    kwargs = {"table": TABLE, "ledger_path": ledger, "private_dir": tmp_path, "pins": PINS, "decisions": lambda: DECISIONS, "now": lambda: NOW, "record_once": record, "admission_check": lambda: None}
    return ledger, kwargs


LOCK = "sandbox-locks/fireemu-oracle-sbx.lock"


def test_two_fresh_namespaces_are_frozen_then_the_lock_is_released(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    result = runner.record_twice(**kwargs)
    directory = result["runDir"]
    assert directory.name.startswith("fs-transaction-toy-failed-commit-")
    first = json.loads((directory / "recording-1.json").read_text())
    second = json.loads((directory / "recording-2.json").read_text())
    assert first["nonce"] != second["nonce"] and first["ownerId"] != second["ownerId"]
    frozen = json.loads((directory / "freeze.json").read_text())
    assert frozen["kind"] == "txn-program-freeze-v1" and frozen["authorizesProduction"] is False
    assert frozen["projection"]["program"] == "FS-TRANSACTION-TOY"
    assert not (tmp_path / LOCK).exists()
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert [row["outcome"] for row in rows[1:]] == ["reserved", "recorded", "reserved", "recorded"]
    assert all(row["requests"] == 22 for row in rows[1:] if row["outcome"] == "recorded")
    assert all(row["packetId"] == PINS["packetId"] and row["envelopeId"] == PINS["envelopeId"] for row in rows[1:])


@pytest.mark.parametrize("failure", ["incomplete", "exception", "save", "freeze"])
def test_first_stop_does_not_send_second_and_retains_the_shared_lock(tmp_path, monkeypatch, failure):
    ledger, kwargs = fixture(tmp_path)
    calls = []
    def once(*args):
        calls.append(args[0])
        if failure == "exception": raise ValueError("local failure")
        receipt = record(*args)
        if failure == "incomplete": receipt["complete"] = False
        if failure == "freeze" and args[0] == 1: receipt["observations"][0]["result"]["code"] = 3
        return receipt
    kwargs["record_once"] = once
    if failure == "save": monkeypatch.setattr(runner, "save_private", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("save failed")))
    with pytest.raises((ValueError, OSError)): runner.record_twice(**kwargs)
    assert calls == ([0, 1] if failure == "freeze" else [0])
    assert (tmp_path / LOCK).is_file()
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert rows[-1]["outcome"] == "stopped-needs-review"


def test_source_recheck_failure_before_reservation_releases_its_own_lock(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    kwargs["admission_check"] = lambda: (_ for _ in ()).throw(ValueError("source changed"))
    with pytest.raises(ValueError): runner.record_twice(**kwargs)
    assert len(ledger.read_text().splitlines()) == 1
    assert not (tmp_path / LOCK).exists()


def test_a_control_clock_receipt_cannot_be_a_production_recording(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    def control(*args):
        receipt = record(*args)
        receipt["timingMode"] = "control-clock"; receipt["timingSource"] = "local-control-clock"
        return receipt
    kwargs["record_once"] = control
    with pytest.raises(ValueError): runner.record_twice(**kwargs)
    assert (tmp_path / LOCK).is_file()


def test_a_different_valid_second_recording_retains_the_shared_lock(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    def varied(index, nonce, owner, directory):
        return record(index, nonce, owner, directory, **({} if index == 0 else {"writer_code": 10}))
    kwargs["record_once"] = varied
    with pytest.raises(ValueError, match="differ"): runner.record_twice(**kwargs)
    assert (tmp_path / LOCK).is_file()
    assert not list(tmp_path.glob("fs-transaction-*/freeze.json"))
    assert list(tmp_path.glob("fs-transaction-*/freeze-differences.json"))


def test_a_stopped_recording_forbids_the_second_and_keeps_the_recovery_lock(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    calls = []
    def stopped(index, nonce, owner, directory):
        calls.append(index)
        return record(index, nonce, owner, directory, writer_code=4)
    kwargs["record_once"] = stopped
    with pytest.raises(ValueError, match="stopped"): runner.record_twice(**kwargs)
    assert calls == [0]
    assert (tmp_path / LOCK).is_file()


def test_the_charged_count_of_a_recording_cannot_exceed_the_packets_cap(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    kwargs["record_once"] = lambda *args: {**record(*args), "sandboxRequests": PINS["requestsPerRecording"] + 1}
    with pytest.raises(ValueError): runner.record_twice(**kwargs)
    assert (tmp_path / LOCK).is_file()


@pytest.fixture
def session(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(runner.time, "monotonic", lambda: clock[0])
    counts = []
    plan = compile_plan(TABLE, "a" * 32, "b" * 32)
    budget = runner.SessionBudget(plan, TABLE, lambda: None, counts.append)
    return clock, counts, budget, plan


def test_mid_observation_releases_do_not_start_final_recovery(session):
    clock, counts, budget, plan = session
    for _ in range(4):
        clock[0] += 30
        budget.charge("observation")
        budget.charge("tokenCleanup")
        assert budget.recovery_deadline is None
    assert budget.observation_deadline == 100 + plan["observationSeconds"]
    assert budget.used["tokenCleanup"] == 4
    assert counts[-1]["kind"] == "txn-program-charged-count-v1"
    assert len(counts) == 8


def test_final_recovery_is_explicit_once_and_cannot_return_to_observation(session):
    clock, _, budget, plan = session
    clock[0] = 205
    budget.begin_recovery()
    assert budget.recovery_deadline == 205 + plan["recoverySeconds"]
    clock[0] = 300
    budget.begin_recovery()
    assert budget.recovery_deadline == 205 + plan["recoverySeconds"]
    budget.charge("documentCleanup")
    budget.charge("management")
    with pytest.raises(ValueError, match="observation|recovery"):
        budget.charge("observation")


def test_document_cleanup_requires_the_explicit_final_transition(session):
    *_, budget, _plan = session
    with pytest.raises(ValueError, match="recovery"):
        budget.charge("documentCleanup")
    assert budget.total == 0


@pytest.mark.parametrize("phase", ["observation", "tokenCleanup", "management", "credential"])
def test_every_mid_observation_phase_checks_the_observation_deadline(session, phase):
    clock, counts, budget, plan = session
    clock[0] = 100 + plan["observationSeconds"] - 12
    with pytest.raises(TimeoutError, match="deadline"):
        budget.charge(phase)
    assert budget.recovery_deadline is None and budget.total == 0 and counts == []


def test_the_recovery_deadline_replaces_the_remaining_observation_time(session):
    clock, _, budget, plan = session
    budget.begin_recovery()
    clock[0] = 100 + plan["recoverySeconds"] - 12
    with pytest.raises(TimeoutError, match="deadline"):
        budget.charge("documentCleanup")
    assert budget.total == 0


def test_a_journal_failure_permanently_blocks_later_dispatch(session):
    *_, budget, _plan = session
    calls = []
    def fail(value):
        calls.append(value)
        raise OSError("synthetic journal failure")
    budget.save_count = fail
    with pytest.raises(OSError, match="journal"):
        budget.charge("observation")
    assert budget.failed and budget.total == 1
    with pytest.raises(ValueError, match="journal"):
        budget.charge("tokenCleanup")
    assert len(calls) == 1


def test_time_spent_saving_the_charged_count_is_rechecked_before_dispatch(session):
    clock, counts, budget, plan = session
    def delay(value):
        counts.append(value)
        clock[0] = 100 + plan["observationSeconds"] - 12
    budget.save_count = delay
    with pytest.raises(TimeoutError, match="journal"):
        budget.charge("observation")
    assert budget.total == 1 and len(counts) == 1


def test_cancellation_is_rechecked_after_the_count_journal(session):
    _, counts, budget, _plan = session
    calls = []
    def check():
        calls.append(True)
        if len(calls) == 2: raise ValueError("REVOKED")
    budget.check = check
    with pytest.raises(ValueError, match="REVOKED"):
        budget.charge("observation")
    assert budget.total == 1 and len(counts) == 1


@pytest.mark.parametrize("clock_value", [99.0, float("nan"), float("inf")])
def test_an_invalid_or_backwards_monotonic_clock_blocks_dispatch(session, clock_value):
    clock, counts, budget, _plan = session
    clock[0] = clock_value
    with pytest.raises(ValueError, match="clock"):
        budget.charge("observation")
    assert budget.total == 0 and not counts


def test_the_wire_scope_is_the_tables(tmp_path):
    assert runner.wire_scope(TABLE) == {"slug": "txn-toy", "documents": ["a", "m"], "states": ["created", "held", "moved"]}


def test_a_journal_failure_blocks_the_metadata_postflight(tmp_path, monkeypatch):
    clock = Clock(); monkeypatch.setattr(runner.time, "monotonic", clock.now)
    post = []
    class Metadata:
        def __init__(self, _bearer, _baseline, budget, **kwargs): self.budget = budget
        def preflight(self):
            for _ in range(5): self.budget.charge("management")
            return {"rulesetName": "fixed", "rulesSourceSha256": "d" * 64}
        def postflight(self):
            for name in ["project", "database"]:
                self.budget.charge("management"); post.append(name)
            return {}
    monkeypatch.setattr(runner, "MetadataSession", Metadata)
    monkeypatch.setattr(runner, "refresh", lambda *_args, **_kwargs: "owner")
    monkeypatch.setattr(runner, "NodeWire", lambda _runtime, _scope: Service(clock))
    collector = runner.Collector
    monkeypatch.setattr(runner, "Collector", lambda *args, **kwargs: collector(*args, **kwargs, monotonic=clock.now, utc=clock.utc))
    save = runner.save_private
    failed = False
    def once(path, value):
        nonlocal failed
        if value.get("kind") == "txn-program-responsibility-v1" and not failed:
            failed = True; raise OSError("transient fsync failure")
        return save(path, value)
    monkeypatch.setattr(runner, "save_private", once)
    receipt = runner.run_once(0, TABLE, "a" * 32, "b" * 32, tmp_path, baseline={}, runtime={}, check=lambda: None)
    assert receipt["journalFailure"] is True and receipt["complete"] is False
    assert post == []


def test_recordings_whose_rules_metadata_differ_do_not_freeze(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    def varied(index, nonce, owner, directory):
        receipt = record(index, nonce, owner, directory)
        if index == 1: receipt["metadata"] = {"rulesSourceSha256": "e" * 64, "rulesetName": "projects/fireemu-oracle-sbx/rulesets/other"}
        return receipt
    kwargs["record_once"] = varied
    with pytest.raises(ValueError, match="differ"): runner.record_twice(**kwargs)
    assert (tmp_path / LOCK).is_file() and not list(tmp_path.glob("fs-transaction-*/freeze.json"))


def test_a_first_recording_that_cannot_be_projected_forbids_the_second(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    calls = []
    def once(*args):
        calls.append(args[0])
        receipt = record(*args)
        receipt["observations"][0]["result"]["code"] = 3
        return receipt
    kwargs["record_once"] = once
    with pytest.raises(ValueError): runner.record_twice(**kwargs)
    assert calls == [0]
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert [row["outcome"] for row in rows[1:]] == ["reserved", "stopped-needs-review"], "an unprojectable recording is never ledgered as recorded"


def test_authority_is_reread_before_each_reservation(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    reads = []
    def decisions():
        reads.append(True)
        return DECISIONS if len(reads) <= 2 else DECISIONS + f"- 2026-09-28 | FS-TRANSACTION toy-failed-commit | decision=REVOKED; envelopeId={PINS['envelopeId']} | オーナー（直接） | {PINS['packetPath']}\n"
    kwargs["decisions"] = decisions
    with pytest.raises(ValueError, match="REVOKED|revoked"): runner.record_twice(**kwargs)
    assert [json.loads(line)["outcome"] for line in ledger.read_text().splitlines()[1:]] == [], "no reservation is written once the authority is revoked"


def test_the_whole_task_budget_is_rechecked_before_each_recording(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    calls = []
    def once(index, nonce, owner, directory):
        calls.append(index)
        receipt = record(index, nonce, owner, directory)
        with ledger.open("a") as handle:
            handle.write(json.dumps({**LAST, "attemptId": "other-session", "estimatedUsd": 9.95, "ts": "2026-09-28T04:59:00Z"}) + "\n")
        return receipt
    kwargs["record_once"] = once
    with pytest.raises(ValueError, match="limit"): runner.record_twice(**kwargs)
    assert calls == [0]


def test_run_once_passes_resolved_declarations_to_the_real_wire(tmp_path, monkeypatch):
    import txn_program_wire as wire_module
    table = {**TABLE, "databases": {"named": "projects/fireemu-oracle-sbx/databases/txn-{nonce}"}, "placements": {}}
    scopes = []
    class Metadata:
        def __init__(self, *args, **kwargs): pass
        def preflight(self): return {}
        def postflight(self): return {}
    class Recording:
        def __init__(self, plan, table, budget, wire, *args, **kwargs):
            scopes.append(wire.scope)
        def run(self): return {"complete": True}
    monkeypatch.setattr(runner, "MetadataSession", Metadata)
    monkeypatch.setattr(runner, "Collector", Recording)
    monkeypatch.setattr(runner, "refresh", lambda *args, **kwargs: "owner")
    monkeypatch.setattr(wire_module, "verify_runtime", lambda _: None)
    receipt = runner.run_once(0, table, "a" * 32, "b" * 32, tmp_path, baseline={}, runtime={}, check=lambda: None)
    assert receipt["complete"] is True
    assert scopes[0]["databases"] == {"named": "projects/fireemu-oracle-sbx/databases/txn-" + "a" * 32}
    assert scopes[0]["placements"] == {}


@pytest.mark.parametrize("unknown", [None, "create-database", "delete-database", "document-recovery"])
def test_p16_real_runner_orders_management_and_keeps_unknown_mutations_open(tmp_path, monkeypatch, unknown):
    table = importlib.import_module("fs_txn_table_p16").TABLE
    from test_txn_program_management import BASELINE, ABSENT, DELETE, answer
    import txn_program_wire as wire_module
    named = "projects/fireemu-oracle-query/databases/txn-" + "a" * 32
    calls = []
    deleted = []
    def request(slot, token, resource=None, *, project):
        assert project == table["project"]
        calls.append(slot)
        if slot == unknown: return answer(None, 503, False)
        if slot == "oauth-tokeninfo":
            return answer({"issued_to": "test-client", "user_id": "test-subject", "scope": BASELINE["credentialPrincipal"]["requiredScopes"][0], "expires_in": 3600})
        if slot == "project": return answer({"projectId": project, "projectNumber": "123456789"})
        if slot == "database": return answer({**BASELINE["databaseExpected"], "uid": "synthetic-query-uid"})
        if slot == "named-database":
            return answer({"name": named}) if "create-database" in calls and not deleted else ABSENT
        if slot == "create-database": return answer({"name": named + "/operations/create-1", "done": True, "response": {"name": named}})
        assert slot == "delete-database"
        deleted.append(True)
        return copy.deepcopy(DELETE)
    class Recording:
        def __init__(self, plan, table, budget, wire, *args, **kwargs):
            assert wire.scope["databases"] == plan["databases"]
            assert wire.scope["placements"] == table["placements"]
            calls.append("collector")
        def run(self): return {"complete": unknown != "document-recovery", "journalFailure": False, "unrecovered": unknown == "document-recovery"}
    monkeypatch.setattr(runner, "request_once", request)
    monkeypatch.setattr(runner, "refresh", lambda *args, **kwargs: "owner")
    monkeypatch.setattr(runner, "Collector", Recording)
    monkeypatch.setattr(wire_module, "verify_runtime", lambda _: None)
    receipt = runner.run_once(0, table, "a" * 32, "b" * 32, tmp_path, baseline=copy.deepcopy(BASELINE), runtime={}, check=lambda: None)
    assert receipt["complete"] is (unknown is None)
    assert receipt["closureReady"] is (unknown is None)
    assert calls.count("create-database") == 1
    if unknown == "create-database":
        assert "collector" not in calls and "delete-database" not in calls
        assert receipt["namedDatabase"]["unknownCreate"] is True
        assert receipt["unrecovered"] is False
    elif unknown == "document-recovery":
        assert "collector" in calls and "delete-database" not in calls
        assert receipt["namedDatabase"]["createConfirmed"] is True
    else:
        assert calls.index("create-database") < calls.index("collector") < calls.index("delete-database")
        assert calls.count("delete-database") == 1
    if unknown == "delete-database": assert receipt["namedDatabase"]["unknownDelete"] is True


def test_stopped_graph_with_recovered_documents_still_deletes_named_database(tmp_path, monkeypatch):
    table = importlib.import_module("fs_txn_table_p16").TABLE
    deleted = []
    class Metadata:
        def __init__(self, *args, **kwargs): self.named_database = {"closureReady": False}
        def preflight(self): return {}
        def create_named_database(self, resource, save): self.named_database["database"] = resource
        def delete_named_database(self, save):
            deleted.append(self.named_database["database"])
            self.named_database.update(closureReady=True, deleteConfirmed=True)
            return self.named_database
        def postflight(self): return {}
    class Recording:
        def __init__(self, *args, **kwargs): pass
        def run(self): return {"complete": False, "graphComplete": False, "unrecovered": False}
    monkeypatch.setattr(runner, "MetadataSession", Metadata)
    monkeypatch.setattr(runner, "Collector", Recording)
    monkeypatch.setattr(runner, "refresh", lambda *args, **kwargs: "owner")
    monkeypatch.setattr(runner, "NodeWire", lambda *args, **kwargs: None)
    receipt = runner.run_once(0, table, "a" * 32, "b" * 32, tmp_path, baseline={}, runtime={}, check=lambda: None)
    assert deleted == ["projects/fireemu-oracle-query/databases/txn-" + "a" * 32]
    assert receipt["closureReady"] and receipt["namedDatabase"]["deleteConfirmed"]
    assert not receipt["complete"]


def test_both_envelope_projects_are_locked_ledgered_and_released(tmp_path, monkeypatch):
    ledger, kwargs = fixture(tmp_path)
    kwargs["pins"] = {**PINS, "scope": {**PINS["scope"], "project": "fireemu-oracle-sbx/(default)+fireemu-oracle-txn/(default)"}}
    monkeypatch.setattr(runner, "authorize", lambda *args: None)
    monkeypatch.setattr(runner, "verify_initial_gates", lambda *args: None)
    once = kwargs["record_once"]
    def locked(*args):
        assert (tmp_path / LOCK).exists()
        assert (tmp_path / "sandbox-locks/fireemu-oracle-txn.lock").exists()
        return once(*args)
    kwargs["record_once"] = locked
    runner.record_twice(**kwargs)
    assert not (tmp_path / LOCK).exists()
    assert not (tmp_path / "sandbox-locks/fireemu-oracle-txn.lock").exists()
    rows = [json.loads(line) for line in ledger.read_text().splitlines()][1:]
    assert all(row["projects"] == ["fireemu-oracle-sbx", "fireemu-oracle-txn"] for row in rows)


@pytest.mark.parametrize("command,mutation,status,closed", [("readback-a2", "delete", 404, True), ("readback-a2", "create", 404, False), ("readback-a2", "create", 200, False), ("recover-database", "retained", 200, True)])
def test_database_action_reads_each_journal_nonce_once_and_recovery_deletes_once(tmp_path, monkeypatch, command, mutation, status, closed):
    from test_txn_program_management import BASELINE, NAMED, ABSENT, DELETE, answer
    table = importlib.import_module("fs_txn_table_p16").TABLE
    state = {"database": NAMED, "closureReady": False, "unknownCreate": mutation == "create", "unknownDelete": mutation == "delete", "createConfirmed": mutation != "create", "createRefused": False, "deleteAttempted": mutation == "delete", "deleteConfirmed": False, "lastRequestEpoch": 1000, "a2": False}
    calls = []
    def request(slot, token, resource=None, *, project):
        calls.append(slot)
        if slot == "oauth-tokeninfo": return answer({"issued_to": "test-client", "user_id": "test-subject", "scope": BASELINE["credentialPrincipal"]["requiredScopes"][0], "expires_in": 3600})
        if slot == "project": return answer({"projectId": project, "projectNumber": "123456789"})
        if slot == "database": return answer({**BASELINE["databaseExpected"], "uid": "synthetic-query-uid"})
        if slot == "delete-database": return copy.deepcopy(DELETE)
        assert slot == "named-database"
        return ABSENT if status == 404 or "delete-database" in calls else answer({"name": NAMED})
    monkeypatch.setattr(runner, "request_once", request)
    def refresh(_baseline, budget, *, before_send):
        assert budget.recovery_deadline is not None
        before_send(); budget.charge("credential")
        return "owner"
    monkeypatch.setattr(runner, "refresh", refresh)
    monkeypatch.setattr(runner.time, "time", lambda: 1600)
    result = runner.recover_named_databases(command, table, [{"nonce": "a" * 32, "state": state, "receipt": {"unrecovered": False}}], tmp_path / "action", baseline=copy.deepcopy(BASELINE), check=lambda: None)
    assert result["complete"]
    assert json.loads((tmp_path / "action/result.json").read_text()) == result
    final = result["runs"][0]
    assert final["closureReady"] is closed
    assert calls.count("named-database") == 1
    assert calls.count("delete-database") == (1 if command == "recover-database" else 0)
    assert result["requests"] == (8 if command == "recover-database" else 7)
    if mutation == "create" and status == 200:
        assert final["createConfirmed"] and not final["unknownCreate"]
    with pytest.raises(FileExistsError):
        runner.recover_named_databases(command, table, [{"nonce": "a" * 32, "state": state, "receipt": {"unrecovered": False}}], tmp_path / "action", baseline=copy.deepcopy(BASELINE), check=lambda: None)


@pytest.mark.parametrize("reason", ["early", "unknown-delete", "unknown-create", "unrecovered", "foreign-resource", "unconfirmed"])
def test_database_action_refuses_before_refresh_when_journal_does_not_authorize_it(tmp_path, monkeypatch, reason):
    from test_txn_program_management import NAMED
    table = importlib.import_module("fs_txn_table_p16").TABLE
    state = {"database": NAMED, "closureReady": False, "unknownCreate": False, "unknownDelete": False, "createConfirmed": True, "deleteAttempted": False, "deleteConfirmed": False, "lastRequestEpoch": 1000}
    receipt = {"unrecovered": False}
    command = "recover-database"
    if reason == "early": command = "readback-a2"
    elif reason == "unknown-delete": state.update(unknownDelete=True, deleteAttempted=True)
    elif reason == "unknown-create": state.update(unknownCreate=True, createConfirmed=False)
    elif reason == "unrecovered": receipt["unrecovered"] = True
    elif reason == "unconfirmed": state["createConfirmed"] = False
    else: state["database"] = NAMED.replace("fireemu-oracle-query", "fireemu-oracle-txn")
    monkeypatch.setattr(runner.time, "time", lambda: 1599 if reason == "early" else 1600)
    monkeypatch.setattr(runner, "refresh", lambda *args, **kwargs: pytest.fail("refused action reached credentials"))
    with pytest.raises(ValueError):
        runner.recover_named_databases(command, table, [{"nonce": "a" * 32, "state": state, "receipt": receipt}], tmp_path / "action", baseline={}, check=lambda: None)
    assert not (tmp_path / "action").exists()


def test_recovery_refuses_unknown_create_even_with_prior_confirmation(tmp_path, monkeypatch):
    from test_txn_program_management import NAMED
    table = importlib.import_module("fs_txn_table_p16").TABLE
    state = {"database": NAMED, "createConfirmed": True, "unknownCreate": True, "deleteAttempted": False, "lastRequestEpoch": 1000}
    monkeypatch.setattr(runner, "refresh", lambda *args, **kwargs: pytest.fail("unknown create reached credentials"))
    with pytest.raises(ValueError, match="confirmed database"):
        runner.recover_named_databases("recover-database", table, [{"nonce": "a" * 32, "state": state, "receipt": {"unrecovered": False}}], tmp_path / "action", baseline={}, check=lambda: None)
    assert not (tmp_path / "action").exists()


def test_database_action_refuses_existing_directory_before_refresh(tmp_path, monkeypatch):
    from test_txn_program_management import NAMED
    table = importlib.import_module("fs_txn_table_p16").TABLE
    state = {"database": NAMED, "createConfirmed": True, "unknownCreate": False, "deleteAttempted": False, "lastRequestEpoch": 1000}
    directory = tmp_path / "action"; directory.mkdir()
    monkeypatch.setattr(runner, "refresh", lambda *args, **kwargs: pytest.fail("replayed action reached credentials"))
    with pytest.raises(FileExistsError):
        runner.recover_named_databases("recover-database", table, [{"nonce": "a" * 32, "state": state, "receipt": {"unrecovered": False}}], directory, baseline={}, check=lambda: None)
    assert list(directory.iterdir()) == []
