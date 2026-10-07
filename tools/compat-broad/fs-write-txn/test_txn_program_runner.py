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


@pytest.mark.parametrize('fault', ['complete', 'unknown-commit', 'unknown-rollback', 'foreign-document', 'forged-status', 'journal-failure', 'event-journal-failure', 'final-journal-failure'])
def test_sdk_broker_preserves_responsibility_and_denies_failure_paths(tmp_path, monkeypatch, fault):
    import shutil
    from txn_program_cli import table_for
    from txn_program_wire import discover_runtime
    import txn_program_cli
    import txn_program_collector
    table = table_for('p17-admin-sdk-retry')
    local_path = runner.Path(__file__).resolve().parents[3] / 'target/codex-out/s5a-step2/local.receipt.json'
    if not local_path.is_file(): pytest.skip('requires the local strict SDK receipt')
    runtime = discover_runtime(runner.Path(shutil.which('node')))
    original = runner.subprocess.Popen
    script = r"""
const fs = require('fs');
const local = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
const fault = process.argv[2];
function exchange(event) {
  fs.writeSync(1, JSON.stringify(event) + '\n');
  const b = Buffer.alloc(1), bytes = [];
  while (fs.readSync(0, b, 0, 1, null)) { if (b[0] === 10) break; bytes.push(b[0]); }
  return JSON.parse(Buffer.from(bytes).toString());
}
const spec = exchange({ event: 'ready' });
const raw = JSON.stringify(local).split(local.nonce).join(spec.nonce).split(local.ownerId).join(spec.ownerId).split('demo-admin-retry').join('fireemu-oracle-txn');
const receipt = JSON.parse(raw);
receipt.runtime.target = 'production';
const rows = [...receipt.steps, ...receipt.cleanupSteps].sort((a,b) => a.sequence-b.sequence);
for (const row of rows) {
  const dispatch = JSON.parse(JSON.stringify(row));
  delete dispatch.frames; delete dispatch.result; delete dispatch.outcomeClass;
  delete dispatch.timing.responseUtc; delete dispatch.timing.responseMonotonic;
  if (fault === 'foreign-document') { dispatch.request.database = 'projects/foreign-project/databases/(default)'; }
  exchange({event: 'dispatch', row: dispatch});
  for (const frame of row.frames ?? []) exchange({event: 'frame', sequence: row.sequence, frame});
  if (fault === 'forged-status') row.request.database = 'projects/foreign-project/databases/(default)';
    if (fault === 'unknown-commit' && row.rpc === 'Commit' && row.client === 'transaction' || fault === 'unknown-rollback' && row.rpc === 'Rollback') { row.result.code = 14; row.result.details = 'offline unavailable'; row.result.response = null; row.outcomeClass = 'UNKNOWN'; }
  row.result.childReaped = false; row.result.workerExitCode = null;
  exchange({event: 'status', row});
  row.result.childReaped = true; row.result.workerExitCode = 0;
}
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const bound = {...receipt}; delete bound.receiptDigest;
receipt.receiptDigest = require('crypto').createHash('sha256').update(JSON.stringify(canonical(bound))).digest('hex');
fs.writeSync(1, JSON.stringify({event: 'receipt', receipt}) + '\n');
"""
    def popen(args, **kwargs):
        if len(args) == 3 and args[1:] == [table['sourceFile'], 'production']:
            return original([args[0], '-e', script, str(local_path), fault, table['sourceFile']], **kwargs)
        return original(args, **kwargs)
    monkeypatch.setattr(runner.subprocess, 'Popen', popen)
    def refresh(_baseline, budget, **kwargs):
        budget.charge('credential')
        return 'offline-parent'
    class Metadata:
        def __init__(self, _bearer, _baseline, budget, **kwargs): self.budget = budget
        def preflight(self):
            for _ in range(4): self.budget.charge('management')
            return {'rules-absent': 'absent'}
        def postflight(self):
            for _ in range(2): self.budget.charge('management')
            return {'unchanged': True}
    monkeypatch.setattr(runner, 'refresh', refresh)
    monkeypatch.setattr(runner, 'MetadataSession', Metadata)
    if fault == 'journal-failure': monkeypatch.setattr(runner.shared, 'append_ledger', lambda *_args: (_ for _ in ()).throw(OSError('offline journal failure')))
    if fault in ('event-journal-failure', 'final-journal-failure'):
        append = runner.shared.append_ledger
        def final_failure(path, event):
            if event['event'] == ('dispatch' if fault == 'event-journal-failure' else 'final'): raise OSError('offline journal failure')
            return append(path, event)
        monkeypatch.setattr(runner.shared, 'append_ledger', final_failure)
    if fault in ('journal-failure', 'final-journal-failure'):
        with pytest.raises(OSError): runner.run_once(0, table, 'a' * 32, 'b' * 32, tmp_path, baseline={}, runtime=runtime, check=lambda: None)
        final = json.loads((tmp_path / 'journal-1/sdk-final-receipt.json').read_text())
        assert final['complete'] is False
        assert final['unrecovered'] is True
        assert final['journalFailure'] is True
        bound = {key: value for key, value in final.items() if key != 'receiptDigest'}
        assert final['receiptDigest'] == __import__('hashlib').sha256(json.dumps(bound, sort_keys=True, separators=(',', ':'), allow_nan=False, ensure_ascii=False).encode()).hexdigest()
        return
    receipt = runner.run_once(0, table, 'a' * 32, 'b' * 32, tmp_path, baseline={}, runtime=runtime, check=lambda: None)
    if fault == 'complete':
        assert receipt['complete'] is True
        assert receipt['phaseRequests']['management'] == 6
        assert receipt['phaseRequests']['credential'] == 1
        local = json.loads(local_path.read_text())
        assert receipt['sandboxRequests'] == local['sandboxRequests'] + 7
        assert txn_program_collector.projection(receipt, table)['kind'] == 'txn-admin-sdk-projection-v1'
        tampered = copy.deepcopy(receipt)
        tampered['runtimeManifest']['lockSha256'] = 'changed'
        with pytest.raises(ValueError, match='digest'): txn_program_collector.projection(tampered, table)
    else:
        assert receipt['complete'] is False
        assert receipt['unrecovered'] is True
        if fault == 'unknown-commit':
            assert receipt['unknownCommits']
            assert receipt['unknownWrites']
            assert receipt['openTokens']
        if fault == 'unknown-rollback':
            assert receipt['unknownRollbacks']
            assert receipt['openTokens']
        if fault == 'event-journal-failure': assert receipt['journalFailure'] is True
    assert json.loads((tmp_path / 'journal-1/sdk-final-receipt.json').read_text()) == receipt
    events = [json.loads(line) for line in (tmp_path / 'journal-1/sdk-journal.jsonl').read_text().splitlines()]
    if fault == 'foreign-document': assert not any(event['event'] == 'dispatch' for event in events)
    if fault == 'forged-status': assert not any(event['event'] == 'status' for event in events)
    assert events[-1]['event'] == 'final'
    assert events[-1]['receiptDigest'] == receipt['receiptDigest']


def test_sdk_campaign_wall_cap_forbids_second_recording_and_keeps_lock(tmp_path, monkeypatch):
    from txn_program_cli import table_for
    table = table_for('p17-admin-sdk-retry')
    ledger, kwargs = fixture(tmp_path)
    pins = {**PINS, 'packetName': table['name'], 'project': table['project'], 'envelopeId': table['envelopeId'], 'requestsPerRecording': 98, 'estimatedUsdPerRecording': 0}
    times = iter([0, 0, 0, 301])
    monkeypatch.setattr(runner.time, 'monotonic', lambda: next(times))
    monkeypatch.setattr(runner, 'verify_initial_gates', lambda *_args: None)
    monkeypatch.setattr(runner, 'authorize', lambda *_args: None)
    monkeypatch.setattr(runner, 'projection', lambda *_args: {'kind': 'txn-admin-sdk-projection-v1'})
    calls = []
    def once(index, *_args):
        calls.append(index)
        return {'complete': True, 'sandboxRequests': 74, 'timingMode': 'wall-clock', 'timingSource': 'grpc-js-client-interceptor', 'metadata': {'rules-absent': 'absent'}}
    kwargs.update(table=table, pins=pins, record_once=once)
    with pytest.raises(TimeoutError, match='wall cap'): runner.record_twice(**kwargs)
    assert calls == [0]
    assert (tmp_path / 'sandbox-locks/fireemu-oracle-txn.lock').exists()
    assert not list(tmp_path.glob('fs-transaction-*/freeze.json'))
