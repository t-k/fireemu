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


@pytest.mark.parametrize('fault', ['complete', 'unknown-commit', 'unknown-rollback', 'foreign-document', 'forged-status', 'journal-failure', 'event-journal-failure', 'final-journal-failure', 'quota-missing', 'quota-wrong', 'loopback-quota-present', 'loopback-quota-missing', 'two-writes', 'foreign-owner', 'foreign-nonce', 'delete-no-witness', 'delete-wrong-version', 'delete-no-version', 'frame-cap', 'request-count'])
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
if (fault.startsWith('loopback-')) {
  (async () => {
    const url = require('url').pathToFileURL(process.argv[3]);
    const sdkRequire = require('module').createRequire(new URL('../../../conformance/package.json', url));
    const grpc = sdkRequire('@grpc/grpc-js');
    const { Firestore, v1: { FirestoreClient } } = sdkRequire('@google-cloud/firestore');
    const descriptor = new FirestoreClient({ projectId: 'demo-descriptors' });
    const protos = descriptor._protos.google.firestore.v1;
    const server = new grpc.Server();
    server.addService({ BatchGetDocuments: { path: '/google.firestore.v1.Firestore/BatchGetDocuments', requestStream: false, responseStream: true,
      requestSerialize: protos.BatchGetDocumentsRequest.serialize, requestDeserialize: protos.BatchGetDocumentsRequest.deserialize,
      responseSerialize: protos.BatchGetDocumentsResponse.serialize, responseDeserialize: protos.BatchGetDocumentsResponse.deserialize } }, {
      BatchGetDocuments(call) {
        fs.writeFileSync(process.argv[4], JSON.stringify([call.metadata.get('x-goog-user-project')]));
        call.sendMetadata(new grpc.Metadata());
        call.emit('error', { code: 9, details: 'offline stop after metadata' });
      },
    });
    const port = await new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, value) => error ? reject(error) : resolve(value)));
    const settings = Firestore.prototype.settings;
    Firestore.prototype.settings = function (value) {
      return settings.call(this, { ...value, host: `127.0.0.1:${port}`, ssl: false, ...(fault === 'loopback-quota-missing' ? { customHeaders: {} } : {}) });
    };
    try {
      const spec = exchange({ event: 'ready' });
      const { recordAdminRetries } = await import(url.href);
      const receipt = await recordAdminRetries({ project: 'fireemu-oracle-txn', admission: { ...spec, check: () => {}, journal: event => exchange(event) } });
      fs.writeSync(1, JSON.stringify({ event: 'receipt', receipt }) + '\n');
    } finally { Firestore.prototype.settings = settings; server.forceShutdown(); await descriptor.close(); }
  })().catch(() => { process.exitCode = 1; });
} else {
const spec = exchange({ event: 'ready' });
const raw = JSON.stringify(local).split(local.nonce).join(spec.nonce).split(local.ownerId).join(spec.ownerId).split('demo-admin-retry').join('fireemu-oracle-txn');
const receipt = JSON.parse(raw);
receipt.runtime.target = 'production';
for (const row of [...receipt.steps, ...receipt.cleanupSteps]) { row.metadataKeys = ['x-goog-user-project']; row.quotaProject = 'fireemu-oracle-txn'; }
const rows = [...receipt.steps, ...receipt.cleanupSteps].sort((a,b) => a.sequence-b.sequence);
for (const row of rows) {
  const dispatch = JSON.parse(JSON.stringify(row));
  delete dispatch.frames; delete dispatch.result; delete dispatch.outcomeClass;
  delete dispatch.timing.responseUtc; delete dispatch.timing.responseMonotonic;
  if (fault === 'foreign-document') { dispatch.request.database = 'projects/foreign-project/databases/(default)'; }
  if (fault === 'quota-missing') dispatch.metadataKeys = [];
  if (fault === 'quota-wrong') dispatch.quotaProject = 'foreign-project';
  if (dispatch.rpc === 'Commit' && dispatch.request.writes[0].update) {
    if (fault === 'two-writes') dispatch.request.writes.push(dispatch.request.writes[0]);
    if (fault === 'foreign-owner') dispatch.request.writes[0].update.fields.owner.stringValue = 'foreign-owner';
    if (fault === 'foreign-nonce') dispatch.request.writes[0].update.fields.nonce.stringValue = 'foreign-nonce';
  }
  if (dispatch.rpc === 'Commit' && dispatch.request.writes[0].delete) {
    if (fault === 'delete-no-witness') dispatch.site += '/foreign';
    if (fault === 'delete-wrong-version') dispatch.request.writes[0].currentDocument.updateTime.nanos += 1;
    if (fault === 'delete-no-version') delete dispatch.request.writes[0].currentDocument.updateTime;
  }
  exchange({event: 'dispatch', row: dispatch});
  if (fault === 'frame-cap' && row.rpc === 'BatchGetDocuments') for (let i=0;i<4;i++) exchange({event:'frame',sequence:row.sequence,frame:{missing:'owned'}});
  for (const frame of row.frames ?? []) exchange({event: 'frame', sequence: row.sequence, frame});
  if (fault === 'forged-status') row.request.database = 'projects/foreign-project/databases/(default)';
    if (fault === 'unknown-commit' && row.rpc === 'Commit' && row.client === 'transaction' || fault === 'unknown-rollback' && row.rpc === 'Rollback') { row.result.code = 14; row.result.details = 'offline unavailable'; row.result.response = null; row.outcomeClass = 'UNKNOWN'; }
  row.result.childReaped = false; row.result.workerExitCode = null;
  exchange({event: 'status', row});
  row.result.childReaped = true; row.result.workerExitCode = 0;
}
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
if (fault === 'request-count') receipt.sandboxRequests += 1;
const bound = {...receipt}; delete bound.receiptDigest;
receipt.receiptDigest = require('crypto').createHash('sha256').update(JSON.stringify(canonical(bound))).digest('hex');
fs.writeSync(1, JSON.stringify({event: 'receipt', receipt}) + '\n');
}
"""
    loopback_metadata = tmp_path / 'loopback-metadata.json'
    if fault.startswith('loopback-'): loopback_metadata.write_text('[]')
    def popen(args, **kwargs):
        if len(args) == 3 and args[1:] == [table['sourceFile'], 'production']:
            return original([args[0], '-e', script, str(local_path), fault, table['sourceFile'], str(loopback_metadata)], **kwargs)
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
    if fault in ('quota-missing', 'quota-wrong', 'loopback-quota-missing', 'two-writes', 'foreign-owner', 'foreign-nonce'):
        assert not any(event['event'] == 'dispatch' and (event['row']['rpc'] == 'Commit' or 'quota' in fault) for event in events)
    if fault.startswith('loopback-'):
        expected = [['fireemu-oracle-txn']] if fault == 'loopback-quota-present' else []
        assert json.loads(loopback_metadata.read_text()) == expected
        if expected:
            assert receipt['steps'][0]['quotaProject'] == 'fireemu-oracle-txn'
            assert receipt['steps'][0]['metadataKeys'].count('x-goog-user-project') == 1
    if fault in ('delete-no-witness', 'delete-wrong-version', 'delete-no-version'):
        assert not any(event['event'] == 'dispatch' and event['row']['rpc'] == 'Commit' and 'delete' in event['row']['request']['writes'][0] for event in events)
    if fault == 'frame-cap': assert len([event for event in events if event['event'] == 'frame']) == 3

    assert events[-1]['event'] == 'final'
    assert events[-1]['receiptDigest'] == receipt['receiptDigest']


def test_sdk_campaign_wall_cap_forbids_second_recording_and_keeps_lock(tmp_path, monkeypatch):
    from txn_program_cli import table_for
    from txn_program_authority import envelope_scope
    table = table_for('p17-admin-sdk-retry')
    ledger, kwargs = fixture(tmp_path)
    pins = {**PINS, 'packetName': table['name'], 'project': table['project'], 'scope': envelope_scope(table), 'envelopeId': table['envelopeId'], 'requestsPerRecording': 131, 'estimatedUsdPerRecording': 0}
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

@pytest.mark.parametrize('action', ['cleanup', 'a2'])
@pytest.mark.parametrize('unknown', ['create', 'update', 'delete', 'none'])
@pytest.mark.parametrize('present', [True, False])
def test_sdk_document_action_settles_only_owned_version_evidence(action, unknown, present):
    from txn_program_cli import table_for
    plan = compile_plan(table_for('p17-admin-sdk-retry'), 'a' * 32, 'b' * 32)
    name = plan['documents']['conflict-a']
    fields = {key: {'stringValue': value} for key, value in {'owner': 'b' * 32, 'nonce': 'a' * 32, 'role': 'a', 'state': 'baseline'}.items()}
    write = {'delete': name} if unknown == 'delete' else {'update': {'name': name, 'fields': fields}, 'currentDocument': {'exists': False} if unknown == 'create' else {}}
    snapshot = {'kind': 'txn-program-recording-v1', 'packetName': 'p17-admin-sdk-retry', 'nonce': 'a' * 32, 'ownerId': 'b' * 32, 'documents': {'conflict-a': {'name': name, 'status': 'possibly-owned'}}, 'tokens': {}, 'steps': [] if unknown == 'none' else [{'sequence': 0, 'rpc': 'Commit', 'request': {'writes': [write]}, 'outcomeClass': 'UNKNOWN', 'timing': {'dispatchUtc': '2026-10-07T00:00:00Z'}}], 'cleanupSteps': [], 'unknownStarts': []}
    initially_present = present
    calls = []
    def send(rpc, request):
        nonlocal present
        calls.append((rpc, request))
        if rpc == 'GetDocument': return {'complete': True, 'code': 0 if present else 5, 'response': {'name': name, 'fields': fields, 'updateTime': {'seconds': '1', 'nanos': 2}} if present else None}
        assert rpc == 'DeleteDocument'
        assert request == {'name': name, 'currentDocument': {'updateTime': {'seconds': '1', 'nanos': 2}}}
        present = False
        return {'complete': True, 'code': 0, 'response': {}}
    result = runner.sdk_document_action(snapshot, action, send, now=__import__('datetime').datetime.fromisoformat('2026-10-07T00:10:00+00:00'))
    assert result['unknownWrites'] == ([0] if unknown in ('create', 'update') and not initially_present or unknown == 'delete' and initially_present else [])
    if action == 'a2': assert all(rpc == 'GetDocument' for rpc, _ in calls)
    if action == 'cleanup' and len(calls) == 3: assert result['documents']['conflict-a']['status'] == 'confirmed-absent'


def test_sdk_a2_wait_and_unknown_recovery_never_resend_writes():
    from txn_program_cli import table_for
    name = compile_plan(table_for('p17-admin-sdk-retry'), 'a' * 32, 'b' * 32)['documents']['conflict-a']
    snapshot = {'kind': 'txn-program-recording-v1', 'packetName': 'p17-admin-sdk-retry', 'nonce': 'a' * 32, 'ownerId': 'b' * 32, 'documents': {'conflict-a': {'name': name}}, 'tokens': {}, 'steps': [{'sequence': 0, 'rpc': 'Commit', 'request': {'writes': [{'update': {'name': name, 'fields': {}}}]}, 'outcomeClass': 'UNKNOWN', 'timing': {'dispatchUtc': '2026-10-07T00:00:00Z'}}], 'cleanupSteps': [], 'unknownStarts': []}
    instant = __import__('datetime').datetime.fromisoformat
    with pytest.raises(ValueError, match='10-minute'): runner.sdk_document_action(snapshot, 'a2', lambda *_: pytest.fail('must not dispatch'), now=instant('2026-10-07T00:09:59+00:00'))
    calls = []
    result = runner.sdk_document_action(snapshot, 'cleanup', lambda rpc, request: calls.append(rpc) or {'complete': False, 'code': 14}, now=instant('2026-10-07T00:10:00+00:00'))
    assert calls == ['GetDocument']
    assert result['complete'] is False
    assert result['unknownWrites'] == [0]


@pytest.mark.parametrize('field', ['owner', 'nonce'])
def test_sdk_cleanup_refuses_foreign_markers(field):
    from txn_program_cli import table_for
    name = compile_plan(table_for('p17-admin-sdk-retry'), 'a' * 32, 'b' * 32)['documents']['conflict-a']
    snapshot = {'kind': 'txn-program-recording-v1', 'packetName': 'p17-admin-sdk-retry', 'nonce': 'a' * 32, 'ownerId': 'b' * 32, 'documents': {'conflict-a': {'name': name}}, 'tokens': {}, 'steps': [], 'cleanupSteps': [], 'unknownStarts': []}
    fields = {'owner': {'stringValue': 'b' * 32}, 'nonce': {'stringValue': 'a' * 32}, 'role': {'stringValue': 'a'}}
    fields[field] = {'stringValue': 'foreign'}
    calls = []
    result = runner.sdk_document_action(snapshot, 'cleanup', lambda rpc, request: calls.append(rpc) or {'complete': True, 'code': 0, 'response': {'name': name, 'fields': fields, 'updateTime': {'seconds': '1', 'nanos': 2}}}, now=__import__('datetime').datetime.now(__import__('datetime').timezone.utc))
    assert calls == ['GetDocument']
    assert result['complete'] is False


def test_sdk_cleanup_keeps_unmatched_unknown_create_evidence_for_a2():
    from txn_program_cli import table_for
    name = compile_plan(table_for('p17-admin-sdk-retry'), 'a' * 32, 'b' * 32)['documents']['conflict-a']
    fields = {key: {'stringValue': value} for key, value in {'owner': 'b' * 32, 'nonce': 'a' * 32, 'role': 'a', 'state': 'writer'}.items()}
    snapshot = {'kind': 'txn-program-recording-v1', 'packetName': 'p17-admin-sdk-retry', 'nonce': 'a' * 32, 'ownerId': 'b' * 32, 'documents': {'conflict-a': {'name': name}}, 'tokens': {}, 'steps': [{'sequence': 0, 'rpc': 'Commit', 'request': {'writes': [{'update': {'name': name, 'fields': {**fields, 'state': {'stringValue': 'baseline'}}}, 'currentDocument': {'exists': False}}]}, 'outcomeClass': 'UNKNOWN', 'timing': {'dispatchUtc': '2026-10-07T00:00:00Z'}}], 'cleanupSteps': [], 'unknownStarts': []}
    calls = []
    result = runner.sdk_document_action(snapshot, 'cleanup', lambda rpc, request: calls.append(rpc) or {'complete': True, 'code': 0, 'response': {'name': name, 'fields': fields, 'updateTime': {'seconds': '1', 'nanos': 2}}}, now=__import__('datetime').datetime.fromisoformat('2026-10-07T00:10:00+00:00'))
    assert calls == ['GetDocument']
    assert result['unknownWrites'] == [0]
    assert result['complete'] is False


def test_sdk_recovery_unknown_delete_can_be_read_back_by_later_a2():
    from txn_program_cli import table_for
    name = compile_plan(table_for('p17-admin-sdk-retry'), 'a' * 32, 'b' * 32)['documents']['conflict-a']
    fields = {key: {'stringValue': value} for key, value in {'owner': 'b' * 32, 'nonce': 'a' * 32, 'role': 'a', 'state': 'baseline'}.items()}
    snapshot = {'kind': 'txn-program-recording-v1', 'packetName': 'p17-admin-sdk-retry', 'nonce': 'a' * 32, 'ownerId': 'b' * 32, 'documents': {'conflict-a': {'name': name}}, 'tokens': {}, 'steps': [], 'cleanupSteps': [], 'unknownStarts': []}
    instant = __import__('datetime').datetime.fromisoformat
    result = runner.sdk_document_action(snapshot, 'cleanup', lambda rpc, request: {'complete': True, 'code': 0, 'response': {'name': name, 'fields': fields, 'updateTime': {'seconds': '1', 'nanos': 2}}} if rpc == 'GetDocument' else {'complete': False, 'code': 14}, now=instant('2026-10-07T00:00:00+00:00'))
    assert result['complete'] is False
    assert result['unknownWrites'] == [1]
    calls = []
    final = runner.sdk_document_action(result, 'a2', lambda rpc, request: calls.append(rpc) or {'complete': True, 'code': 5}, now=instant('2026-10-07T00:10:00+00:00'))
    assert calls == ['GetDocument']
    assert final['complete'] is True
    assert final['unknownWrites'] == []


@pytest.mark.parametrize('action', ['cleanup', 'a2'])
@pytest.mark.parametrize('postflight_failure', [False, True])
def test_sdk_action_reuses_bounded_wire_journals_and_per_case_scope(tmp_path, monkeypatch, action, postflight_failure):
    from txn_program_cli import table_for
    table = table_for('p17-admin-sdk-retry')
    plan = compile_plan(table, 'a' * 32, 'b' * 32)
    name = plan['documents']['retry-older-a']
    snapshot = {'kind': 'txn-program-recording-v1', 'packetName': 'p17-admin-sdk-retry', 'nonce': 'a' * 32, 'ownerId': 'b' * 32, 'documents': {'retry-older-a': {'name': name}}, 'tokens': {}, 'steps': [], 'cleanupSteps': [], 'unknownStarts': []}
    present = True
    calls = []
    checks = []
    def refresh(_baseline, budget, **kwargs):
        budget.charge('credential')
        return 'offline-parent'
    class Metadata:
        def __init__(self, _bearer, _baseline, budget, **kwargs): self.budget = budget
        def preflight(self):
            for _ in range(4): self.budget.charge('management')
            return {'project': 'fixed-project', 'database': 'fixed-database'}
        def postflight(self):
            if postflight_failure: raise ValueError('offline postflight unavailable')
            for _ in range(2): self.budget.charge('management')
            return {'project': 'fixed-project', 'database': 'fixed-database'}
    class Wire:
        def __init__(self, _runtime, scope, **kwargs):
            assert scope['slug'] == 'txn-p17-retry-older'
            assert scope['documents'] == ['a', 'b', 'c']
            assert kwargs['project'] == 'fireemu-oracle-txn'
        def send(self, transport, rpc, request, **kwargs):
            nonlocal present
            assert transport == 'grpc'
            calls.append(rpc)
            if rpc == 'DeleteDocument':
                assert request == {'name': name, 'currentDocument': {'updateTime': {'seconds': '1', 'nanos': 2}}}
                present = False
                return {'complete': True, 'code': 0, 'response': {}}
            assert rpc == 'GetDocument'
            fields = {key: {'stringValue': value} for key, value in {'owner': 'b' * 32, 'nonce': 'a' * 32, 'role': 'a', 'state': 'baseline'}.items()}
            return {'complete': True, 'code': 0 if present else 5, 'response': {'name': name, 'fields': fields, 'updateTime': {'seconds': '1', 'nanos': 2}} if present else None}
    monkeypatch.setattr(runner, 'refresh', refresh)
    monkeypatch.setattr(runner, 'MetadataSession', Metadata)
    monkeypatch.setattr(runner, 'NodeWire', Wire)
    if postflight_failure:
        with pytest.raises(ValueError, match='postflight'):
            runner.record_sdk_action(table=table, snapshot=snapshot, action=action, directory=tmp_path / 'action', baseline={}, runtime={}, check=lambda: None, now=lambda: __import__('datetime').datetime.now(__import__('datetime').timezone.utc))
        assert json.loads((tmp_path / 'action/sdk-recovery-receipt.json').read_text())['complete'] is False
        return
    result = runner.record_sdk_action(table=table, snapshot=snapshot, action=action, directory=tmp_path / 'action', baseline={}, runtime={}, check=lambda: checks.append(True), now=lambda: __import__('datetime').datetime.now(__import__('datetime').timezone.utc))
    assert result['complete'] is (action == 'cleanup')
    assert calls == (['GetDocument', 'DeleteDocument', 'GetDocument'] if action == 'cleanup' else ['GetDocument'])
    final = json.loads((tmp_path / 'action/sdk-recovery-receipt.json').read_text())
    assert final['sandboxRequests'] == len(calls) + 7
    events = [json.loads(line)['event'] for line in (tmp_path / 'action/sdk-recovery-journal.jsonl').read_text().splitlines()]
    assert events == ['dispatch', 'status'] * len(calls)
    assert checks


def test_sdk_document_cleanup_passes_the_actual_native_validator():
    import shutil
    node = shutil.which('node')
    if not node or runner.subprocess.run([node, '--version'], capture_output=True, text=True).stdout.strip() != 'v24.14.0':
        pytest.skip('requires the reviewed Node v24.14.0 executable')
    if not (runner.Path(__file__).resolve().parents[3] / 'conformance' / 'node_modules').is_dir():
        pytest.skip('requires the conformance install the native validator loads')
    from txn_program_cli import table_for
    table = table_for('p17-admin-sdk-retry')
    plan = compile_plan(table, 'a' * 32, 'b' * 32)
    name = plan['documents']['retry-older-a']
    fields = {key: {'stringValue': value} for key, value in {'owner': 'b' * 32, 'nonce': 'a' * 32, 'role': 'a', 'state': 'baseline'}.items()}
    snapshot = {'kind': 'txn-program-recording-v1', 'packetName': 'p17-admin-sdk-retry', 'nonce': 'a' * 32, 'ownerId': 'b' * 32, 'documents': {'retry-older-a': {'name': name}}, 'tokens': {}, 'steps': [], 'cleanupSteps': [], 'unknownStarts': []}
    calls = []
    present = True
    def send(rpc, request):
        nonlocal present
        spec = {'kind': 'txn-program-call-v1', 'transport': 'grpc', 'target': {'kind': 'production'}, 'projectId': 'fireemu-oracle-txn', 'nonce': snapshot['nonce'], 'ownerId': snapshot['ownerId'], 'slug': 'txn-p17-retry-older', 'documents': ['a', 'b', 'c'], 'states': table['states'], 'method': rpc, 'request': request, 'bearer': 'offline-parent', 'deadlineMs': 10000}
        command = [shutil.which('node'), '--input-type=module', '-e', "import { readFileSync } from 'node:fs'; import { validateCall } from './tools/compat-broad/fs-write-txn/txn_program_transport.mjs'; validateCall(JSON.parse(readFileSync(0, 'utf8')));"]
        validated = runner.subprocess.run(command, input=json.dumps(spec), capture_output=True, text=True, env={'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'})
        assert validated.returncode == 0, validated.stderr
        calls.append(rpc)
        if rpc == 'GetDocument': return {'complete': True, 'code': 0 if present else 5, 'response': {'name': name, 'fields': fields, 'updateTime': {'seconds': '1', 'nanos': 2}} if present else None}
        present = False
        return {'complete': True, 'code': 0, 'response': {}}
    result = runner.sdk_document_action(snapshot, 'cleanup', send, now=__import__('datetime').datetime.now(__import__('datetime').timezone.utc))
    assert result['complete'] is True
    assert calls == ['GetDocument', 'DeleteDocument', 'GetDocument']


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
        def run(self): return {"complete": unknown != "document-recovery", "journalFailure": False, "unrecovered": unknown == "document-recovery", "documents": {"b": {"status": "possibly-owned"}} if unknown == "document-recovery" else {}}
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
    original_receipt = {"unrecovered": True, "openTokens": ["primary"], "unknownCommits": ["setup/create-b"], "documents": {"b": {"status": "possibly-owned"}}}
    before = copy.deepcopy(original_receipt)
    result = runner.recover_named_databases(command, table, [{"nonce": "a" * 32, "state": state, "receipt": original_receipt}], tmp_path / "action", baseline=copy.deepcopy(BASELINE), check=lambda: None)
    assert result["complete"]
    assert original_receipt == before
    assert result["settlesDocumentOrTokenObservations"] is False
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


@pytest.mark.parametrize("reason", ["early", "early-recovery", "unknown-delete", "unknown-create", "foreign-resource", "unconfirmed"])
def test_database_action_refuses_before_refresh_when_journal_does_not_authorize_it(tmp_path, monkeypatch, reason):
    from test_txn_program_management import NAMED
    table = importlib.import_module("fs_txn_table_p16").TABLE
    state = {"database": NAMED, "closureReady": False, "unknownCreate": False, "unknownDelete": False, "createConfirmed": True, "deleteAttempted": False, "deleteConfirmed": False, "lastRequestEpoch": 1000}
    receipt = {"unrecovered": False}
    command = "recover-database"
    if reason == "early": command = "readback-a2"
    elif reason == "early-recovery": pass
    elif reason == "unknown-delete": state.update(unknownDelete=True, deleteAttempted=True)
    elif reason == "unknown-create": state.update(unknownCreate=True, createConfirmed=False)
    elif reason == "unconfirmed": state["createConfirmed"] = False
    else: state["database"] = NAMED.replace("fireemu-oracle-query", "fireemu-oracle-txn")
    monkeypatch.setattr(runner.time, "time", lambda: 1599 if reason in ("early", "early-recovery") else 1600)
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


@pytest.mark.parametrize("item,origin,retained", [
    ("token", "default", False), ("token", "foreign", False), ("token", "named", True),
    ("document", "default", False), ("document", "foreign", False), ("document", "named", True), ("created-document", "named", True),
    ("start", "default", False), ("start", "named", True),
    ("commit", "default", False), ("commit", "named", True),
    ("rollback", "default", False), ("rollback", "named", True),
])
def test_named_database_retention_follows_unresolved_resource_origin(tmp_path, monkeypatch, item, origin, retained):
    table = importlib.import_module("fs_txn_table_p16").TABLE
    plan = compile_plan(table, "a" * 32, "b" * 32)
    database = plan["database"] if origin == "default" else plan["databases"][origin]
    receipt = {"complete": False, "unrecovered": True, "tokens": {}, "documents": {}, "openTokens": [], "unknownStarts": [], "unknownCommits": [], "unknownRollbacks": []}
    if item in ("token", "rollback"):
        receipt["tokens"]["unresolved"] = {"state": "unconfirmed-release", **({"database": database} if origin != "default" else {})}
        receipt["openTokens" if item == "token" else "unknownRollbacks"] = ["unresolved"]
    elif item in ("document", "created-document"):
        receipt["documents"][{"default": "a", "named": "b", "foreign": "m"}[origin]] = {"status": "created" if item == "created-document" else "possibly-owned"}
    else:
        step = next(step for step in plan["steps"] if step["rpc"] == ("BeginTransaction" if item == "start" else "Commit") and step.get("onDatabase", "default") == origin)
        receipt["unknownStarts" if item == "start" else "unknownCommits"] = [step["id"]]
    deleted = []
    class Metadata:
        def __init__(self, *args, **kwargs): self.named_database = {"closureReady": False}
        def preflight(self): return {}
        def create_named_database(self, resource, save): self.named_database["database"] = resource
        def delete_named_database(self, save):
            deleted.append(True)
            self.named_database["closureReady"] = True
            return self.named_database
        def postflight(self): return {}
    class Recording:
        def __init__(self, *args, **kwargs): pass
        def run(self): return copy.deepcopy(receipt)
    monkeypatch.setattr(runner, "MetadataSession", Metadata)
    monkeypatch.setattr(runner, "Collector", Recording)
    monkeypatch.setattr(runner, "refresh", lambda *args, **kwargs: "owner")
    monkeypatch.setattr(runner, "NodeWire", lambda *args, **kwargs: None)
    result = runner.run_once(0, table, "a" * 32, "b" * 32, tmp_path, baseline={}, runtime={}, check=lambda: None)
    assert bool(deleted) is not retained
    assert result["closureReady"] is not retained
    assert result["unrecovered"] and not result["complete"]


@pytest.mark.parametrize("stop", ["primary-release", "named-commit"])
def test_unresolved_origin_through_real_collector_controls_database_retention(tmp_path, monkeypatch, stop):
    import functools
    table = importlib.import_module("fs_txn_table_p16").TABLE
    clock = Clock()
    service = Service(clock)
    send = service.send
    primary = "projects/fireemu-oracle-query/databases/(default)"
    def wire_send(transport, method, request, **kwargs):
        database = request.get("database") or request.get("name", "").split("/documents/")[0]
        if stop == "named-commit" and method == "Commit" and request.get("writes") and request["writes"][0]["update"]["name"].endswith("/b"):
            return service._receipt(transport, 14, details="Unknown commit", complete=False)
        if stop == "primary-release" and method == "Rollback" and database == primary:
            service.calls.append((transport, method, copy.deepcopy(request)))
            return service._receipt(transport, 3, details="Invalid transaction.")
        return send(transport, method, request, **kwargs)
    service.send = wire_send
    deleted = []
    class Metadata:
        def __init__(self, *args, **kwargs): self.named_database = {"closureReady": False}
        def preflight(self): return {}
        def create_named_database(self, resource, save): self.named_database["database"] = resource
        def delete_named_database(self, save):
            deleted.append(True)
            self.named_database.update(closureReady=True, deleteConfirmed=True)
            return self.named_database
        def postflight(self): return {}
    monkeypatch.setattr(runner, "MetadataSession", Metadata)
    monkeypatch.setattr(runner, "NodeWire", lambda *args, **kwargs: service)
    monkeypatch.setattr(runner, "Collector", functools.partial(Collector, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep))
    monkeypatch.setattr(runner.time, "monotonic", clock.now)
    monkeypatch.setattr(runner, "refresh", lambda *args, **kwargs: "owner")
    result = runner.run_once(0, table, "a" * 32, "b" * 32, tmp_path, baseline={}, runtime={}, check=lambda: None)
    assert result["unrecovered"]
    if stop == "primary-release":
        assert result["openTokens"]
        assert any(row["result"]["code"] == 3 and row["result"]["details"] == "Invalid transaction." and row["request"]["database"] == primary for row in result["steps"] if row["rpc"] == "Rollback")
        assert deleted == [True] and result["closureReady"]
    else:
        assert result["unknownCommits"] == ["setup/create-b"]
        assert not deleted and not result["closureReady"]
    assert not result["complete"]



def test_two_database_recovery_reserves_each_delete_readback_and_postflight(tmp_path, monkeypatch):
    from test_txn_program_management import BASELINE, NAMED, DELETE, answer
    table = importlib.import_module("fs_txn_table_p16").TABLE
    state = {"database": NAMED, "closureReady": False, "unknownCreate": False, "createConfirmed": True, "deleteAttempted": False, "lastRequestEpoch": 1000}
    calls = []
    def request(slot, token, resource=None, *, project):
        calls.append(slot)
        if slot == "oauth-tokeninfo": return answer({"issued_to": "test-client", "user_id": "test-subject", "scope": BASELINE["credentialPrincipal"]["requiredScopes"][0], "expires_in": 3600})
        if slot == "project": return answer({"projectId": project, "projectNumber": "123456789"})
        if slot == "database": return answer({**BASELINE["databaseExpected"], "uid": "synthetic-query-uid"})
        if slot == "delete-database":
            body = copy.deepcopy(DELETE["body"])
            body["name"] = resource + "/operations/delete-1"
            body["response"]["previousId"] = resource.rsplit("/", 1)[1]
            return answer(body)
        assert slot == "named-database"
        return answer(None, 429)
    monkeypatch.setattr(runner, "request_once", request)
    def refresh(_baseline, budget, *, before_send):
        budget.charge("credential")
        return "owner"
    monkeypatch.setattr(runner, "refresh", refresh)
    monkeypatch.setattr(runner.time, "time", lambda: 1600)
    runs = [{"nonce": char * 32, "state": {**state, "database": NAMED.replace("a" * 32, char * 32)}, "receipt": {"unrecovered": True}} for char in ("a", "c")]
    result = runner.recover_named_databases("recover-database", table, runs, tmp_path / "action", baseline=copy.deepcopy(BASELINE), check=lambda: None)
    assert result["complete"] and result["requests"] == 10
    assert calls == ["oauth-tokeninfo", "project", "database", "delete-database", "named-database", "delete-database", "named-database", "project", "database"]
    assert all(state["unknownDelete"] and not state["closureReady"] for state in result["runs"])
