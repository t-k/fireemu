"""Auth-list completion boundaries and its actual owned loopback fixture.

The public-result tests inject supervisor reports; they do not build fireemu.
The socket tests execute the real reader/fixture with the actual Gate, not cloud.
"""
from __future__ import annotations

import copy
import http.client
import json
from pathlib import Path
import sys
import threading
from types import ModuleType
from urllib.parse import quote, urlencode

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import campaign_auth_list_shadow as shadow
import campaign_gate
import shared_gate
from campaign_auth_list import campaign_manifest
from campaign_gate import CampaignGate, create
from test_batch_wire_completion import frame, raw_server

KIND = 'identitytoolkit#GetAccountInfoResponse'


def worker_report():
    return {
        'schemaVersion': 1, 'target': 'owned-fireemu-artifact',
        'productionExecuted': False, 'recordingComplete': True,
        'stateValidation': True, 'cleanupComplete': True, 'completed': True,
        'failure': None, 'gate': {'total': 39},
        'rows': [{'body': {'idToken': 'private-worker-token'}}],
    }


def runtime_report():
    return {
        'status': 'completed', 'recordingComplete': True, 'stateValidation': True,
        'ownedProcess': {'listenersClosed': True}, 'failure': None,
        'stopReason': 'child-completed', 'artifactSha256': 'a' * 64,
        'executionCommit': 'b' * 40,
        'localObservations': [{'operationType': 'auth-refresh', 'resource': 'local',
            'principal': 'owned-account:uid', 'status': 200,
            'body': {'id_token': 'private-runtime-token'}}],
    }


def summarize(tmp_path, monkeypatch, *, worker=None, runtime=None, raw=None, missing=False, path_kind=None):
    output = tmp_path / 'output'
    (output / 'worker').mkdir(parents=True)
    worker_path = output / 'worker/result.json'
    if not missing:
        if path_kind == 'directory':
            worker_path.mkdir()
        elif path_kind == 'symlink':
            target = tmp_path / 'other-receipt.json'
            target.write_text(json.dumps(worker_report()))
            worker_path.symlink_to(target)
        else:
            worker_path.write_text(raw if raw is not None else json.dumps(worker_report() if worker is None else worker))
    runtime = runtime_report() if runtime is None else runtime
    broad = ModuleType('broad')
    calls, saved = [], []
    def run(path, **kwargs):
        calls.append((path, kwargs))
        return copy.deepcopy(runtime)
    broad.run = run
    monkeypatch.setitem(sys.modules, 'broad', broad)
    monkeypatch.setattr(shadow, 'save', lambda path, value: saved.append((path, copy.deepcopy(value))))
    result = shadow.run(output)
    assert len(calls) == 1
    assert calls[0][1]['project'] == 'demo-firestore-probe'
    assert saved == [(output / 'result.json', result)]
    assert 'private-runtime-token' not in json.dumps(result)
    assert 'private-worker-token' not in json.dumps(result)
    return result


def test_complete_worker_and_supervisor_produce_complete_public_result(tmp_path, monkeypatch):
    result = summarize(tmp_path, monkeypatch)
    assert result['completed'] is True
    assert result['cleanupComplete'] is True
    assert result.get('completionIssues', []) == []
    assert result['recordingComplete'] is True
    assert result['stateValidation'] is True
    assert result['failure'] is None
    assert result['stopReason'] == 'child-completed'
    assert result['rows'][0]['bodyKeys'] == ['id_token']
    assert result['gate'] == {'total': 39}


@pytest.mark.parametrize('field', ['completed', 'recordingComplete', 'stateValidation', 'cleanupComplete'])
@pytest.mark.parametrize('value', [False, None, 1, 'true'])
def test_worker_completion_flags_are_required_strict_booleans(tmp_path, monkeypatch, field, value):
    worker = worker_report()
    worker[field] = value
    result = summarize(tmp_path, monkeypatch, worker=worker)
    assert result['completed'] is False
    assert 'worker-' + field + '-incomplete' in result['completionIssues']
    if field == 'cleanupComplete':
        assert result['processCleanupComplete'] is True
        assert result['resourceCleanupComplete'] is False
        assert result['cleanupComplete'] is False
    if field in ('recordingComplete', 'stateValidation'):
        assert result[field] is False
        assert result['cleanupComplete'] is True  # Independent resource proof remains valid.


@pytest.mark.parametrize('field', ['completed', 'recordingComplete', 'stateValidation', 'cleanupComplete'])
def test_missing_worker_flags_do_not_inherit_runtime_success(tmp_path, monkeypatch, field):
    worker = worker_report()
    worker.pop(field)
    result = summarize(tmp_path, monkeypatch, worker=worker)
    assert result['completed'] is False


@pytest.mark.parametrize('field,value', [
    ('schemaVersion', True), ('schemaVersion', 2), ('schemaVersion', None),
    ('target', 'loopback-python-fixture'), ('productionExecuted', True),
    ('productionExecuted', 0), ('productionExecuted', None),
])
def test_wrong_worker_identity_does_not_prove_resource_cleanup(tmp_path, monkeypatch, field, value):
    worker = worker_report()
    worker[field] = value
    result = summarize(tmp_path, monkeypatch, worker=worker)
    assert result['completed'] is False
    assert result['resourceCleanupComplete'] is False
    assert result['cleanupComplete'] is False
    assert result['processCleanupComplete'] is True


@pytest.mark.parametrize('options', [
    {'missing': True}, {'raw': '{"completed":'}, {'raw': 'null'},
    {'raw': '[]'}, {'raw': 'true'}, {'raw': '"not an object"'},
    {'path_kind': 'symlink'}, {'path_kind': 'directory'},
])
def test_missing_or_unreadable_receipt_is_reported_not_promoted(tmp_path, monkeypatch, options):
    result = summarize(tmp_path, monkeypatch, **options)
    assert result['completed'] is False
    assert result['cleanupComplete'] is False
    assert any(issue.startswith('worker-receipt-') for issue in result['completionIssues'])


@pytest.mark.parametrize('field,value', [
    ('status', 'failed'), ('recordingComplete', False), ('recordingComplete', 1),
    ('stateValidation', False), ('stateValidation', 1), ('failure', 'injected-failure'),
    ('ownedProcess', {'listenersClosed': False}), ('ownedProcess', {'listenersClosed': 1}),
    ('ownedProcess', None), ('ownedProcess', []),
])
def test_worker_success_does_not_override_incomplete_runtime(tmp_path, monkeypatch, field, value):
    runtime = runtime_report()
    runtime[field] = value
    result = summarize(tmp_path, monkeypatch, runtime=runtime)
    assert result['completed'] is False
    assert result['completionIssues']
    if field == 'ownedProcess':
        assert result['processCleanupComplete'] is False
        assert result['resourceCleanupComplete'] is True
        assert result['cleanupComplete'] is False
    if field == 'failure':
        assert result['failure'] == value


def test_worker_failure_is_not_erased_by_normal_child_exit(tmp_path, monkeypatch):
    worker = worker_report()
    worker['failure'] = 'write-failed'
    result = summarize(tmp_path, monkeypatch, worker=worker)
    assert result['completed'] is False
    assert 'worker-failure' in result['completionIssues']
    assert result['stopReason'] == 'child-completed'


@pytest.mark.parametrize('status,body', [
    (200, {'kind': KIND}), (200, {'users': []}), (200, {'kind': KIND, 'users': []}),
    (404, {'error': {'status': 'USER_NOT_FOUND'}}),
    (404, {'error': {'code': 404, 'status': 'USER_NOT_FOUND'}}),
])
def test_deleted_lookup_accepts_explicit_typed_absence(status, body):
    shadow.validate_deleted_lookup(status, body)
    assert campaign_gate._absent_response(status, body) is True


@pytest.mark.parametrize('status,body', [
    (200, {}), (200, {'users': None}), (200, {'users': False}),
    (200, {'users': [{'localId': 'still-present'}]}),
    (200, {'users': [], 'error': {'status': 'ERROR'}}),
    (200, {'users': [], 'kind': 'wrong'}), (200, {'kind': KIND, 'users': ['user']}),
    (404, {'error': None}), (404, {'error': []}), (404, {'error': {'status': 'NOT_FOUND'}}),
    (404, {'error': {'code': 404.0, 'status': 'USER_NOT_FOUND'}}),
    (404, {'error': {'code': True, 'status': 'USER_NOT_FOUND'}}),
    (404, {'error': {'status': 'USER_NOT_FOUND'}, 'users': [{'localId': 'present'}]}),
    (404, {'error': {'status': 'USER_NOT_FOUND'}, 'users': []}),
    (404, {'error': {'status': 'USER_NOT_FOUND'}, 'kind': KIND}),
    (200.0, {'kind': KIND}), (404.0, {'error': {'status': 'USER_NOT_FOUND'}}),
    (True, {'users': []}), (200, []), (404, None),
])
def test_deleted_lookup_rejects_missing_contradictory_or_malformed_evidence(status, body):
    assert campaign_gate._absent_response(status, body) is False
    with pytest.raises(ValueError):
        shadow.validate_deleted_lookup(status, body)


@pytest.mark.parametrize('headers', [
    [('Content-Length', '99')], [('Content-Length', '2'), ('Content-Length', '9')],
    [('Transfer-Encoding', 'identity')], [('Content-Length', '+2')],
])
def test_shadow_reader_rejects_ambiguous_or_partial_json(headers):
    with raw_server(frame(b'{}', headers=headers)) as (origin, _requests):
        with pytest.raises(ValueError):
            shadow.wire(origin + '/owned', 'GET', None, {}, local=True)


def test_shadow_reader_preserves_complete_json():
    with raw_server(frame(b'{"users":[]}')) as (origin, _requests):
        assert shadow.wire(origin + '/owned', 'GET', None, {}, local=True) == (
            200, {'users': []}, 'application/json',
        )


def test_shadow_reader_closes_connection_after_receive_exception(monkeypatch):
    closed = []
    class Broken:
        def request(self, *_args, **_kwargs):
            pass
        def getresponse(self):
            raise http.client.RemoteDisconnected('injected disconnect')
        def close(self):
            closed.append(True)
    monkeypatch.setattr(shadow.http.client, 'HTTPConnection', lambda *_args, **_kwargs: Broken())
    with pytest.raises(http.client.RemoteDisconnected):
        shadow.wire('http://127.0.0.1:18081/owned', 'GET', None, {}, local=True)
    assert closed == [True]


def test_actual_loopback_fixture_runs_full_auth_list_gate_recipe(tmp_path, monkeypatch):
    """Real sockets and Gate, but a Python fixture rather than the Rust daemon."""
    for name in ('accounts', 'documents', 'tokens'):
        setattr(shadow.ShadowHandler, name, {})
    shadow.ShadowHandler.token_counter = 0
    original_do_post = shadow.ShadowHandler.do_POST

    def typed_absence_lookup(handler):
        if ":lookup" not in handler.path:
            return original_do_post(handler)
        body = handler.body()
        uid = body.get("localId") or shadow.ShadowHandler.tokens.get(body.get("idToken"))
        if uid in shadow.ShadowHandler.accounts:
            return handler.reply(200, {"users": [{"localId": uid}]})
        return handler.reply(200, {"kind": KIND})

    monkeypatch.setattr(shadow.ShadowHandler, "do_POST", typed_absence_lookup)
    server = shadow.ThreadingHTTPServer(('127.0.0.1', 0), shadow.ShadowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f'http://127.0.0.1:{server.server_port}'
        plan = campaign_manifest('d' * 32)
        plan['localOrigins'] = {'auth': origin, 'firestore': origin}
        create(tmp_path / 'gate', plan)
        gate = CampaignGate(tmp_path / 'gate', 'auth-list')
        for index in range(2):
            gate.coordinator_call(index, lambda: (200, {}))
        gate.claim()
        bindings, versions, rows = {}, {}, []
        for phase in ('observation', 'recovery'):
            for declared in plan['jobs']['auth-list'][phase]:
                operation = shadow.replace(copy.deepcopy(declared), bindings)
                source = operation.pop('versionFrom', None)
                if source is not None:
                    operation['path'] += '?currentDocument.updateTime=' + quote(versions[operation['resource']], safe='')
                def send(op=operation):
                    path = op['path'] if op['service'] == 'firestore' else '/' + op['path']
                    body = urlencode(op['body']) if op['form'] else op['body']
                    headers = {'Content-Type': 'application/x-www-form-urlencoded' if op['form'] else 'application/json'}
                    status, value, _content_type = shadow.wire(origin + path, op['method'], body, headers, local=True)
                    return status, value
                status, body = gate.dispatch(operation, phase == 'recovery', send)
                if phase == 'observation':
                    shadow.bind(gate, bindings, declared, body)
                    rows.append({**operation, 'status': status, 'body': body})
                elif operation['method'] == 'GET' and status == 200:
                    versions[operation['resource']] = body['updateTime']
                if phase == 'recovery' and operation['operationType'] == 'auth-lookup':
                    shadow.validate_deleted_lookup(status, body)
        shadow.validate_list_observations(rows, plan['nonce'])
        gate.finish()
        state = gate.snapshot()
        assert state['total'] == 39
        assert state['jobs']['auth-list']['complete'] is True
        assert shared_gate.unconfirmed_creates(state, 'auth-list') == 0
        assert len(state['jobs']['auth-list']['absenceProofs']) == 7
        assert not shadow.ShadowHandler.accounts
        assert not shadow.ShadowHandler.documents
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()
