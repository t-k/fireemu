"""Local-only worker lifecycle and reviewed runtime tests for the shared graph."""

import copy
import shutil
import subprocess
from pathlib import Path

import pytest

from txn_program_wire import NodeWire, discover_runtime, verify_runtime

NODE = shutil.which('node')
NONCE, OWNER = 'a' * 32, 'b' * 32
SCOPE = {'slug': 'txn-toy', 'documents': ['a', 'm'], 'states': ['created', 'held', 'moved']}
DATABASE = 'projects/fireemu-oracle-sbx/databases/(default)'


@pytest.fixture(scope='module')
def runtime():
    if not NODE or subprocess.run([NODE, '--version'], capture_output=True, text=True, check=True).stdout.strip() != 'v24.14.0':
        pytest.skip('requires the reviewed Node v24.14.0 executable')
    return discover_runtime(Path(NODE))


def receipt(transport='grpc', **changes):
    value = {'kind': 'txn-program-receipt-v1', 'transport': transport, 'complete': True, 'code': 0, 'details': '', 'response': {}, 'http': None if transport == 'grpc' else 200, 'dispatchedRequests': 1}
    return {**value, **changes}


def rollback(wire, **kwargs):
    return wire.send('grpc', 'Rollback', {'database': DATABASE, 'transaction': 'aXNzdWVk'}, nonce=NONCE, owner_id=OWNER, bearer='private-credential', **kwargs)


def test_actual_node_dependency_trees_and_python_are_bound(runtime):
    verify_runtime(runtime)
    assert runtime['nodeVersion'] == 'v24.14.0'
    assert runtime['pythonVersion'] == '3.12.13'
    assert runtime['dependencies']['@grpc/grpc-js']['version'] == '1.14.4'
    assert runtime['dependencies']['@google-cloud/firestore']['version'] == '8.7.1'
    assert sum(row['fileCount'] for row in runtime['dependencies'].values()) > 1000


@pytest.mark.parametrize('field', ['nodeSha256', 'workerSha256', 'lockSha256', 'pythonSha256', 'nodeVersion'])
def test_changed_runtime_is_rejected_before_worker_dispatch(runtime, field):
    changed = copy.deepcopy(runtime)
    changed[field] = 'changed'
    with pytest.raises(ValueError):
        verify_runtime(changed)


def test_changed_dependency_tree_is_rejected(runtime):
    changed = copy.deepcopy(runtime)
    changed['dependencies']['@grpc/grpc-js']['treeSha256'] = '0' * 64
    with pytest.raises(ValueError):
        verify_runtime(changed)


def test_the_worker_is_the_shared_graphs_own(runtime):
    import txn_program_wire
    assert txn_program_wire.WORKER.name == 'txn_program_transport.mjs'


def test_the_call_carries_the_transport_and_the_plans_scope(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE)
    seen = {}
    def child(spec, timeout):
        seen.update(spec=spec, timeout=timeout)
        return receipt(), {'childReaped': True}
    monkeypatch.setattr(wire, '_child', child)
    for transport in ['rest', 'grpc']:
        monkeypatch.setattr(wire, '_child', lambda spec, timeout, _t=transport: (seen.update(spec=spec, timeout=timeout) or receipt(_t), {'childReaped': True}))
        wire.send(transport, 'Rollback', {'database': DATABASE, 'transaction': 'aXNzdWVk'}, nonce=NONCE, owner_id=OWNER, bearer='private-credential')
        spec = seen['spec']
        assert spec['kind'] == 'txn-program-call-v1' and spec['transport'] == transport
        assert (spec['slug'], spec['documents'], spec['states']) == ('txn-toy', ['a', 'm'], ['created', 'held', 'moved'])
        assert spec['projectId'] == 'fireemu-oracle-sbx' and spec['deadlineMs'] == 10000


def test_the_ipc_deadline_follows_the_step_deadline(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE)
    seen = []
    monkeypatch.setattr(wire, '_child', lambda spec, timeout: (seen.append(timeout) or receipt(), {'childReaped': True}))
    name = f'{DATABASE}/documents/oracle/{NONCE}/txn-toy/a'
    writer = {'database': DATABASE, 'writes': [{'update': {'name': name, 'fields': {}}, 'currentDocument': {'exists': True}}]}
    rollback(wire)
    wire.send('grpc', 'Commit', writer, nonce=NONCE, owner_id=OWNER, bearer='private-credential', deadline_ms=30000)
    assert seen[0] < seen[1] and seen[1] >= 30 + 2
    # an outside writer held by a lock may wait up to 90 s (P06 stopped at 30 s on its second recording)
    wire.send('grpc', 'Commit', writer, nonce=NONCE, owner_id=OWNER, bearer='private-credential', deadline_ms=90000)
    assert seen[-1] >= 90 + 2
    with pytest.raises(ValueError, match='deadline'):
        wire.send('grpc', 'Commit', writer, nonce=NONCE, owner_id=OWNER, bearer='private-credential', deadline_ms=90001)
    with pytest.raises(ValueError, match='deadline'):
        rollback(wire, deadline_ms=0)
    with pytest.raises(ValueError, match='deadline'):
        rollback(wire, deadline_ms=10001)
    with pytest.raises(ValueError, match='deadline'):
        wire.send('grpc', 'Commit', {**writer, 'transaction': 'aXNzdWVk'}, nonce=NONCE, owner_id=OWNER, bearer='private-credential', deadline_ms=30000)


@pytest.mark.parametrize('bad', [{'code': 0}, {'kind': 'txn-p10b-grpc-receipt-v1'}, {'transport': 'rest'}, {'dispatchedRequests': 2}, {'code': 99}, {'complete': True, 'code': 14}, {'details': 5}, {'details': 'x' * 20000}, {'code': 0, 'response': None}, {'extra': 1}, {'http': 200}, {'http': 99}, {'transport': 'rest', 'http': None}])
def test_a_receipt_that_is_not_the_closed_native_form_is_rejected(runtime, monkeypatch, bad):
    wire = NodeWire(runtime, SCOPE)
    monkeypatch.setattr(wire, '_child', lambda _spec, _timeout: ({**receipt(), **bad} if set(bad) != {'code'} or bad['code'] != 0 else bad, {'childReaped': True}))
    with pytest.raises(ValueError):
        rollback(wire)


def test_a_credential_echo_or_a_live_worker_is_rejected(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE)
    monkeypatch.setattr(wire, '_child', lambda _spec, _timeout: (receipt(details='private-credential'), {'childReaped': True}))
    with pytest.raises(ValueError, match='credential'):
        rollback(wire)
    monkeypatch.setattr(wire, '_child', lambda _spec, _timeout: (receipt(), {'childReaped': False}))
    with pytest.raises(ValueError, match='live'):
        rollback(wire)


def test_lifecycle_fields_are_appended_to_the_receipt(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE)
    monkeypatch.setattr(wire, '_child', lambda _spec, _timeout: (receipt(), {'childPid': 7, 'childReaped': True, 'workerExitCode': 0, 'ipcComplete': True}))
    assert rollback(wire) == {**receipt(), 'childPid': 7, 'childReaped': True, 'workerExitCode': 0, 'ipcComplete': True}


def test_local_document_name_rebase_retains_the_actual_wire_response(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE, target={'kind': 'local', 'host': '127.0.0.1', 'port': 12345})
    logical = f'{DATABASE}/documents/oracle/{"a" * 32}/txn-toy/a'
    actual = logical.replace('fireemu-oracle-sbx', 'demo-program', 1)
    def child(spec, _timeout):
        assert spec['request']['name'] == actual and spec['projectId'] == 'demo-program'
        return receipt(response={'name': actual}), {'childReaped': True}
    monkeypatch.setattr(wire, '_child', child)
    result = wire.send('grpc', 'GetDocument', {'name': logical}, nonce=NONCE, owner_id=OWNER, bearer='owner')
    assert result['response']['name'] == logical
    assert result['localWireResponse']['name'] == actual
    assert result['localNameRebased'] is True


def test_local_rebase_covers_commit_writes_and_database(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE, target={'kind': 'local', 'host': '127.0.0.1', 'port': 12345})
    name = f'{DATABASE}/documents/oracle/{NONCE}/txn-toy/a'
    request = {'database': DATABASE, 'writes': [{'update': {'name': name, 'fields': {}}, 'currentDocument': {'exists': True}}]}
    seen = {}
    monkeypatch.setattr(wire, '_child', lambda spec, _timeout: (seen.update(spec=spec) or receipt(response={'writeResults': []}), {'childReaped': True}))
    wire.send('grpc', 'Commit', request, nonce=NONCE, owner_id=OWNER, bearer='owner')
    assert seen['spec']['request']['database'].startswith('projects/demo-program/')
    assert seen['spec']['request']['writes'][0]['update']['name'].startswith('projects/demo-program/')
    assert request['writes'][0]['update']['name'].startswith('projects/fireemu-oracle-sbx/'), 'the caller request is not mutated'


@pytest.mark.parametrize('change', ['referent-bytes', 'ancestor-link'])
def test_runtime_stamp_cache_rejects_changed_executable_through_symlink(tmp_path, monkeypatch, change):
    import sys
    import txn_program_wire as module
    first = tmp_path / 'first'
    second = tmp_path / 'second'
    first.mkdir(); second.mkdir()
    (first / 'node').write_bytes(b'first executable')
    (second / 'node').write_bytes(b'second executable')
    link = tmp_path / 'linked-directory'
    link.symlink_to(first, target_is_directory=True)
    executable = link / 'node'
    if change == 'referent-bytes':
        executable = tmp_path / 'linked-node'
        executable.symlink_to(first / 'node')
    value = {'pythonExecutable': sys.executable, 'pythonVersion': '3.12.13', 'nodeExecutable': str(executable), 'dependencies': {}}
    monkeypatch.setattr(module, '_verify_runtime_full', lambda _value: None)
    monkeypatch.setattr(module, '_RUNTIME_STAMPS', {})
    module.verify_runtime(value)
    if change == 'referent-bytes':
        (first / 'node').write_bytes(b'changed executable')
    else:
        link.unlink(); link.symlink_to(second, target_is_directory=True)
    with pytest.raises(ValueError): module.verify_runtime(value)


def test_the_scope_sent_is_the_one_the_wire_was_built_with(runtime, monkeypatch):
    other = {'slug': 'txn-p08', 'documents': ['a', 'm', 'q'], 'states': ['created', 'rest-a-writer']}
    wire = NodeWire(runtime, other)
    seen = {}
    monkeypatch.setattr(wire, '_child', lambda spec, _timeout: (seen.update(spec=spec) or receipt(), {'childReaped': True}))
    rollback(wire)
    assert (seen['spec']['slug'], seen['spec']['documents'], seen['spec']['states']) == ('txn-p08', ['a', 'm', 'q'], ['created', 'rest-a-writer'])
    with pytest.raises(ValueError, match='scope'):
        NodeWire(runtime, {'slug': 'x'})


def test_a_rest_receipt_needs_an_http_status_and_a_grpc_one_forbids_it(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE)
    monkeypatch.setattr(wire, '_child', lambda _spec, _timeout: (receipt('rest', http=None), {'childReaped': True}))
    result = wire.send('rest', 'Rollback', {'database': DATABASE, 'transaction': 'aXNzdWVk'}, nonce=NONCE, owner_id=OWNER, bearer='private-credential')
    assert result['http'] is None, 'an incomplete REST outcome may carry no status; the collector decides what that means'


def test_local_batch_names_are_rebased_for_the_request_and_back_for_the_answer(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE, target={'kind': 'local', 'host': '127.0.0.1', 'port': 12345})
    logical = [f'{DATABASE}/documents/oracle/{NONCE}/txn-toy/{role}' for role in ('a', 'm')]
    local = [name.replace('fireemu-oracle-sbx', 'demo-program', 1) for name in logical]
    def child(spec, _timeout):
        assert spec['request']['documents'] == local and spec['request']['database'].startswith('projects/demo-program/')
        entries = [{'found': {'name': local[0], 'fields': {}}, 'readTime': 'x'}, {'missing': local[1], 'readTime': 'x'}]
        return receipt(response={'responses': entries}), {'childReaped': True}
    monkeypatch.setattr(wire, '_child', child)
    request = {'database': DATABASE, 'documents': logical}
    result = wire.send('grpc', 'BatchGetDocuments', request, nonce=NONCE, owner_id=OWNER, bearer='owner')
    assert [entry.get('found', {}).get('name') or entry['missing'] for entry in result['response']['responses']] == logical
    assert result['localWireResponse']['responses'][0]['found']['name'] == local[0] and result['localWireResponse']['responses'][1]['missing'] == local[1]
    assert request['documents'] == logical, 'the caller request is not mutated'


def test_a_dependency_root_of_another_checkout_names_the_root_the_packet_holds_and_this_checkout_expects(runtime):
    import copy
    import txn_program_wire as module
    changed = copy.deepcopy(runtime)
    key = sorted(changed['dependencies'])[0]
    changed['dependencies'][key]['root'] = f"/elsewhere/conformance/node_modules/{key}"
    with pytest.raises(ValueError, match=r"the packet names /elsewhere/conformance/node_modules/.*this checkout's is .*conformance/node_modules/"):
        module._verify_runtime_full(changed)


PARENT = f'{DATABASE}/documents/oracle/{NONCE}'
QUERY = {'parent': PARENT, 'structuredQuery': {'from': [{'collectionId': 'txn-toy'}]}, 'transaction': 'aXNzdWVk'}
CANCELLED = 'cancelled by the client after 1 frame(s)'


def test_a_cancelled_native_query_stream_is_carried_and_accepted_only_as_a_definite_client_cancel(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE)
    seen = []
    answers = iter([receipt(code=1, details=CANCELLED, response={'responses': [{}]})])
    monkeypatch.setattr(wire, '_child', lambda spec, timeout: (seen.append(spec) or next(answers), {'childReaped': True}))
    result = wire.send('grpc', 'RunQuery', QUERY, nonce=NONCE, owner_id=OWNER, bearer='private-credential', cancel_after=1)
    assert seen[0]['cancelAfter'] == 1 and result['code'] == 1 and result['complete'] is True
    # without a cancel asked for, a complete code 1 is an unknown outcome claimed complete
    monkeypatch.setattr(wire, '_child', lambda spec, timeout: (receipt(code=1, details=CANCELLED, response={'responses': []}), {'childReaped': True}))
    with pytest.raises(ValueError, match='indeterminate'):
        wire.send('grpc', 'RunQuery', QUERY, nonce=NONCE, owner_id=OWNER, bearer='private-credential')
    # with a cancel asked for, a code 1 that does not say it was the client's cancel is still unknown
    monkeypatch.setattr(wire, '_child', lambda spec, timeout: (receipt(code=1, details='Cancelled on client', response={'responses': []}), {'childReaped': True}))
    with pytest.raises(ValueError, match='indeterminate'):
        wire.send('grpc', 'RunQuery', QUERY, nonce=NONCE, owner_id=OWNER, bearer='private-credential', cancel_after=1)
    # and one that carries no frames list is not a cancel of a stream
    monkeypatch.setattr(wire, '_child', lambda spec, timeout: (receipt(code=1, details=CANCELLED, response=None), {'childReaped': True}))
    with pytest.raises(ValueError):
        wire.send('grpc', 'RunQuery', QUERY, nonce=NONCE, owner_id=OWNER, bearer='private-credential', cancel_after=1)


def test_a_cancel_belongs_to_a_native_query_stream_alone(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE)
    monkeypatch.setattr(wire, '_child', lambda spec, timeout: (receipt(), {'childReaped': True}))
    for transport, method, request in [('rest', 'RunQuery', QUERY), ('grpc', 'Rollback', {'database': DATABASE, 'transaction': 'aXNzdWVk'}), ('grpc', 'GetDocument', {'name': f'{PARENT}/txn-toy/a'})]:
        with pytest.raises(ValueError, match='cancel'):
            wire.send(transport, method, request, nonce=NONCE, owner_id=OWNER, bearer='private-credential', cancel_after=1)
    for bad in (0, 17, 1.5, '1', True):
        with pytest.raises(ValueError, match='cancel'):
            wire.send('grpc', 'RunQuery', QUERY, nonce=NONCE, owner_id=OWNER, bearer='private-credential', cancel_after=bad)


def test_a_local_query_is_rebased_to_the_local_project_and_its_frames_are_named_as_production_would(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE, target={'kind': 'local', 'host': '127.0.0.1', 'port': 1})
    seen = []
    local_name = f'projects/demo-program/databases/(default)/documents/oracle/{NONCE}/txn-toy/a'
    frames = {'responses': [{'document': {'name': local_name, 'fields': {}}}, {'readTime': {'seconds': '1', 'nanos': 0}}]}
    monkeypatch.setattr(wire, '_child', lambda spec, timeout: (seen.append(spec) or receipt(response=frames), {'childReaped': True}))
    result = wire.send('grpc', 'RunQuery', QUERY, nonce=NONCE, owner_id=OWNER, bearer='private-credential')
    assert seen[0]['request']['parent'].startswith('projects/demo-program/databases/(default)/documents/oracle/')
    assert result['response']['responses'][0]['document']['name'] == f'{PARENT}/txn-toy/a'
    assert result['localWireResponse']['responses'][0]['document']['name'] == local_name
    assert result['response']['responses'][1] == {'readTime': {'seconds': '1', 'nanos': 0}}


def test_only_a_code_1_cancel_is_a_complete_cancel(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE)
    # a deadline (4) that says it is a cancel is still an unknown outcome claimed complete
    monkeypatch.setattr(wire, '_child', lambda spec, timeout: (receipt(code=4, details=CANCELLED, response={'responses': []}), {'childReaped': True}))
    with pytest.raises(ValueError, match='indeterminate'):
        wire.send('grpc', 'RunQuery', QUERY, nonce=NONCE, owner_id=OWNER, bearer='private-credential', cancel_after=1)


def test_the_frames_of_a_local_cancel_are_named_as_production_would(runtime, monkeypatch):
    wire = NodeWire(runtime, SCOPE, target={'kind': 'local', 'host': '127.0.0.1', 'port': 1})
    local_name = f'projects/demo-program/databases/(default)/documents/oracle/{NONCE}/txn-toy/a'
    frames = {'responses': [{'document': {'name': local_name, 'fields': {}}}]}
    monkeypatch.setattr(wire, '_child', lambda spec, timeout: (receipt(code=1, details=CANCELLED, response=frames), {'childReaped': True}))
    result = wire.send('grpc', 'RunQuery', QUERY, nonce=NONCE, owner_id=OWNER, bearer='private-credential', cancel_after=1)
    assert result['code'] == 1 and result['response']['responses'][0]['document']['name'] == f'{PARENT}/txn-toy/a'
    assert result['localWireResponse']['responses'][0]['document']['name'] == local_name
