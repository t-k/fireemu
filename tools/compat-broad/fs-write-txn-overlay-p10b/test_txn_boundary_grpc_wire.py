"""Local-only worker lifecycle and reviewed runtime tests."""

import copy
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from txn_boundary_grpc_wire import NodeWire, discover_runtime, verify_runtime

NODE = shutil.which('node')


@pytest.fixture(scope='module')
def runtime():
    if not NODE or subprocess.run([NODE, '--version'], capture_output=True, text=True, check=True).stdout.strip() != 'v24.14.0':
        pytest.skip('requires the reviewed Node v24.14.0 executable')
    return discover_runtime(Path(NODE))


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


def test_non_native_receipt_and_credential_echo_are_rejected(runtime, monkeypatch):
    wire = NodeWire(runtime)
    monkeypatch.setattr(wire, '_child', lambda _spec: ({'code': 0}, {'childReaped': True}))
    with pytest.raises(ValueError):
        wire.send('Rollback', {'database': 'projects/fireemu-oracle-sbx/databases/(default)', 'transaction': 'aXNzdWVk'}, nonce='a' * 32, owner_id='b' * 32, bearer='private-credential')


def test_local_document_name_rebase_retains_the_actual_wire_response(runtime, monkeypatch):
    wire = NodeWire(runtime, target={'kind': 'local', 'host': '127.0.0.1', 'port': 12345})
    logical = f'projects/fireemu-oracle-sbx/databases/(default)/documents/oracle/{"a" * 32}/txn-p10b/control'
    actual = logical.replace('fireemu-oracle-sbx', 'demo-p10b', 1)
    def child(spec):
        assert spec['request']['name'] == actual
        return {'kind': 'txn-p10b-grpc-receipt-v1', 'complete': True, 'code': 0, 'details': '', 'response': {'name': actual}, 'dispatchedRequests': 1}, {'childReaped': True}
    monkeypatch.setattr(wire, '_child', child)
    result = wire.send('GetDocument', {'name': logical}, nonce='a' * 32, owner_id='b' * 32, bearer='owner')
    assert result['response']['name'] == logical
    assert result['localWireResponse']['name'] == actual
    assert result['localNameRebased'] is True


@pytest.mark.parametrize('change', ['referent-bytes', 'ancestor-link'])
def test_runtime_stamp_cache_rejects_changed_executable_through_symlink(tmp_path, monkeypatch, change):
    import sys
    import txn_boundary_grpc_wire as module
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
    # Isolate the stamp cache from version/hash verification of real runtimes.
    monkeypatch.setattr(module, '_verify_runtime_full', lambda _value: None)
    monkeypatch.setattr(module, '_RUNTIME_STAMPS', {})
    module.verify_runtime(value)
    if change == 'referent-bytes':
        (first / 'node').write_bytes(b'changed executable')
    else:
        link.unlink(); link.symlink_to(second, target_is_directory=True)
    with pytest.raises(ValueError): module.verify_runtime(value)
