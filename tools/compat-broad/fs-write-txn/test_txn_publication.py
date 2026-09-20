"""Local parent/result publication contracts, using a synthetic child and real files."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parents[1])]
import txn_expiry_shadow as shadow
import txn_expiry_collector as collector
import txn_expiry_comparison as comparison
import test_txn_expiry_comparison as fixtures


def test_save_is_private_complete_and_not_overwritable(tmp_path):
    path = tmp_path / 'receipt.json'
    shadow.save(path, {'hello': '日本語', 'n': 1})
    original = path.read_bytes()
    assert json.loads(original)['hello'] == '日本語'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        shadow.save(path, {'overwritten': True})
    assert path.read_bytes() == original
    assert not list(tmp_path.glob('.txn-result-*'))


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'directory', 'fifo'])
def test_save_does_not_replace_existing_objects(tmp_path, kind):
    path = tmp_path / 'receipt.json'; target = tmp_path / 'target'
    target.write_bytes(b'untouched')
    if kind == 'symlink': path.symlink_to(target)
    elif kind == 'hardlink': os.link(target, path)
    elif kind == 'directory': path.mkdir()
    else: os.mkfifo(path)
    with pytest.raises(FileExistsError): shadow.save(path, {'x': 1})
    assert target.read_bytes() == b'untouched'


def test_save_handles_short_write_without_losing_suffix(tmp_path, monkeypatch):
    original = os.write; calls = []
    def short(fd, data):
        calls.append(len(data)); return original(fd, data[:3])
    monkeypatch.setattr(shadow.os, 'write', short)
    path = tmp_path / 'receipt.json'
    shadow.save(path, {'value': 'abcdefghijklmnopqrstuvwxyz'})
    assert json.loads(path.read_bytes()) == {'value': 'abcdefghijklmnopqrstuvwxyz'}
    assert len(calls) > 5


@pytest.mark.parametrize('fault', ['zero-write', 'write', 'file-fsync', 'link', 'directory-fsync'])
def test_save_failure_never_reports_success(tmp_path, monkeypatch, fault):
    real_sync = os.fsync
    def fail(*_args, **_kw): raise OSError('private diagnostic must not be published')
    if fault == 'zero-write': monkeypatch.setattr(shadow.os, 'write', lambda *_a: 0)
    elif fault == 'write': monkeypatch.setattr(shadow.os, 'write', fail)
    elif fault == 'link': monkeypatch.setattr(shadow.os, 'link', fail)
    else:
        calls = []
        def sync(fd):
            calls.append(fd)
            if len(calls) == (1 if fault == 'file-fsync' else 2): fail()
            return real_sync(fd)
        monkeypatch.setattr(shadow.os, 'fsync', sync)
    path = tmp_path / 'receipt.json'
    with pytest.raises(OSError): shadow.save(path, {'complete': True})
    if path.exists():
        assert fault == 'directory-fsync'
        assert json.loads(path.read_bytes()) == {'complete': True}
    assert not list(tmp_path.glob('.txn-result-*'))


def test_racing_publisher_is_not_overwritten(tmp_path, monkeypatch):
    link = os.link
    def race(source, target, **kw):
        Path(target).write_bytes(b'other-publisher')
        return link(source, target, **kw)
    monkeypatch.setattr(shadow.os, 'link', race)
    path = tmp_path / 'receipt.json'
    with pytest.raises(FileExistsError): shadow.save(path, {'complete': True})
    assert path.read_bytes() == b'other-publisher'


@pytest.mark.parametrize('value', [float('nan'), float('inf'), {'v': float('-inf')}])
def test_save_nonfinite_value_never_creates_receipt(tmp_path, value):
    path = tmp_path / 'receipt.json'
    with pytest.raises(ValueError): shadow.save(path, value)
    assert not path.exists()


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo', 'directory', 'public', 'too-big'])
def test_reader_refuses_unsafe_file_without_blocking(tmp_path, kind):
    path = tmp_path / 'receipt.json'; target = tmp_path / 'target'
    if kind == 'symlink':
        target.write_bytes(b'{}'); path.symlink_to(target)
    elif kind == 'hardlink':
        target.write_bytes(b'{}'); target.chmod(0o600); os.link(target, path)
    elif kind == 'fifo': os.mkfifo(path, 0o600)
    elif kind == 'directory': path.mkdir()
    elif kind == 'public': path.write_bytes(b'{}'); path.chmod(0o644)
    else:
        with path.open('wb') as f: f.truncate(shadow.MAX_SAVED_BYTES + 1)
        path.chmod(0o600)
    with pytest.raises((OSError, ValueError)): shadow._read_result(path)


@pytest.mark.parametrize('raw', [b'', b'null', b'[]', b'{', b'{"complete":true,"complete":false}',
    b'{"n":NaN}', b'{"n":1e999}', '{}'.encode('utf-16')])
def test_reader_refuses_ambiguous_or_incomplete_json(tmp_path, raw):
    path = tmp_path / 'receipt.json'; path.write_bytes(raw); path.chmod(0o600)
    with pytest.raises((OSError, ValueError)): shadow._read_result(path)


def test_reader_rejects_replacement_during_read(tmp_path, monkeypatch):
    path = tmp_path / 'receipt.json'; shadow.save(path, {'n': 1})
    original = os.read; changed = []
    def read(fd, amount):
        result = original(fd, amount)
        if not changed:
            path.unlink(); path.write_bytes(b'{"n":2}'); path.chmod(0o600); changed.append(True)
        return result
    monkeypatch.setattr(shadow.os, 'read', read)
    with pytest.raises(ValueError): shadow._read_result(path)


def parent_fixture(tmp_path, monkeypatch, *, mutation=None, contract_mutation=None,
                   file_mutation=None, exit_code=0):
    """Real run_shadow, fake executable/Popen + explicit synthetic case results."""
    artifact = tmp_path / 'artifact'; artifact.write_bytes(b'not-a-native-artifact')
    artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    binding = {'artifactSha256': artifact_sha, 'sourceCommit': 'a' * 40,
               'sourceRoot': 'repository-root', 'runtimeInputsDigest': 'b' * 64,
               'runtimeInputCount': 1, 'runtimeInputsClean': True}
    monkeypatch.setattr(shadow, 'runtime_binding', lambda *_a: binding)
    monkeypatch.setattr(shadow.subprocess, 'check_output', lambda *_a, **_kw: 'fixture-version')
    seen = {'stop': 0}
    class Process:
        pid = 123456
        returncode = exit_code
        def __init__(self, command, *, cwd, **kw):
            self.command = command; self.output = Path(cwd); seen['environment'] = kw.get('env')
        def wait(self, **_kw):
            nonce = self.command[self.command.index('--nonce') + 1]
            receipt = fixtures.receipt('local', project=shadow.PROJECT, nonce=nonce,
                                      timing=collector.CONTROL_CLOCK)
            receipt['instance'] = {'pid': 123457, 'parentPid': self.pid,
                'firestoreOrigin': 'http://127.0.0.1:8080', 'controlOrigin': 'http://127.0.0.1:8081',
                'wrongTokenStatus': 403, 'artifactSha256': artifact_sha}
            contract = comparison.local_self_contract(receipt)
            assert contract['classification'] == 'MATCH'
            if mutation: mutation(receipt)
            if contract_mutation: contract_mutation(contract)
            shadow.save(self.output / 'receipt.json', receipt)
            shadow.save(self.output / 'self-contract.json', contract)
            if file_mutation: file_mutation(self.output)
            return self.returncode
    monkeypatch.setattr(shadow.subprocess, 'Popen', Process)
    def stop(*_args):
        seen['stop'] += 1
        return {'stopped': True, 'signal': None, 'exitCode': exit_code}
    monkeypatch.setattr(shadow, 'stop_child', stop)
    return artifact, seen


def test_parent_accepts_only_current_bound_receipt_and_recomputed_contract(tmp_path, monkeypatch):
    artifact, seen = parent_fixture(tmp_path, monkeypatch)
    monkeypatch.setenv('GOOGLE_APPLICATION_CREDENTIALS', 'ambient-credential')
    result = shadow.run_shadow(artifact, tmp_path / 'run')
    assert result['complete'] is True and seen['stop'] == 1
    assert 'GOOGLE_APPLICATION_CREDENTIALS' not in seen['environment']
    for name, expected in result['publication']['inputDigests'].items():
        assert hashlib.sha256((tmp_path / 'run' / name).read_bytes()).hexdigest() == expected
    assert result['publication']['failures'] == []
    assert result['productionExecuted'] is False and result['promotionReady'] is False


@pytest.mark.parametrize('field,value', [
    ('nonce', 'other-run-00000001'), ('documentPrefix', 'other/documents'),
    ('projectId', 'other-project'), ('database', 'other'), ('target', 'production'),
    ('timing', 'wall-clock'), ('sourceDigest', '0'*64), ('casesDigest', '0'*64), ('kind', 'unknown'),
])
def test_parent_refuses_replayed_or_unbound_receipt(field, value, tmp_path, monkeypatch):
    artifact, seen = parent_fixture(tmp_path, monkeypatch, mutation=lambda r: r.update({field: value}))
    result = shadow.run_shadow(artifact, tmp_path / 'run')
    assert result['complete'] is False and seen['stop'] == 1
    assert 'receipt-run-binding-mismatch' in result['publication']['failures']


@pytest.mark.parametrize('field,value', [
    ('parentPid', 1), ('parentPid', True), ('pid', 0), ('pid', True),
    ('firestoreOrigin', 'https://external.invalid'), ('controlOrigin', None),
])
def test_parent_refuses_mismatched_instance(field, value, tmp_path, monkeypatch):
    artifact, _ = parent_fixture(tmp_path, monkeypatch, mutation=lambda r: r['instance'].update({field: value}))
    result = shadow.run_shadow(artifact, tmp_path / 'run')
    assert result['complete'] is False
    assert 'receipt-instance-binding-mismatch' in result['publication']['failures']


def test_forged_match_file_cannot_hide_case_difference(tmp_path, monkeypatch):
    def change(receipt):
        row = next(r for r in receipt['rows'] if r['caseId'])
        row['observed'] = {'code': 13, 'status': 'INTERNAL', 'message': 'different'}
    artifact, _ = parent_fixture(tmp_path, monkeypatch, mutation=change)
    result = shadow.run_shadow(artifact, tmp_path / 'run')
    assert result['complete'] is False
    assert 'self-contract-recomputation-mismatch' in result['publication']['failures']


@pytest.mark.parametrize('name', ['receipt.json', 'self-contract.json'])
def test_missing_child_result_is_recorded_not_crash(tmp_path, monkeypatch, name):
    artifact, seen = parent_fixture(tmp_path, monkeypatch, file_mutation=lambda d: (d/name).unlink())
    result = shadow.run_shadow(artifact, tmp_path / 'run')
    assert result['complete'] is False and seen['stop'] == 1
    assert 'unusable-' + name in result['publication']['failures']
    assert (tmp_path / 'run' / 'shadow.json').exists()


@pytest.mark.parametrize('raw', [b'null', b'{', b'{"complete":true,"complete":false}'])
def test_malformed_child_result_does_not_hide_shutdown(tmp_path, monkeypatch, raw):
    artifact, seen = parent_fixture(tmp_path, monkeypatch,
                                   file_mutation=lambda d: (d/'receipt.json').write_bytes(raw))
    result = shadow.run_shadow(artifact, tmp_path / 'run')
    assert result['complete'] is False and seen['stop'] == 1
    assert 'unusable-receipt.json' in result['publication']['failures']


def test_final_publication_failure_happens_after_shutdown(tmp_path, monkeypatch):
    artifact, seen = parent_fixture(tmp_path, monkeypatch)
    original = shadow.save
    def save(path, value):
        if Path(path).name == 'shadow.json': raise OSError('private failure')
        return original(path, value)
    monkeypatch.setattr(shadow, 'save', save)
    with pytest.raises(OSError): shadow.run_shadow(artifact, tmp_path / 'run')
    assert seen['stop'] == 1 and (tmp_path/'run'/'receipt.json').exists()
    assert not (tmp_path/'run'/'shadow.json').exists()


def test_launch_publication_failure_prevents_spawn(tmp_path, monkeypatch):
    artifact, seen = parent_fixture(tmp_path, monkeypatch)
    original = shadow.save
    def save(path, value):
        if Path(path).name == 'launch.json': raise OSError('private failure')
        return original(path, value)
    monkeypatch.setattr(shadow, 'save', save)
    with pytest.raises(OSError): shadow.run_shadow(artifact, tmp_path / 'run')
    assert seen['stop'] == 0 and 'environment' not in seen


def test_cli_does_not_expose_exception_text_on_publication_failure(tmp_path, monkeypatch, capsys):
    def fail(*_args): raise OSError('TOKEN-private-sensitive-value')
    monkeypatch.setattr(shadow, 'run_shadow', fail)
    code = shadow.main(['--artifact', 'unused', '--output', str(tmp_path/'run')])
    output = capsys.readouterr()
    assert code == 2 and 'TOKEN-private-sensitive-value' not in output.err
    assert json.loads(output.err)['failure'] == 'OSError'
