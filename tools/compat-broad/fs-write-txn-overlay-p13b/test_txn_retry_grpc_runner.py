"""One reserved session, two fresh recordings, retained locks on every stop."""

import copy
import json
from datetime import datetime, timezone

import pytest

from txn_retry_grpc_runner import record_twice
from txn_retry_grpc_program import RequestBudget, compile_plan
from txn_retry_grpc_collector import Collector
from test_txn_retry_grpc_collector import FakeWire
from test_txn_retry_grpc_authority import DECISIONS, LAST, NOW, PINS


def record(_index, nonce, owner, _directory):
    plan = compile_plan(nonce, owner)
    receipt = Collector(plan, RequestBudget(plan), FakeWire(plan), 'owner', save=lambda _state: None).run()
    receipt['metadata'] = {'rulesSourceSha256': 'd' * 64, 'rulesetName': 'projects/fireemu-oracle-sbx/rulesets/fixed'}
    return receipt


def fixture(tmp_path):
    tmp_path.chmod(0o700)
    ledger = tmp_path / 'sandbox-ledger.jsonl'
    ledger.write_text(json.dumps(LAST) + '\n'); ledger.chmod(0o600)
    kwargs = {'ledger_path': ledger, 'private_dir': tmp_path, 'pins': PINS, 'decisions': lambda: DECISIONS, 'now': lambda: NOW, 'record_once': record, 'admission_check': lambda: None}
    return ledger, kwargs


def test_two_fresh_namespaces_are_fsynced_frozen_then_lock_released(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    result = record_twice(**kwargs)
    directory = result['runDir']
    first = json.loads((directory / 'recording-1.json').read_text())
    second = json.loads((directory / 'recording-2.json').read_text())
    assert first['nonce'] != second['nonce'] and first['ownerId'] != second['ownerId']
    assert (directory / 'freeze.json').is_file()
    assert not (tmp_path / 'sandbox-locks/fireemu-oracle-sbx.lock').exists()
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert [row['outcome'] for row in rows[1:]] == ['reserved', 'recorded', 'reserved', 'recorded']
    assert all(row['requests'] == 28 for row in rows[1:] if row['outcome'] == 'recorded')


@pytest.mark.parametrize('failure', ['incomplete', 'exception', 'save', 'freeze'])
def test_first_stop_does_not_send_second_and_retains_shared_lock(tmp_path, monkeypatch, failure):
    import txn_retry_grpc_runner as runner
    ledger, kwargs = fixture(tmp_path)
    calls = []
    def once(*args):
        calls.append(args[0])
        if failure == 'exception': raise ValueError('local failure')
        receipt = record(*args)
        if failure == 'incomplete': receipt['complete'] = False
        if failure == 'freeze' and args[0] == 1: receipt['observations'][0]['result']['code'] = 3
        return receipt
    kwargs['record_once'] = once
    if failure == 'save': monkeypatch.setattr(runner, 'save_private', lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError('save failed')))
    with pytest.raises((ValueError, OSError)): record_twice(**kwargs)
    assert calls == ([0, 1] if failure == 'freeze' else [0])
    assert (tmp_path / 'sandbox-locks/fireemu-oracle-sbx.lock').is_file()
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert rows[-1]['outcome'] == 'stopped-needs-review'


def test_source_recheck_failure_before_reservation_releases_own_lock(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    kwargs['admission_check'] = lambda: (_ for _ in ()).throw(ValueError('source changed'))
    with pytest.raises(ValueError): record_twice(**kwargs)
    assert len(ledger.read_text().splitlines()) == 1
    assert not (tmp_path / 'sandbox-locks/fireemu-oracle-sbx.lock').exists()
