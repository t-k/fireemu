"""One reserved session, two fresh recordings, retained locks on every stop."""

import copy
import json
from datetime import datetime, timezone

import pytest

from txn_boundary_grpc_runner import record_twice
from txn_boundary_grpc_program import RequestBudget, compile_plan
from txn_boundary_grpc_collector import Collector
from test_txn_boundary_grpc_collector import Wire, Clock
from test_txn_boundary_grpc_authority import DECISIONS, LAST, NOW, PINS


def record(_index, nonce, owner, _directory):
    plan = compile_plan(nonce, owner)
    clock = Clock()
    receipt = Collector(plan, RequestBudget(plan), Wire(clock, (0, 0, 0, 0, 0, 0)), 'owner', save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()
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
    assert all(row['requests'] == 29 for row in rows[1:] if row['outcome'] == 'recorded')


@pytest.mark.parametrize('failure', ['incomplete', 'exception', 'save', 'freeze'])
def test_first_stop_does_not_send_second_and_retains_shared_lock(tmp_path, monkeypatch, failure):
    import txn_boundary_grpc_runner as runner
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




def test_control_clock_receipt_cannot_be_production_recording(tmp_path):
    ledger, kwargs = fixture(tmp_path)
    def control(*args):
        receipt = record(*args)
        receipt['timingMode'] = 'control-clock'
        receipt['timingSource'] = 'local-control-clock'
        return receipt
    kwargs['record_once'] = control
    with pytest.raises(ValueError): record_twice(**kwargs)
    assert (tmp_path / 'sandbox-locks/fireemu-oracle-sbx.lock').is_file()






def test_responsibility_journal_failure_blocks_metadata_postflight(tmp_path, monkeypatch):
    import txn_boundary_grpc_runner as runner
    clock = Clock(); monkeypatch.setattr(runner.time, 'monotonic', clock.now)
    post_requests = []
    class Metadata:
        def __init__(self, _bearer, _baseline, budget, **kwargs): self.budget = budget
        def preflight(self):
            for _ in range(5): self.budget.charge('management')
            return {'rulesetName': 'fixed', 'rulesSourceSha256': 'd' * 64}
        def postflight(self):
            for name in ['project', 'database']:
                self.budget.charge('management'); post_requests.append(name)
            return {}
    monkeypatch.setattr(runner, 'MetadataSession', Metadata)
    monkeypatch.setattr(runner, 'refresh', lambda *_args, **_kwargs: 'owner')
    monkeypatch.setattr(runner, 'NodeWire', lambda _runtime: Wire(clock, (0, 0, 0, 0, 0, 0)))
    collector = runner.Collector
    monkeypatch.setattr(runner, 'Collector', lambda *args, **kwargs: collector(*args, **kwargs, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep))
    save = runner.save_private
    failed = False
    def once(path, value):
        nonlocal failed
        if value.get('kind') == 'txn-p10b-responsibility-v1' and not failed:
            failed = True; raise OSError('transient fsync failure')
        return save(path, value)
    monkeypatch.setattr(runner, 'save_private', once)
    receipt = runner.run_once(0, 'a' * 32, 'b' * 32, tmp_path, baseline={}, runtime={}, check=lambda: None)
    assert receipt['journalFailure'] is True and receipt['complete'] is False
    assert post_requests == []




def test_different_valid_second_sample_pattern_retains_the_shared_lock(tmp_path):
    ledger,kwargs=fixture(tmp_path)
    def varied(index,nonce,owner,directory):
        plan=compile_plan(nonce,owner); clock=Clock()
        codes=(0,0,0,0,0,0) if index==0 else (10,10,10,10,10,10)
        receipt=Collector(plan,RequestBudget(plan),Wire(clock,codes),'owner',save=lambda _:None,monotonic=clock.now,utc=clock.utc,sleep=clock.sleep).run()
        receipt['metadata']={'rulesSourceSha256':'d'*64,'rulesetName':'projects/fireemu-oracle-sbx/rulesets/fixed'}
        return receipt
    kwargs['record_once']=varied
    with pytest.raises(ValueError,match='differ'): record_twice(**kwargs)
    assert (tmp_path/'sandbox-locks/fireemu-oracle-sbx.lock').is_file()
    assert not list(tmp_path.glob('fs-transaction-p10b-*/freeze.json'))


def test_rollback_refusal_forbids_second_recording_and_keeps_recovery_lock(tmp_path):
    ledger,kwargs=fixture(tmp_path)
    calls=[]
    def stopped(index,nonce,owner,directory):
        calls.append(index); plan=compile_plan(nonce,owner); clock=Clock()
        return Collector(plan,RequestBudget(plan),Wire(clock,(10,)*6,rollback_code=10),'owner',save=lambda _:None,monotonic=clock.now,utc=clock.utc,sleep=clock.sleep).run()
    kwargs['record_once']=stopped
    with pytest.raises(ValueError,match='stopped'): record_twice(**kwargs)
    assert calls==[0]
    assert (tmp_path/'sandbox-locks/fireemu-oracle-sbx.lock').is_file()
