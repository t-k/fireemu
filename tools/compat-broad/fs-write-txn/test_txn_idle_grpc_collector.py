"""Measured idle intervals and conservative unknown-operation ownership."""

import base64
import copy
import datetime as dt

import pytest

from txn_idle_grpc_collector import Collector, idle_interval, projection, _timing
from txn_idle_grpc_program import RequestBudget, compile_plan


class Clock:
    def __init__(self): self.seconds = 100.0
    def now(self): return self.seconds
    def utc(self): return (dt.datetime(2026, 9, 28, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=self.seconds)).isoformat().replace('+00:00', 'Z')
    def sleep(self, seconds): self.seconds += seconds


class FakeWire:
    def __init__(self, clock, *, fail_at=None, cleanup_code=0, cleanup_details='', retry_refusal=True):
        self.clock, self.fail_at = clock, fail_at
        self.cleanup_code, self.cleanup_details, self.retry_refusal = cleanup_code, cleanup_details, retry_refusal
        self.calls, self.transactions = [], {}
        self.document = None
        self.foreign_cleanup = self.wrong_state = False

    def send(self, method, request, **kwargs):
        self.calls.append((method, copy.deepcopy(request)))
        self.clock.sleep(0.01)
        if len(self.calls) == self.fail_at:
            return {'complete': False, 'code': 14, 'details': 'lost', 'response': None, 'childReaped': True, 'dispatchedRequests': 1}
        code, details, response = 0, '', {}
        token = request.get('transaction')
        if method == 'BeginTransaction':
            previous = request['options']['readWrite'].get('retryTransaction')
            if previous and self.transactions[previous]['touched'] and self.retry_refusal:
                code, details, response = 3, 'Invalid retry transaction.', None
            else:
                token = base64.b64encode(f'token-{len(self.transactions)}'.encode()).decode()
                self.transactions[token] = {'snapshot': copy.deepcopy(self.document), 'last': self.clock.now(), 'touched': False}
                response = {'transaction': token}
        elif method == 'Commit':
            if token and self.clock.now() - self.transactions[token]['last'] >= 60:
                self.transactions[token]['touched'] = True
                code, details, response = 10, 'The referenced transaction has expired or is no longer valid.', None
            else:
                self.document = copy.deepcopy(request['writes'][0]['update'])
                self.document['updateTime'] = {'seconds': '1788004860', 'nanos': len(self.calls)}
                response = {'writeResults': [{'updateTime': self.document['updateTime']}]}
        elif method == 'GetDocument':
            if token and self.clock.now() - self.transactions[token]['last'] >= 60:
                self.transactions[token]['touched'] = True
                code, details, response = 10, 'The referenced transaction has expired or is no longer valid.', None
            else:
                found = self.transactions[token]['snapshot'] if token else self.document
                if token: self.transactions[token]['last'] = self.clock.now()
                if found is None: code, response = 5, None
                else:
                    response = copy.deepcopy(found)
                    if len(self.calls) > 24 and not token and self.foreign_cleanup: response['fields']['owner']['stringValue'] = 'foreign'
                    if len(self.calls) > 24 and not token and self.wrong_state: response['fields']['state']['stringValue'] = 'created'
        elif method == 'Rollback':
            if len(self.calls) > 24:
                code, details = self.cleanup_code, self.cleanup_details
                if code: response = None
        elif method == 'DeleteDocument':
            assert request['currentDocument']['updateTime'] == self.document['updateTime']
            self.document = None
        return {'complete': True, 'code': code, 'details': details, 'response': response, 'childReaped': True, 'dispatchedRequests': 1}


def fixture(**kwargs):
    clock = Clock()
    plan = compile_plan('a' * 32, 'b' * 32)
    wire = FakeWire(clock, **kwargs)
    budget, journal = RequestBudget(plan), []
    collector = Collector(plan, budget, wire, 'owner', save=lambda value: journal.append(copy.deepcopy(value)), monotonic=clock.now, utc=clock.utc, sleep=clock.sleep)
    return collector, wire, budget, journal, clock


def timing(dispatch, response):
    clock = Clock()
    clock.seconds = dispatch; du = clock.utc()
    clock.seconds = response; ru = clock.utc()
    return {'dispatchMonotonic': dispatch, 'responseMonotonic': response, 'dispatchUtc': du, 'responseUtc': ru}


def test_server_idle_bounds_include_both_parent_rpc_envelopes():
    try: interval = idle_interval(timing(1, 2), timing(57, 58))
    except ValueError as error: raise AssertionError('valid parent timing interval was refused') from error
    assert interval == {'lowerSeconds': 55, 'upperSeconds': 57, 'classification': 'BEFORE', 'thresholdSeconds': 60}
    assert idle_interval(timing(1, 2), timing(67, 68))['classification'] == 'AFTER'
    assert idle_interval(timing(1, 2), timing(61, 62))['classification'] == 'INDETERMINATE'
    assert idle_interval(timing(1, 2), timing(62, 63))['classification'] == 'INDETERMINATE'
    malformed = timing(67, 68); malformed['responseUtc'] = timing(1, 2)['responseUtc']
    with pytest.raises(ValueError): idle_interval(timing(1, 2), malformed)


def test_rpc_elapsed_must_agree_in_utc_and_monotonic_clocks():
    malformed = timing(67, 68)
    malformed['responseUtc'] = timing(67, 80)['responseUtc']
    with pytest.raises(ValueError): _timing(malformed)


def test_complete_graph_measures_four_waits_and_preserves_native_order():
    collector, wire, budget, journal, clock = fixture()
    receipt = collector.run()
    assert receipt['complete'] is True
    assert budget.used['observation'] == 24 and budget.used['tokenCleanup'] == 1 and budget.used['documentCleanup'] == 3
    assert len(receipt['observations']) == 7
    assert [row['idleInterval']['classification'] for row in receipt['waits']] == ['BEFORE', 'AFTER', 'AFTER', 'AFTER']
    assert clock.seconds >= 350
    assert any(row['unknownStarts'] == ['live/begin'] for row in journal)
    assert any('expired/commit' in row['unknownCommits'] for row in journal)
    assert len(projection(receipt)['cases']) == 7


@pytest.mark.parametrize('fail_at', [2, 3, 5, 7, 9, 13, 15, 17, 20, 21, 23, 25, 26, 27, 28])
def test_unknown_dispatch_stays_owned_and_never_repeats(fail_at):
    collector, wire, budget, journal, _clock = fixture(fail_at=fail_at)
    receipt = collector.run()
    assert receipt['complete'] is False and budget.total <= 48
    if fail_at in [2, 5, 9]: assert receipt['unknownCommits']
    if fail_at in [3, 7, 15, 23]: assert receipt['unknownStarts']
    if fail_at in [13, 17, 21]:
        failed = receipt['steps'][-1]
        assert not any(row['request'] == failed['request'] and row['rpc'] == 'Rollback' for row in receipt['cleanupSteps'])
        assert receipt['unknownRollbacks']


@pytest.mark.parametrize('code,message,complete', [(10, 'The referenced transaction has expired or is no longer valid.', True), (9, 'The referenced transaction has expired or is no longer valid.', False), (10, 'other ABORTED', False), (4, 'deadline exceeded', False)])
def test_invalidated_cleanup_requires_exact_native_refusal(code, message, complete):
    collector, wire, _budget, _journal, _clock = fixture(cleanup_code=code, cleanup_details=message)
    receipt = collector.run()
    assert receipt['complete'] is complete
    if complete:
        assert receipt['tokens']['late']['state'] == 'invalidated'
        assert projection(receipt)['cleanup'] == {'absent': True}
    else: assert receipt['unrecovered'] is True


def test_invalidated_cleanup_does_not_accept_wrong_final_state():
    collector, wire, _budget, _journal, _clock = fixture(cleanup_code=10, cleanup_details='The referenced transaction has expired or is no longer valid.')
    wire.wrong_state = True
    receipt = collector.run()
    assert receipt['complete'] is False
    assert not any(method == 'DeleteDocument' for method, _request in wire.calls)


def test_journal_failure_stops_all_dispatch():
    collector, wire, _budget, _journal, _clock = fixture()
    collector.save = lambda _value: (_ for _ in ()).throw(OSError('fsync failed'))
    assert collector.run()['complete'] is False
    assert wire.calls == []


def test_malformed_successful_commit_keeps_unknown_commit_responsibility():
    collector, wire, _budget, _journal, _clock = fixture()
    send = wire.send
    def malformed(method, request, **kwargs):
        result = send(method, request, **kwargs)
        if len(wire.calls) == 5: result['response'] = {}
        return result
    wire.send = malformed
    receipt = collector.run()
    assert receipt['complete'] is False
    assert receipt['unknownCommits'] == ['live/commit']


def test_foreign_cleanup_never_deletes():
    collector, wire, _budget, _journal, _clock = fixture()
    wire.foreign_cleanup = True
    assert collector.run()['complete'] is False
    assert not any(method == 'DeleteDocument' for method, _request in wire.calls)


def test_revocation_during_wait_blocks_probe_and_cleanup():
    collector, wire, _budget, _journal, clock = fixture()
    def check():
        if clock.now() > 105: raise ValueError('REVOKED')
    collector.before_send = check
    receipt = collector.run()
    assert receipt['complete'] is False
    assert len(wire.calls) == 4


def test_early_returning_sleep_cannot_claim_idle_wait_completed():
    collector, wire, _budget, _journal, _clock = fixture()
    collector.sleep = lambda _seconds: None
    assert collector.run()['complete'] is False
    assert not any(row['site'] == 'live/commit' for row in collector.rows)


@pytest.mark.parametrize('mutation', ['timing', 'wait', 'unknown', 'terminal', 'delete'])
def test_freeze_rederives_time_responsibility_and_cleanup(mutation):
    collector, _wire, _budget, _journal, _clock = fixture(cleanup_code=10, cleanup_details='The referenced transaction has expired or is no longer valid.')
    receipt = collector.run()
    if mutation == 'timing': receipt['steps'][4]['timing']['dispatchMonotonic'] = 1
    elif mutation == 'wait': receipt['waits'][0]['idleInterval']['classification'] = 'AFTER'
    elif mutation == 'unknown': receipt['unknownCommits'] = ['expired/commit']
    elif mutation == 'terminal': receipt['cleanupSteps'][0]['result']['details'] = 'other ABORTED'
    elif mutation == 'delete': receipt['cleanupSteps'][-2]['request']['currentDocument'] = {'exists': True}
    with pytest.raises(ValueError): projection(receipt)
