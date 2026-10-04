"""Closed local P09 observations and conservative stop responsibility."""

import base64
import copy

import pytest

from txn_retry_grpc_collector import Collector, projection
from txn_retry_grpc_program import RequestBudget, compile_plan


class FakeWire:
    def __init__(self, plan, *, fail_at=None, accept_unexpected=False):
        self.plan = plan
        self.calls = []
        self.document = None
        self.transactions = {}
        self.fail_at = fail_at
        self.accept_unexpected = accept_unexpected
        self.foreign_cleanup = False

    def send(self, method, request, **_kwargs):
        self.calls.append((method, copy.deepcopy(request)))
        if len(self.calls) == self.fail_at:
            return {'complete': False, 'code': 14, 'details': 'lost outcome', 'response': None, 'childReaped': True, 'dispatchedRequests': 1}
        code, details, response = 0, '', {}
        if method == 'BeginTransaction':
            previous = request['options'].get('readWrite', {}).get('retryTransaction')
            previous_row = self.transactions.get(previous)
            if previous and (previous_row is None or previous_row['readOnly']) and not self.accept_unexpected:
                code, details, response = 3, 'Cannot retry a read-only transaction' if previous_row else 'Invalid retry transaction.', None
            else:
                token = base64.b64encode(f'token-{len(self.transactions)}'.encode()).decode()
                self.transactions[token] = {'readOnly': 'readOnly' in request['options'], 'snapshot': copy.deepcopy(self.document), 'state': 'open'}
                response = {'transaction': token}
        elif method == 'Commit':
            self.document = copy.deepcopy(request['writes'][0]['update'])
            self.document['updateTime'] = {'seconds': '1788004860', 'nanos': len(self.calls)}
            if request.get('transaction'): self.transactions[request['transaction']]['state'] = 'committed'
            response = {'writeResults': [{'updateTime': self.document['updateTime']}]}
        elif method == 'GetDocument':
            found = self.transactions[request['transaction']]['snapshot'] if request.get('transaction') else self.document
            if found is None: code, response = 5, None
            else:
                response = copy.deepcopy(found)
                if self.foreign_cleanup and not request.get('transaction') and len(self.calls) > 25:
                    response['fields']['owner']['stringValue'] = 'foreign'
        elif method == 'Rollback':
            row = self.transactions[request['transaction']]
            if row['state'] == 'committed': code, details, response = 10, 'The referenced transaction has expired or is no longer valid.', None
            else: row['state'] = 'rolled-back'
        elif method == 'DeleteDocument':
            assert request['currentDocument']['updateTime'] == self.document['updateTime']
            self.document = None
        return {'complete': True, 'code': code, 'details': details, 'response': response, 'childReaped': True, 'dispatchedRequests': 1}


def fixture(**kwargs):
    plan = compile_plan('a' * 32, 'b' * 32)
    budget = RequestBudget(plan)
    journal = []
    wire = FakeWire(plan, **kwargs)
    collector = Collector(plan, budget, wire, 'owner', save=lambda state: journal.append(copy.deepcopy(state)))
    return collector, wire, budget, journal


def test_closed_program_records_six_cases_and_cleans_one_owned_document():
    collector, wire, budget, journal = fixture()
    receipt = collector.run()
    assert receipt['complete'] is True
    assert len(receipt['observations']) == 6
    assert len(wire.calls) == 28
    assert budget.used == {'observation': 25, 'tokenCleanup': 0, 'documentCleanup': 3, 'management': 0, 'credential': 0}
    assert receipt['unknownStarts'] == [] and receipt['openTokens'] == []
    assert receipt['cleanup']['absent'] is True
    assert any(row['unknownStarts'] == ['committed/begin'] for row in journal)
    assert projection(receipt)['cases'][1]['code'] == 0


@pytest.mark.parametrize('fail_at', [2, 3, 4, 5, 8, 15, 21, 24, 26, 27, 28])
def test_lost_response_retains_unknown_responsibility_and_never_retries(fail_at):
    collector, wire, budget, _journal = fixture(fail_at=fail_at)
    receipt = collector.run()
    assert receipt['complete'] is False
    assert receipt['unrecovered'] or receipt['failureType']
    assert budget.total <= 48
    assert budget.used['tokenCleanup'] <= 7 and budget.used['documentCleanup'] <= 7
    if fail_at in [3, 8, 15, 21, 24]: assert receipt['unknownStarts']
    assert len(wire.calls) == budget.total


def test_unexpected_success_tokens_are_known_and_both_released_in_cleanup():
    collector, wire, budget, _journal = fixture(accept_unexpected=True)
    receipt = collector.run()
    assert receipt['complete'] is True
    assert len(receipt['tokens']) == 7
    assert receipt['openTokens'] == []
    assert budget.used['tokenCleanup'] == 2
    assert len(wire.calls) == 30


def test_foreign_marker_never_becomes_a_delete_target():
    collector, wire, _budget, _journal = fixture()
    wire.foreign_cleanup = True
    receipt = collector.run()
    assert receipt['complete'] is False
    assert receipt['unrecovered'] is True
    assert not any(method == 'DeleteDocument' for method, _request in wire.calls)


def test_journal_save_failure_stops_dispatch_and_keeps_lock_responsibility():
    collector, wire, _budget, _journal = fixture()
    collector.save = lambda _state: (_ for _ in ()).throw(OSError('disk unavailable'))
    receipt = collector.run()
    assert receipt['complete'] is False
    assert receipt['journalFailure'] is True
    assert wire.calls == []


def test_revoked_authority_prevents_even_cleanup_from_sending():
    collector, wire, _budget, _journal = fixture()
    def check():
        if len(wire.calls) >= 3: raise ValueError('REVOKED')
    collector.before_send = check
    receipt = collector.run()
    assert receipt['complete'] is False
    assert len(wire.calls) == 3
    assert receipt['unrecovered'] is True


@pytest.mark.parametrize('mutation', ['scope', 'accounting', 'case', 'token', 'delete-version', 'absence'])
def test_freeze_rejects_forged_complete_acquisitions(mutation):
    collector, _wire, _budget, _journal = fixture()
    receipt = collector.run()
    if mutation == 'scope': receipt['steps'][0]['request']['name'] = 'foreign'
    elif mutation == 'accounting': receipt['phaseRequests']['observation'] = 24
    elif mutation == 'case': receipt['observations'] = receipt['observations'][:-1]
    elif mutation == 'token': receipt['tokens']['committed']['value'] = 'Zm9yZWlnbg=='
    elif mutation == 'delete-version': receipt['cleanupSteps'][1]['request']['currentDocument'] = {'exists': True}
    elif mutation == 'absence': receipt['cleanupSteps'][-1]['result']['code'] = 0
    with pytest.raises(ValueError): projection(receipt)


def test_freeze_rejects_terminal_token_state_not_derived_from_native_outcomes():
    collector, _wire, _budget, _journal = fixture()
    receipt = collector.run()
    receipt['tokens']['committed']['state'] = 'committed'
    with pytest.raises(ValueError): projection(receipt)


def test_definitive_retry_refusal_is_recorded_with_only_its_dependent_slots_skipped():
    collector, wire, budget, _journal = fixture()
    send = wire.send
    def refusing(method, request, **kwargs):
        previous = request.get('options', {}).get('readWrite', {}).get('retryTransaction')
        if method == 'BeginTransaction' and previous and wire.transactions.get(previous, {}).get('state') == 'committed':
            wire.calls.append((method, copy.deepcopy(request)))
            return {'complete': True, 'code': 3, 'details': 'Invalid retry transaction.', 'response': None, 'childReaped': True, 'dispatchedRequests': 1}
        return send(method, request, **kwargs)
    wire.send = refusing
    receipt = collector.run()
    assert receipt['complete'] is True
    frozen = projection(receipt)
    assert len(frozen['cases']) == 6
    assert frozen['cases'][1]['code'] == 3
    assert [row['site'] for row in frozen['skipped']] == ['committed/snapshot', 'committed/rollback-retry']
    assert budget.used['observation'] == 23 and budget.total == 26


def test_required_rollback_refusal_stops_before_dependent_cases():
    collector, wire, _budget, _journal = fixture()
    send = wire.send
    def refusing(method, request, **kwargs):
        if len(wire.calls) == 12:
            assert method == 'Rollback'
            wire.calls.append((method, copy.deepcopy(request)))
            return {'complete': True, 'code': 9, 'details': 'refused context', 'response': None, 'childReaped': True, 'dispatchedRequests': 1}
        return send(method, request, **kwargs)
    wire.send = refusing
    receipt = collector.run()
    assert receipt['complete'] is False
    assert receipt['graphComplete'] is False
    assert len(receipt['steps']) == 13
    assert not any(row['site'] == 'rolled-back/rollback-again' for row in receipt['steps'])
    assert receipt['tokens']['rolled-back']['state'] == 'unconfirmed-release'


def test_freeze_rejects_a_refused_preparatory_rollback():
    collector, _wire, _budget, _journal = fixture()
    receipt = collector.run()
    row = next(row for row in receipt['steps'] if row['site'] == 'rolled-back/rollback')
    row['result'].update(code=9, details='refused context', response=None)
    with pytest.raises(ValueError): projection(receipt)


@pytest.mark.parametrize('site', ['committed/rollback', 'committed/rollback-retry', 'rolled-back/rollback', 'rolled-back/rollback-again', 'rolled-back/rollback-retry', 'read-only/rollback'])
def test_indeterminate_rollback_is_not_automatically_resent(site):
    plan = compile_plan('a' * 32, 'b' * 32)
    index = next(index for index, row in enumerate(plan['steps'], 1) if row['id'] == site)
    collector, wire, _budget, journal = fixture(fail_at=index)
    receipt = collector.run()
    assert receipt['complete'] is False
    failed = receipt['steps'][-1]
    assert failed['site'] == site
    request = failed['request']
    assert not any(row['rpc'] == 'Rollback' and row['request'] == request for row in receipt['cleanupSteps'])
    role = next(role for role, entry in receipt['tokens'].items() if entry['value'] == request['transaction'])
    assert receipt['unknownRollbacks'] == [role]
    assert receipt['unrecovered'] is True
    assert any(role in row['unknownRollbacks'] for row in journal)
    assert wire.calls.count(('Rollback', request)) == (2 if site == 'rolled-back/rollback-again' else 1)
