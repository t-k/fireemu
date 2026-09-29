"""P10-A-only authorization; legacy envelopes never authorize this graph."""

from __future__ import annotations

import datetime as dt
from decimal import Decimal, InvalidOperation

import txn_sandbox_admission as shared

NAME = 'FS-TRANSACTION p10-grpc-idle'
TASK_ID = 'FS-TRANSACTION-SANDBOX'


def _values(columns):
    values = {}
    for token in columns[2].split(';'):
        if '=' not in token:
            continue
        key, value = map(str.strip, token.split('=', 1))
        if key in values:
            raise ValueError('duplicate P10-A authority key')
        values[key] = value
    return values


def authorize(decisions, pins):
    """Re-read before every external dispatch, including cleanup and refresh."""
    if pins.get('packetName') != 'p10-grpc-idle' or pins.get('requestsPerRecording') != 48 or type(pins.get('requestsPerRecording')) is not int or pins.get('estimatedUsdPerRecording') != 0.01 or not str(pins.get('envelopeId', '')).startswith('FS-TRANSACTION-p10-grpc-idle-'):
        raise ValueError('fresh P10-A authority scope required')
    shared.reject_revocations(decisions, pins)
    entries = shared._decision_entries(decisions)
    scope = {'FS-TRANSACTION', NAME, NAME + ' envelope'}
    for columns, _tokens in entries:
        if columns[1] in scope and shared._revoked_packet(columns[2], pins['packetSha256'], pins['envelopeId']):
            raise ValueError('P10-A packet or envelope is REVOKED')
    expected = {'decision': 'APPROVE', 'envelopeId': pins['envelopeId'], 'packetSha256': pins['packetSha256'], 'sourceCommit': pins['sourceCommit'], 'runnerSha256': pins['runnerSha256'], 'requestsPerRecording': '48', 'estimatedUsdPerRecording': '0.01', 'recordings': '2'}
    exact = []
    for columns, _tokens in entries:
        if columns[1] not in {'FS-TRANSACTION', NAME} or columns[4] != pins['packetPath']:
            continue
        values = _values(columns)
        actor = columns[3]
        delegated = shared._delegated_actor(actor, entries, decisions, allow_within_envelope=True)
        if all(values.get(key) == value for key, value in expected.items()) and (actor.startswith('オーナー') or delegated):
            exact.append(columns)
    if len(exact) != 1:
        raise ValueError('one explicit exact-version P10-A APPROVE row required')
    if exact[0][3].startswith('オーナー'):
        return 96, 0.02
    envelopes = []
    for columns, _tokens in entries:
        if columns[1] != NAME + ' envelope' or columns[4] != pins['envelopePath']:
            continue
        values = _values(columns)
        actor = columns[3]
        delegated = shared._delegated_actor(actor, entries, decisions) and values.get('根拠') == '2026-09-28 調整役への委任（本番の送信）'
        if values.get('envelopeId') == pins['envelopeId'] and (actor.startswith('オーナー') or delegated):
            envelopes.append(values)
    if len(envelopes) != 1:
        raise ValueError('one owner or delegation-i P10-A envelope required')
    values = envelopes[0]
    expected_scope = {'project': 'fireemu-oracle-sbx/(default)', 'writes': 'owned-one-document', 'iamConfig': 'none', 'retries': 'none', 'onStop': 'needs-recovery-lock-held'}
    if any(values.get(key) != value for key, value in expected_scope.items()):
        raise ValueError('P10-A envelope resource scope differs')
    try:
        count = int(values['maxRequests'])
        reserve = Decimal(values['reserveUsd'])
    except (KeyError, ValueError, InvalidOperation):
        raise ValueError('P10-A envelope bound is invalid') from None
    if str(count) != values['maxRequests'] or count != 96 or not reserve.is_finite() or reserve != Decimal('0.04'):
        raise ValueError('P10-A envelope does not cover the graph within task limits')
    return count, float(reserve)


def remaining_task_budget(rows, reservation=0.02):
    latest = {}
    unlinked = Decimal('0')
    for row in rows:
        if row.get('taskId') != TASK_ID:
            continue
        raw = row.get('estimatedUsd')
        if type(raw) not in (int, float):
            raise ValueError('FS-TRANSACTION historical cost missing')
        value = Decimal(str(raw))
        if not value.is_finite() or value < 0:
            raise ValueError('FS-TRANSACTION historical cost invalid')
        if row.get('attemptId'):
            latest[row['attemptId']] = value
        else:
            unlinked += value
    spent = unlinked + sum(latest.values(), Decimal('0'))
    if spent + Decimal(str(reservation)) > Decimal('10'):
        raise ValueError('FS-TRANSACTION whole-task US$10 limit exceeded')
    return float(Decimal('10') - spent)


def verify_initial_gates(rows, now, decisions, pins):
    """Apply the shared sbx history rules before reservation or any credential read."""
    authorize(decisions, pins)
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise ValueError('timezone-aware P10-A admission time required')
    if any(row.get('envelopeId') == pins['envelopeId'] for row in rows) or any(row.get('packetId') == pins['packetId'] and row.get('outcome') == 'reserved' for row in rows):
        raise ValueError('P10-A packet or envelope already consumed')
    sandbox = [row for row in rows if row.get('project') == shared.PROJECT]
    for index, row in enumerate(sandbox):
        shared._instant(row.get('ts'))
        if row.get('outcome') == 'reserved' or row.get('event') == 'started':
            key = next((name for name in ('attemptId', 'runId', 'runDir') if row.get(name)), None)
            if key is None or not shared._closed_attempt(row, key, sandbox[index + 1:]):
                raise ValueError('sbx has an open attempt')
    task = [row for row in sandbox if row.get('taskId') == TASK_ID]
    if task and not shared._terminal(max(reversed(task), key=lambda row: shared._instant(row['ts']))):
        raise ValueError('FS-TRANSACTION requires recovery')
    activity = [row for row in sandbox if row.get('event') not in ('note', 'started') and not str(row.get('outcome', '')).startswith('reserved') and row.get('outcome') != 'historical-unknown-hold']
    latest = max(activity, key=lambda row: shared._instant(row['ts'])) if activity else None
    if latest and now - shared._instant(latest['ts']) < shared.IDLE_GAP:
        raise ValueError('sbx needs 30 minutes since last activity')
    remaining_task_budget(rows)
    return latest['ts'] if latest else None
