"""Program-scoped authorization; another program's or the legacy envelopes never authorize this graph."""

from __future__ import annotations

import datetime as dt
import re
from decimal import Decimal, InvalidOperation

import txn_sandbox_admission as shared
from txn_program_program import compile_plan

TASK_ID = 'FS-TRANSACTION-SANDBOX'
_PACKET_NAME = re.compile(r'[a-z][a-z0-9]*(-[a-z0-9]+){1,5}\Z')
SCOPE_KEYS = ('project', 'writes', 'iamConfig', 'retries', 'onStop', 'observationSeconds', 'recoverySeconds', 'maxTokens', 'maxUnresolvedTokens', 'releasePolicy', 'timing', 'timingSource', 'transports', 'writerDeadlineSeconds')
_TAKEN_NAMES = ('p09-grpc-retry', 'p10-grpc-boundary', 'p10-grpc-idle', 'expiry-retry-04')


def envelope_scope(table):
    """The resource scope an envelope must state, derived from the table alone."""
    plan = compile_plan(table, 'a' * 32, 'b' * 32)
    writer = any(step['role'] == 'outside-writer' for step in plan['steps'])
    return {'project': 'fireemu-oracle-sbx/(default)', 'writes': f"owned-{len(plan['documents'])}-documents", 'iamConfig': 'none', 'retries': 'none', 'onStop': 'needs-recovery-lock-held', 'observationSeconds': str(plan['observationSeconds']), 'recoverySeconds': str(plan['recoverySeconds']), 'maxTokens': str(plan['maxTokens']), 'maxUnresolvedTokens': str(plan['maxUnresolvedTokens']), 'releasePolicy': plan['releasePolicy'], 'timing': plan['timing'], 'timingSource': 'parent-wire-envelope', 'transports': '+'.join(sorted({step['transport'] for step in plan['steps']})), 'writerDeadlineSeconds': '30' if writer else 'none'}


def _values(columns):
    values = {}
    for token in shared.normalize_authority(columns[2]).split(';'):
        if '=' not in token:
            continue
        key, value = map(lambda value: shared.normalize_authority(value.strip()), token.split('=', 1))
        if key in values:
            raise ValueError('duplicate authority key')
        values[key] = value
    return values


def _check_scope(pins):
    name = pins.get('packetName')
    requests = pins.get('requestsPerRecording')
    envelope = pins.get('envelopeId')
    if not isinstance(name, str) or not _PACKET_NAME.fullmatch(name) or name in _TAKEN_NAMES or type(requests) is not int or requests <= 0 or pins.get('estimatedUsdPerRecording') != 0.01 or not isinstance(pins.get('scope'), dict) or set(pins['scope']) != set(SCOPE_KEYS) or any(not isinstance(value, str) or not value for value in pins['scope'].values()) or not isinstance(envelope, str) or not envelope.startswith(f'FS-TRANSACTION-{name}-'):
        raise ValueError('fresh program authority scope required')
    return name, requests


def authorize(decisions, pins):
    """Re-read before every external dispatch, including cleanup and refresh."""
    packet_name, requests = _check_scope(pins)
    name = f'FS-TRANSACTION {packet_name}'
    shared.reject_revocations(decisions, pins)
    entries = shared._decision_entries(decisions)
    scope = {shared.normalize_authority(value) for value in ('FS-TRANSACTION', name, name + ' envelope')}
    for columns, _tokens in entries:
        if shared.normalize_authority(columns[1]) in scope and shared._revoked_packet(columns[2], pins['packetSha256'], pins['envelopeId']):
            raise ValueError('program packet or envelope is REVOKED')
    expected = {'decision': 'APPROVE', 'envelopeId': pins['envelopeId'], 'packetSha256': pins['packetSha256'], 'sourceCommit': pins['sourceCommit'], 'runnerSha256': pins['runnerSha256'], 'requestsPerRecording': str(requests), 'estimatedUsdPerRecording': '0.01', 'recordings': '2'}
    exact = []
    for columns, _tokens in entries:
        if shared.normalize_authority(columns[1]) not in {shared.normalize_authority(value) for value in ('FS-TRANSACTION', name)} or columns[4] != pins['packetPath']:
            continue
        values = _values(columns)
        actor = columns[3]
        delegated = shared._delegated_actor(actor, entries, decisions, allow_within_envelope=True)
        if all(values.get(shared.normalize_authority(key)) == shared.normalize_authority(value) for key, value in expected.items()) and (shared.normalize_authority(actor).startswith(shared.normalize_authority('オーナー')) or delegated):
            exact.append(columns)
    if len(exact) != 1:
        raise ValueError('one explicit exact-version program APPROVE row required')
    if shared.normalize_authority(exact[0][3]).startswith(shared.normalize_authority('オーナー')):
        return 2 * requests, 0.02
    envelopes = []
    for columns, _tokens in entries:
        if shared.normalize_authority(columns[1]) != shared.normalize_authority(name + ' envelope') or columns[4] != pins['envelopePath']:
            continue
        values = _values(columns)
        actor = columns[3]
        delegated = shared._delegated_actor(actor, entries, decisions) and values.get(shared.normalize_authority('根拠')) == shared.normalize_authority('2026-09-28 調整役への委任（本番の送信）')
        if values.get(shared.normalize_authority('envelopeId')) == shared.normalize_authority(pins['envelopeId']) and (shared.normalize_authority(actor).startswith(shared.normalize_authority('オーナー')) or delegated):
            envelopes.append(values)
    if len(envelopes) != 1:
        raise ValueError('one owner or delegation-i program envelope required')
    values = envelopes[0]
    if any(values.get(shared.normalize_authority(key)) != shared.normalize_authority(value) for key, value in pins['scope'].items()):
        raise ValueError('program envelope resource scope differs')
    try:
        count = int(values[shared.normalize_authority('maxRequests')])
        reserve = Decimal(values[shared.normalize_authority('reserveUsd')])
    except (KeyError, ValueError, InvalidOperation):
        raise ValueError('program envelope bound is invalid') from None
    if str(count) != values[shared.normalize_authority('maxRequests')] or count != 2 * requests or not reserve.is_finite() or reserve != Decimal('0.04'):
        raise ValueError('program envelope does not cover the graph within task limits')
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
        raise ValueError('timezone-aware program admission time required')
    if any(row.get('envelopeId') == pins['envelopeId'] for row in rows) or any(row.get('packetId') == pins['packetId'] and row.get('outcome') == 'reserved' for row in rows):
        raise ValueError('program packet or envelope already consumed')
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
    remaining_task_budget(rows, 0.04)
    return latest['ts'] if latest else None
