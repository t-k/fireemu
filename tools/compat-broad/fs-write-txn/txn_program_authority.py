"""Program-scoped authorization; another program's or the legacy envelopes never authorize this graph."""

from __future__ import annotations

import datetime as dt
import re
from decimal import Decimal, InvalidOperation

import txn_sandbox_admission as shared
from txn_program_program import PROJECT, budget_for, compile_plan

TASK_ID = 'FS-TRANSACTION-SANDBOX'
_PACKET_NAME = re.compile(r'[a-z][a-z0-9]*(-[a-z0-9]+){1,5}\Z')
SCOPE_KEYS = ('project', 'writes', 'iamConfig', 'retries', 'onStop', 'observationSeconds', 'recoverySeconds', 'maxTokens', 'maxUnresolvedTokens', 'releasePolicy', 'timing', 'timingSource', 'transports', 'writerDeadlineSeconds')
_TAKEN_NAMES = ('p09-grpc-retry', 'p10-grpc-boundary', 'p10-grpc-idle', 'expiry-retry-04')


def envelope_scope(table):
    """The resource scope an envelope must state, derived from the table alone."""
    plan = compile_plan(table, 'a' * 32, 'b' * 32)
    if table['name'] == 's5b-web-sdk-retry':
        return {'project': 'fireemu-oracle-query/(default)', 'writes': 'owned-6-documents+2-no-write-probes', 'iamConfig': 'none', 'retries': 'web-optimistic-callback-only-max-two', 'onStop': 'needs-recovery-lock-held', 'observationSeconds': '180', 'recoverySeconds': '120', 'maxTokens': '0', 'maxUnresolvedTokens': '0', 'releasePolicy': 'owned-version-delete-definite-before-release', 'timing': 'wall-clock', 'timingSource': 'sdk-parent-before-payload', 'transports': 'node+browser', 'writerDeadlineSeconds': '10'}
    if table['name'] == 'p17-admin-sdk-retry':
        return {'project': 'fireemu-oracle-txn/(default)', 'writes': 'owned-12-documents', 'iamConfig': 'none', 'retries': 'sdk-aborted-callback-only-max-two', 'onStop': 'needs-recovery-lock-held', 'observationSeconds': '180', 'recoverySeconds': '120', 'maxTokens': '9', 'maxUnresolvedTokens': '9', 'releasePolicy': 'sdk-rollback-definite-before-next-case', 'timing': 'wall-clock', 'timingSource': 'grpc-js-client-interceptor', 'transports': 'grpc', 'writerDeadlineSeconds': '30'}
    resources = [plan['database'], *table.get('databases', {}).values()]
    project_scope = '+'.join(sorted(resource.removeprefix('projects/').replace('/databases/', '/') for resource in resources))
    writer = any(step['role'] == 'outside-writer' for step in plan['steps'])
    return {'project': project_scope, 'writes': f"owned-{len(plan['documents'])}-documents", 'iamConfig': 'none', 'retries': 'none', 'onStop': 'needs-recovery-lock-held', 'observationSeconds': str(plan['observationSeconds']), 'recoverySeconds': str(plan['recoverySeconds']), 'maxTokens': str(plan['maxTokens']), 'maxUnresolvedTokens': str(plan['maxUnresolvedTokens']), 'releasePolicy': plan['releasePolicy'], 'timing': plan['timing'], 'timingSource': 'parent-wire-envelope', 'transports': '+'.join(sorted({step['transport'] for step in plan['steps']})), 'writerDeadlineSeconds': str(-(-max(step['deadlineMs'] for step in plan['steps'] if step['role'] == 'outside-writer') // 1000)) if writer else 'none'}


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


def _same_amount(text, amount):
    """The APPROVE line states the packet's own estimate, compared as an amount (0, 0.0 and 0.00 are the same US$0)."""
    try:
        return Decimal(str(text)) == Decimal(str(amount))
    except (InvalidOperation, TypeError, ValueError):
        return False


def _s5b_recovery(pins):
    return pins.get('packetName') == 's5b-web-sdk-retry' and pins.get('envelopeId') in ('FS-TRANSACTION-s5b-web-sdk-retry-recovery-001', 'FS-TRANSACTION-s5b-web-sdk-retry-recovery-002', 'FS-TRANSACTION-s5b-web-sdk-retry-recovery-003')


def _check_scope(pins):
    name = pins.get('packetName')
    requests = pins.get('requestsPerRecording')
    envelope = pins.get('envelopeId')
    if not isinstance(name, str) or not _PACKET_NAME.fullmatch(name) or name in _TAKEN_NAMES or type(requests) is not int or requests <= 0 or pins.get('estimatedUsdPerRecording') != (0.01 if _s5b_recovery(pins) else budget_for(pins.get('project', PROJECT))[0]) or not isinstance(pins.get('scope'), dict) or set(pins['scope']) != set(SCOPE_KEYS) or any(not isinstance(value, str) or not value for value in pins['scope'].values()) or not isinstance(envelope, str) or not envelope.startswith(f'FS-TRANSACTION-{name}-'):
        raise ValueError('fresh program authority scope required')
    if _s5b_recovery(pins):
        from txn_program_cli import table_for
        expected = {**envelope_scope(table_for(name)), 'retries': 'none', 'releasePolicy': 'sdk-recovery-lock-held', 'observationSeconds': '120', 'transports': 'grpc', 'timingSource': 'parent-wire-envelope', 'writerDeadlineSeconds': 'none', 'writes': pins['scope']['writes']}
        expected_requests = 20 if envelope.endswith('-001') else 29
        if requests != expected_requests or pins.get('reserveUsd') != 0.01 or pins.get('project') != 'fireemu-oracle-query' or pins['scope']['writes'] not in ('owned-version-delete-only', 'none') or pins['scope'] != expected:
            raise ValueError('closed S5b recovery authority required')
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
    expected = {'decision': 'APPROVE', 'envelopeId': pins['envelopeId'], 'packetSha256': pins['packetSha256'], 'sourceCommit': pins['sourceCommit'], 'runnerSha256': pins['runnerSha256'], 'requestsPerRecording': str(requests), 'recordings': '1' if _s5b_recovery(pins) else '2'}
    exact = []
    for columns, _tokens in entries:
        if shared.normalize_authority(columns[1]) not in {shared.normalize_authority(value) for value in ('FS-TRANSACTION', name)} or columns[4] != pins['packetPath']:
            continue
        values = _values(columns)
        actor = columns[3]
        delegated = shared._delegated_actor(actor, entries, decisions, allow_within_envelope=True)
        if all(values.get(shared.normalize_authority(key)) == shared.normalize_authority(value) for key, value in expected.items()) and _same_amount(values.get(shared.normalize_authority('estimatedUsdPerRecording')), pins['estimatedUsdPerRecording']) and (shared.normalize_authority(actor).startswith(shared.normalize_authority('オーナー')) or delegated):
            exact.append(columns)
    if len(exact) != 1:
        raise ValueError('one explicit exact-version program APPROVE row required')
    if packet_name not in ('p17-admin-sdk-retry', 's5b-web-sdk-retry') and shared.normalize_authority(exact[0][3]).startswith(shared.normalize_authority('オーナー')):
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
    if str(count) != values[shared.normalize_authority('maxRequests')] or count != (requests if _s5b_recovery(pins) else 2 * requests) or not reserve.is_finite() or reserve != Decimal(str(0.01 if _s5b_recovery(pins) else budget_for(pins.get('project', PROJECT))[1])):
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
    """Apply the sandbox history rules of the packet's project before reservation or any credential read."""
    authorize(decisions, pins)
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise ValueError('timezone-aware program admission time required')
    if any(row.get('envelopeId') == pins['envelopeId'] for row in rows) or any(row.get('packetId') == pins['packetId'] and row.get('outcome') == 'reserved' for row in rows):
        raise ValueError('program packet or envelope already consumed')
    latest_primary = None
    for project in sorted({resource.split('/')[0] for resource in pins['scope']['project'].split('+')}):
        sandbox = [row for row in rows if row.get('project') == project or project in row.get('projects', [])]
        task = []
        for index, row in enumerate(sandbox):
            shared._instant(row.get('ts'))
            own = row.get('taskId') in (TASK_ID, 'FS-TRANSACTION') or row.get('packetId') == pins['packetId'] or row.get('envelopeId') == pins['envelopeId'] or isinstance(row.get('packetId'), str) and re.fullmatch(r'fs-transaction-p17-admin-sdk-retry-[A-Za-z0-9_-]{4,64}', row['packetId'])
            if own: task.append(row)
            if own and (row.get('outcome') == 'reserved' or row.get('event') == 'started'):
                key = next((name for name in ('attemptId', 'runId', 'runDir') if row.get(name)), None)
                if key is None or not shared._closed_attempt(row, key, sandbox[index + 1:]):
                    raise ValueError(f'{project} has an open attempt')
        if task and not shared._terminal(max(reversed(task), key=lambda row: shared._instant(row['ts']))):
            raise ValueError('FS-TRANSACTION requires recovery')
        latest = max(sandbox, key=lambda row: shared._instant(row['ts'])) if sandbox else None
        if latest and now - shared._instant(latest['ts']) < shared.IDLE_GAP:
            raise ValueError(f'{project} needs 30 minutes since last activity')
        if project == pins.get('project', PROJECT):
            latest_primary = latest
    remaining_task_budget(rows, budget_for(pins.get('project', PROJECT))[1])
    return latest_primary['ts'] if latest_primary else None


def authorize_database_action(decisions, pins):
    """An A2 or recovery packet needs a distinct exact approval and envelope."""
    shared.reject_revocations(decisions, pins)
    entries = shared._decision_entries(decisions)
    name = "FS-TRANSACTION p16 database action"
    expected = {key: str(pins[key]) for key in ("command", "originalPacketSha256", "sourceCommit", "runnerSha256", "envelopeId", "maxRequests", "reserveUsd", "resources")}
    expected.update(retries="none", onStop="lock-held", writes="none" if pins["command"] == "readback-a2" else "one-owned-database-delete")
    for topic, path, values in ((name, pins["packetPath"], {**expected, "decision": "APPROVE", "packetSha256": pins["packetSha256"]}), (name + " envelope", pins["envelopePath"], expected)):
        matches = []
        for columns, _tokens in entries:
            if shared.normalize_authority(columns[1]) != shared.normalize_authority(topic):
                continue
            if shared._revoked_packet(columns[2], pins["packetSha256"], pins["envelopeId"]):
                raise ValueError("database action packet or envelope is REVOKED")
            if columns[4] != path:
                continue
            actual = _values(columns)
            actor = shared.normalize_authority(columns[3]).startswith(shared.normalize_authority("オーナー"))
            delegated = shared._delegated_actor(columns[3], entries, decisions, allow_within_envelope=topic == name)
            if delegated and topic != name:
                delegated = actual.get(shared.normalize_authority("根拠")) == shared.normalize_authority("2026-09-28 調整役への委任（本番の送信）")
            if (actor or delegated) and all(actual.get(shared.normalize_authority(key)) == shared.normalize_authority(value) for key, value in values.items()):
                matches.append(columns)
        if len(matches) != 1:
            raise ValueError("one exact database action approval and its own envelope required")
    return pins["maxRequests"], pins["reserveUsd"]
