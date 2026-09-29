"""Fresh P09 scope, revocation, shared history and send-time authorization."""

from datetime import datetime, timezone

import pytest

from txn_retry_grpc_authority import authorize, verify_initial_gates
from test_txn_sandbox_runtime_and_wire_integration import AUTHORITY

PINS = {'packetName': 'p09-grpc-retry', 'packetId': 'fs-transaction-p09-test', 'packetSha256': 'a' * 64, 'sourceCommit': 'b' * 40, 'runnerSha256': 'c' * 64, 'packetPath': 'docs.local/reviews/p09-test.json', 'envelopeId': 'FS-TRANSACTION-p09-grpc-retry-001', 'envelopePath': 'docs.local/reviews/p09-envelope.md', 'requestsPerRecording': 48, 'estimatedUsdPerRecording': 0.01}
ACTOR = 'Claude（委任。オーナーの裁量の委任 2026-09-28）'
ENVELOPE = f'- 2026-09-28 | FS-TRANSACTION p09-grpc-retry envelope | envelopeId={PINS["envelopeId"]}; project=fireemu-oracle-sbx/(default); maxRequests=96; reserveUsd=0.04; writes=owned-one-document; iamConfig=none; retries=none; onStop=needs-recovery-lock-held; 根拠=2026-09-28 調整役への委任（本番の送信） | {ACTOR} | {PINS["envelopePath"]}\n'
APPROVE = f'- 2026-09-28 | FS-TRANSACTION p09-grpc-retry | decision=APPROVE; envelopeId={PINS["envelopeId"]}; packetSha256={PINS["packetSha256"]}; sourceCommit={PINS["sourceCommit"]}; runnerSha256={PINS["runnerSha256"]}; requestsPerRecording=48; estimatedUsdPerRecording=0.01; recordings=2 | {ACTOR} | {PINS["packetPath"]}\n'
DECISIONS = AUTHORITY + ENVELOPE + APPROVE
NOW = datetime(2026, 9, 28, 5, tzinfo=timezone.utc)
LAST = {'ts': '2026-09-28T04:00:00Z', 'project': 'fireemu-oracle-sbx', 'taskId': 'FS-TRANSACTION-SANDBOX', 'attemptId': 'prior', 'outcome': 'recorded', 'estimatedUsd': 0.05}


def test_delegation_i_with_exact_foundation_envelope_and_version_is_accepted():
    assert authorize(DECISIONS, PINS) == (96, 0.04)
    assert verify_initial_gates([LAST], NOW, DECISIONS, PINS) == LAST['ts']


@pytest.mark.parametrize('old,new', [('owned-one-document', 'owned-five-documents'), ('maxRequests=96', 'maxRequests=95'), ('reserveUsd=0.04', 'reserveUsd=10.01'), ('decision=APPROVE;', ''), ('recordings=2', 'recordings=1'), ('根拠=2026-09-28 調整役への委任（本番の送信）', '根拠=unknown')])
def test_scope_and_explicit_approval_are_not_inferred(old, new):
    with pytest.raises(ValueError): authorize(DECISIONS.replace(old, new), PINS)


def test_missing_or_altered_actual_owner_delegation_fails():
    for text in [ENVELOPE + APPROVE, DECISIONS.replace('費用が10ドル以内', '費用が20ドル以内'), DECISIONS + APPROVE]:
        with pytest.raises(ValueError): authorize(text, PINS)


def test_revocation_is_rechecked_for_dispatch_and_cannot_be_undone_by_later_approve():
    revoked = DECISIONS + f'- 2026-09-28 | FS-TRANSACTION p09-grpc-retry | decision=REVOKED; envelopeId={PINS["envelopeId"]} | オーナー（直接） | {PINS["packetPath"]}\n' + APPROVE
    with pytest.raises(ValueError): authorize(revoked, PINS)


def test_shared_history_idle_replay_and_open_attempts_fail_closed():
    for rows in [[{**LAST, 'ts': '2026-09-28T04:45:00Z'}], [LAST, {**LAST, 'outcome': 'reserved', 'attemptId': 'open'}], [{**LAST, 'envelopeId': PINS['envelopeId']}], [{**LAST, 'packetId': PINS['packetId'], 'outcome': 'reserved'}], [{**LAST, 'estimatedUsd': 9.99}]]:
        with pytest.raises(ValueError): verify_initial_gates(rows, NOW, DECISIONS, PINS)


def test_project_isolation_does_not_ignore_equal_timestamp_open_sbx_attempt():
    opened = {**LAST, 'outcome': 'reserved'}
    closed = {**LAST, 'outcome': 'recorded'}
    assert verify_initial_gates([opened, closed, {**opened, 'project': 'fireemu-oracle-idp'}], NOW, DECISIONS, PINS)
    with pytest.raises(ValueError): verify_initial_gates([closed, opened], NOW, DECISIONS, PINS)


def test_explicit_owner_version_is_the_documented_alternative_to_an_envelope():
    direct = APPROVE.replace(ACTOR, 'オーナー（直接）')
    assert authorize(direct, PINS) == (96, 0.02)
    revoked = f'- 2026-09-28 | FS-TRANSACTION | decision=REVOKED; envelopeId={PINS["envelopeId"]} | オーナー（直接） | {PINS["packetPath"]}\n'
    with pytest.raises(ValueError): authorize(direct + revoked, PINS)


def test_owner_envelope_and_documented_within_envelope_actor_are_accepted():
    owner_envelope = ENVELOPE.replace(ACTOR, 'オーナー（直接）')
    within_envelope = APPROVE.replace(ACTOR, 'Claude（委任。枠の内の承認し直し）')
    assert authorize(AUTHORITY + owner_envelope + within_envelope, PINS) == (96, 0.04)
    with pytest.raises(ValueError): authorize(within_envelope, PINS)
