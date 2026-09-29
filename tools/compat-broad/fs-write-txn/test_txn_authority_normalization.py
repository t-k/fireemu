"""Coordinator cancellation table, raw foundations and authority caller controls."""

import unicodedata

import pytest

import txn_sandbox_admission as shared
import test_txn_boundary_grpc_authority as boundary
import test_txn_idle_grpc_authority as idle
import test_txn_retry_grpc_authority as retry
import test_txn_sandbox_admission as legacy
from test_txn_delegation_fixtures import AUTHORITY, ENVELOPE_AUTHORITY, SENDING_AUTHORITY


def row(topic, decision, columns=5):
    parts = ['- 2026-09-29', topic, decision, 'オーナー（直接）', 'synthetic.md']
    return ' | '.join(parts[:columns]) + '\n'


def fullwidth(value):
    return ''.join(chr(ord(char) + 0xFEE0) if '!' <= char <= '~' else '\u3000' if char == ' ' else char for char in value)


PINS = boundary.PINS
OTHER = 'd' * 64
REVIEW_REFUSALS = [
    ('1b', row('調整役への委任（本番の送信）', 'REVOKED', 4)),
    ('1c', row('調整役への委任(本番の送信)', 'REVOKED')),
    ('2a', row('調整役への委任（枠の承認）', 'REVOKED')),
    ('2b', row('調整役への委任（枠の承認）', 'REVOKED', 4)),
    ('3a', row('FS-TRANSACTION p10-grpc-boundary', 'decision=revoked; packetSha256=' + PINS['packetSha256'])),
    ('3b', row('FS-TRANSACTION p10-grpc-boundary', 'decision=revoked')),
    ('3c', row('FS-TRANSACTION p10-grpc-boundary', 'Revoked')),
    ('5a', row('fs-transaction p10-grpc-boundary', 'REVOKED')),
    ('5b', row(fullwidth('FS-TRANSACTION ') + 'p10-grpc-boundary', 'REVOKED')),
    ('5c', row(fullwidth('FS') + '-' + fullwidth('TRANSACTION') + ' p10-grpc-boundary', 'REVOKED')),
    ('6a', row('FS-TRANSACTION p10-grpc-boundary', 'ＲＥＶＯＫＥＤ packetSha256=' + PINS['packetSha256'])),
    ('6b', row('FS-TRANSACTION p10-grpc-boundary', 'ＲＥＶＯＫＥＤ')),
    ('8b', row('AUTH-OTHER', 'REVOKED sourceCommit=' + PINS['sourceCommit'])),
    ('9a', row('FS-TRANSACTION p10-grpc-boundary', 'REVOKED envelopeId=' + PINS['envelopeId'].lower())),
    ('9b', row('FS-TRANSACTION p10-grpc-boundary envelope', 'REVOKED envelopeId=' + PINS['envelopeId'].lower())),
]


@pytest.mark.parametrize('case,cancellation', REVIEW_REFUSALS, ids=[case for case, _ in REVIEW_REFUSALS])
def test_coordinator_must_table_refuses_raw_cancellation(case, cancellation):
    with pytest.raises(ValueError, match='revoked|REVOKED'):
        boundary.authorize(boundary.DECISIONS + cancellation, PINS)


def test_coordinator_14a_requires_envelope_approval_foundation():
    with pytest.raises(ValueError):
        boundary.authorize(SENDING_AUTHORITY + boundary.ENVELOPE + boundary.APPROVE, PINS)


def test_coordinator_15c_within_actor_does_not_bypass_revoked_owner_delegation():
    decisions = AUTHORITY + boundary.ENVELOPE.replace(boundary.ACTOR, 'オーナー（直接）') + boundary.APPROVE.replace(boundary.ACTOR, 'Claude（委任。枠の内の承認し直し）')
    with pytest.raises(ValueError):
        boundary.authorize(decisions + row('調整役への委任（本番の送信）', 'REVOKED'), PINS)


@pytest.mark.parametrize('case,decisions', [
    ('11b', boundary.DECISIONS + row('FS-TRANSACTION p10-grpc-boundary', 'REVOKED packetSha256=' + OTHER, 4)),
    ('12a', boundary.DECISIONS + row('FS-TRANSACTION p10-grpc-boundary', 'REVOKED packetSha256=' + OTHER)),
    ('15a', AUTHORITY + boundary.ENVELOPE + boundary.APPROVE.replace(boundary.ACTOR, 'Claude（委任。枠の内の承認し直し）')),
    ('16d', boundary.DECISIONS.replace('reserveUsd=0.04', 'reserveUsd=0.040')),
])
def test_coordinator_positive_controls_remain_accepted(case, decisions):
    assert boundary.authorize(decisions, PINS) == (96, 0.04)


def authority_fixture(kind, actor):
    if kind == 'legacy':
        approval = legacy.DELEGATED.replace('Claude（委任。枠の内の承認し直し）', actor)
        return shared._owner_approval, AUTHORITY + legacy.ENVELOPE + approval, legacy.PINS
    module = {'retry': retry, 'idle': idle, 'boundary': boundary}[kind]
    envelope = module.ENVELOPE.replace(module.ACTOR, 'オーナー（直接）')
    return module.authorize, AUTHORITY + envelope + module.APPROVE.replace(module.ACTOR, actor), module.PINS


@pytest.mark.parametrize('kind', ['legacy', 'retry', 'idle', 'boundary'])
@pytest.mark.parametrize('actor', [boundary.ACTOR, 'Claude（委任。枠の内の承認し直し）'])
@pytest.mark.parametrize('foundation', [SENDING_AUTHORITY, ENVELOPE_AUTHORITY], ids=['365', '395'])
def test_every_delegated_actor_requires_both_raw_owner_foundations(kind, actor, foundation):
    function, decisions, pins = authority_fixture(kind, actor)
    function(decisions, pins)
    with pytest.raises(ValueError):
        function(decisions.replace(foundation, ''), pins)


@pytest.mark.parametrize('kind', ['legacy', 'retry', 'idle', 'boundary'])
@pytest.mark.parametrize('topic', ['調整役への委任（本番の送信）', '調整役への委任(枠の承認)', '調整役への委任（訂正）'])
@pytest.mark.parametrize('columns', [3, 4, 5])
def test_all_callers_refuse_raw_delegation_prefix_cancellation(kind, topic, columns):
    function, decisions, pins = authority_fixture(kind, 'Claude（委任。枠の内の承認し直し）')
    with pytest.raises(ValueError, match='revoked|REVOKED'):
        function(decisions + row(topic, 'Ｒｅｖｏｋｅｄ', columns), pins)


@pytest.mark.parametrize('kind', ['legacy', 'retry', 'idle', 'boundary'])
def test_delegation_cancellation_in_non_topic_field_cannot_be_other_packet_scoped(kind):
    function, decisions, pins = authority_fixture(kind, boundary.ACTOR)
    with pytest.raises(ValueError, match='revoked|REVOKED'):
        function(decisions + row('AUTH-OTHER', 'revoked; packetSha256=' + OTHER + '; 根拠=調整役への委任(枠の承認)'), pins)


@pytest.mark.parametrize('key', ['packetSha256', 'sourceCommit', 'runnerSha256', 'envelopeId'])
@pytest.mark.parametrize('transform', [str.lower, str.upper, fullwidth])
def test_all_current_identities_are_normalized_on_unrelated_raw_rows(key, transform):
    with pytest.raises(ValueError, match='revoked|REVOKED'):
        shared.reject_revocations(row('AUTH-OTHER', 'Revoked; ' + transform(key + '=' + PINS[key]), 4), PINS)


@pytest.mark.parametrize('size', [8, 16, 39, 40])
def test_bounded_source_commit_prefixes_are_current_identity(size):
    with pytest.raises(ValueError, match='revoked|REVOKED'):
        shared.reject_revocations(row('AUTH-OTHER', 'ＲＥＶＯＫＥＤ; SOURCECOMMIT=' + PINS['sourceCommit'][:size].upper()), PINS)


@pytest.mark.parametrize('kind', ['legacy', 'retry', 'idle', 'boundary'])
@pytest.mark.parametrize('punctuation', ['.', '…', '。', ']', '}', "'", '"'])
def test_shortened_source_followed_by_punctuation_revokes_before_approval(kind, punctuation):
    function, decisions, pins = authority_fixture(kind, boundary.ACTOR)
    cancellation = row('AUTH-OTHER', 'REVOKED; sourceCommit=' + pins['sourceCommit'][:8] + punctuation)
    with pytest.raises(ValueError, match='revoked'):
        function(decisions + cancellation, pins)


@pytest.mark.parametrize('reference', ['b' * 7, 'b' * 41, 'b' * 8 + 'z', 'd' * 8])
def test_short_or_nonhex_other_source_references_do_not_become_current_identity(reference):
    shared.reject_revocations(row('AUTH-OTHER', 'REVOKED; sourceCommit=' + reference), PINS)


@pytest.mark.parametrize('scope', ['PACKETSHA256=' + OTHER, 'EnVeLoPeId=FS-TRANSACTION-other-001', fullwidth('closurePacketSha256=' + OTHER)])
def test_normalized_well_formed_other_scope_controls(scope):
    shared.reject_revocations(row('ｆｓ－ｔｒａｎｓａｃｔｉｏｎ correction', 'ＲＥＶＯＫＥＤ; ' + scope), PINS)


@pytest.mark.parametrize('topic', ['fs-transaction correction', 'ＦＳ－ＴＲＡＮＳＡＣＴＩＯＮ correction'])
@pytest.mark.parametrize('columns', [3, 4, 5])
def test_normalized_task_constant_and_raw_row_scope_refuse_global_cancellation(topic, columns):
    with pytest.raises(ValueError, match='revoked'):
        shared.reject_revocations(row(topic, 'revoked', columns), PINS)


def test_current_task_reference_outside_topic_still_refuses_unscoped_cancellation():
    with pytest.raises(ValueError, match='revoked'):
        shared.reject_revocations(row('AUTH-OTHER', 'revoked; target=ＦＳ－ＴＲＡＮＳＡＣＴＩＯＮ'), PINS)


@pytest.mark.parametrize('foundation', [SENDING_AUTHORITY, ENVELOPE_AUTHORITY], ids=['365', '395'])
def test_foundation_hashes_remain_raw_and_duplicate_approvals_fail(foundation):
    normalized = unicodedata.normalize('NFKC', foundation)
    assert normalized != foundation
    for value in (boundary.DECISIONS.replace(foundation, normalized), boundary.DECISIONS + foundation):
        with pytest.raises(ValueError):
            boundary.authorize(value, PINS)


def test_both_sides_of_positive_b_authority_comparisons_share_normalization():
    sending = SENDING_AUTHORITY.split(' | ')
    envelope = ENVELOPE_AUTHORITY.split(' | ')
    for parts in (sending, envelope):
        parts[1] = unicodedata.normalize('NFKC', parts[1])
        parts[3] = unicodedata.normalize('NFKC', parts[3])
    foundation = ' | '.join(sending) + ' | '.join(envelope)
    rows = []
    for original in (boundary.ENVELOPE, boundary.APPROVE):
        parts = original.split(' | ')
        for index in (1, 2, 3):
            parts[index] = fullwidth(parts[index])
        rows.append(' | '.join(parts))
    # Dates, column separators and resource paths retain their strict syntax.
    assert boundary.authorize(foundation + ''.join(rows), PINS) == (96, 0.04)


def test_nfkc_casefold_duplicate_b_authority_keys_are_rejected():
    altered = boundary.DECISIONS.replace('maxRequests=96;', 'maxRequests=96; ＭＡＸＲＥＱＵＥＳＴＳ=96;')
    with pytest.raises(ValueError, match='duplicate'):
        boundary.authorize(altered, PINS)


def test_existing_two_argument_actor_caller_retains_unparsed_cancellation():
    actor = boundary.ACTOR
    assert shared._authorized_actor(actor, shared._decision_entries(AUTHORITY))
    for columns in (3, 4, 5):
        decisions = AUTHORITY + row('調整役への委任(枠の承認)', 'revoked', columns)
        assert not shared._authorized_actor(actor, shared._decision_entries(decisions))
    assert not shared._authorized_actor(actor, list(shared._decision_entries(AUTHORITY)))
    assert not shared._authorized_actor('Claude（委任。枠の内の承認し直し）', shared._decision_entries(AUTHORITY))
    extra = row('調整役への委任(枠の承認)', 'revoked').rstrip() + ' | extra\n'
    assert not shared._authorized_actor(actor, shared._decision_entries(AUTHORITY + extra))
    assert shared._authorized_actor('オーナー（直接）', [])


def test_delegation_rejects_mismatched_raw_snapshot_and_parsed_entries():
    entries = shared._decision_entries(AUTHORITY)
    entries.pop()
    assert not shared._authorized_actor(boundary.ACTOR, entries)
    assert not shared._authorized_actor(boundary.ACTOR, shared._decision_entries(AUTHORITY), SENDING_AUTHORITY)
    cancelled = AUTHORITY + row('調整役への委任(枠の承認)', 'revoked', 3)
    assert not shared._authorized_actor(boundary.ACTOR, shared._decision_entries(cancelled), AUTHORITY)
