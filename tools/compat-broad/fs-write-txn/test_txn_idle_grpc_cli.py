"""Exact packet/review/GO pins are checked before credential access."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

import txn_idle_grpc_cli as cli


@pytest.fixture
def packet(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, 'verify_runtime', lambda _runtime: None)
    baseline = tmp_path / 'baseline.json'; baseline.write_text('{}\n')
    envelope = tmp_path / 'envelope.md'; envelope.write_text('scope proposal\n')
    value = cli.packet_value(source_commit='b' * 40, runtime={'reviewed': True}, baseline_sha256=cli.sha(baseline.read_bytes()), envelope_sha256=cli.sha(envelope.read_bytes()), packet_id='fs-transaction-p10-unit', envelope_relative='docs.local/reviews/p10-envelope.md')
    path = tmp_path / 'packet.json'
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    def load():
        return cli.load_packet(path, cli.sha(path.read_bytes()), baseline, envelope, source_commit='b' * 40, packet_relative='docs.local/reviews/p10-unit.json', envelope_relative=value['envelopePath'])
    return path, baseline, envelope, value, load


def test_fresh_scope_and_caps_are_exact(packet):
    _path, _baseline, _envelope, _value, load = packet
    pins = load()
    assert pins['requestsPerRecording'] == 48
    assert pins['packetName'] == 'p10-grpc-idle'
    assert pins['estimatedUsdPerRecording'] == 0.01
    value = packet[3]
    assert value['observationSeconds'] == 900 and value['recoverySeconds'] == 180
    assert value['timing'] == 'wall-clock' and value['timingSource'] == 'parent-wire-envelope'
    assert value['maxTokens'] == 6 and value['reserveUsd'] == 0.04


@pytest.mark.parametrize('field,changed', [('extra', True), ('requestsPerRecording', 49), ('recordings', True), ('packetName', 'expiry-retry-04'), ('envelopeId', 'FS-TRANSACTION-expiry-retry-04-003'), ('envelopeId', 'FS-TRANSACTION-p10-grpc-idle-001'), ('project', 'fireemu-oracle-idp'), ('runnerSha256', '0' * 64), ('sourceCommit', 'c' * 40), ('closureSha256', '0' * 64), ('corpusDigest', '0' * 64), ('planSourceDigest', '0' * 64)])
def test_changed_packet_refused_before_any_wire(packet, field, changed):
    path, _baseline, _envelope, value, load = packet
    path.write_text(json.dumps({**value, field: changed}))
    with pytest.raises(ValueError): load()


def test_baseline_or_envelope_bytes_cannot_change(packet):
    _path, baseline, envelope, _value, load = packet
    baseline.write_text('{"changed":true}')
    with pytest.raises(ValueError): load()
    baseline.write_text('{}\n'); envelope.write_text('changed')
    with pytest.raises(ValueError): load()


def test_exact_approve_without_must_or_should_and_explicit_go_are_required(packet, tmp_path):
    _path, _baseline, _envelope, _value, load = packet
    pins = load()
    review = tmp_path / 'review.txt'
    text = cli.review_template(pins)
    review.write_text(text)
    cli.verify_review(review, cli.sha(review.read_bytes()), pins)
    cli.verify_go(pins['packetSha256'], pins)
    for changed in [text.replace('APPROVE\n', 'APPROVE WITH CHANGES\n'), text.replace('Must=NONE', 'Must=CHANGES'), text + 'unreviewed-extra=YES\n']:
        review.write_text(changed)
        with pytest.raises(ValueError): cli.verify_review(review, cli.sha(review.read_bytes()), pins)
    with pytest.raises(ValueError): cli.verify_go('0' * 64, pins)


@pytest.mark.parametrize('initial', ['unreviewed-runtime', 'oversize'])
def test_initial_packet_snapshot_is_hash_checked_before_runtime_is_retained(packet, tmp_path, monkeypatch, initial):
    path, baseline, envelope, value, _load = packet
    private = tmp_path / 'docs.local/reviews'
    private.mkdir(parents=True)
    reviewed = private / 'packet.json'
    reviewed.write_bytes(path.read_bytes())
    (private / 'p10-envelope.md').write_bytes(envelope.read_bytes())
    digest = cli.sha(reviewed.read_bytes())
    unreviewed = json.dumps({**value, 'runtime': {'unreviewed': True}}).encode()
    if initial == 'oversize': unreviewed = b' ' * 65536 + reviewed.read_bytes()
    decoded = []
    loads = json.loads
    def observed_decode(raw, *args, **kwargs):
        if raw == unreviewed: decoded.append(True)
        return loads(raw, *args, **kwargs)
    monkeypatch.setattr(cli.json, 'loads', observed_decode)
    read_bytes = Path.read_bytes
    reads = 0
    def replaced_first_read(self):
        nonlocal reads
        if self == reviewed:
            reads += 1
            if reads == 1: return unreviewed
        return read_bytes(self)
    monkeypatch.setattr(Path, 'read_bytes', replaced_first_read)
    # Isolate packet admission; no credential, ledger, lock, or wire is accessed.
    monkeypatch.setattr(cli, '_git', lambda *_args: str(tmp_path / '.git'))
    monkeypatch.setattr(cli, '_private', lambda path, _root: Path(path))
    monkeypatch.setattr(cli, 'signed_source_commit', lambda: value['sourceCommit'])
    monkeypatch.setattr(cli, 'assert_clean_environment', lambda: None)
    monkeypatch.setattr(cli, 'verify_review', lambda *_args: None)
    invoked = []
    def record(**kwargs):
        invoked.append(True)
        kwargs['record_once'](0, 'a' * 32, 'b' * 32, tmp_path)
        return {}
    monkeypatch.setattr(cli, 'record_twice', record)
    monkeypatch.setattr(cli, 'run_once', lambda *_args, **kwargs: invoked.append(kwargs['runtime']))
    argv = ['record-production', '--packet', str(reviewed), '--packet-sha256', digest, '--baseline', str(baseline), '--review', str(tmp_path / 'review.txt'), '--review-sha256', 'a' * 64, '--go-packet-sha256', digest]
    with pytest.raises(ValueError, match='packet bytes differ'):
        cli.main(argv)
    assert invoked == []
    assert decoded == []


@pytest.mark.parametrize('changed_read', [1, 2])
def test_baseline_snapshot_cannot_differ_from_its_packet_pin(packet, tmp_path, monkeypatch, changed_read):
    path, baseline, envelope, value, _load = packet
    private = tmp_path / 'docs.local/reviews'
    private.mkdir(parents=True)
    reviewed = private / 'packet.json'
    reviewed.write_bytes(path.read_bytes())
    (private / 'p10-envelope.md').write_bytes(envelope.read_bytes())
    digest = cli.sha(reviewed.read_bytes())
    read_bytes = Path.read_bytes
    reads = 0
    def replaced_read(self):
        nonlocal reads
        if self == baseline:
            reads += 1
            if reads == changed_read: return b'{"unreviewed": true}'
        return read_bytes(self)
    monkeypatch.setattr(Path, 'read_bytes', replaced_read)
    monkeypatch.setattr(cli, '_git', lambda *_args: str(tmp_path / '.git'))
    monkeypatch.setattr(cli, '_private', lambda path, _root: Path(path))
    monkeypatch.setattr(cli, 'signed_source_commit', lambda: value['sourceCommit'])
    monkeypatch.setattr(cli, 'assert_clean_environment', lambda: None)
    monkeypatch.setattr(cli, 'verify_review', lambda *_args: None)
    invoked = []
    def run(*_args, **kwargs):
        kwargs['check']()
        invoked.append(kwargs['baseline'])
    def record(**kwargs):
        kwargs['record_once'](0, 'a' * 32, 'b' * 32, tmp_path)
        return {}
    monkeypatch.setattr(cli, 'record_twice', record)
    monkeypatch.setattr(cli, 'run_once', run)
    monkeypatch.setattr(cli, 'authorize', lambda *_args: None)
    monkeypatch.setattr(cli, 'remaining_task_budget', lambda *_args: 10)
    monkeypatch.setattr(cli, 'read_ledger', lambda *_args: [])
    (tmp_path / 'docs.local/instructions').mkdir()
    (tmp_path / 'docs.local/instructions/owner-decisions.md').write_text('local test only')
    argv = ['record-production', '--packet', str(reviewed), '--packet-sha256', digest, '--baseline', str(baseline), '--review', str(tmp_path / 'review.txt'), '--review-sha256', 'a' * 64, '--go-packet-sha256', digest]
    with pytest.raises(ValueError): cli.main(argv)
    assert invoked == []
