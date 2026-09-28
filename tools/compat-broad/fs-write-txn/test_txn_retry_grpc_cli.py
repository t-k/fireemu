"""Exact packet/review/GO pins are checked before credential access."""

import copy
import hashlib
import json

import pytest

import txn_retry_grpc_cli as cli


@pytest.fixture
def packet(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, 'verify_runtime', lambda _runtime: None)
    baseline = tmp_path / 'baseline.json'; baseline.write_text('{}\n')
    envelope = tmp_path / 'envelope.md'; envelope.write_text('scope proposal\n')
    value = cli.packet_value(source_commit='b' * 40, runtime={'reviewed': True}, baseline_sha256=cli.sha(baseline.read_bytes()), envelope_sha256=cli.sha(envelope.read_bytes()), packet_id='fs-transaction-p09-unit', envelope_relative='docs.local/reviews/p09-envelope.md')
    path = tmp_path / 'packet.json'
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    def load():
        return cli.load_packet(path, cli.sha(path.read_bytes()), baseline, envelope, source_commit='b' * 40, packet_relative='docs.local/reviews/p09-unit.json', envelope_relative=value['envelopePath'])
    return path, baseline, envelope, value, load


def test_fresh_scope_and_caps_are_exact(packet):
    _path, _baseline, _envelope, _value, load = packet
    pins = load()
    assert pins['requestsPerRecording'] == 48
    assert pins['packetName'] == 'p09-grpc-retry'
    assert pins['estimatedUsdPerRecording'] == 0.01


@pytest.mark.parametrize('field,changed', [('extra', True), ('requestsPerRecording', 49), ('recordings', True), ('packetName', 'expiry-retry-04'), ('envelopeId', 'FS-TRANSACTION-expiry-retry-04-003'), ('project', 'fireemu-oracle-idp'), ('runnerSha256', '0' * 64), ('sourceCommit', 'c' * 40), ('closureSha256', '0' * 64), ('corpusDigest', '0' * 64), ('planSourceDigest', '0' * 64)])
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
