"""The command cannot enter production without exact source and review pins."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_expiry_cases as cases
import txn_expiry_plan as plan
import txn_sandbox_cli as cli


def test_closure_path_matches_the_tracked_case_sensitive_name():
    assert cli.CLOSURE.name == "FS-TRANSACTION.json"
    assert cli.CLOSURE.is_file()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def packet(baseline, envelope, *, source="b" * 40, runner="c" * 64):
    return {
        "schemaVersion": 1,
        "packetId": "fs-transaction-13-a",
        "project": "fireemu-oracle-sbx",
        "database": "(default)",
        "recordings": 2,
        "requestsPerRecording": 96,
        "estimatedUsdPerRecording": 0.05,
        "sourceCommit": source,
        "runnerSha256": runner,
        "closureSha256": "d" * 64,
        "casesDigest": cases.cases_digest(),
        "planSourceDigest": plan.source_digest(),
        "baselineSha256": sha(baseline),
        "packetName": "expiry-retry-04",
        "envelopeId": "FS-TRANSACTION-expiry-retry-04-002",
        "envelopePath": "docs.local/reviews/transaction-envelope.md",
        "envelopeSha256": sha(envelope),
    }


def test_exact_packet_and_review_are_required_before_owner_gate(tmp_path):
    baseline = b'{"projectNumber":"redacted"}\n'
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_bytes(baseline)
    envelope_path = tmp_path / "envelope.md"
    envelope_path.write_text("# Approved scope\n")
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet(baseline, envelope_path.read_bytes())))
    pins = cli.load_packet(
        packet_path,
        sha(packet_path.read_bytes()),
        baseline_path,
        envelope_path,
        source_commit="b" * 40,
        runner_sha256="c" * 64,
        closure_sha256="d" * 64,
        packet_relative="docs.local/reviews/packet.json",
        envelope_relative="docs.local/reviews/transaction-envelope.md",
    )
    assert pins["requestsPerRecording"] == 96
    assert pins["packetSha256"] == sha(packet_path.read_bytes())
    review_path = tmp_path / "review.md"
    review_path.write_text(
        "APPROVE\n"
        f"packetSha256={pins['packetSha256']}\n"
        f"sourceCommit={pins['sourceCommit']}\n"
        f"runnerSha256={pins['runnerSha256']}\n"
        f"envelopeId={pins['envelopeId']}\n"
        "withinEnvelope=YES\n"
    )
    cli.verify_review(review_path, sha(review_path.read_bytes()), pins)
    with pytest.raises(ValueError, match="review"):
        cli.verify_review(review_path, "0" * 64, pins)


def test_packet_rejects_source_budget_and_baseline_drift(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_bytes(b"{}")
    envelope_path = tmp_path / "envelope.md"
    envelope_path.write_text("# Approved scope\n")
    packet_path = tmp_path / "packet.json"
    value = packet(baseline_path.read_bytes(), envelope_path.read_bytes())
    value["requestsPerRecording"] = 97
    packet_path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="request"):
        cli.load_packet(
            packet_path, sha(packet_path.read_bytes()), baseline_path, envelope_path,
            source_commit="b" * 40, runner_sha256="c" * 64,
            closure_sha256="d" * 64, packet_relative="docs.local/reviews/packet.json",
            envelope_relative="docs.local/reviews/transaction-envelope.md",
        )
    value["requestsPerRecording"] = 96
    packet_path.write_text(json.dumps(value))
    baseline_path.write_bytes(b'{"changed":true}')
    with pytest.raises(ValueError, match="baseline"):
        cli.load_packet(
            packet_path, sha(packet_path.read_bytes()), baseline_path, envelope_path,
            source_commit="b" * 40, runner_sha256="c" * 64,
            closure_sha256="d" * 64, packet_relative="docs.local/reviews/packet.json",
            envelope_relative="docs.local/reviews/transaction-envelope.md",
        )
