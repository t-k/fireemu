"""The sandbox send gate and shared lock fail closed before any wire call."""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_sandbox_admission as admission

PACKET = "a" * 64
SOURCE = "b" * 40
RUNNER = "c" * 64
PATH = "docs.local/reviews/transaction-presend.md"
PINS = {
    "packetId": "fs-transaction-13-a",
    "packetSha256": PACKET,
    "sourceCommit": SOURCE,
    "runnerSha256": RUNNER,
    "packetPath": PATH,
    "requestsPerRecording": 96,
    "estimatedUsdPerRecording": 0.05,
    "packetName": "expiry-retry-04",
    "envelopeId": "FS-TRANSACTION-expiry-retry-04-001",
    "envelopePath": "docs.local/reviews/transaction-envelope.md",
}
NOW = datetime(2026, 9, 27, 16, 0, tzinfo=timezone.utc)
LAST = {
    "ts": "2026-09-27T15:00:00Z",
    "project": "fireemu-oracle-sbx",
    "taskId": "FS-DATA-WRITE-SANDBOX",
    "outcome": "recorded",
    "attemptId": "previous",
}
DIRECT = (
    "- 2026-09-27 | FS-TRANSACTION | "
    f"packetSha256={PACKET}; sourceCommit={SOURCE}; runnerSha256={RUNNER}; "
    "requestsPerRecording=96; estimatedUsdPerRecording=0.05; recordings=2 | "
    f"オーナー（直接の承認） | {PATH}\n"
)
ENVELOPE = (
    "- 2026-09-28 | FS-TRANSACTION expiry-retry-04 envelope | "
    "envelopeId=FS-TRANSACTION-expiry-retry-04-001; "
    "project=fireemu-oracle-sbx/(default); maxRequests=192; reserveUsd=0.10; "
    "writes=owned-five-documents; iamConfig=none; retries=none; "
    "onStop=needs-recovery-lock-held | オーナー（直接の承認） | "
    "docs.local/reviews/transaction-envelope.md\n"
)
DELEGATED = (
    "- 2026-09-28 | FS-TRANSACTION expiry-retry-04 | decision=APPROVE; "
    "envelopeId=FS-TRANSACTION-expiry-retry-04-001; "
    f"packetSha256={PACKET}; sourceCommit={SOURCE}; runnerSha256={RUNNER}; "
    "requestsPerRecording=96; estimatedUsdPerRecording=0.05; recordings=2 | "
    "Claude（委任。枠の内の承認し直し） | "
    f"{PATH}\n"
)
DECISION = ENVELOPE + DIRECT


def test_send_gate_requires_owner_line_idle_gap_and_no_open_attempt():
    assert admission.verify_send_gates([LAST], NOW, DECISION, PINS) == LAST["ts"]
    with pytest.raises(ValueError, match="30 minutes"):
        admission.verify_send_gates(
            [LAST], datetime(2026, 9, 27, 15, 20, tzinfo=timezone.utc), DECISION, PINS
        )
    with pytest.raises(ValueError, match="owner"):
        admission.verify_send_gates([LAST], NOW, "", PINS)
    open_attempt = {
        "ts": "2026-09-27T15:20:00Z",
        "project": "fireemu-oracle-sbx",
        "taskId": "OTHER",
        "outcome": "reserved",
        "attemptId": "unfinished",
    }
    with pytest.raises(ValueError, match="open attempt"):
        admission.verify_send_gates([LAST, open_attempt], NOW, DECISION, PINS)


def test_send_gate_rejects_packet_replay_and_duplicate_owner_line():
    replay = {
        "ts": "2026-09-27T15:30:00Z",
        "project": "fireemu-oracle-sbx",
        "packetId": PINS["packetId"],
        "outcome": "reserved",
        "attemptId": "replayed",
    }
    with pytest.raises(ValueError, match="already ran"):
        admission.verify_send_gates([LAST, replay], NOW, DECISION, PINS)
    with pytest.raises(ValueError, match="owner"):
        admission.verify_send_gates([LAST], NOW, DECISION + DECISION, PINS)


def test_envelope_is_single_use_even_with_a_new_packet_id():
    old = {
        **LAST,
        "ts": "2026-09-27T14:00:00Z",
        "taskId": "FS-TRANSACTION-SANDBOX",
        "packetId": "older-packet",
        "envelopeId": PINS["envelopeId"],
        "attemptId": "older-attempt",
        "outcome": "reserved",
    }
    done = {**old, "ts": "2026-09-27T15:00:00Z", "outcome": "recorded", "requests": 94}
    with pytest.raises(ValueError, match="envelope.*already used"):
        admission.verify_send_gates([old, done], NOW, DECISION, PINS)


@pytest.mark.parametrize("ending", ["needs-recovery", "stopped-needs-review", "failed"])
def test_nonterminal_outcome_does_not_close_an_attempt(ending):
    opened = {**LAST, "ts": "2026-09-27T14:00:00Z", "outcome": "reserved"}
    later = {**opened, "outcome": ending, "ts": "2026-09-27T15:00:00Z"}
    with pytest.raises(ValueError, match="open attempt"):
        admission.verify_send_gates([opened, later], NOW, DECISION, PINS)


def test_sandbox_idle_uses_maximum_timestamp_and_rejects_unparseable_rows():
    newer = {**LAST, "ts": "2026-09-27T15:45:00Z"}
    older = {**LAST, "ts": "2026-09-27T14:00:00Z"}
    with pytest.raises(ValueError, match="30 minutes"):
        admission.verify_send_gates([newer, older], NOW, DECISION, PINS)
    malformed = {**LAST, "event": "note", "ts": "not-an-instant"}
    with pytest.raises(ValueError, match="timestamp"):
        admission.verify_send_gates([older, malformed], NOW, DECISION, PINS)


def test_parent_task_revocation_also_refuses_a_direct_approval():
    revoked = (
        "- 2026-09-28 | FS-TRANSACTION | REVOKED | オーナー | "
        "docs.local/reviews/transaction-presend.md\n"
    )
    with pytest.raises(ValueError, match="revoked"):
        admission.verify_send_gates([LAST], NOW, DECISION + revoked, PINS)


def test_unkeyed_started_row_cannot_be_closed_by_unrelated_terminal():
    rows = [
        {"ts": "2026-09-27T14:00:00Z", "project": "fireemu-oracle-sbx", "event": "started"},
        {"ts": "2026-09-27T15:00:00Z", "project": "fireemu-oracle-sbx", "outcome": "recorded"},
    ]
    with pytest.raises(ValueError, match="open attempt"):
        admission.verify_send_gates(rows, NOW, DECISION, PINS)


def test_legacy_reservation_with_same_run_directory_has_a_terminal():
    rows = [
        {"ts": "2026-09-24T05:19:37Z", "project": "fireemu-oracle-sbx", "outcome": "reserved", "runDir": "/private/legacy-run"},
        {"ts": "2026-09-24T08:50:18Z", "project": "fireemu-oracle-sbx", "outcome": "legacy-recovery-reservation-actual-requests", "runDir": "/private/legacy-run"},
        LAST,
    ]
    assert admission.verify_send_gates(rows, NOW, DECISION, PINS) == LAST["ts"]


def test_owner_envelope_and_delegated_exact_version_are_accepted_together():
    assert admission.verify_send_gates([LAST], NOW, ENVELOPE + DELEGATED, PINS) == LAST["ts"]
    with pytest.raises(ValueError, match="owner"):
        admission.verify_send_gates([LAST], NOW, DELEGATED, PINS)
    with pytest.raises(ValueError, match="envelope"):
        admission.verify_send_gates(
            [LAST], NOW, ENVELOPE.replace("maxRequests=192", "maxRequests=193") + DELEGATED,
            PINS,
        )


def test_later_revocation_refuses_direct_and_envelope_paths():
    revoked = (
        "- 2026-09-28 | FS-TRANSACTION expiry-retry-04 | REVOKED; "
        "envelopeId=FS-TRANSACTION-expiry-retry-04-001 | オーナー | "
        "docs.local/reviews/transaction-envelope.md\n"
    )
    for decisions in (DECISION + revoked, ENVELOPE + DELEGATED + revoked):
        with pytest.raises(ValueError, match="revoked"):
            admission.verify_send_gates([LAST], NOW, decisions, PINS)


def test_shared_lock_is_exclusive_and_checks_ownership_before_release(tmp_path):
    path = tmp_path / "sandbox-ledger.jsonl.lock"
    held = admission.acquire_shared_lock(path, PINS["packetId"])
    assert json.loads(path.read_text())["pid"] == os.getpid()
    with pytest.raises(FileExistsError):
        admission.acquire_shared_lock(path, "another-packet")
    path.write_text(json.dumps({"packetId": "changed", "pid": os.getpid()}))
    with pytest.raises(ValueError, match="changed hands"):
        admission.release_shared_lock(held)
    assert path.exists()
    path.write_text(json.dumps({"packetId": PINS["packetId"], "pid": os.getpid()}))
    admission.release_shared_lock(held)
    assert not path.exists()


def test_ledger_append_is_private_and_one_json_object_per_line(tmp_path):
    path = tmp_path / "sandbox-ledger.jsonl"
    admission.append_ledger(path, {"outcome": "reserved", "requests": 0})
    admission.append_ledger(path, {"outcome": "recorded", "requests": 73})
    assert [json.loads(line)["outcome"] for line in path.read_text().splitlines()] == [
        "reserved", "recorded"
    ]
    assert path.stat().st_mode & 0o777 == 0o600


def test_existing_shared_ledger_is_admitted_inside_private_run_directory(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "sandbox-ledger.jsonl"
    path.write_text(json.dumps(LAST) + "\n")
    path.chmod(0o644)
    admission.append_ledger(path, {"outcome": "recorded", "requests": 70})
    assert len(path.read_text().splitlines()) == 2


def project_locks(directory, projects, **kwargs):
    return admission.acquire_project_locks(
        directory, projects, task_id="FS-TRANSACTION-SANDBOX",
        packet_id=PINS["packetId"], source_commit=SOURCE, **kwargs,
    )


def test_project_lock_blocks_same_project_but_allows_another(tmp_path):
    first = project_locks(tmp_path, ["fireemu-oracle-sbx"])
    path = tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock"
    body = json.loads(path.read_text())
    assert set(body) == {"taskId", "packetId", "sourceCommit", "pid", "acquiredAt"}
    assert (tmp_path / "sandbox-locks").stat().st_mode & 0o777 == 0o700
    with pytest.raises(FileExistsError):
        project_locks(tmp_path, ["fireemu-oracle-sbx"])
    other = project_locks(tmp_path, ["fireemu-oracle-query"])
    admission.release_project_locks(other)
    assert path.exists()
    admission.release_project_locks(first)
    assert not path.exists()


def test_legacy_shared_lock_blocks_before_and_after_acquisition(tmp_path):
    legacy = tmp_path / "sandbox-ledger.jsonl.lock"
    legacy.write_text("old")
    with pytest.raises(FileExistsError, match="legacy"):
        project_locks(tmp_path, ["fireemu-oracle-sbx"])
    assert not (tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists()
    legacy.unlink()

    def appear():
        legacy.write_text("old")

    with pytest.raises(FileExistsError, match="legacy"):
        project_locks(tmp_path, ["fireemu-oracle-sbx"], after_acquire=appear)
    assert not (tmp_path / "sandbox-locks/fireemu-oracle-sbx.lock").exists()


def test_multiple_project_locks_are_sorted_and_partial_failure_releases_only_ours(tmp_path):
    held = project_locks(tmp_path, ["fireemu-oracle-query", "fireemu-oracle-idp"])
    assert [item.path.name for item in held] == [
        "fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"
    ]
    admission.release_project_locks(held)
    foreign = project_locks(tmp_path, ["fireemu-oracle-query"])
    with pytest.raises(FileExistsError):
        project_locks(tmp_path, ["fireemu-oracle-query", "fireemu-oracle-idp"])
    assert not (tmp_path / "sandbox-locks/fireemu-oracle-idp.lock").exists()
    assert (tmp_path / "sandbox-locks/fireemu-oracle-query.lock").exists()
    admission.release_project_locks(foreign)


def test_releasing_a_changed_project_lock_refuses_to_remove_it(tmp_path):
    held = project_locks(tmp_path, ["fireemu-oracle-sbx"])
    path = held[0].path
    path.write_text('{"foreign":true}\n')
    with pytest.raises(ValueError, match="changed hands"):
        admission.release_project_locks(held)
    assert path.exists()
