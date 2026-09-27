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
    "requestsPerRecording": 95,
    "estimatedUsdPerRecording": 0.05,
}
NOW = datetime(2026, 9, 27, 16, 0, tzinfo=timezone.utc)
LAST = {
    "ts": "2026-09-27T15:00:00Z",
    "project": "fireemu-oracle-sbx",
    "taskId": "FS-DATA-WRITE-SANDBOX",
    "outcome": "recorded",
    "attemptId": "previous",
}
DECISION = (
    "- 2026-09-27 | FS-TRANSACTION | "
    f"packetSha256={PACKET}; sourceCommit={SOURCE}; runnerSha256={RUNNER}; "
    "requestsPerRecording=95; estimatedUsdPerRecording=0.05; recordings=2 | "
    f"オーナー（直接の承認） | {PATH}\n"
)


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
