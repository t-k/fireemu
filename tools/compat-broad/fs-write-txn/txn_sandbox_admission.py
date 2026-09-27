"""Fail-closed local admission, append-only ledger and shared sandbox lock."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

PROJECT = "fireemu-oracle-sbx"
TASK = "FS-TRANSACTION"
IDLE_GAP = dt.timedelta(minutes=30)


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("sandbox ledger timestamp is missing")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("sandbox ledger timestamp needs a timezone")
    return parsed


def _owner_approval(decisions, pins):
    required = {
        f"packetSha256={pins['packetSha256']}",
        f"sourceCommit={pins['sourceCommit']}",
        f"runnerSha256={pins['runnerSha256']}",
        f"requestsPerRecording={pins['requestsPerRecording']}",
        f"estimatedUsdPerRecording={pins['estimatedUsdPerRecording']}",
        "recordings=2",
    }
    matches = []
    for line in decisions.splitlines():
        columns = [part.strip() for part in re.sub(r"^\s*-\s*", "", line).split("|")]
        if len(columns) != 5 or columns[1] != TASK or columns[4] != pins["packetPath"]:
            continue
        tokens = {part.strip() for part in columns[2].split(";")}
        if not required <= tokens:
            continue
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", columns[0]):
            continue
        if "オーナー" not in columns[3]:
            continue
        matches.append(line)
    if len(matches) != 1:
        raise ValueError("exactly one owner approval row must pin this packet")


def verify_send_gates(rows, now, decisions, pins):
    """Apply replay, idle, open-attempt and owner-decision gates before OAuth."""
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise ValueError("timezone-aware current time required")
    sandbox = [row for row in rows if row.get("project") == PROJECT]
    if any(
        row.get("packetId") == pins["packetId"]
        and row.get("outcome") == "reserved"
        for row in rows
    ):
        raise ValueError("this packet already ran; a new packet and owner decision are required")
    for index, row in enumerate(sandbox):
        opens = row.get("outcome") == "reserved" or row.get("event") == "started"
        if opens and not any(
            later.get("attemptId") == row.get("attemptId")
            and later.get("outcome") != "reserved"
            and later.get("event") != "started"
            for later in sandbox[index + 1 :]
        ):
            raise ValueError("the sandbox has an open attempt")
    activity = [
        row
        for row in sandbox
        if row.get("event") not in ("note", "started")
        and not str(row.get("outcome", "")).startswith("reserved")
        and row.get("outcome") != "historical-unknown-hold"
    ]
    latest = activity[-1] if activity else None
    if latest and now - _instant(latest.get("ts")) < IDLE_GAP:
        raise ValueError("the sandbox must be idle for 30 minutes after its last activity")
    _owner_approval(decisions, pins)
    return latest.get("ts") if latest else None


@dataclass(frozen=True)
class HeldLock:
    path: Path
    packet_id: str
    pid: int
    inode: int


def acquire_shared_lock(path, packet_id):
    """Create the exact shared `<ledger>.lock` file with O_EXCL."""
    path = Path(path)
    if not isinstance(packet_id, str) or not packet_id:
        raise ValueError("packet ID required")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, (json.dumps({"packetId": packet_id, "pid": os.getpid()}) + "\n").encode())
        os.fsync(fd)
        inode = os.fstat(fd).st_ino
    finally:
        os.close(fd)
    return HeldLock(path, packet_id, os.getpid(), inode)


def release_shared_lock(held):
    if held.path.stat().st_ino != held.inode:
        raise ValueError("the shared ledger lock changed hands")
    owner = json.loads(held.path.read_text())
    if owner != {"packetId": held.packet_id, "pid": held.pid} or held.pid != os.getpid():
        raise ValueError("the shared ledger lock changed hands")
    held.path.unlink()


def append_ledger(path, row):
    """Append one bounded JSON row and sync it before the next external action."""
    path = Path(path)
    encoded = (json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > 16_384:
        raise ValueError("ledger row exceeds private bounded format")
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        if os.fstat(fd).st_mode & 0o777 != 0o600:
            raise ValueError("sandbox ledger must have private permissions")
        if os.write(fd, encoded) != len(encoded):
            raise OSError("short ledger write")
        os.fsync(fd)
    finally:
        os.close(fd)


def read_ledger(path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]
