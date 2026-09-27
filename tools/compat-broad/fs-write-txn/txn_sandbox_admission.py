"""Fail-closed local admission, append-only ledger and project sandbox locks."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import stat
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
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
    entries = []
    for line in decisions.splitlines():
        columns = [part.strip() for part in re.sub(r"^\s*-\s*", "", line).split("|")]
        if len(columns) != 5 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", columns[0]):
            continue
        tokens = {part.strip() for part in columns[2].split(";")}
        entries.append((columns, tokens))
    named_parent = f"{TASK} {pins.get('packetName', '')}".strip()
    if any(
        columns[1] in (named_parent, f"{named_parent} envelope")
        and ("REVOKED" in tokens or "decision=REVOKED" in tokens)
        for columns, tokens in entries
    ):
        raise ValueError("this packet or envelope was revoked")
    direct = [
        columns for columns, tokens in entries
        if columns[1] in (TASK, named_parent)
        and columns[4] == pins["packetPath"]
        and required <= tokens
        and columns[3].startswith("オーナー")
    ]
    if len(direct) == 1:
        return
    if len(direct) > 1:
        raise ValueError("exactly one owner approval row must pin this packet")
    envelope_id = pins.get("envelopeId")
    if not envelope_id:
        raise ValueError("exactly one owner approval row must pin this packet")
    envelope = [
        tokens for columns, tokens in entries
        if columns[1] == f"{named_parent} envelope"
        and columns[4] == pins.get("envelopePath")
        and columns[3].startswith("オーナー")
        and f"envelopeId={envelope_id}" in tokens
    ]
    delegated = [
        columns for columns, tokens in entries
        if columns[1] == named_parent
        and columns[4] == pins["packetPath"]
        and columns[3] == "Claude（委任。枠の内の承認し直し）"
        and {"decision=APPROVE", f"envelopeId={envelope_id}"} <= tokens
        and required <= tokens
    ]
    if len(envelope) != 1 or len(delegated) != 1:
        raise ValueError("owner envelope and delegated exact-version approval are required")
    tokens = envelope[0]
    expected = {
        "project=fireemu-oracle-sbx/(default)",
        "writes=owned-five-documents",
        "iamConfig=none",
        "retries=none",
        "onStop=needs-recovery-lock-held",
    }
    if not expected <= tokens:
        raise ValueError("owner envelope scope differs from the sandbox runner")
    values = dict(part.split("=", 1) for part in tokens if "=" in part)
    try:
        requests = int(values["maxRequests"])
        reserve = Decimal(values["reserveUsd"])
    except (KeyError, ValueError, InvalidOperation) as error:
        raise ValueError("owner envelope request or reserve bound is invalid") from None
    packet_requests = pins["requestsPerRecording"] * 2
    packet_reserve = Decimal(str(pins["estimatedUsdPerRecording"])) * 2
    if not (packet_requests <= requests <= 192 and packet_reserve <= reserve <= Decimal("0.10")):
        raise ValueError("owner envelope exceeds the runner or does not cover the packet")


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
        if opens:
            key = next(
                (candidate for candidate in ("attemptId", "runId", "runDir") if row.get(candidate)),
                None,
            )
            identity = row.get(key)
            if not identity or not any(
                later.get(key) == identity
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
    body_text: str | None = None


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


def acquire_project_locks(
    private_dir, projects, *, task_id, packet_id, source_commit, after_acquire=None,
):
    """Take project locks in sorted order, refusing a concurrent legacy runner."""
    private_dir = Path(private_dir)
    legacy = private_dir / "sandbox-ledger.jsonl.lock"
    if legacy.exists():
        raise FileExistsError("legacy shared sandbox lock is held")
    if (
        not isinstance(projects, (list, tuple))
        or not projects
        or len(set(projects)) != len(projects)
        or any(not isinstance(project, str) or not re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", project) for project in projects)
    ):
        raise ValueError("distinct bounded project IDs required")
    if not isinstance(task_id, str) or not task_id or not isinstance(packet_id, str) or not packet_id:
        raise ValueError("task and packet IDs required")
    if not isinstance(source_commit, str) or not re.fullmatch(r"[a-f0-9]{40}", source_commit):
        raise ValueError("signed source commit required")
    lock_dir = private_dir / "sandbox-locks"
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    if not lock_dir.is_dir() or lock_dir.is_symlink() or lock_dir.stat().st_mode & 0o077:
        raise ValueError("sandbox lock directory must be private")
    held = []
    try:
        for project in sorted(projects):
            path = lock_dir / f"{project}.lock"
            body = {
                "taskId": task_id,
                "packetId": packet_id,
                "sourceCommit": source_commit,
                "pid": os.getpid(),
                "acquiredAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            body_text = json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n"
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                if os.write(fd, body_text.encode()) != len(body_text.encode()):
                    raise OSError("short project lock write")
                os.fsync(fd)
                inode = os.fstat(fd).st_ino
            finally:
                os.close(fd)
            held.append(HeldLock(path, packet_id, os.getpid(), inode, body_text))
        if after_acquire is not None:
            after_acquire()
        if legacy.exists():
            raise FileExistsError("legacy shared sandbox lock appeared after acquisition")
        return held
    except Exception:
        if held:
            release_project_locks(held)
        raise


def release_project_locks(held):
    """Release only the exact inodes and bytes this process acquired."""
    for item in held:
        if (
            item.pid != os.getpid()
            or item.path.stat().st_ino != item.inode
            or item.path.read_text() != item.body_text
        ):
            raise ValueError("the project sandbox lock changed hands")
    for item in reversed(held):
        item.path.unlink()


def append_ledger(path, row):
    """Append one bounded JSON row and sync it before the next external action."""
    path = Path(path)
    encoded = (json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > 16_384:
        raise ValueError("ledger row exceeds private bounded format")
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        mode = os.fstat(fd).st_mode
        parent_mode = path.parent.stat().st_mode
        if not stat.S_ISREG(mode) or (
            mode & 0o077 and parent_mode & 0o077
        ):
            raise ValueError("sandbox ledger and its directory must protect private rows")
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
