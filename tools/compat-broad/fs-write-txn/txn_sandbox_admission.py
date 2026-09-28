"""Fail-closed local admission, append-only ledger and project sandbox locks."""

from __future__ import annotations

import datetime as dt
import hashlib
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
DELEGATED_ACTOR = "Claude（委任。オーナーの裁量の委任 2026-09-28）"
DELEGATION_SCOPE_SHA256 = "d57a2ebb9efdcb798ff64afca7ed2bc15e28556822336342505e41fb822cad46"
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z")


def _instant(value):
    if not isinstance(value, str):
        raise ValueError("sandbox ledger timestamp is missing")
    if not _TIMESTAMP.fullmatch(value):
        raise ValueError("sandbox ledger timestamp is invalid")
    # Preserve microseconds while avoiding interpreter-specific fractional parsing.
    value = re.sub(r"\.([0-9]{1,9})(?=Z|[+-])", lambda match: "." + (match[1] + "000000")[:6], value)
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("sandbox ledger timestamp is invalid") from None
    if parsed.tzinfo is None:
        raise ValueError("sandbox ledger timestamp needs a timezone")
    return parsed


def _decision_entries(decisions):
    entries = []
    for line in decisions.splitlines():
        columns = [part.strip() for part in re.sub(r"^\s*-\s*", "", line).split("|")]
        if len(columns) == 5 and re.fullmatch(r"\d{4}-\d{2}-\d{2}", columns[0]):
            entries.append((columns, {part.strip() for part in columns[2].split(";")}))
    return entries


def _has_delegation(entries):
    """Require the exact owner authority text, including its budget and exclusions."""
    matching = []
    for columns, _tokens in entries:
        if columns[1] != "調整役への委任（本番の送信）":
            continue
        if _is_revocation(columns[2]):
            return False
        if (
            columns[0] == "2026-09-28"
            and columns[3] == "オーナー（このセッションへの直接の返答）"
            and columns[4] == "docs.local/instructions/owner-decisions.md"
            and hashlib.sha256(columns[2].encode()).hexdigest() == DELEGATION_SCOPE_SHA256
        ):
            matching.append(columns)
    return len(matching) == 1


def _authorized_actor(actor, entries):
    return actor.startswith("オーナー") or actor == DELEGATED_ACTOR and _has_delegation(entries)


def _is_revocation(decision):
    return re.search(r"(?:^|[;\s])(?:decision=)?REVOKED(?=[;\s]|$)", decision) is not None


def _revoked_packet(decision, packet_sha, envelope_id=None):
    """A scoped revocation cannot revoke another packet or fall through unrecognized."""
    if not _is_revocation(decision):
        return False
    packets = re.findall(r"packetSha256=([a-f0-9]{64})(?![a-f0-9])", decision)
    if "packetSha256=" in decision:
        return len(packets) != 1 or decision.count("packetSha256=") != 1 or packets[0] == packet_sha
    envelopes = re.findall(r"envelopeId=([A-Za-z0-9_-]+)", decision)
    if "envelopeId=" in decision and envelope_id is not None:
        return len(envelopes) != 1 or decision.count("envelopeId=") != 1 or envelopes[0] == envelope_id
    return True


def _owner_approval(decisions, pins):
    required = {
        f"packetSha256={pins['packetSha256']}",
        f"sourceCommit={pins['sourceCommit']}",
        f"runnerSha256={pins['runnerSha256']}",
        f"requestsPerRecording={pins['requestsPerRecording']}",
        f"estimatedUsdPerRecording={pins['estimatedUsdPerRecording']}",
        "recordings=2",
    }
    entries = _decision_entries(decisions)
    named_parent = f"{TASK} {pins.get('packetName', '')}".strip()
    for columns, _tokens in entries:
        if columns[1] not in (TASK, named_parent, f"{named_parent} envelope"):
            continue
        if _revoked_packet(columns[2], pins["packetSha256"], pins.get("envelopeId")):
            raise ValueError("this packet or envelope was revoked")
    direct = [
        columns for columns, tokens in entries
        if columns[1] in (TASK, named_parent)
        and columns[4] == pins["packetPath"]
        and required <= tokens
        and columns[3].startswith("オーナー")
    ]
    if len(direct) > 1:
        raise ValueError("exactly one owner approval row must pin this packet")
    envelope_id = pins.get("envelopeId")
    if not envelope_id:
        raise ValueError("exactly one owner approval row must pin this packet")
    envelope = [
        tokens for columns, tokens in entries
        if columns[1] == f"{named_parent} envelope"
        and columns[4] == pins.get("envelopePath")
        and _authorized_actor(columns[3], entries)
        and f"envelopeId={envelope_id}" in tokens
    ]
    delegated = [
        columns for columns, tokens in entries
        if columns[1] == named_parent
        and columns[4] == pins["packetPath"]
        and (columns[3] == "Claude（委任。枠の内の承認し直し）" or columns[3] == DELEGATED_ACTOR and _has_delegation(entries))
        and {"decision=APPROVE", f"envelopeId={envelope_id}"} <= tokens
        and required <= tokens
    ]
    if len(envelope) != 1 or len(direct) + len(delegated) != 1:
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
    return requests, reserve


def _terminal(row):
    outcome = row.get("outcome")
    return (
        outcome in ("recorded", "prepared", "legacy-recovery-reservation-actual-requests")
        or _recovered(row)
        or row.get("event") == "cleanup-verified" and row.get("sandboxAtBaseline") is True
        and type(row.get("requests")) is int and row["requests"] >= 0
        or outcome == "failed" and "requests" in row and (row["requests"] is None or type(row["requests"]) is int and row["requests"] == 0)
        or row.get("event") == "finished" and outcome == "presend-cancelled-no-send"
    )


def _recovered(row):
    outcome = row.get("outcome")
    return outcome == "recovered" or isinstance(outcome, str) and outcome.startswith("recovered-")


def _same_run(first, second):
    key = next((candidate for candidate in ("runDir", "runId") if first.get(candidate)), None)
    return key is not None and second.get(key) == first[key]


def _closed_attempt(open_row, key, later_rows):
    identity = open_row.get(key)
    if not identity:
        return False
    for index, ending in enumerate(later_rows):
        if ending.get(key) != identity or ending.get("taskId") != open_row.get("taskId"):
            continue
        if _terminal(ending):
            if not _recovered(ending) or not open_row.get("runDir") or _same_run(open_row, ending):
                return True
        if ending.get("outcome") not in ("failed", "bulk-delete-cancelled", "needs-recovery", "stopped-needs-review"):
            continue
        if not _same_run(ending, open_row):
            continue
        if any(
            recovered.get("taskId") == open_row.get("taskId")
            and _same_run(ending, recovered)
            and _recovered(recovered)
            for recovered in later_rows[index + 1 :]
        ):
            return True
    return False


def verify_send_gates(rows, now, decisions, pins):
    """Apply replay, idle, open-attempt and owner-decision gates before OAuth."""
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise ValueError("timezone-aware current time required")
    sandbox = [row for row in rows if row.get("project") == PROJECT]
    for row in sandbox:
        _instant(row.get("ts"))
    envelope_id = pins.get("envelopeId")
    if not isinstance(envelope_id, str) or not envelope_id:
        raise ValueError("owner envelope identity required")
    if any(row.get("envelopeId") == envelope_id for row in rows):
        raise ValueError("owner envelope was already used; retries are forbidden")
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
            if not _closed_attempt(row, key, sandbox[index + 1 :]):
                raise ValueError("the sandbox has an open attempt")
    task_rows = [row for row in sandbox if row.get("taskId") == "FS-TRANSACTION-SANDBOX"]
    if task_rows:
        # Equal timestamps use the later append as the latest responsibility state.
        most_recent = max(reversed(task_rows), key=lambda row: _instant(row["ts"]))
        if not _terminal(most_recent):
            raise ValueError("the FS-TRANSACTION sandbox attempt needs recovery")
    activity = [
        row
        for row in sandbox
        if row.get("event") not in ("note", "started")
        and not str(row.get("outcome", "")).startswith("reserved")
        and row.get("outcome") != "historical-unknown-hold"
    ]
    latest = max(activity, key=lambda row: _instant(row["ts"])) if activity else None
    if latest and now - _instant(latest["ts"]) < IDLE_GAP:
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
