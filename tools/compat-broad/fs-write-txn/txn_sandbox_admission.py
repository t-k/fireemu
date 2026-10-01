"""Fail-closed local admission, append-only ledger and project sandbox locks."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

PROJECT = "fireemu-oracle-sbx"
TASK = "FS-TRANSACTION"
IDLE_GAP = dt.timedelta(minutes=30)
DELEGATED_ACTOR = "Claude（委任。オーナーの裁量の委任 2026-09-28）"
WITHIN_ENVELOPE_ACTOR = "Claude（委任。枠の内の承認し直し）"
DELEGATION_TOPIC_PREFIX = "調整役への委任"
DELEGATION_SCOPE_SHA256 = "d57a2ebb9efdcb798ff64afca7ed2bc15e28556822336342505e41fb822cad46"
ENVELOPE_DELEGATION_SCOPE_SHA256 = "9027f967c3479e7c43f2390ccc0bcddf3a7dccaa2b6164e2f5025a4f3c6516a5"
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


class _DecisionEntries(list):
    """Retain unparsed rows for existing actor callers without granting authority."""

    def __init__(self, decisions):
        super().__init__()
        self._raw_decisions = decisions

    @property
    def raw_decisions(self):
        return self._raw_decisions


def _decision_entries(decisions):
    entries = _DecisionEntries(decisions)
    for line in decisions.splitlines():
        columns = [part.strip() for part in re.sub(r"^\s*-\s*", "", line).split("|")]
        if len(columns) == 5 and re.fullmatch(r"\d{4}-\d{2}-\d{2}", columns[0]):
            entries.append((columns, {part.strip() for part in columns[2].split(";")}))
    return entries


def normalize_authority(value):
    """Use the same comparison view for ledger fields and authority constants."""
    return unicodedata.normalize("NFKC", value).casefold()


def _has_delegation(entries, decisions):
    """Require both raw owner permissions, retaining their budget and exclusions."""
    snapshot = entries.raw_decisions if isinstance(entries, _DecisionEntries) else None
    decisions = decisions if decisions is not None else snapshot
    if decisions is None or snapshot is not None and snapshot != decisions or entries != _decision_entries(decisions):
        return False
    if any(
        normalize_authority(DELEGATION_TOPIC_PREFIX) in normalize_authority(line)
        and _is_revocation(line) for line in decisions.splitlines()
    ):
        return False
    foundations = (
        ("調整役への委任（本番の送信）", "オーナー（このセッションへの直接の返答）", "docs.local/instructions/owner-decisions.md", DELEGATION_SCOPE_SHA256),
        ("調整役への委任（枠の承認）", "オーナー（このセッションへの直接の返答「委任も (イ)で」）", "docs.local/instructions/2026-09-28-envelope-approval.md", ENVELOPE_DELEGATION_SCOPE_SHA256),
    )
    for topic, actor, path, scope_sha in foundations:
        matching = [columns for columns, _tokens in entries if
            normalize_authority(columns[1]) == normalize_authority(topic)
            and normalize_authority(columns[0]) == "2026-09-28"
            and normalize_authority(columns[3]) == normalize_authority(actor)
            and columns[4] == path
            and hashlib.sha256(columns[2].encode()).hexdigest() == scope_sha
        ]
        if len(matching) != 1:
            return False
    return True


def _delegated_actor(actor, entries, decisions, *, allow_within_envelope=False):
    recognized = normalize_authority(actor) == normalize_authority(DELEGATED_ACTOR)
    if allow_within_envelope:
        recognized = recognized or normalize_authority(actor) == normalize_authority(WITHIN_ENVELOPE_ACTOR)
    return recognized and _has_delegation(entries, decisions)


def _authorized_actor(actor, entries, decisions=None):
    return normalize_authority(actor).startswith(normalize_authority("オーナー")) or _delegated_actor(actor, entries, decisions)


def _is_revocation(decision):
    return re.search(r"(?<![a-z0-9_])revoked(?![a-z0-9_])", normalize_authority(decision)) is not None


def _revocation_scope(decision, keys, value_pattern):
    decision = normalize_authority(decision)
    keys = {normalize_authority(key) for key in keys}
    declared = 0
    values = []
    scope_keys = r"(?<![a-z0-9_-])(?:" + "|".join(map(normalize_authority, ("packetSha256", "closurePacketSha256", "envelopeId"))) + r")(?![a-z0-9_-])"
    consumed = 0
    for declaration in re.finditer(scope_keys, decision, re.IGNORECASE):
        if declaration.start() < consumed:
            continue
        value = re.match(r"\s*=\s*([^\s;|()（）:：,，]+)", decision[declaration.end():])
        if value is not None:
            # A scope value can itself contain a scope-key identifier.
            consumed = declaration.end() + value.end()
        if declaration.group() not in keys:
            continue
        declared += 1
        if value is not None and declaration.group() in keys:
            values.append(value.group(1))
    if declared == 0:
        return False, None
    if declared != 1 or len(values) != 1 or not re.fullmatch(value_pattern, values[0]):
        return True, None
    return True, values[0]


def _revoked_packet(decision, packet_sha, envelope_id=None):
    """A scoped revocation cannot revoke another packet or fall through unrecognized."""
    if not _is_revocation(decision):
        return False
    packet_sha = normalize_authority(packet_sha)
    envelope_id = normalize_authority(envelope_id) if envelope_id is not None else None
    packet_declared, packet = _revocation_scope(
        decision, ("packetSha256", "closurePacketSha256"), r"[a-f0-9]{64}"
    )
    envelope_declared, envelope = _revocation_scope(
        decision, ("envelopeId",), r"[A-Za-z0-9_-]+"
    )
    if packet_declared and packet is None or envelope_declared and envelope is None:
        return True
    if packet == packet_sha or envelope_declared and (envelope_id is None or envelope == envelope_id):
        return True
    return not (packet_declared or envelope_declared)


def reject_revocations(decisions, pins):
    """Check cancellation before topic/date/column filtering can hide its identity."""
    packet = normalize_authority(pins["packetSha256"])
    envelope = normalize_authority(pins["envelopeId"]) if pins.get("envelopeId") is not None else None
    identities = [re.compile(r"(?<![a-z0-9_-])" + re.escape(normalize_authority(pins[key])) + r"(?![a-z0-9_-])")
        for key in ("packetSha256", "envelopeId", "sourceCommit", "runnerSha256") if pins.get(key)]
    hex_identities = [normalize_authority(pins[key])
        for key in ("packetSha256", "sourceCommit", "runnerSha256") if pins.get(key)]
    hex_runs = re.compile(r"(?<![a-f0-9])[a-f0-9]{8,64}(?![a-f0-9])")
    for line in decisions.splitlines():
        line = normalize_authority(line)
        if not _is_revocation(line):
            continue
        if normalize_authority(DELEGATION_TOPIC_PREFIX) in line:
            raise ValueError("owner delegation was revoked")
        hex_prefix = any(identity.startswith(match[0])
            for match in hex_runs.finditer(line) for identity in hex_identities)
        if any(identity.search(line) for identity in identities) or hex_prefix:
            raise ValueError("this packet or envelope was revoked")
        if normalize_authority(TASK) in line and _revoked_packet(line, packet, envelope):
            raise ValueError("this packet or envelope was revoked")


def _owner_approval(decisions, pins):
    required = {
        f"packetSha256={pins['packetSha256']}",
        f"sourceCommit={pins['sourceCommit']}",
        f"runnerSha256={pins['runnerSha256']}",
        f"requestsPerRecording={pins['requestsPerRecording']}",
        f"estimatedUsdPerRecording={pins['estimatedUsdPerRecording']}",
        "recordings=2",
    }
    reject_revocations(decisions, pins)
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
        and _authorized_actor(columns[3], entries, decisions)
        and f"envelopeId={envelope_id}" in tokens
    ]
    delegated = [
        columns for columns, tokens in entries
        if columns[1] == named_parent
        and columns[4] == pins["packetPath"]
        and _delegated_actor(columns[3], entries, decisions, allow_within_envelope=True)
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
