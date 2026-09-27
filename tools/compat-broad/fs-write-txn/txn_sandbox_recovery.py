"""Pure exact-name recovery plan and bounded wire sequence for a stopped run."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import signal
import sys
from pathlib import Path

import txn_expiry_cases as cases
import txn_expiry_collector as collector
import txn_expiry_plan as plan
import txn_sandbox_admission as admission
import txn_sandbox_cli as cli
import txn_sandbox_management as management
import txn_sandbox_run as runner
import txn_sandbox_session as session
import txn_sandbox_wire as wire_module

PROJECT = "fireemu-oracle-sbx"
DATABASE = "(default)"
MAX_DATA_REQUESTS = 15
ROLES = tuple(cases.RESOURCE_ROLES)
MAX_TOTAL_REQUESTS = 23
RECOVERY_WAIT = dt.timedelta(seconds=180)
PACKET_FIELDS = {
    "schemaVersion", "packetId", "originalPacketId", "originalAttemptId",
    "sourceCommit", "runnerSha256", "project", "database", "maxRequests",
    "estimatedUsd", "snapshotPath", "snapshotSha256", "baselineSha256",
    "lockSha256", "lockInode", "notBefore", "roles",
}


class RecoveryBudget:
    """One credential, seven management requests and at most fifteen data requests."""

    def __init__(self):
        self.credential = 0
        self.management = 0
        self.data = 0

    @property
    def total(self):
        return self.credential + self.management + self.data

    def charge(self, kind, *, phase=None):
        if kind == "credential" and phase is None and self.credential < 1:
            self.credential += 1
        elif kind == "management" and phase is None and self.management < 7:
            self.management += 1
        elif kind == "data" and phase == "recovery" and self.data < MAX_DATA_REQUESTS:
            self.data += 1
        else:
            raise ValueError("exact-name recovery request bound reached")
        if self.total > MAX_TOTAL_REQUESTS:
            raise ValueError("exact-name recovery total bound reached")
        return self.total


def targets(snapshot):
    """Build exactly five names from a source-bound responsibility snapshot."""
    if not isinstance(snapshot, dict) or snapshot.get("kind") != "txn-responsibility-v1":
        raise ValueError("bounded responsibility snapshot required")
    nonce, owner = snapshot.get("nonce"), snapshot.get("ownerId")
    plan._validate_identity(nonce, owner)
    prefix = plan.document_prefix(nonce)
    if (
        snapshot.get("target") != "production"
        or snapshot.get("projectId") != PROJECT
        or snapshot.get("database") != DATABASE
        or snapshot.get("documentPrefix") != prefix
    ):
        raise ValueError("responsibility project or prefix differs from the sandbox")
    if (
        snapshot.get("sourceDigest") != plan.source_digest()
        or snapshot.get("casesDigest") != cases.cases_digest()
        or snapshot.get("authorizesCleanup") is not False
        or snapshot.get("authorizesResume") is not False
        or snapshot.get("terminalComplete") is True
    ):
        raise ValueError("responsibility source or authority differs")
    states = snapshot.get("resourceStates")
    if not isinstance(states, dict) or set(states) != set(ROLES) or any(
        state not in collector.RESOURCE_STATES for state in states.values()
    ):
        raise ValueError("five typed resource states required")
    entries = snapshot.get("preconditions")
    if not isinstance(entries, list) or any(
        not isinstance(entry, dict) or entry.get("role") not in ROLES for entry in entries
    ):
        raise ValueError("typed precondition list required")
    by_role = {entry["role"]: entry for entry in entries}
    if len(by_role) != len(entries):
        raise ValueError("duplicate resource precondition")
    absent = snapshot.get("typedAbsenceConfirmed")
    if not isinstance(absent, list) or len(set(absent)) != len(absent) or set(absent) - set(ROLES):
        raise ValueError("typed absence list differs")
    result = []
    for role in ROLES:
        state = states[role]
        may_delete = state in (collector.SENT_UNKNOWN, collector.CREATION_CONFIRMED) and role not in absent
        if may_delete and by_role.get(role, {}).get("absence") is not True:
            raise ValueError("preflight absence does not authorize exact-name recovery")
        result.append({
            "role": role,
            "name": collector.document_name(PROJECT, DATABASE, f"{prefix}/{role}"),
            "mayDelete": may_delete,
        })
    return result


def _request(rpc, name, site, *, body=None):
    return {
        "rpc": rpc,
        "projectId": PROJECT,
        "database": DATABASE,
        "name": name if rpc == "GetDocument" else None,
        "body": body,
        "query": None,
        "site": site,
        "timeoutSeconds": plan.DEFAULT_REQUEST_TIMEOUT_SECONDS,
        "maxRequestBytes": plan.MAX_REQUEST_BYTES,
        "maxResponseBytes": plan.MAX_RESPONSE_BYTES,
    }


def recover(snapshot, send):
    """Read all five names and conditionally delete only proven owned documents."""
    fixed = targets(snapshot)
    if not callable(send):
        raise ValueError("bounded recovery transport required")
    requests = 0
    recovered = []

    def dispatch(request):
        nonlocal requests
        if requests >= MAX_DATA_REQUESTS:
            raise ValueError("exact-name recovery request bound reached")
        requests += 1
        return send(request)

    for item in fixed:
        role, name = item["role"], item["name"]
        read = dispatch(_request("GetDocument", name, f"cleanup/owned-read/{role}"))
        if not isinstance(read, dict) or read.get("complete") is not True:
            return {"complete": False, "requests": requests, "recovered": recovered, "failure": "read-incomplete"}
        if read.get("code") == collector.NOT_FOUND:
            recovered.append(role)
            continue
        body = read.get("body")
        if (
            read.get("code") != collector.OK
            or not item["mayDelete"]
            or not isinstance(body, dict)
            or body.get("name") != name
            or not collector.is_owned(body, snapshot["ownerId"], role, snapshot["nonce"])
        ):
            return {"complete": False, "requests": requests, "recovered": recovered, "failure": "ownership-unproven"}
        delete = dispatch(_request(
            "Commit", name, f"cleanup/conditional-delete/{role}",
            body={"writes": [{
                "delete": name,
                "currentDocument": {"updateTime": body["updateTime"]},
            }]},
        ))
        if not isinstance(delete, dict) or delete.get("complete") is not True or delete.get("code") != collector.OK:
            return {"complete": False, "requests": requests, "recovered": recovered, "failure": "delete-unconfirmed"}
        final = dispatch(_request("GetDocument", name, f"cleanup/typed-absence/{role}"))
        if not isinstance(final, dict) or final.get("complete") is not True or final.get("code") != collector.NOT_FOUND:
            return {"complete": False, "requests": requests, "recovered": recovered, "failure": "absence-unconfirmed"}
        recovered.append(role)
    return {"complete": True, "requests": requests, "recovered": recovered}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_packet(packet, *, packet_sha, snapshot_raw, baseline_raw, lock_path,
                  ledger_rows, now, decisions, review, packet_path):
    """Refuse any production recovery without exact bytes and a distinct owner row."""
    if not isinstance(packet, dict) or set(packet) != PACKET_FIELDS:
        raise ValueError("closed exact-name recovery packet required")
    if (
        packet["schemaVersion"] != 1
        or packet["project"] != PROJECT
        or packet["database"] != DATABASE
        or packet["maxRequests"] != MAX_TOTAL_REQUESTS
        or packet["estimatedUsd"] != 0.02
        or packet["roles"] != list(ROLES)
        or packet["snapshotSha256"] != _sha(snapshot_raw)
        or packet["baselineSha256"] != _sha(baseline_raw)
        or packet["sourceCommit"] != cli._source_commit()
        or packet["runnerSha256"] != cli.runner_source_sha256()
        or not re.fullmatch(r"[A-Za-z0-9_-]{8,100}", packet["packetId"])
        or packet["packetId"] == packet["originalPacketId"]
    ):
        raise ValueError("exact-name recovery packet scope or signed source differs")
    snapshot = json.loads(snapshot_raw)
    targets(snapshot)
    expected_path = f"docs.local/runs/{Path(packet['snapshotPath']).parent.name}/responsibility.json"
    if packet["snapshotPath"] != expected_path:
        raise ValueError("responsibility snapshot path differs")
    if not isinstance(lock_path, Path) or not lock_path.is_file():
        raise ValueError("original project lock is missing")
    lock_raw = lock_path.read_bytes()
    if _sha(lock_raw) != packet["lockSha256"] or lock_path.stat().st_ino != packet["lockInode"]:
        raise ValueError("original project lock bytes or inode differ")
    lock = json.loads(lock_raw)
    if (
        lock.get("taskId") != runner.TASK_ID
        or lock.get("packetId") != packet["originalPacketId"]
        or lock.get("sourceCommit") != packet["sourceCommit"]
        or type(lock.get("pid")) is not int
        or lock["pid"] <= 0
    ):
        raise ValueError("project lock is not the original run lock")
    try:
        os.kill(lock["pid"], 0)
    except ProcessLookupError:
        pass
    else:
        raise ValueError("original runner process still exists")
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise ValueError("timezone-aware recovery time required")
    not_before = admission._instant(packet["notBefore"])
    original = [row for row in ledger_rows if (
        row.get("project") == PROJECT
        and row.get("taskId") == runner.TASK_ID
        and row.get("packetId") == packet["originalPacketId"]
        and row.get("attemptId") == packet["originalAttemptId"]
    )]
    if not original or original[-1].get("outcome") not in ("needs-recovery", "stopped-needs-review"):
        raise ValueError("original attempt has no open recovery responsibility")
    if (
        original[-1].get("nonce") != snapshot["nonce"]
        or Path(original[-1].get("runDir", "")).resolve()
        != (cli._main_root() / packet["snapshotPath"]).parent.resolve()
    ):
        raise ValueError("responsibility snapshot differs from original attempt")
    if any(row.get("recoveryPacketId") == packet["packetId"] for row in ledger_rows):
        raise ValueError("this exact-name recovery packet was already sent")
    latest = max(admission._instant(row["ts"]) for row in original)
    snapshot_mtime = dt.datetime.fromtimestamp(
        (cli._main_root() / packet["snapshotPath"]).stat().st_mtime, dt.timezone.utc
    )
    if not_before < max(latest, snapshot_mtime) + RECOVERY_WAIT or now < not_before:
        raise ValueError("exact-name recovery wait has not elapsed")
    required_review = {
        "APPROVE", f"packetSha256={packet_sha}",
        f"sourceCommit={packet['sourceCommit']}",
        f"runnerSha256={packet['runnerSha256']}", "withinRecoveryEnvelope=YES",
    }
    lines = review.splitlines()
    if not lines or lines[0] != "APPROVE" or not required_review <= set(lines):
        raise ValueError("independent exact-name recovery review is required")
    owner_rows = []
    for line in decisions.splitlines():
        columns = [part.strip() for part in re.sub(r"^\s*-\s*", "", line).split("|")]
        if len(columns) != 5 or columns[1] != "FS-TRANSACTION recovery":
            continue
        tokens = {part.strip() for part in columns[2].split(";")}
        if "REVOKED" in tokens or "decision=REVOKED" in tokens:
            raise ValueError("exact-name recovery approval was revoked")
        if (
            columns[3].startswith("オーナー")
            and columns[4] == packet_path
            and {
                "decision=APPROVE", f"packetSha256={packet_sha}",
                f"sourceCommit={packet['sourceCommit']}",
                "maxRequests=23", "reserveUsd=0.02",
                "writes=exact-owned-five-documents", "onStop=lock-held",
                "onSuccess=release-lock",
            } <= tokens
        ):
            owner_rows.append(columns)
    if len(owner_rows) != 1:
        raise ValueError("one exact owner recovery approval is required")
    return snapshot, original[-1]


def record_recovery(*, packet, packet_sha, packet_path, snapshot_raw, baseline_raw,
                    lock_path, ledger_path, private_dir, now, decisions, review,
                    credential_fn=session._access_token,
                    metadata_factory=management.MetadataSession,
                    wire_factory=wire_module.FixedDataWire):
    """Send one separately approved bounded recovery and release only a verified lock."""
    ledger_rows = admission.read_ledger(ledger_path)
    snapshot, original = verify_packet(
        packet, packet_sha=packet_sha, snapshot_raw=snapshot_raw,
        baseline_raw=baseline_raw, lock_path=lock_path, ledger_rows=ledger_rows,
        now=now, decisions=decisions, review=review, packet_path=packet_path,
    )
    lock_inode = lock_path.stat().st_ino
    lock_raw = lock_path.read_bytes()
    legacy_lock = Path(str(ledger_path) + ".lock")
    if legacy_lock.exists():
        raise ValueError("legacy shared sandbox lock is held")
    result_dir = Path(private_dir) / f"fs-transaction-recovery-{packet['packetId']}"
    result_dir.mkdir(mode=0o700)
    row = {
        "ts": now.isoformat().replace("+00:00", "Z"),
        "project": PROJECT, "database": DATABASE, "taskId": runner.TASK_ID,
        "packetId": packet["originalPacketId"], "attemptId": packet["originalAttemptId"],
        "recoveryPacketId": packet["packetId"], "runDir": original["runDir"],
        "estimatedUsd": round(original["estimatedUsd"] + packet["estimatedUsd"], 2),
        "recoveryEstimatedUsd": packet["estimatedUsd"], "requests": None,
    }
    admission.append_ledger(ledger_path, {**row, "outcome": "reserved-recovery"})
    budget = RecoveryBudget()
    try:
        budget.charge("credential")
        token = credential_fn()
        metadata = metadata_factory(token, json.loads(baseline_raw), budget)
        before = metadata.preflight()
        wire = wire_factory(token, budget)
        result = recover(snapshot, wire)
        after = metadata.postflight() if result["complete"] else None
        if result["complete"] and any(before[slot] != after[slot] for slot in ("project", "database")):
            result = {**result, "complete": False, "failure": "configuration-changed"}
        result["totalRequests"] = budget.total
        runner._save_private(result_dir / "recovery.json", result)
        if result["complete"] is not True or result["recovered"] != list(ROLES):
            admission.append_ledger(ledger_path, {**row, "outcome": "needs-recovery", "requests": budget.total})
            raise ValueError("exact-name recovery is incomplete")
        if lock_path.stat().st_ino != lock_inode or lock_path.read_bytes() != lock_raw:
            raise ValueError("project lock changed before verified release")
        admission.append_ledger(ledger_path, {**row, "outcome": "recovered-exact-name", "requests": budget.total})
        try:
            lock_path.unlink()
        except OSError:
            admission.append_ledger(ledger_path, {
                **row, "outcome": "needs-recovery", "requests": budget.total,
                "reason": "lock-release-failed",
            })
            raise
        return result
    except (Exception, KeyboardInterrupt):
        rows = admission.read_ledger(ledger_path)
        if rows[-1].get("recoveryPacketId") == packet["packetId"] and rows[-1].get("outcome") == "reserved-recovery":
            admission.append_ledger(ledger_path, {**row, "outcome": "needs-recovery", "requests": budget.total})
        raise


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", required=True)
    parser.add_argument("--packet-sha256", required=True)
    parser.add_argument("--review", required=True)
    parser.add_argument("--review-sha256", required=True)
    parser.add_argument("--baseline", required=True)
    args = parser.parse_args(argv)
    root = cli._main_root()
    packet_path = cli._private(args.packet, root)
    review_path = cli._private(args.review, root)
    baseline_path = cli._private(args.baseline, root)
    packet_raw = packet_path.read_bytes()
    review_raw = review_path.read_bytes()
    if _sha(packet_raw) != args.packet_sha256 or _sha(review_raw) != args.review_sha256:
        raise ValueError("reviewed recovery bytes differ")
    packet = json.loads(packet_raw)
    snapshot_path = cli._private(root / packet["snapshotPath"], root)
    lock_path = root / "docs.local/runs/sandbox-locks/fireemu-oracle-sbx.lock"
    session.assert_clean_environment()

    def interrupt_on_sigterm(_signum, _frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupt_on_sigterm)
    try:
        result = record_recovery(
            packet=packet, packet_sha=args.packet_sha256,
            packet_path=packet_path.relative_to(root).as_posix(),
            snapshot_raw=snapshot_path.read_bytes(), baseline_raw=baseline_path.read_bytes(),
            lock_path=lock_path, ledger_path=root / "docs.local/runs/sandbox-ledger.jsonl",
            private_dir=root / "docs.local/runs", now=dt.datetime.now(dt.timezone.utc),
            decisions=(root / "docs.local/instructions/owner-decisions.md").read_text(),
            review=review_raw.decode(),
        )
    finally:
        signal.signal(signal.SIGTERM, previous)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 -- never print credentials.
        print(f"sandbox recovery stopped: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(1) from None
