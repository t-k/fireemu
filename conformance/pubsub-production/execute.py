"""Coordinator-only read preflight, using the existing reviewed private project lock."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

PROJECT = "fireemu-oracle-idp"
TASK = "PUBSUB-EVENTARC-PREFLIGHT"
ENVELOPE = "PUBSUB-EVENTARC-preflight-002"
LOCK_HELPER = "docs.local/runs/functions-events-stage2-env007-v3-prep/sandbox_lock.py"


class Rejected(RuntimeError):
    pass


def utc(value):
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise Rejected("ledger timestamp lacks timezone")
    return result


def check_ledger(rows, now, packet_sha):
    if any(row.get("packetSha256") == packet_sha for row in rows):
        raise Rejected("packet already consumed")
    relevant = [row for row in rows if row.get("project") == PROJECT]
    if not relevant or now < max(utc(row["ts"]) for row in relevant) + dt.timedelta(minutes=30):
        raise Rejected("project setup or 30-minute spacing is missing")
    for index, row in enumerate(relevant):
        if row.get("outcome") == "needs-recovery":
            recovered = any(candidate.get("event") == "finished"
                and candidate.get("outcome") == "recovered-no-observation"
                and candidate.get("sandboxAtBaseline") is True
                and row.get("runDir") and candidate.get("recoveredRunDir") == row["runDir"]
                and candidate.get("recoveredFinishedTs") == row["ts"]
                and candidate.get("taskId") == row.get("taskId")
                for candidate in relevant[index + 1:])
            if not recovered:
                raise Rejected("unresolved project recovery")
        if row.get("event") not in ("reserved", "started") and row.get("outcome") != "reserved":
            continue
        identity = next((key for key in ("runDir", "runId", "attemptId") if row.get(key)), None)
        # Old setup runs lack an identity; their terminal rows are paired by task, as in the existing executor.
        if not any(candidate.get("taskId") == row.get("taskId")
            and (identity is None or candidate.get(identity) == row[identity])
            and candidate.get("event") == "finished"
            and candidate.get("outcome") != "needs-recovery"
            for candidate in relevant[index + 1:]):
            raise Rejected("unclosed project reservation")
    consumed = {}
    for index, row in enumerate(rows):
        if row.get("taskId") != TASK:
            continue
        value = row.get("estimatedUsd", 0)
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise Rejected("invalid task cost")
        key = row.get("runDir") or row.get("runId") or row.get("attemptId") or f"legacy-{index}"
        consumed[key] = max(consumed.get(key, 0), value)
    if sum(consumed.values()) + 0.01 > 10:
        raise Rejected("task cost cap exceeded")


def check_authority(lines, number, packet_sha, go):
    if go != packet_sha or not 1 <= number <= len(lines):
        raise Rejected("exact coordinator go and owner row required")
    columns = lines[number - 1].split("|")
    row = columns[2].strip() if len(columns) >= 4 else ""
    if not row.startswith("decision=APPROVE;") or not re.search(rf"(?:^|;\s*)packetSha256={packet_sha}(?:;|$)", row) or not re.search(rf"(?:^|;\s*)envelopeId={ENVELOPE}(?:;|$)", row):
        raise Rejected("owner row does not authorize packet")
    if any(packet_sha in later and any(word in later for word in ("REVOKED", "WITHDRAWN", "SUPERSEDED")) for later in lines[number:]):
        raise Rejected("packet authorization revoked")


def append_ledger(path, row):
    payload = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        if os.write(descriptor, payload) != len(payload):
            raise Rejected("ledger append incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def receipt_counts(directory):
    path = directory / "requests.jsonl"
    before, after = set(), set()
    if not path.exists():
        return {"attempted": 0, "completed": 0, "unknown": 0}
    for line in path.read_text().splitlines():
        row = json.loads(line)
        target = before if row["state"] == "before-send" else after if row["state"] == "response-persisted" else None
        if target is None or row["id"] in target or target is after and row["id"] not in before:
            raise Rejected("invalid durable receipt sequence")
        target.add(row["id"])
    if len(before) > 13:
        raise Rejected("resource request cap exceeded")
    return {"attempted": len(before), "completed": len(after), "unknown": len(before - after)}


def execute(*, root, worktree, manifest, packet_sha, manifest_sha, locks,
            command=subprocess.run, append=append_ledger,
            now=lambda: dt.datetime.now(dt.timezone.utc), monotonic=time.monotonic):
    ledger = root / "docs.local/runs/sandbox-ledger.jsonl"
    started = monotonic()
    directory = root / "docs.local/runs/codex-lane7" / ("preflight-002-" + uuid.uuid4().hex)
    directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    locks.acquire()
    reserved = False
    terminal = False
    credential_attempts = 0
    try:
        rows = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
        check_ledger(rows, now(), packet_sha)
        common = dict(taskId=TASK, project=PROJECT, runDir=str(directory), packetId="preflight-002",
            envelopeId=ENVELOPE, packetSha256=packet_sha, corpusDigest=manifest_sha,
            sourceCommit=manifest["sourceCommit"], estimatedUsd=0.01)
        append(ledger, {**common, "ts": now().isoformat(), "event": "reserved",
                        "maxRequests": 13, "maxCredentialCliAttempts": 1})
        reserved = True
        result = {"outcome": "incomplete-read-only", "attempted": 0, "completed": 0, "unknown": 0}
        try:
            env = dict(os.environ)
            for key in ("GOOGLE_APPLICATION_CREDENTIALS", "FIREBASE_TOKEN", "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "CLOUDSDK_AUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"):
                if env.get(key):
                    raise Rejected("credential override forbidden")
            env.update(CLOUDSDK_CORE_DISABLE_PROMPTS="true", CLOUDSDK_CORE_DISABLE_USAGE_REPORTING="true")
            remaining = 600 - (monotonic() - started)
            if remaining <= 0:
                raise Rejected("wall limit before credential command")
            credential_attempts = 1
            locks.mark_sent(mutation=False)
            token_result = command(["gcloud", "auth", "application-default", "print-access-token"],
                capture_output=True, text=True, timeout=min(60, remaining), check=False, env=env)
            token = token_result.stdout.strip()
            if token_result.returncode != 0 or not token or len(token) > 16384 or any(ch.isspace() for ch in token):
                raise Rejected("credential command failed")
            remaining = 600 - (monotonic() - started)
            if remaining <= 0:
                raise Rejected("wall limit before capture")
            completed = command(["node", str(worktree / "conformance/pubsub-production/capture.mjs"), str(directory)],
                input=json.dumps({"projectNumber": manifest["project"]["number"], "accessToken": token}),
                capture_output=True, text=True, timeout=remaining, check=False, env=env)
            counts = receipt_counts(directory)
            summary = json.loads((directory / "summary.json").read_text())
            if any(summary.get(key) != value for key, value in counts.items()):
                raise Rejected("summary disagrees with durable receipts")
            result.update(counts)
            if completed.returncode == 0 and counts == {"attempted": 13, "completed": 13, "unknown": 0} and summary.get("outcome") == "recorded-preflight":
                result["outcome"] = "recorded-preflight"
        except (Exception, KeyboardInterrupt):
            try:
                result.update(receipt_counts(directory))
            except Exception:
                # Corrupt or truncated WAL cannot establish a send count: retain a conservative upper bound.
                result.update(attempted=13, completed=0, unknown=13)
        result["credentialCliAttempts"] = credential_attempts
        result["credentialHttpRequests"] = "opaque-cli-managed" if credential_attempts else 0
        append(ledger, {**common, "ts": now().isoformat(), "event": "finished", **result})
        terminal = True
        return result
    finally:
        locks.close(success=terminal, retain=reserved and not terminal)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approval-line", type=int, default=0)
    parser.add_argument("--go", default="")
    args = parser.parse_args()
    worktree = Path(__file__).resolve().parents[2]
    common = Path(subprocess.check_output(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=worktree, text=True).strip())
    root = common.parent
    manifest = json.loads(args.manifest.read_text())
    for path in (args.manifest, args.packet):
        if not path.resolve().is_relative_to(root / "docs.local") or path.is_symlink():
            raise Rejected("packet must be a private regular file")
    if manifest["project"]["id"] != PROJECT or manifest["sender"] != "coordinator":
        raise Rejected("wrong project or sender")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=worktree, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=worktree, text=True)
    if head != manifest["sourceCommit"] or dirty:
        raise Rejected("reviewed commit must be clean")
    for entry in (manifest["collector"], manifest["captureAdapter"], manifest["executor"]):
        path = worktree / entry["path"]
        if not path.resolve().is_relative_to(worktree) or path.is_symlink() or sha(path) != entry["sha256"]:
            raise Rejected("reviewed source hash mismatch")
    requests = json.loads(subprocess.check_output(["node", "--input-type=module", "-e",
        "import {preflightRequests} from './conformance/pubsub-production/preflight.mjs'; "
        "process.stdout.write(JSON.stringify(preflightRequests(process.argv[1])))", manifest["project"]["number"]],
        cwd=worktree, text=True, timeout=10))
    if requests != manifest["requests"] or manifest["bounds"]["maxResourceRequests"] != 13 or manifest["bounds"]["maxCredentialCliInvocations"] != 1:
        raise Rejected("manifest differs from fixed executor bounds")
    manifest_sha = sha(args.manifest)
    packet_text = args.packet.read_text()
    if manifest_sha not in packet_text or head not in packet_text:
        raise Rejected("packet does not bind this manifest and source commit")
    helper = root / LOCK_HELPER
    helper_source = helper.read_bytes()
    if helper.is_symlink() or hashlib.sha256(helper_source).hexdigest() != manifest["lockHelperSha256"]:
        raise Rejected("reviewed project lock helper changed")
    if not args.execute:
        print(json.dumps({"outcome": "offline-source-check", "productionRequests": 0, "credentialCliAttempts": 0}))
        return
    packet_sha = sha(args.packet)
    lines = (root / "docs.local/instructions/owner-decisions.md").read_text().splitlines()
    check_authority(lines, args.approval_line, packet_sha, args.go)
    if (root / "docs.local/runs/QUIET-WINDOW").exists():
        raise Rejected("quiet window active")
    spec = importlib.util.spec_from_file_location("reviewed_sandbox_lock", helper)
    module = importlib.util.module_from_spec(spec)
    # Compile the hash-checked bytes directly; do not accept a stale private pyc.
    exec(compile(helper_source, str(helper), "exec"), module.__dict__)
    locks = module.ProjectLocks(root, [PROJECT], TASK, ENVELOPE, head)
    previous = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        result = execute(root=root, worktree=worktree, manifest=manifest, packet_sha=packet_sha,
                         manifest_sha=manifest_sha, locks=locks)
        print(json.dumps(result))
        if result["outcome"] != "recorded-preflight":
            raise SystemExit(1)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Coordinator preflight stopped; inspect only private receipts and ledger.", file=sys.stderr)
        raise SystemExit(1)
