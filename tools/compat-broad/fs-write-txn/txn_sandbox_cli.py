"""Locally admitted entry point for two FS-TRANSACTION sandbox recordings."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))

import txn_expiry_cases as cases
import txn_expiry_plan as plan_module
import txn_sandbox_run as runner
import txn_sandbox_session as session

SOURCE_FILES = (
    "tools/compat-broad/fs-write-txn/txn_expiry_cases.py",
    "tools/compat-broad/fs-write-txn/txn_expiry_plan.py",
    "tools/compat-broad/fs-write-txn/txn_expiry_collector.py",
    "tools/compat-broad/fs-write-txn/txn_expiry_remote_transport.py",
    "tools/compat-broad/fs-write-txn/txn_expiry_https_worker.py",
    "tools/compat-broad/fs-write-txn/txn_sandbox_contract.py",
    "tools/compat-broad/fs-write-txn/txn_sandbox_admission.py",
    "tools/compat-broad/fs-write-txn/txn_sandbox_wire.py",
    "tools/compat-broad/fs-write-txn/txn_sandbox_management.py",
    "tools/compat-broad/fs-write-txn/txn_sandbox_session.py",
    "tools/compat-broad/fs-write-txn/txn_sandbox_run.py",
    "tools/compat-broad/fs-write-txn/txn_sandbox_cli.py",
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_preflight.py",
    "tools/compat-broad/fs-write-txn/credential_prep.py",
    "tools/compat-broad/batch_adapter.py",
)
CLOSURE = ROOT / "spec/compatibility/closure/fs-transaction.json"
PACKET_FIELDS = {
    "schemaVersion", "packetId", "project", "database", "recordings",
    "requestsPerRecording", "estimatedUsdPerRecording", "sourceCommit",
    "runnerSha256", "closureSha256", "casesDigest", "planSourceDigest",
    "baselineSha256",
}


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def runner_source_sha256():
    source = {path: sha256((ROOT / path).read_bytes()) for path in SOURCE_FILES}
    return sha256(json.dumps(source, sort_keys=True, separators=(",", ":")).encode())


def load_packet(
    packet_path, packet_sha256, baseline_path, *, source_commit,
    runner_sha256, closure_sha256, packet_relative,
):
    packet_path, baseline_path = Path(packet_path), Path(baseline_path)
    raw = packet_path.read_bytes()
    if sha256(raw) != packet_sha256:
        raise ValueError("packet bytes differ from the reviewed SHA-256")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != PACKET_FIELDS:
        raise ValueError("closed FS-TRANSACTION packet schema required")
    if (
        value["schemaVersion"] != 1
        or value["project"] != "fireemu-oracle-sbx"
        or value["database"] != "(default)"
        or value["recordings"] != 2
        or value["casesDigest"] != cases.cases_digest()
        or value["planSourceDigest"] != plan_module.source_digest()
    ):
        raise ValueError("packet scope or corpus differs from the frozen campaign")
    if value["requestsPerRecording"] != 95:
        raise ValueError("reviewed request bound must be exactly 95 per recording")
    if value["estimatedUsdPerRecording"] != 0.05:
        raise ValueError("reviewed cost reservation must be US$0.05 per recording")
    if (
        value["sourceCommit"] != source_commit
        or value["runnerSha256"] != runner_sha256
        or value["closureSha256"] != closure_sha256
    ):
        raise ValueError("packet source, runner or closure differs")
    if sha256(baseline_path.read_bytes()) != value["baselineSha256"]:
        raise ValueError("private baseline differs from the packet")
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,100}", value["packetId"]):
        raise ValueError("bounded packet ID required")
    return {
        "packetId": value["packetId"],
        "packetSha256": packet_sha256,
        "sourceCommit": source_commit,
        "runnerSha256": runner_sha256,
        "packetPath": packet_relative,
        "requestsPerRecording": value["requestsPerRecording"],
        "estimatedUsdPerRecording": value["estimatedUsdPerRecording"],
    }


def verify_review(review_path, review_sha256, pins):
    raw = Path(review_path).read_bytes()
    if sha256(raw) != review_sha256:
        raise ValueError("review bytes differ from their SHA-256")
    lines = raw.decode().splitlines()
    if not lines or lines[0] != "APPROVE":
        raise ValueError("an exact APPROVE review is required")
    required = {
        f"packetSha256={pins['packetSha256']}",
        f"sourceCommit={pins['sourceCommit']}",
        f"runnerSha256={pins['runnerSha256']}",
    }
    if not required <= set(lines[1:]):
        raise ValueError("review did not pin this packet and runner")


def _git(*args):
    result = subprocess.run(
        ["git", *args], cwd=ROOT, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _source_commit():
    if _git("status", "--porcelain"):
        raise ValueError("sandbox runner requires a clean signed source tree")
    commit = _git("rev-parse", "HEAD")
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("signed source commit required")
    _git("verify-commit", commit)
    return commit


def _main_root():
    common = Path(_git("rev-parse", "--path-format=absolute", "--git-common-dir"))
    return common.parent


def _private(path, root):
    value = Path(path).resolve(strict=True)
    if not value.is_relative_to(root / "docs.local"):
        raise ValueError("private packet, review and baseline must stay under docs.local")
    if value.stat().st_mode & 0o777 != 0o600:
        raise ValueError("private packet, review and baseline need mode 600")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("plan-local", "record-production"))
    parser.add_argument("--packet")
    parser.add_argument("--packet-sha256")
    parser.add_argument("--review")
    parser.add_argument("--review-sha256")
    parser.add_argument("--baseline")
    args = parser.parse_args(argv)
    if args.command == "plan-local":
        print(json.dumps({
            "runnerSha256": runner_source_sha256(),
            "closureSha256": sha256(CLOSURE.read_bytes()),
            "casesDigest": cases.cases_digest(),
            "planSourceDigest": plan_module.source_digest(),
            "requestsPerRecording": 95,
            "estimatedUsdPerRecording": 0.05,
        }, sort_keys=True))
        return 0
    if not all((args.packet, args.packet_sha256, args.review, args.review_sha256, args.baseline)):
        raise ValueError("record-production needs the exact packet, review and baseline pins")
    root = _main_root()
    packet_path = _private(args.packet, root)
    review_path = _private(args.review, root)
    baseline_path = _private(args.baseline, root)
    packet_relative = packet_path.relative_to(root).as_posix()

    def admit():
        commit = _source_commit()
        pins = load_packet(
            packet_path, args.packet_sha256, baseline_path,
            source_commit=commit,
            runner_sha256=runner_source_sha256(),
            closure_sha256=sha256(CLOSURE.read_bytes()),
            packet_relative=packet_relative,
        )
        verify_review(review_path, args.review_sha256, pins)
        return pins

    pins = admit()
    baseline = json.loads(baseline_path.read_bytes())
    ledger_path = root / "docs.local/runs/sandbox-ledger.jsonl"
    result = runner.record_twice(
        ledger_path=ledger_path,
        private_dir=ledger_path.parent,
        pins=pins,
        decisions=lambda: (root / "docs.local/instructions/owner-decisions.md").read_text(),
        now=lambda: dt.datetime.now(dt.timezone.utc),
        record_once=lambda index, nonce, owner, directory: session.run_once(
            nonce, owner, directory, baseline
        ),
        admission_check=admit,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001 -- never print credential or response material.
        print(f"sandbox recording stopped: {type(error).__name__}", file=sys.stderr)
        raise SystemExit(1) from None
