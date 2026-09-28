"""Two independent sandbox recordings under project locks and one budget."""

from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
import secrets
from pathlib import Path

import txn_sandbox_admission as admission
import txn_sandbox_contract as contract

TASK_ID = "FS-TRANSACTION-SANDBOX"
TASK_LIMIT_USD = 10.0


def _save_private(path, value):
    encoded = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    if any(marker.encode() in encoded for marker in contract.SECRET_MARKERS):
        raise ValueError("private recording contains a secret marker")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        if os.write(fd, encoded) != len(encoded):
            raise OSError("short private recording write")
        os.fsync(fd)
    finally:
        os.close(fd)
    return encoded


def _remaining_task_budget(rows, estimate):
    if not isinstance(estimate, (int, float)) or not math.isfinite(estimate) or estimate <= 0:
        raise ValueError("finite positive sandbox estimate required")
    latest = {}
    unlinked = 0.0
    for row in rows:
        if row.get("taskId") != TASK_ID:
            continue
        value = row.get("estimatedUsd")
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
            raise ValueError("invalid FS-TRANSACTION sandbox ledger cost")
        attempt = row.get("attemptId")
        if attempt:
            latest[attempt] = value
        else:
            unlinked += value
    spent = unlinked + sum(latest.values())
    if spent + estimate > TASK_LIMIT_USD + 1e-9:
        raise ValueError("FS-TRANSACTION sandbox budget exceeded")
    return TASK_LIMIT_USD - spent


def _freeze_differences(first, second):
    differences = []
    for name in ("rulesetName", "rulesSourceSha256"):
        left = (first.get("preflight") or {}).get(name)
        right = (second.get("preflight") or {}).get(name)
        if left != right:
            differences.append({"field": name, "first": left, "second": right})
    try:
        left, right = contract._project(first), contract._project(second)
    except ValueError as error:
        differences.append({"field": "projection", "failure": str(error)})
    else:
        for case_id in sorted(set(left) | set(right)):
            if left.get(case_id) != right.get(case_id):
                differences.append({
                    "field": "case", "caseId": case_id,
                    "first": left.get(case_id), "second": right.get(case_id),
                })
    return {"kind": "freeze-mismatch", "differences": differences}


def _ledger_row(pins, attempt_id, run_dir, nonce, outcome, requests):
    if requests is not None and (
        type(requests) is not int
        or not 0 <= requests <= pins["requestsPerRecording"]
    ):
        raise ValueError("sandbox request count escaped the reviewed cap")
    return {
        "ts": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "project": contract.PROJECT,
        "database": contract.DATABASE,
        "taskId": TASK_ID,
        "envelopeId": pins["envelopeId"],
        "packetId": pins["packetId"],
        "gitSha": pins["sourceCommit"],
        "runnerSha256": pins["runnerSha256"],
        "attemptId": attempt_id,
        "runDir": str(run_dir),
        "nonce": nonce,
        "outcome": outcome,
        "requests": requests,
        "estimatedUsd": pins["estimatedUsdPerRecording"],
    }


def record_twice(*, ledger_path, private_dir, pins, decisions, now, record_once, admission_check=None):
    """Run exactly two fresh acquisitions or preserve the lock for review."""
    ledger_path, private_dir = Path(ledger_path), Path(private_dir)
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,100}", pins.get("packetId", "")):
        raise ValueError("bounded packet ID required")
    if not callable(record_once):
        raise ValueError("recording function required")
    current_now = now if callable(now) else lambda: now
    current_decisions = decisions() if callable(decisions) else decisions
    rows = admission.read_ledger(ledger_path)
    admission.verify_send_gates(rows, current_now(), current_decisions, pins)
    _remaining_task_budget(rows, pins["estimatedUsdPerRecording"] * 2)
    private_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    held = admission.acquire_project_locks(
        private_dir,
        [contract.PROJECT],
        task_id=TASK_ID,
        packet_id=pins["packetId"],
        source_commit=pins["sourceCommit"],
    )
    release = False
    sent = False
    try:
        # Recheck after lock acquisition; another lane may have finished since the first read.
        if admission_check is not None:
            admission_check()
        current_decisions = decisions() if callable(decisions) else decisions
        rows = admission.read_ledger(ledger_path)
        admission.verify_send_gates(rows, current_now(), current_decisions, pins)
        _remaining_task_budget(rows, pins["estimatedUsdPerRecording"] * 2)
        run_dir = private_dir / f"fs-transaction-{secrets.token_hex(8)}"
        run_dir.mkdir(mode=0o700)
        receipts = []
        for index in range(2):
            nonce = secrets.token_hex(16)
            owner = secrets.token_hex(16)
            attempt_id = secrets.token_hex(16)
            reservation = _ledger_row(
                pins, attempt_id, run_dir, nonce, "reserved", None
            )
            admission.append_ledger(ledger_path, reservation)
            try:
                sent = True
                receipt = record_once(index, nonce, owner, run_dir)
                if not isinstance(receipt, dict):
                    raise ValueError("recording did not return a receipt")
                rendered = json.dumps(receipt, ensure_ascii=False)
                if any(marker in rendered for marker in contract.SECRET_MARKERS):
                    raise ValueError("recording contains a secret marker")
                requests = receipt.get("sandboxRequests")
                if type(requests) is not int or not 0 <= requests <= pins["requestsPerRecording"]:
                    raise ValueError("recording request count escaped the reviewed cap")
                _save_private(run_dir / f"recording-{index + 1}.json", receipt)
                if receipt.get("complete") is not True:
                    outcome = "needs-recovery" if receipt.get("unrecovered") else "stopped-needs-review"
                    admission.append_ledger(
                        ledger_path,
                        _ledger_row(pins, attempt_id, run_dir, nonce, outcome, requests),
                    )
                    raise ValueError("the first sandbox recording is incomplete")
                contract._project(receipt)
                admission.append_ledger(
                    ledger_path,
                    _ledger_row(pins, attempt_id, run_dir, nonce, "recorded", requests),
                )
                receipts.append(receipt)
            except (Exception, KeyboardInterrupt) as error:
                last = next(
                    (row for row in reversed(admission.read_ledger(ledger_path))
                     if row.get("attemptId") == attempt_id),
                    None,
                )
                if last is not None and last.get("outcome") == "reserved":
                    requests = getattr(error, "sandbox_requests", None)
                    if type(requests) is not int or not 0 <= requests <= pins["requestsPerRecording"]:
                        requests = None
                    failure = {
                        "failureType": type(error).__name__,
                        "sandboxRequests": requests,
                        "requestCountBasis": "precharged-upper-bound" if requests is not None else "unavailable",
                    }
                    _save_private(run_dir / f"failure-{index + 1}.json", failure)
                    stopped = _ledger_row(
                        pins, attempt_id, run_dir, nonce, "stopped-needs-review", requests
                    )
                    stopped["requestCountBasis"] = failure["requestCountBasis"]
                    admission.append_ledger(
                        ledger_path, stopped,
                    )
                raise
        try:
            frozen = contract.freeze(*receipts)
        except Exception:
            try:
                _save_private(
                    run_dir / "freeze-differences.json",
                    _freeze_differences(*receipts),
                )
            finally:
                stopped = _ledger_row(
                    pins, attempt_id, run_dir, nonce, "stopped-needs-review", None
                )
                stopped["reason"] = "freeze-mismatch"
                admission.append_ledger(ledger_path, stopped)
            raise
        frozen["sourceCommit"] = pins["sourceCommit"]
        frozen["packetSha256"] = pins["packetSha256"]
        freeze_path = run_dir / "freeze.json"
        _save_private(freeze_path, frozen)
        release = True
        return {"runDir": str(run_dir), "freezePath": str(freeze_path)}
    finally:
        if release or not sent:
            admission.release_project_locks(held)
