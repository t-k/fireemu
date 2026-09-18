"""Offline cleanup and failure rehearsal for the FS-CONFIG-LIFECYCLE campaign.

The rehearsal is a pure state machine over the owned-resource ledger. It issues no
request and starts no process; it exists so the recovery path is reviewable before any
collector exists, and so a failure that leaves a resource behind is visible as an
explicit unrecovered outcome rather than as a silent success.
"""

from __future__ import annotations

from typing import Any

from .manifest import compile_manifest

FAILURES = (
    "none",
    "precondition-unexpected-database",
    "create-refused",
    "operation-deadline",
    "interrupt-after-create",
    "revert-refused",
)

CLEAN = "clean"
ABORTED_RECOVERED = "aborted-recovered"
ABORTED_UNRECOVERED = "aborted-unrecovered"

_RESUME_NOTE = (
    "A resumed run reads the checkpoint and the ledger written by the interrupted run. "
    "It recovers the resources already created and does not re-run any observation case."
)


def _ledger(nonce: str) -> list[dict[str, Any]]:
    entries = compile_manifest(nonce)["cleanup"]["ledger"]
    return [dict(entry) for entry in entries]


def rehearse(nonce: str, failure: str = "none") -> dict[str, Any]:
    """Replay the cleanup path under one injected failure."""
    if failure not in FAILURES:
        raise ValueError(f"unknown failure injection: {failure}")
    planned = _ledger(nonce)
    # The ledger only ever lists resources a run actually created.
    ledger: list[dict[str, Any]] = []
    steps: list[str] = ["read-baseline", "verify-database-identity"]
    resumed = False

    if failure == "precondition-unexpected-database":
        steps.append("abort-before-any-mutation")
        return _result(nonce, failure, steps, ledger, ABORTED_RECOVERED, resumed)

    if failure == "create-refused":
        steps.extend(["attempt-create", "record-refusal", "abort-without-retry"])
        return _result(nonce, failure, steps, ledger, ABORTED_RECOVERED, resumed)

    steps.append("create-owned-database")
    created = next(entry for entry in planned if entry["kind"] == "database")
    ledger.append(created)

    if failure == "operation-deadline":
        steps.extend(["poll-until-deadline", "abort-and-run-cleanup"])
        steps.extend(["delete-created-database", "verify-database-absence"])
        created["recovered"] = True
        return _result(nonce, failure, steps, ledger, ABORTED_RECOVERED, resumed)

    if failure == "interrupt-after-create":
        steps.append("interrupted")
        resumed = True
        steps.extend(
            [
                "resume-from-checkpoint",
                "delete-created-database",
                "verify-database-absence",
            ]
        )
        created["recovered"] = True
        return _result(nonce, failure, steps, ledger, ABORTED_RECOVERED, resumed)

    steps.append("patch-field-configurations")
    fields = [entry for entry in planned if entry["kind"] == "fieldConfig"]
    ledger.extend(fields)

    if failure == "revert-refused":
        steps.extend(["attempt-revert", "readback-differs-from-baseline"])
        for entry in fields[1:]:
            entry["recovered"] = True
        created["recovered"] = True
        steps.extend(["delete-created-database", "report-unrecovered-resource"])
        return _result(nonce, failure, steps, ledger, ABORTED_UNRECOVERED, resumed)

    steps.extend(
        [
            "revert-field-configurations",
            "verify-field-configuration-baseline",
            "delete-created-database",
            "verify-database-absence",
            "write-final-ledger",
        ]
    )
    for entry in ledger:
        entry["recovered"] = True
    return _result(nonce, failure, steps, ledger, CLEAN, resumed)


def _result(
    nonce: str,
    failure: str,
    steps: list[str],
    ledger: list[dict[str, Any]],
    outcome: str,
    resumed: bool,
) -> dict[str, Any]:
    unrecovered = [entry for entry in ledger if not entry["recovered"]]
    if unrecovered and outcome != ABORTED_UNRECOVERED:
        raise AssertionError("an unrecovered resource cannot be reported as recovered")
    return {
        "schema": "fs-config-lifecycle-cleanup-rehearsal-v1",
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "requestsIssued": 0,
        "failureInjected": failure,
        "nonceLength": len(nonce),
        "steps": steps,
        "ledger": ledger,
        "unrecovered": unrecovered,
        "outcome": outcome,
        "exitCode": 0 if outcome == CLEAN else 1,
        "resumedFromCheckpoint": resumed,
        "resumeNote": _RESUME_NOTE,
    }
