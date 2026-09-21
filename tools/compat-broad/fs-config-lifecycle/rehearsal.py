"""Offline recovery and failure rehearsal for the FS-CONFIG-LIFECYCLE campaign.

The rehearsal is a pure state machine over the owned-resource ledger. It issues no
request and starts no process; it exists so the recovery path is reviewable next to
the collector, and so a failure that leaves a field configuration changed is visible
as an explicit unrecovered outcome rather than as a silent success.
"""

from __future__ import annotations

from typing import Any

from .manifest import compile_manifest

FAILURES = (
    "none",
    "precondition-projection-drift",
    "patch-refused",
    "operation-deadline",
    "stop-after-ttl-patch",
    "wall-exhausted",
    "credential-refused",
    "revert-refused",
    "reconciliation-mismatch",
)

CLEAN = "clean"
ABORTED_RESTORED = "aborted-restored"
ABORTED_UNRECOVERED = "aborted-unrecovered"

# What the shared Ledger reservation is entitled to after each outcome. A clean run is
# release-eligible in principle; today the shared core cannot release a
# configuration-only reservation, so the collector records a typed release-blocked
# record instead of a release. A restored abort stays held until the owner closes it.
# An unrecovered abort stays held until the owner restores the field by hand.
LEDGER_OUTCOMES = {
    CLEAN: "release-eligible",
    ABORTED_RESTORED: "held-restored",
    ABORTED_UNRECOVERED: "held-unrecovered",
}

_RESUME_NOTE = (
    "A resumed run reads the gate checkpoint and the ledger written by the interrupted "
    "run. It reverts the field configurations already patched and does not re-run any "
    "observation case."
)


def _ledger(nonce: str) -> list[dict[str, Any]]:
    entries = compile_manifest(nonce)["cleanup"]["ledger"]
    return [dict(entry) for entry in entries]


def rehearse(nonce: str, failure: str = "none") -> dict[str, Any]:
    """Replay the recovery path under one injected failure."""
    if failure not in FAILURES:
        raise ValueError(f"unknown failure injection: {failure}")
    planned = _ledger(nonce)
    ttl, exemption = planned
    # The ledger only ever lists field configurations a run actually patched.
    ledger: list[dict[str, Any]] = []
    steps: list[str] = ["read-projection", "verify-projection-digest"]
    resumed = False

    if failure == "precondition-projection-drift":
        steps.append("abort-before-any-mutation")
        return _result(nonce, failure, steps, ledger, ABORTED_RESTORED, resumed)

    steps.extend(["enumerate-databases", "read-ttl-baseline", "patch-ttl"])
    ledger.append(ttl)

    if failure == "operation-deadline":
        steps.extend(["poll-until-deadline", "abort-and-run-recovery"])
        steps.extend(["revert-ttl", "verify-ttl-baseline"])
        ttl["recovered"] = True
        steps.extend(["reconcile-field-listings", "reconcile-database-enumeration"])
        return _result(nonce, failure, steps, ledger, ABORTED_RESTORED, resumed)

    if failure == "stop-after-ttl-patch":
        steps.append("interrupted")
        resumed = True
        steps.extend(["resume-from-checkpoint", "revert-ttl", "verify-ttl-baseline"])
        ttl["recovered"] = True
        steps.extend(["reconcile-field-listings", "reconcile-database-enumeration"])
        return _result(nonce, failure, steps, ledger, ABORTED_RESTORED, resumed)

    if failure == "wall-exhausted":
        steps.extend(["poll-ttl-operation", "read-ttl-applied"])
        steps.extend(["observation-wall-exhausted", "abort-and-run-recovery"])
        steps.extend(["revert-ttl", "verify-ttl-baseline"])
        ttl["recovered"] = True
        steps.extend(["reconcile-field-listings", "reconcile-database-enumeration"])
        return _result(nonce, failure, steps, ledger, ABORTED_RESTORED, resumed)

    if failure == "credential-refused":
        steps.extend(
            ["poll-ttl-operation", "credential-refused", "abort-and-run-recovery"]
        )
        steps.extend(
            ["attempt-revert-ttl", "revert-refused", "report-unrecovered-resource"]
        )
        steps.extend(["reconcile-field-listings", "reconcile-database-enumeration"])
        return _result(nonce, failure, steps, ledger, ABORTED_UNRECOVERED, resumed)

    steps.extend(["poll-ttl-operation", "read-ttl-applied", "revert-ttl"])

    if failure == "revert-refused":
        steps.extend(["readback-differs-from-baseline", "report-unrecovered-resource"])
        steps.extend(["reconcile-field-listings", "reconcile-database-enumeration"])
        return _result(nonce, failure, steps, ledger, ABORTED_UNRECOVERED, resumed)

    steps.extend(["verify-ttl-baseline"])
    ttl["recovered"] = True
    steps.extend(["read-exemption-baseline", "patch-exemption"])

    if failure == "patch-refused":
        # A refused patch changed nothing; the step needs no revert and the run goes on.
        steps.extend(["record-refusal", "list-owned-fields"])
        steps.extend(["reconcile-field-listings", "reconcile-database-enumeration"])
        steps.append("write-final-ledger")
        return _result(
            nonce, failure, steps, ledger, CLEAN, resumed, refused=["patch-exemption"]
        )

    ledger.append(exemption)
    steps.extend(
        ["read-exemption-applied", "revert-exemption", "verify-exemption-baseline"]
    )
    exemption["recovered"] = True
    steps.append("list-owned-fields")

    if failure == "reconciliation-mismatch":
        stray = dict(exemption)
        stray["recovered"] = False
        stray["foundBy"] = "reconcile-field-listings"
        ledger.append(stray)
        steps.extend(["reconcile-field-listings", "report-unrecovered-resource"])
        return _result(nonce, failure, steps, ledger, ABORTED_UNRECOVERED, resumed)

    steps.extend(
        [
            "reconcile-field-listings",
            "reconcile-database-enumeration",
            "write-final-ledger",
        ]
    )
    return _result(nonce, failure, steps, ledger, CLEAN, resumed)


def _result(
    nonce: str,
    failure: str,
    steps: list[str],
    ledger: list[dict[str, Any]],
    outcome: str,
    resumed: bool,
    refused: list[str] | None = None,
) -> dict[str, Any]:
    unrecovered = [entry for entry in ledger if not entry["recovered"]]
    if unrecovered and outcome != ABORTED_UNRECOVERED:
        raise AssertionError("an unrecovered resource cannot be reported as recovered")
    return {
        "schema": "fs-config-lifecycle-recovery-rehearsal-v2",
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "requestsIssued": 0,
        "failureInjected": failure,
        "nonceLength": len(nonce),
        "steps": steps,
        "ledger": ledger,
        "unrecovered": unrecovered,
        "refusedApplies": list(refused or []),
        "outcome": outcome,
        "ledgerReservation": LEDGER_OUTCOMES[outcome],
        "exitCode": 0 if outcome == CLEAN else 1,
        "resumedFromCheckpoint": resumed,
        "resumeNote": _RESUME_NOTE,
    }
