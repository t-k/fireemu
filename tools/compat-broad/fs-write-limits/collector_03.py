"""Finite Gate-owned collection for FS-WRITE-LIMITS-03.

The lifecycle is the one `collector.py` established for limits-02: an already
admitted and claimed Gate, bounded wire observations persisted before they are
validated, and ownership/version-checked recovery through Gate dispatch. Two
things differ, and both are widenings rather than relaxations.

* Every mutating method is gated by the write-safety predicate, not only
  `PATCH`. This campaign sends its first writes over `:batchWrite`.
* The preflight prefix is read from the plan instead of being a fixed count.

`collector.py` is left byte-for-byte unchanged so the frozen limits-02
collector source digest still resolves.
"""

# ruff: noqa: BLE001 -- Preserve acquisition and cleanup failures independently.
from __future__ import annotations

from expectations_03 import MUTATING, evaluate_rows, preflight_count, writes_safe
from shadow import digest, resolve_recovery, save, typed_absence


def collect(gate, plan, output, wire, *, before_recovery=None, excused=()):
    """Collect through an already admitted/claimed Gate, never grant production access.

    `excused` defaults to nothing, so a production collection excuses no row.
    Only a caller that knows something about its own side, such as the local
    shadow running under an index configuration it cannot change, passes any.
    """
    declared = plan["localGatePlan"]["jobs"]["limits"]
    actual = gate.snapshot()["plan"]["jobs"]
    if digest(actual) != digest({"limits": declared}):
        raise ValueError("collector Gate operation binding differs")
    preflights = preflight_count(plan)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    rows, cleanup, failures = [], [], []
    observation = declared["observation"]

    def dispatch(operation, recovery, index, request_index):
        entry = {"index": index, "request": operation}
        phase = "cleanup" if recovery else "observation"

        def send():
            result = wire(operation, recovery, index, request_index)
            entry.update(result)
            save(output / f"{phase}-{index:02d}-wire.json", entry)
            if result.get("complete") is not True or result.get("failure") is not None:
                raise ValueError("incomplete bounded transport")
            return result["status"], result["body"]

        try:
            status, body = gate.dispatch(operation, recovery, send)
            if "complete" not in entry:
                entry.update(
                    status=status, body=body, complete=True, failure=None, skipped=True
                )
        except Exception as error:
            entry["dispatchFailure"] = type(error).__name__
            failures.append(
                {"phase": phase, "index": index, "failure": type(error).__name__}
            )
        save(output / f"{phase}-{index:02d}.json", entry)
        return entry

    abandoned = None
    try:
        for index, operation in enumerate(observation):
            if operation["method"] in MUTATING and not writes_safe(
                rows, plan, excused=excused
            ):
                abandoned = "write-safety predicate refused a mutating request"
                break
            entry = dispatch(operation, False, index, index)
            rows.append(entry)
            if entry.get("dispatchFailure"):
                abandoned = "a dispatch failed"
                break
            if index < preflights and not typed_absence(
                entry.get("status"), entry.get("body")
            ):
                abandoned = "a namespace preflight did not prove typed absence"
                break
    except Exception as error:
        abandoned = "an observation raised"
        failures.append({"phase": "observation", "failure": type(error).__name__})
    finally:
        # With a declared schedule the Gate admits only the next slot in the
        # frozen order, so an observation that ends early has to say so before
        # its cleanup slots become reachable. Without one, stopping is enough.
        scheduled = "schedule" in plan["localGatePlan"]["jobs"]["limits"]
        if abandoned is not None and scheduled:
            try:
                gate.abandon_observation(abandoned)
            except Exception as error:
                failures.append({"phase": "abandon", "failure": type(error).__name__})
        else:
            gate.stop()
        recovery_ready = True
        if before_recovery is not None:
            try:
                before_recovery()
            except Exception as error:
                recovery_ready = False
                failures.append(
                    {"phase": "recovery-admission", "failure": type(error).__name__}
                )
        if recovery_ready:
            for index, operation in enumerate(declared["recovery"]):
                operation = resolve_recovery(operation, cleanup)
                cleanup.append(
                    dispatch(operation, True, index, len(observation) + index)
                )
        absence = {}
        for index, operation in enumerate(declared["recovery"]):
            if index % 3 == 2:
                row = cleanup[index] if index < len(cleanup) else {}
                absence[operation["path"].removeprefix("/v1/")] = row.get(
                    "complete"
                ) is True and typed_absence(row.get("status"), row.get("body"))
        cleanup_complete = False
        try:
            gate.finish()
            cleanup_complete = all(absence.values()) and not any(
                row.get("dispatchFailure") for row in cleanup
            )
        except Exception as error:
            failures.append({"phase": "finish", "failure": type(error).__name__})
    recording = len(rows) == len(observation) and all(
        row.get("complete") is True and row.get("failure") is None for row in rows
    )
    problems = evaluate_rows(rows, plan, excused=excused)
    mismatches = [problem for problem in problems if not problem["pending"]]
    pending = [problem for problem in problems if problem["pending"]]
    result = {
        "recordingComplete": recording,
        "cleanupComplete": cleanup_complete,
        "collectionComplete": recording and cleanup_complete and not failures,
        "expectationMismatches": mismatches,
        "pendingDifferences": pending,
        "infrastructureFailures": failures,
        "rows": rows,
        "cleanup": cleanup,
        "resourceAbsence": absence,
        "gate": gate.snapshot(),
    }
    save(output / "collection.json", result)
    return result
