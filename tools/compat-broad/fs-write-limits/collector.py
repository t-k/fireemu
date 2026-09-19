"""Finite Gate-owned limits collection; caller owns target admission and provenance."""

# ruff: noqa: BLE001 -- Preserve acquisition and cleanup failures independently.
from __future__ import annotations

from shadow import (
    digest,
    evaluate_rows,
    rehearsal_fault,
    resolve_recovery,
    save,
    should_interrupt,
    typed_absence,
)


def writes_safe(rows, plan):
    """Only namespace absence and accepted-control invariants authorize later writes."""
    if len(rows) < 4:
        return False
    operations = plan["localGatePlan"]["jobs"]["limits"]["observation"]
    controls = {
        doc["resource"]: doc
        for key, doc in plan["documents"].items()
        if key.startswith("exact-")
    }
    versions = {}
    for index, row in enumerate(rows):
        if (
            index >= len(operations)
            or row.get("index") != index
            or digest(row.get("request")) != digest(operations[index])
            or row.get("complete") is not True
            or row.get("failure") is not None
            or row.get("dispatchFailure") is not None
        ):
            return False
        status, body = row.get("status"), row.get("body")
        if index < 4:
            if not typed_absence(status, body):
                return False
            continue
        resource = operations[index]["path"].split("?")[0].removeprefix("/v1/")
        if resource not in controls:
            continue
        if (
            type(status) is not int
            or status != 200
            or not isinstance(body, dict)
            or body.get("name") != resource
            or digest(body.get("fields")) != digest(controls[resource]["fields"])
            or not isinstance(body.get("updateTime"), str)
            or not body["updateTime"]
        ):
            return False
        if operations[index]["method"] == "PATCH":
            versions[resource] = body["updateTime"]
        elif versions.get(resource) != body["updateTime"]:
            return False
    return True


def collect(gate, plan, output, wire, *, before_recovery=None, rehearsal=None):
    """Collect through an already admitted/claimed Gate, never grant production access."""
    fault = rehearsal_fault(rehearsal)
    declared = plan["localGatePlan"]["jobs"]["limits"]
    actual = gate.snapshot()["plan"]["jobs"]
    if digest(actual) != digest({"limits": declared}):
        raise ValueError("collector Gate operation binding differs")
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

    try:
        for index, operation in enumerate(observation):
            if operation["method"] == "PATCH" and not writes_safe(rows, plan):
                break
            entry = dispatch(operation, False, index, index)
            rows.append(entry)
            if entry.get("dispatchFailure"):
                break
            if index < 4 and not typed_absence(entry.get("status"), entry.get("body")):
                break
            if fault is not None and should_interrupt(rehearsal, rows, plan):
                fault["triggered"] = True
                break
    except Exception as error:
        failures.append({"phase": "observation", "failure": type(error).__name__})
    finally:
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
    mismatches = evaluate_rows(rows, plan)
    result = {
        "recordingComplete": recording,
        "cleanupComplete": cleanup_complete,
        "collectionComplete": recording and cleanup_complete and not failures,
        "expectationMismatches": mismatches,
        "infrastructureFailures": failures,
        "rows": rows,
        "cleanup": cleanup,
        "resourceAbsence": absence,
        "gate": gate.snapshot(),
        "injectedFault": fault,
    }
    save(output / "collection.json", result)
    return result
