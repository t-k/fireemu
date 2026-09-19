"""Gate-connected bounded collector for the Commit transform campaign."""

from __future__ import annotations

import copy
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from broad_contract import digest
from commit_production_bridge import CommitProductionBridge, classify_receipt
from gate_adapter import CommitGate, compiler_plan


def _save(path: Path, value: Any) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x") as stream:
        json.dump(value, stream, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    try:
        # link() publishes atomically with exclusive destination semantics;
        # unlike replace(), it can never overwrite a historical receipt.
        os.link(temporary, path)
    except OSError:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
    temporary.unlink()
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _receipt(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"complete": False, "failure": "invalid-wire-receipt"}
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return {"complete": False, "failure": "invalid-wire-receipt"}
    return copy.deepcopy(value)


def _expected(
    plan: dict[str, Any], operation: dict[str, Any], recovery: bool, index: int
) -> dict[str, Any]:
    declared = plan["recovery"][index] if recovery else plan["observation"][index]
    if recovery and declared.get("versionFrom") is not None:
        declared = copy.deepcopy(declared)
        declared.pop("versionFrom")
        # The Gate independently checks the ownership proof. This resolution only
        # makes the operation digest match the Gate's declared versioned request.
        return declared
    return declared


def collect_commit(
    gate: CommitGate,
    plan: dict[str, Any],
    output: Path,
    *,
    transmit,
) -> dict[str, Any]:
    """Collect exactly 11 observations and six Gate-charged recovery slots."""
    canonical = compiler_plan(plan["project"], plan["database"], plan["nonce"])
    if digest(plan) != digest(canonical):
        raise ValueError("compiler plan differs from canonical output")
    if not isinstance(gate, CommitGate) or digest(gate.compiler) != digest(plan):
        raise ValueError("Commit Gate/compiler binding differs")
    if len(plan["observation"]) != 11 or len(plan["recovery"]) != 6:
        raise ValueError("closed 11 observation/6 recovery schedule required")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    bridge = CommitProductionBridge(plan, transmit=transmit)
    rows: list[dict[str, Any]] = []
    cleanup: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    persistence_failed = False

    def dispatch(
        operation: dict[str, Any], recovery: bool, index: int, *, row_name: str
    ) -> dict[str, Any]:
        holder: dict[str, Any] = {}

        def send():
            deadline = gate.consume_wire(operation, recovery)
            if time.monotonic() + 13 > deadline:
                raise ValueError("phase deadline after shared Gate wait")
            expected = _expected(plan, operation, recovery, index)
            # Gate is authoritative for version resolution; exact matching here
            # prevents a caller from smuggling a different non-Commit operation.
            if operation.get("kind") != "cleanup-conditional-delete" and digest(
                operation
            ) != digest(expected):
                raise ValueError("request differs from frozen compiler plan")
            raw = (
                bridge.send(operation)
                if operation.get("kind") == "commit-transform"
                else classify_receipt(transmit(copy.deepcopy(operation)))
            )
            holder["receipt"] = raw
            if raw["classification"] == "indeterminate":
                raise ValueError("incomplete bounded transport")
            return raw["status"], raw["body"]

        entry: dict[str, Any] = {"index": index, "request": copy.deepcopy(operation)}
        if recovery and operation.get("kind") == "cleanup-conditional-delete":
            # Retain the compiler annotation in the journal; it is not sent on
            # the wire. The frozen comparator binds it to the ownership read.
            entry["wireRequest"] = copy.deepcopy(operation)
            entry["request"]["versionFrom"] = plan["recovery"][index]["versionFrom"]
        try:
            result = gate.dispatch(operation, recovery, send)
            if isinstance(result, tuple):
                status, body = result
                if status is None:
                    entry.update(
                        {
                            "complete": True,
                            "failure": None,
                            "status": None,
                            "body": body,
                            "skipped": body.get("skipped"),
                        }
                    )
                else:
                    entry.update(
                        {
                            "complete": True,
                            "failure": None,
                            "status": status,
                            "body": body,
                        }
                    )
            elif "receipt" in holder:
                entry.update(holder["receipt"])
        except Exception as error:  # noqa: BLE001 -- retain the Gate's durable failure event
            entry.update(
                holder.get(
                    "receipt", {"complete": False, "failure": type(error).__name__}
                )
            )
            failures.append(
                {
                    "phase": "recovery" if recovery else "observation",
                    "index": index,
                    "failure": type(error).__name__,
                }
            )
        nonlocal persistence_failed
        try:
            _save(output / f"{row_name}-{index:02d}.json", entry)
        except OSError as error:
            persistence_failed = True
            failures.append(
                {
                    "phase": "recovery" if recovery else "observation",
                    "index": index,
                    "failure": f"receipt-persistence:{type(error).__name__}",
                }
            )
        return entry

    try:
        for index, operation in enumerate(plan["observation"]):
            row = dispatch(operation, False, index, row_name="observation")
            rows.append(row)
            if (
                persistence_failed
                or row.get("complete") is not True
                or row.get("failure") is not None
            ):
                break
    finally:
        # A receipt failure must stop observation before entering owned recovery.
        gate.stop()
    for index, declared in enumerate(plan["recovery"]):
        operation = copy.deepcopy(declared)
        if operation.get("kind") == "cleanup-conditional-delete":
            source = operation.pop("versionFrom")
            capture = gate.snapshot()["jobs"]["commit"]["captures"].get(str(source), {})
            version = capture.get("updateTime") if isinstance(capture, dict) else None
            if isinstance(version, str):
                operation["path"] += "?currentDocument.updateTime=" + quote(
                    version, safe=""
                )
        cleanup.append(dispatch(operation, True, index, row_name="recovery"))

    cleanup_complete = False
    try:
        if not persistence_failed:
            gate.finish()
            cleanup_complete = True
    except Exception as error:  # noqa: BLE001 -- retain cleanup ownership failure
        failures.append({"phase": "finish", "failure": type(error).__name__})
    recording = len(rows) == 11 and all(
        row.get("complete") is True and row.get("failure") is None for row in rows
    )
    result = {
        "recordingComplete": recording,
        "cleanupComplete": cleanup_complete,
        "collectionComplete": recording and cleanup_complete and not failures,
        "rows": rows,
        "cleanup": cleanup,
        "infrastructureFailures": failures,
        "gate": gate.snapshot(),
    }
    _save(output / "collection.json", result)
    return result
