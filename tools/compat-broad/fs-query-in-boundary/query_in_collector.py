"""Credential-free bounded collection for the compiled IN query case."""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from query_in_compiler import validate_plan

_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
_MAX_SERIALIZED_RECEIPT_BYTES = 131072


def _complete(receipt: Any) -> bool:
    return (
        isinstance(receipt, dict)
        and receipt.get("complete") is True
        and receipt.get("failure") is None
        and type(receipt.get("status")) is int
        and 100 <= receipt["status"] <= 599
        and "body" in receipt
    )


def _typed_not_found(receipt: Any) -> bool:
    body = receipt.get("body") if isinstance(receipt, dict) else None
    error = body.get("error") if isinstance(body, dict) else None
    return (
        _complete(receipt)
        and receipt["status"] == 404
        and isinstance(error, dict)
        and set(error) <= {"code", "status", "message", "details"}
        and type(error.get("code")) is int
        and error["code"] == 404
        and error.get("status") == "NOT_FOUND"
    )


def _owned(receipt: Any, resource: str, fields: dict[str, Any]) -> bool:
    body = receipt.get("body") if isinstance(receipt, dict) else None
    return (
        _complete(receipt)
        and receipt["status"] == 200
        and isinstance(body, dict)
        and body.get("name") == resource
        and body.get("fields") == fields
        and isinstance(body.get("updateTime"), str)
        and _TIMESTAMP.fullmatch(body["updateTime"]) is not None
    )


def _row(index: int, operation: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "index": index,
        "request": copy.deepcopy(operation),
        **copy.deepcopy(receipt),
    }


def _normalize(receipt: Any) -> dict[str, Any]:
    serialized = json.dumps(receipt, allow_nan=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > _MAX_SERIALIZED_RECEIPT_BYTES:
        return {
            "complete": False,
            "failure": "receipt-too-large",
            "status": None,
            "body": None,
        }
    if not isinstance(receipt, dict) or any(
        key in receipt for key in ("index", "request", "phase", "skipped", "absent")
    ):
        raise ValueError("invalid receipt envelope")
    normalized = json.loads(serialized)
    if not _complete(normalized):
        normalized.update(
            complete=False, failure=normalized.get("failure") or "invalid-receipt"
        )
    return normalized


def _publish(output: Path, filename: str, value: Any) -> None:
    """Publish one bounded JSON row atomically without replacing an existing row."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )
    if len(encoded) > _MAX_SERIALIZED_RECEIPT_BYTES:
        raise ValueError("row-too-large")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=output, prefix=".receipt-", delete=False
        ) as stream:
            temporary = stream.name
            stream.write(encoded)
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, output / filename)
        os.unlink(temporary)
        temporary = None
        directory = os.open(output, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _semantic_match(plan: dict[str, Any], operation: dict[str, Any], receipt: dict[str, Any]) -> bool:
    if not _complete(receipt):
        return False
    expect = operation["expect"]
    if "status" in expect and receipt["status"] != expect["status"]:
        return False
    if operation["kind"] in {"preflight-typed-absence", "cleanup-verify-absence"}:
        return _typed_not_found(receipt)
    if operation["kind"] == "cleanup-ownership-read":
        return _typed_not_found(receipt) or _owned(
            receipt, plan["document"], plan["fixtureFields"]
        )
    if operation["kind"] == "cleanup-conditional-delete":
        return receipt["status"] == 200
    if operation["kind"] in {"create-only-patch", "before-readback", "after-readback"}:
        return _owned(receipt, plan["document"], plan["fixtureFields"])
    if operation["kind"] == "positive-query":
        body = receipt.get("body")
        return receipt["status"] == 200 and isinstance(body, dict) and body.get(
            "documents"
        ) == [plan["expectedPositiveDocument"]]
    if operation["kind"] == "diagnostic-query":
        body = receipt.get("body")
        error = body.get("error") if isinstance(body, dict) else None
        return (
            receipt["status"] == 400
            and isinstance(error, dict)
            and error.get("status") == "INVALID_ARGUMENT"
        )
    return False


def _skip(index: int, operation: dict[str, Any], reason: str) -> dict[str, Any]:
    return _row(
        index,
        operation,
        {
            "complete": True,
            "failure": None,
            "status": None,
            "body": None,
            "skipped": reason,
        },
    )


def collect_local(
    plan: dict[str, Any],
    execute: Callable[[dict[str, Any]], dict[str, Any]],
    output: str | Path,
) -> dict[str, Any]:
    """Collect exactly six observations and three safe recovery slots locally.

    ``execute`` is an injected bounded transport. No production transport or
    credential lookup is performed here. Every attempted create remains a
    recovery responsibility, including an incomplete or lost response.
    """
    validate_plan(plan)
    plan = copy.deepcopy(plan)
    output = Path(output)
    persistence_complete = True
    persistence_failures: list[str] = []
    try:
        if output.exists():
            if not output.is_dir():
                raise NotADirectoryError(output)
        else:
            output.mkdir(mode=0o700, parents=False, exist_ok=False)
    except Exception as error:  # noqa: BLE001 -- report local recording failure.
        persistence_complete = False
        persistence_failures.append(f"output-init:{type(error).__name__}")

    def persist(filename: str, value: Any) -> None:
        nonlocal persistence_complete
        if not persistence_complete and persistence_failures:
            return
        try:
            _publish(output, filename, value)
        except Exception as error:  # noqa: BLE001 -- preserve rows and cleanup responsibility.
            persistence_complete = False
            persistence_failures.append(f"{filename}:{type(error).__name__}")

    def dispatch(operation: dict[str, Any]) -> dict[str, Any]:
        try:
            return _normalize(execute(copy.deepcopy(operation)))
        except Exception as error:  # noqa: BLE001 -- ambiguous calls require recovery.
            return {
                "complete": False,
                "failure": f"local-executor:{type(error).__name__}",
            }

    rows: list[dict[str, Any]] = []
    semantic: list[dict[str, Any]] = []
    infrastructure: list[str] = []
    attempted = False
    stop_observation = False
    for index, declared in enumerate(plan["observation"]):
        if stop_observation:
            break
        operation = copy.deepcopy(declared)
        if operation["kind"] == "create-only-patch":
            attempted = True
        receipt = dispatch(operation)
        row = _row(index, operation, receipt)
        rows.append(row)
        persist(f"observation-{index:02d}.json", row)
        if not persistence_complete:
            infrastructure.append(f"observation-{index}:publication-failure")
            stop_observation = True
            continue
        if not _complete(receipt):
            infrastructure.append(f"observation-{index}:incomplete")
            stop_observation = True
            continue
        if not _semantic_match(plan, operation, receipt):
            semantic.append({"phase": "observation", "index": index, "reason": operation["kind"]})
            if operation["kind"] in {"preflight-typed-absence", "create-only-patch"}:
                stop_observation = True

    cleanup: list[dict[str, Any]] = []
    for index, declared in enumerate(plan["recovery"]):
        operation = copy.deepcopy(declared)
        if operation["kind"] == "cleanup-conditional-delete":
            prior = cleanup[0]
            if _typed_not_found(prior):
                row = _skip(index, operation, "already-absent")
            elif _owned(prior, plan["document"], plan["fixtureFields"]):
                operation["path"] += "?currentDocument.updateTime=" + quote(
                    prior["body"]["updateTime"], safe=""
                )
                row = _row(index, operation, dispatch(operation))
            else:
                row = _skip(index, operation, "unsafe-delete")
        else:
            receipt = dispatch(operation)
            row = _row(index, operation, receipt)
        cleanup.append(row)
        persist(f"recovery-{index:02d}.json", row)
        if operation["kind"] != "cleanup-conditional-delete" and not _complete(row):
            infrastructure.append(f"recovery-{index}:incomplete")
        if operation["kind"] == "cleanup-conditional-delete" and row.get("skipped") == "unsafe-delete":
            semantic.append({"phase": "recovery", "index": index, "reason": "unsafe-delete"})
        elif operation["kind"] != "cleanup-conditional-delete" and _complete(row) and not _semantic_match(plan, operation, row):
            semantic.append({"phase": "recovery", "index": index, "reason": operation["kind"]})

    absence = bool(cleanup) and _typed_not_found(cleanup[2])
    recovery_ok = (
        len(cleanup) == 3
        and (_typed_not_found(cleanup[0]) or _owned(cleanup[0], plan["document"], plan["fixtureFields"]))
        and (cleanup[1].get("skipped") == "already-absent" or (_complete(cleanup[1]) and cleanup[1]["status"] == 200))
        and _typed_not_found(cleanup[2])
    )
    recording_complete = len(rows) == 6 and all(_complete(row) for row in rows)
    result = {
        "productionExecuted": False,
        "localOnly": True,
        "acquisitionValidated": False,
        "promotionReady": False,
        "recordingComplete": recording_complete and persistence_complete,
        "cleanupComplete": recovery_ok and persistence_complete,
        "completed": recording_complete and recovery_ok and persistence_complete and not infrastructure,
        "rows": rows,
        "cleanup": cleanup,
        "resourceAbsence": {plan["document"]: absence},
        "attemptedResources": [plan["document"]] if attempted else [],
        "semanticMismatches": semantic,
        "infrastructureFailures": infrastructure + persistence_failures,
        "persistenceComplete": persistence_complete,
    }
    persist("collection.json", result)
    return result
