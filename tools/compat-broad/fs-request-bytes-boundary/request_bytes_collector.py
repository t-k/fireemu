"""Bounded, local-only acquisition for the compiled request-byte plan."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from request_bytes_compiler import compact_utf8, logical_fields_digest, validate_request_bytes_plan

MAX_ROW_BYTES = 131_072
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


def complete(receipt: Any) -> bool:
    return isinstance(receipt, dict) and receipt.get("complete") is True and receipt.get("failure") is None and type(receipt.get("status")) is int and 100 <= receipt["status"] <= 599 and "body" in receipt


def typed_not_found(receipt: Any) -> bool:
    body = receipt.get("body") if isinstance(receipt, dict) else None
    error = body.get("error") if isinstance(body, dict) else None
    return complete(receipt) and receipt["status"] == 404 and isinstance(error, dict) and type(error.get("code")) is int and error.get("code") == 404 and error.get("status") == "NOT_FOUND"


def _error_status(receipt: Any, status: str) -> bool:
    body = receipt.get("body") if isinstance(receipt, dict) else None
    error = body.get("error") if isinstance(body, dict) else None
    return complete(receipt) and receipt["status"] == 400 and isinstance(error, dict) and error.get("status") == status


def _document_fields(receipt: Any) -> dict[str, Any] | None:
    body = receipt.get("body") if isinstance(receipt, dict) else None
    fields = body.get("fields") if isinstance(body, dict) else None
    return fields if isinstance(fields, dict) else None


def owned_document(receipt: Any, resource: str, expected_digest: str, nonce: str) -> bool:
    body = receipt.get("body") if isinstance(receipt, dict) else None
    fields = _document_fields(receipt)
    return bool(
        complete(receipt)
        and receipt["status"] == 200
        and isinstance(body, dict)
        and body.get("name") == resource
        and isinstance(body.get("updateTime"), str)
        and _TIMESTAMP.fullmatch(body["updateTime"]) is not None
        and isinstance(fields, dict)
        and fields.get("_owner") == {"stringValue": nonce}
        and logical_fields_digest(fields) == expected_digest
    )


def commit_versions(receipt: Any, resources: list[str]) -> list[str] | None:
    if not complete(receipt) or receipt["status"] != 200:
        return None
    body = receipt.get("body")
    writes = body.get("writeResults") if isinstance(body, dict) else None
    if not isinstance(writes, list) or len(writes) != len(resources):
        return None
    versions: list[str] = []
    for item, resource in zip(writes, resources):
        if not isinstance(item, dict) or not isinstance(item.get("updateTime"), str) or not _TIMESTAMP.fullmatch(item["updateTime"]):
            return None
        if item.get("name", resource) != resource:
            return None
        versions.append(item["updateTime"])
    return versions


def readback_matches(receipt: Any, resource: str, expected_digest: str, nonce: str, version: str | None) -> bool:
    if not owned_document(receipt, resource, expected_digest, nonce):
        return False
    return version is None or receipt["body"].get("updateTime") == version


def validate_schedule(plan: dict[str, Any]) -> None:
    """Reject flat-array dispatch and require the compiler's exact schedule."""
    validate_request_bytes_plan(plan)
    expected = [
        item
        for probe in range(3)
        for item in ([{"phase": "observation", "index": i} for i in range(probe * 35, (probe + 1) * 35)] + [{"phase": "recovery", "index": i} for i in range(probe * 51, (probe + 1) * 51)])
    ]
    if plan.get("executionSchedule") != expected:
        raise ValueError("request-byte execution schedule drift")


def _safe_json(value: Any) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_ROW_BYTES:
        raise ValueError("row-too-large")
    return encoded


def _publish(directory: Path, name: str, value: Any) -> None:
    encoded = _safe_json(value) + b"\n"
    if "/" in name or name.startswith("."):
        raise ValueError("unsafe output filename")
    path = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _row(phase: str, index: int, operation: dict[str, Any], receipt: dict[str, Any], status: str, *, skipped: str | None = None) -> dict[str, Any]:
    body = operation.get("body")
    request_bytes = compact_utf8(body) if body is not None else b""
    row: dict[str, Any] = {
        "phase": phase,
        "index": index,
        "kind": operation.get("kind"),
        "probe": operation.get("probe"),
        "resource": operation.get("resource"),
        "method": operation.get("method"),
        "path": operation.get("path"),
        "requestBytes": len(request_bytes),
        "requestSha256": hashlib.sha256(request_bytes).hexdigest(),
        "status": status,
        "receipt": {key: value for key, value in receipt.items() if key not in {"body", "rawBody"}},
    }
    if skipped is not None:
        row["skipped"] = skipped
    response_body = receipt.get("body")
    if response_body is not None:
        raw = compact_utf8(response_body)
        row["responseBytes"] = min(len(raw), MAX_RESPONSE_BYTES)
        row["responseSha256"] = hashlib.sha256(raw[:MAX_RESPONSE_BYTES]).hexdigest()
    return row


def collect_local(plan: dict[str, Any], execute: Callable[[dict[str, Any]], dict[str, Any]], output: str | Path) -> dict[str, Any]:
    """Execute the immutable schedule and persist bounded rows in an exclusive directory."""
    validate_schedule(plan)
    plan = copy.deepcopy(plan)
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    if output.is_symlink():
        raise ValueError("output directory must not be a symlink")
    for probe in plan["probes"]:
        body = compact_utf8(probe["body"])
        if len(body) != probe["bodyBytes"] or len(body) > MAX_RESPONSE_BYTES * 8:
            # The request bodies are intentionally retained outside bounded rows.
            raise ValueError("unexpected compiled Commit body")
        _publish(output, f"request-{probe['label']}.json", {"probe": probe["label"], "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()})
        with (output / f"request-{probe['label']}.body").open("xb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())

    rows: list[dict[str, Any]] = []
    recovery: list[dict[str, Any]] = []
    versions: dict[str, list[str]] = {}
    ownership_reads: dict[tuple[str, str], dict[str, Any]] = {}
    dispatches = 0
    failures: list[str] = []
    for sequence, slot in enumerate(plan["executionSchedule"]):
        phase, index = slot["phase"], slot["index"]
        table = plan[phase]
        operation = copy.deepcopy(table[index])
        expected = copy.deepcopy(operation)
        if phase == "recovery" and operation["kind"] == "cleanup-version-bound-delete":
            key = (operation["probe"], operation["resource"])
            previous = ownership_reads.get(key)
            if previous is None or not owned_document(previous, operation["resource"], plan["documents"][operation["resource"]]["fieldsSha256"], plan["nonce"]):
                row = _row(phase, index, operation, {"complete": True, "failure": None}, "skipped", skipped="ownership-not-proven")
                recovery.append(row)
                _publish(output, f"row-{sequence:03d}.json", row)
                continue
            operation["path"] += "?currentDocument.updateTime=" + quote(previous["body"]["updateTime"], safe="")
        if phase == "recovery" and operation["kind"] == "cleanup-version-bound-delete":
            if operation["path"].split("?", 1)[0] != expected["path"]:
                raise ValueError("cleanup target drift")
        if operation.get("kind") == "conditional-create-commit":
            body = compact_utf8(operation["body"])
            if len(body) not in (10_485_759, 10_485_760, 10_485_761) or hashlib.sha256(body).hexdigest() != hashlib.sha256(compact_utf8(plan["probes"][{"under": 0, "exact": 1, "over": 2}[operation["probe"]]]["body"])).hexdigest():
                raise ValueError("compiled Commit identity drift")
        dispatches += 1
        try:
            receipt = execute(copy.deepcopy(operation))
            if not isinstance(receipt, dict):
                raise ValueError("executor returned non-object")
        except Exception as error:  # noqa: BLE001 - lost responses remain recoverable.
            receipt = {"complete": False, "failure": f"executor:{type(error).__name__}"}
        status = "complete" if complete(receipt) else "infrastructure-incomplete"
        if phase == "recovery" and operation["kind"] == "cleanup-ownership-read":
            ownership_reads[(operation["probe"], operation["resource"])] = receipt
        row = _row(phase, index, operation, receipt, status)
        (rows if phase == "observation" else recovery).append(row)
        _publish(output, f"row-{sequence:03d}.json", row)
        if operation["kind"] == "conditional-create-commit":
            probe = next(p for p in plan["probes"] if p["label"] == operation["probe"])
            found = commit_versions(receipt, probe["resources"])
            if found is not None:
                versions[operation["probe"]] = found
            elif operation["probe"] == "over" and not _error_status(receipt, "INVALID_ARGUMENT"):
                failures.append(f"{operation['probe']}:typed-refusal")
            elif operation["probe"] != "over" and complete(receipt):
                failures.append(f"{operation['probe']}:commit-proof")
        elif operation["kind"] == "preflight-typed-absence" and not typed_not_found(receipt):
            failures.append(f"{phase}:{index}:preflight-not-absent")
        elif operation["kind"] == "probe-readback":
            probe = next(p for p in plan["probes"] if p["label"] == operation["probe"])
            expected_document = plan["documents"][operation["resource"]]
            version = versions.get(operation["probe"], [None] * len(probe["resources"]))[probe["resources"].index(operation["resource"])] if operation["probe"] != "over" else None
            matches = typed_not_found(receipt) if operation["probe"] == "over" else readback_matches(receipt, operation["resource"], expected_document["fieldsSha256"], plan["nonce"], version)
            if not matches:
                failures.append(f"{phase}:{index}:readback-mismatch")
        elif operation["kind"] == "cleanup-ownership-read":
            expected_document = plan["documents"][operation["resource"]]
            if not (typed_not_found(receipt) or owned_document(receipt, operation["resource"], expected_document["fieldsSha256"], plan["nonce"])):
                failures.append(f"{phase}:{index}:unsafe-ownership-read")
        elif operation["kind"] == "cleanup-version-bound-delete" and not (status == "skipped" or (complete(receipt) and receipt["status"] == 200)):
            failures.append(f"{phase}:{index}:delete-failure")
        elif operation["kind"] == "cleanup-verify-absence" and not typed_not_found(receipt):
            failures.append(f"{phase}:{index}:cleanup-not-absent")
        if not complete(receipt) and operation["kind"] != "cleanup-version-bound-delete":
            failures.append(f"{phase}:{index}:incomplete")
    absence = all(row.get("kind") == "cleanup-verify-absence" and row.get("status") == "complete" for row in recovery if row.get("kind") == "cleanup-verify-absence")
    result = {
        "productionExecuted": False,
        "localOnly": True,
        "formalCompatibilityClaim": False,
        "rawHttpMetricStatus": "observation hypothesis",
        "canonicalRequestBytesMeasuredLocally": True,
        "planDigest": hashlib.sha256(compact_utf8(plan)).hexdigest(),
        "rows": rows,
        "recovery": recovery,
        "requestCount": dispatches,
        "resourceAbsence": absence,
        "cleanupComplete": absence and not failures,
        "completed": not failures,
        "failures": failures,
    }
    _publish(output, "result.json", result)
    return result
