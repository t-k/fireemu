"""Bounded collector for the partition/cursor observation plan.

The collector drives the compiled plan through one injected transport. Two
closed entry points bind the target: `collect_local` refuses any origin outside
the declared numeric loopback set, and `collect_production` refuses any origin
other than the one fixed production host. Each refuses before creating its
output directory or sending a single request, so neither can be steered at the
other's target. The production entry point is only reachable through the O8
launcher, which supplies a capability-bound transport; it grants no authority of
its own. Cleanup deletions are bound to receipts recorded in the same run; an
unproven version never authorizes a delete.
"""

# ruff: noqa: BLE001 -- Keep recording, cleanup and publication after any transport failure.
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

from partition_cursor_case import RECONSTRUCTION_SLOTS, validate_plan
from partition_cursor_wire import (
    PRODUCTION_ORIGIN,
    same_json,
    validate_origin,
    validate_production_origin,
    validate_receipt,
)

LOOPBACK_ORIGINS = frozenset({"http://127.0.0.1:8080", "http://[::1]:8080"})
DEFAULT_ORIGIN = "http://127.0.0.1:8080"
LOCAL_TARGET = "owned-local-artifact"
PRODUCTION_TARGET = "fixed-production-wire"
MAX_RAW_BYTES = 65536
BENIGN_SKIPS = frozenset({"no-page-token", "range-not-required"})
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$")


def _write_all(handle: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        count = os.write(handle, view)
        if count <= 0:
            raise OSError("no progress writing retained evidence")
        view = view[count:]


def _publish(directory_fd: int, filename: str, value: Any) -> None:
    """Publish one immutable file with an exclusive link and durable metadata."""
    payload = json.dumps(value, sort_keys=True, allow_nan=False).encode() + b"\n"
    temporary = filename + ".partial"
    handle = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd
    )
    try:
        _write_all(handle, payload)
        os.fsync(handle)
    finally:
        os.close(handle)
    try:
        os.link(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    finally:
        os.unlink(temporary, dir_fd=directory_fd)
    os.fsync(directory_fd)


def _publish_bytes(directory_fd: int, filename: str, payload: bytes) -> None:
    handle = os.open(
        filename,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o400,
        dir_fd=directory_fd,
    )
    try:
        _write_all(handle, payload)
        os.fsync(handle)
    finally:
        os.close(handle)
    os.fsync(directory_fd)


def _typed_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _normalize(receipt: Any) -> dict[str, Any]:
    """Keep only JSON-representable receipt members; raw bytes never leak here."""
    if not isinstance(receipt, dict):
        return {"status": None, "body": None, "complete": False}
    body = receipt.get("body")
    return {
        "status": receipt.get("status") if type(receipt.get("status")) is int else None,
        "body": body if isinstance(body, (dict, list)) or body is None else None,
        "complete": receipt.get("complete") is True,
        "contentType": receipt.get("contentType")
        if isinstance(receipt.get("contentType"), str)
        else None,
        "byteCount": receipt.get("byteCount")
        if type(receipt.get("byteCount")) is int
        else None,
    }


def _documents(body: Any) -> list[dict[str, Any]] | None:
    if not isinstance(body, list):
        return None
    found = []
    for entry in body:
        if not isinstance(entry, dict) or "error" in entry:
            return None
        if "document" in entry:
            document = entry["document"]
            if (not isinstance(document, dict) or "error" in document
                    or not isinstance(document.get("name"), str)
                    or not isinstance(document.get("fields"), dict)):
                return None
            found.append(document)
        elif not _typed_timestamp(entry.get("readTime")):
            # An arbitrary object/error is not an empty query result.
            return None
    return found


def _documents_match(expected: list[dict[str, Any]], body: Any) -> bool:
    found = _documents(body)
    if found is None or len(found) != len(expected):
        return False
    return all(
        document.get("name") == item["name"]
        and same_json(document.get("fields"), item["fields"])
        for document, item in zip(found, expected)
    )


def _cursor_valid(cursor: Any) -> bool:
    # This finite lane orders by __name__ only, not arbitrary field values.
    return (
        isinstance(cursor, dict)
        and set(cursor) <= {"values", "before"}
        and isinstance(cursor.get("values"), list) and len(cursor["values"]) == 1
        and isinstance(cursor["values"][0], dict)
        and set(cursor["values"][0]) == {"referenceValue"}
        and isinstance(cursor["values"][0]["referenceValue"], str)
        and bool(cursor["values"][0]["referenceValue"])
        and ("before" not in cursor or type(cursor["before"]) is bool)
    )


def _cursors_ordered(partitions: list[Any]) -> bool:
    if not all(_cursor_valid(item) for item in partitions):
        return False
    references = [item["values"][0]["referenceValue"] for item in partitions]
    return all(earlier < later for earlier, later in pairwise(references))


def _partitions(body: Any) -> list[Any] | None:
    if not isinstance(body, dict) or "error" in body:
        return None
    found = body.get("partitions", [])
    if not isinstance(found, list) or not all(_cursor_valid(item) for item in found):
        return None
    return found


def _any_typed_error(body: Any, http_status: int) -> bool:
    return (
        isinstance(body, dict) and set(body) == {"error"}
        and isinstance(body["error"], dict)
        and type(body["error"].get("code")) is int
        and body["error"]["code"] == http_status
        and isinstance(body["error"].get("status"), str)
        and bool(body["error"]["status"])
    )


def _typed_error(body: Any, status: str, http_status: int) -> bool:
    return _any_typed_error(body, http_status) and body["error"]["status"] == status


def _owned_root(body: Any, plan: dict[str, Any]) -> bool:
    return (
        isinstance(body, dict)
        and "error" not in body
        and body.get("name") == plan["ownedScope"]
        and same_json(body.get("fields"), {"marker": {"stringValue": plan["campaignId"]}})
        and _typed_timestamp(body.get("updateTime"))
    )


def _write_versions(body: Any, count: int) -> list[str] | None:
    if not isinstance(body, dict) or "error" in body or not _typed_timestamp(body.get("commitTime")):
        return None
    results = body.get("writeResults")
    if not isinstance(results, list) or len(results) != count:
        return None
    versions = []
    for result in results:
        if not isinstance(result, dict) or "error" in result or not _typed_timestamp(
            result.get("updateTime")
        ):
            return None
        versions.append(result["updateTime"])
    return versions


def _matches(
    plan: dict[str, Any], operation: dict[str, Any], receipt: dict[str, Any]
) -> bool:
    expect, body, status = operation["expect"], receipt["body"], receipt["status"]
    if not receipt["complete"]:
        return False
    if "statuses" in expect:
        if status not in expect["statuses"]:
            return False
    elif status != expect["status"]:
        return False
    if expect.get("typed") and not _typed_error(body, expect["typed"], status):
        return False
    if expect.get("typedOpen") and not _any_typed_error(body, status):
        return False
    if expect.get("outcome") == "refused":
        return True
    kind = operation["kind"]
    if kind in ("create-only-patch", "cleanup-ownership-read"):
        return _typed_error(body, "NOT_FOUND", 404) if status == 404 else _owned_root(body, plan)
    if kind in ("seed-commit", "cleanup-seed-delete"):
        if expect.get("updateTimes") is False:
            # A delete never reports an update time, so only the result count and
            # the commit time bind this receipt.
            return (
                isinstance(body, dict) and "error" not in body
                and isinstance(body.get("writeResults"), list)
                and all(isinstance(item, dict) and "error" not in item for item in body["writeResults"])
                and len(body["writeResults"]) == expect["writeResults"]
                and _typed_timestamp(body.get("commitTime"))
            )
        return _write_versions(body, expect["writeResults"]) is not None
    if kind == "cleanup-root-delete":
        return isinstance(body, dict) and not body
    if "documents" in expect:
        return _documents_match(expect["documents"], body)
    if expect.get("documentsAsserted") is False and "maxPartitions" in expect:
        partitions = _partitions(body)
        return (
            partitions is not None
            and len(partitions) <= expect["maxPartitions"]
            and _cursors_ordered(partitions)
            and all(item["values"][0]["referenceValue"] in operation["targetResources"] for item in partitions)
        )
    if expect.get("reconstruction"):
        return _documents(body) is not None
    return status == expect.get("status")


def _row(phase: str, index: int, operation: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase": phase,
        "index": index,
        "kind": operation["kind"],
        "status": "skipped",
        "skipReason": None,
        "request": None,
        "receipt": None,
        "boundFrom": None,
        "raw": {"present": False, "reason": "not-dispatched"},
    }


def _request(phase: str, index: int, operation: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase": phase,
        "index": index,
        "kind": operation["kind"],
        "method": operation["method"],
        "path": operation["path"],
        "body": copy.deepcopy(operation["body"]),
    }


def _bind_page_token(
    operation: dict[str, Any], rows: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, str | None, dict[str, Any] | None]:
    source = rows[operation["pageTokenFrom"]]
    body = (source["receipt"] or {}).get("body") if source["status"] == "pass" else None
    token = body.get("nextPageToken") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        return None, "no-page-token", None
    request = _request("observation", operation["index"], operation)
    request["body"]["pageToken"] = token
    return request, None, {"pageTokenFrom": operation["pageTokenFrom"]}


def _bind_reconstruction(
    operation: dict[str, Any], rows: list[dict[str, Any]]
) -> tuple[dict[str, Any] | None, str | None, dict[str, Any] | None]:
    source = rows[operation["cursorFrom"]]
    receipt = source["receipt"] or {}
    if source["status"] in {"skipped", "failed"} or receipt.get("status") != 200:
        # A refused or undispatched partition response never authorizes a
        # reconstruction range, which would otherwise read the whole query.
        return None, "no-partition-response", None
    partitions = _partitions(receipt.get("body"))
    if partitions is None:
        return None, "malformed-partition-cursor", None
    ranges = len(partitions) + 1
    if ranges > RECONSTRUCTION_SLOTS:
        return None, "reconstruction-slots-exceeded", None
    slot = operation["reconstructionSlot"]
    if (source["status"] != "pass" or not _cursors_ordered(partitions)
            or any(item["values"][0]["referenceValue"] not in operation["targetResources"] for item in partitions)):
        return None, "unusable-partition-response", None
    if slot >= ranges:
        return None, "range-not-required", None
    request = _request("observation", operation["index"], operation)
    query = request["body"]["structuredQuery"]
    if slot:
        query["startAt"] = copy.deepcopy(partitions[slot - 1])
    if slot < len(partitions):
        query["endAt"] = copy.deepcopy(partitions[slot])
    return (
        request,
        None,
        {"cursorFrom": operation["cursorFrom"], "reconstructionSlot": slot},
    )


def _bind_recovery(
    operation: dict[str, Any],
    plan: dict[str, Any],
    rows: list[dict[str, Any]],
    index: int,
    cleanup: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, str | None, dict[str, Any] | None]:
    created = next(
        (row for row in rows if row["kind"] == "create-only-patch"), {"status": None}
    )
    ownership = next(
        (row for row in cleanup if row["kind"] == "cleanup-ownership-read"),
        {"status": None},
    )
    readable = (ownership.get("receipt") or {}).get("status") == 200
    if created["status"] != "pass" or ownership["status"] != "pass" or not readable:
        # Only a creation this run made, still readable as ours right now,
        # authorizes a delete. A 404 ownership read satisfies the plan's
        # expectation but proves no ownership, so it must not authorize one.
        # The recorded version precondition is the second guard.
        return None, "no-current-run-ownership", None
    request = _request("recovery", index, operation)
    if operation["kind"] == "cleanup-seed-delete":
        versions = _write_versions(
            (rows[operation["versionFrom"]]["receipt"] or {}).get("body"),
            len(plan["ownedResources"]) - 1,
        )
        if rows[operation["versionFrom"]]["status"] != "pass" or versions is None:
            return None, "unbound-write-versions", None
        for write, version in zip(request["body"]["writes"], versions):
            write["currentDocument"] = {"updateTime": version}
        return request, None, {"versionFrom": operation["versionFrom"]}
    version = (rows[operation["versionFrom"]]["receipt"] or {}).get("body")
    version = version.get("updateTime") if isinstance(version, dict) else None
    if not _typed_timestamp(version):
        return None, "unbound-root-version", None
    request["path"] = request["path"] + "?currentDocument.updateTime=" + version
    return request, None, {"versionFrom": operation["versionFrom"]}


def _retain_raw(
    receipt: Any, row: dict[str, Any], raw_fd: int, bindings: list[dict[str, Any]]
) -> None:
    payload = receipt.get("rawBody") if isinstance(receipt, dict) else None
    if not isinstance(payload, (bytes, bytearray)):
        row["raw"] = {"present": False, "reason": "no-transport-bytes"}
        return
    payload = bytes(payload)
    if len(payload) > MAX_RAW_BYTES:
        row["raw"] = {"present": False, "reason": "oversized"}
        return
    if receipt.get("complete") is not True or type(receipt.get("byteCount")) is not int or receipt.get("byteCount") != len(payload):
        row["raw"] = {"present": False, "reason": "incomplete-transport-bytes"}
        return
    name = f"{row['phase']}-{row['index']:02d}.raw"
    try:
        _publish_bytes(raw_fd, name, payload)
    except Exception as error:
        row["raw"] = {"present": False, "reason": type(error).__name__}
        return
    binding = {
        "phase": row["phase"],
        "index": row["index"],
        "kind": row["kind"],
        "path": name,
        "byteCount": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    bindings.append(binding)
    row["raw"] = {
        "present": True,
        "path": name,
        "byteCount": binding["byteCount"],
        "sha256": binding["sha256"],
    }


def _verify_raw(raw_fd: int, bindings: list[dict[str, Any]]) -> bool:
    """Re-read every sidecar through the retained directory fd, never by path."""
    for binding in bindings:
        handle = os.open(binding["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=raw_fd)
        try:
            info = os.fstat(handle)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RAW_BYTES:
                return False
            payload = b""
            while len(payload) <= MAX_RAW_BYTES:
                chunk = os.read(handle, MAX_RAW_BYTES + 1 - len(payload))
                if not chunk:
                    break
                payload += chunk
        finally:
            os.close(handle)
        if (
            len(payload) != binding["byteCount"]
            or hashlib.sha256(payload).hexdigest() != binding["sha256"]
        ):
            return False
    return True


def _reconstruction(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Prove the partition ranges rebuild the baseline query, in order.

    A range set that merely returns documents proves nothing; the campaign's
    claim is that concatenating the ranges reproduces the unpartitioned result.
    """
    baseline = next(
        (row for row in rows if row["kind"] == "baseline-group-name-order"), None
    )
    slots = [row for row in rows if row["kind"].startswith("partition-reconstruction")]
    if baseline is None or baseline["status"] != "pass" or not slots:
        return {"checked": False, "reason": "no-baseline", "matches": None}
    dispatched = [row for row in slots if row["status"] != "skipped"]
    if not dispatched or any(row["status"] == "failed" for row in dispatched):
        return {"checked": False, "reason": "no-dispatched-range", "matches": None}
    expected = _documents((baseline["receipt"] or {}).get("body"))
    joined: list[dict[str, Any]] = []
    for row in dispatched:
        found = _documents((row["receipt"] or {}).get("body"))
        if found is None:
            return {"checked": False, "reason": "malformed-range", "matches": None}
        joined.extend(found)
    if expected is None:
        return {"checked": False, "reason": "malformed-baseline", "matches": None}
    names = [document.get("name") for document in joined]
    return {
        "checked": True,
        "matches": same_json(
            [{"name": doc["name"], "fields": doc["fields"]} for doc in joined],
            [{"name": doc["name"], "fields": doc["fields"]} for doc in expected],
        ),
        "ranges": len(dispatched),
        "documents": len(names),
        "reason": None,
    }


def publish_row(
    directory_fd: int,
    raw_fd: int,
    row: dict[str, Any],
    receipt: Any,
    bindings: list[dict[str, Any]],
    publication: dict[str, Any],
) -> None:
    """Retain one dispatched row outside the compiled plan with the same boundary.

    The production recovery ladder issues per-document reads and deletes the
    compiled plan does not carry. They are retained exactly like plan rows: a
    raw sidecar when the transport supplied complete bytes, then an immutable
    row file. Nothing here grants cleanup authority.
    """
    _retain_raw(receipt, row, raw_fd, bindings)
    _record(publication, directory_fd, row)


def collect_local(
    plan: dict[str, Any],
    transmit: Callable[[dict[str, Any]], Any],
    directory: str | Path,
    *,
    origin: str = DEFAULT_ORIGIN,
) -> dict[str, Any]:
    """Drive the compiled plan against one owned loopback artifact."""
    validate_plan(plan)
    validate_origin(origin)
    return _collect(plan, transmit, directory, origin=origin, target=LOCAL_TARGET)


def collect_production(
    plan: dict[str, Any],
    transmit: Callable[[dict[str, Any]], Any],
    directory: str | Path,
    *,
    origin: str = PRODUCTION_ORIGIN,
) -> dict[str, Any]:
    """Drive the compiled plan against the fixed production origin only.

    A loopback origin is refused here. The transport is the caller's: the O8
    launcher binds it to a consumed capability and to the shared Gate, and this
    function adds no wire of its own.
    """
    validate_plan(plan)
    validate_production_origin(origin)
    return _collect(
        plan, transmit, directory, origin=origin, target=PRODUCTION_TARGET
    )


def _collect(
    plan: dict[str, Any],
    transmit: Callable[[dict[str, Any]], Any],
    directory: str | Path,
    *,
    origin: str,
    target: str,
) -> dict[str, Any]:
    plan = copy.deepcopy(plan)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    (directory / "raw").mkdir(mode=0o700)
    directory_fd = os.open(directory, os.O_RDONLY)
    raw_fd = os.open(directory / "raw", os.O_RDONLY)
    bindings: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    cleanup: list[dict[str, Any]] = []
    publication: dict[str, Any] = {"complete": True, "failures": []}
    try:
        _run_phase(
            plan,
            transmit,
            plan["observation"],
            "observation",
            rows,
            raw_fd,
            bindings,
            publication,
            directory_fd,
        )
        _run_recovery(
            plan, transmit, rows, cleanup, raw_fd, bindings, publication, directory_fd
        )
        result = _result(
            plan, origin, rows, cleanup, bindings, publication, raw_fd, target
        )
        try:
            _publish(raw_fd, "manifest.json", {"bindings": bindings})
        except Exception as error:
            publication["complete"] = False
            publication["failures"].append(
                {"file": "raw/manifest.json", "error": type(error).__name__}
            )
            result = _result(
                plan, origin, rows, cleanup, bindings, publication, raw_fd, target
            )
        try:
            _publish(directory_fd, "collection.json", result)
        except Exception as error:
            publication["complete"] = False
            publication["failures"].append(
                {"file": "collection.json", "error": type(error).__name__}
            )
            result["publication"] = copy.deepcopy(publication)
            result["status"] = "incomplete"
        return result
    finally:
        os.close(raw_fd)
        os.close(directory_fd)


def _dispatch(
    plan: dict[str, Any],
    transmit: Callable[[dict[str, Any]], Any],
    operation: dict[str, Any],
    row: dict[str, Any],
    request: dict[str, Any],
    raw_fd: int,
    bindings: list[dict[str, Any]],
) -> None:
    row["request"] = copy.deepcopy(request)
    try:
        receipt = transmit(request)
    except Exception as error:
        row["status"] = "failed"
        row["failure"] = type(error).__name__
        row["raw"] = {"present": False, "reason": "transport-failure"}
        return
    # Own the response snapshot before any caller can mutate it. Persist raw bytes
    # for diagnostics, but never derive authorization from mismatching JSON.
    try:
        receipt = copy.deepcopy(receipt)
        decoded = validate_receipt(receipt)
        row["receipt"] = _normalize(receipt)
        row["receipt"]["body"] = decoded
        row["status"] = "pass" if _matches(plan, operation, row["receipt"]) else "mismatch"
    except Exception as error:
        row["receipt"] = {"status": None, "body": None, "complete": False}
        row["status"] = "failed"
        row["failure"] = type(error).__name__
        row["evidenceFailure"] = True
    _retain_raw(receipt, row, raw_fd, bindings)


def _run_phase(
    plan: dict[str, Any],
    transmit: Callable[[dict[str, Any]], Any],
    operations: list[dict[str, Any]],
    phase: str,
    rows: list[dict[str, Any]],
    raw_fd: int,
    bindings: list[dict[str, Any]],
    publication: dict[str, Any],
    directory_fd: int,
) -> None:
    aborted = False
    for index, operation in enumerate(operations):
        row = _row(phase, index, operation)
        rows.append(row)
        bound: dict[str, Any] | None = None
        if aborted:
            row["skipReason"] = "aborted-after-failure"
        else:
            request: dict[str, Any] | None
            if "pageTokenFrom" in operation:
                request, reason, bound = _bind_page_token(
                    {**operation, "index": index}, rows
                )
            elif "reconstructionSlot" in operation:
                request, reason, bound = _bind_reconstruction(
                    {**operation, "index": index}, rows
                )
            else:
                request, reason = _request(phase, index, operation), None
            if reason:
                row["skipReason"] = reason
            else:
                row["boundFrom"] = bound
                _dispatch(plan, transmit, operation, row, request, raw_fd, bindings)
                aborted = row["status"] == "failed" or (
                    operation["kind"] in {"preflight-typed-absence", "create-only-patch", "seed-commit"}
                    and row["status"] != "pass"
                )
        _record(publication, directory_fd, row)


def _run_recovery(
    plan: dict[str, Any],
    transmit: Callable[[dict[str, Any]], Any],
    rows: list[dict[str, Any]],
    cleanup: list[dict[str, Any]],
    raw_fd: int,
    bindings: list[dict[str, Any]],
    publication: dict[str, Any],
    directory_fd: int,
) -> None:
    for index, operation in enumerate(plan["recovery"]):
        row = _row("recovery", index, operation)
        cleanup.append(row)
        if "versionFrom" in operation:
            request, reason, bound = _bind_recovery(
                operation, plan, rows, index, cleanup
            )
            if reason:
                row["skipReason"] = reason
                _record(publication, directory_fd, row)
                continue
            row["boundFrom"] = bound
        else:
            request = _request("recovery", index, operation)
        _dispatch(plan, transmit, operation, row, request, raw_fd, bindings)
        _record(publication, directory_fd, row)


def _record(
    publication: dict[str, Any], directory_fd: int, row: dict[str, Any]
) -> None:
    name = f"row-{row['phase']}-{row['index']:02d}.json"
    try:
        _publish(directory_fd, name, row)
    except Exception as error:
        publication["complete"] = False
        publication["failures"].append({"file": name, "error": type(error).__name__})


def _result(
    plan: dict[str, Any],
    origin: str,
    rows: list[dict[str, Any]],
    cleanup: list[dict[str, Any]],
    bindings: list[dict[str, Any]],
    publication: dict[str, Any],
    raw_fd: int,
    target: str = LOCAL_TARGET,
) -> dict[str, Any]:
    dispatched = [row for row in rows + cleanup if row["status"] != "skipped"]
    verified = False
    try:
        verified = bool(dispatched) and _verify_raw(raw_fd, bindings)
    except Exception as error:
        # An unreadable sidecar must not stop the receipt from being published,
        # but it is a publication failure and must be recorded as one.
        publication["complete"] = False
        publication["failures"].append({"file": "raw", "error": type(error).__name__})
    raw_complete = (
        verified
        and len(bindings) == len(dispatched)
        and all(row["raw"]["present"] for row in dispatched)
    )
    cleanup_complete = all(row["status"] == "pass" for row in cleanup)
    reconstruction = _reconstruction(rows)
    healthy = (
        all(
            row["status"] == "pass"
            or (row["status"] == "skipped" and row["skipReason"] in BENIGN_SKIPS)
            for row in rows
        )
        and cleanup_complete
        and raw_complete
        and publication["complete"]
        and reconstruction["matches"] is True
    )
    return {
        "schemaVersion": 1,
        "campaignId": plan["campaignId"],
        "planDigest": plan["planDigest"],
        "project": plan["project"],
        "database": plan["database"],
        "nonce": plan["nonce"],
        "ownedScope": plan["ownedScope"],
        "groupCollection": plan["groupCollection"],
        "origin": origin,
        "target": target,
        # The flag states which wire the rows came from, never a verdict: a
        # production bundle is still compared, never promoted, by the lane.
        "productionExecuted": target == PRODUCTION_TARGET,
        "promotionReady": False,
        "status": "pass" if healthy else "incomplete",
        "rows": copy.deepcopy(rows),
        "cleanup": {"complete": cleanup_complete, "rows": copy.deepcopy(cleanup)},
        "raw": {"complete": raw_complete, "bindings": len(bindings)},
        "reconstruction": reconstruction,
        "publication": copy.deepcopy(publication),
    }
