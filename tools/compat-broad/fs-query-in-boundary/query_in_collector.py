"""Credential-free bounded collection for the compiled IN query case."""

from __future__ import annotations

import base64
import binascii
import copy
import json
import os
import re
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from query_in_compiler import validate_plan
from query_in_production import (
    RawJournal,
    _reject_json_constant,
    _unique_json_object,
)

_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
_MAX_SERIALIZED_RECEIPT_BYTES = 131072
_MAX_RAW_BYTES = 65536
_MAX_RAW_BASE64 = 4 * ((_MAX_RAW_BYTES + 2) // 3)


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


def _owned_version(
    receipt: Any,
    resource: str,
    fields: dict[str, Any],
    update_time: str,
    create_time: str | None,
) -> bool:
    if not _owned(receipt, resource, fields):
        return False
    body = receipt["body"]
    if body.get("updateTime") != update_time:
        return False
    return create_time is None or body.get("createTime") == create_time


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


def _publish(directory_fd: int, filename: str, value: Any) -> None:
    """Publish one bounded JSON row atomically without replacing an existing row."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )
    if len(encoded) > _MAX_SERIALIZED_RECEIPT_BYTES:
        raise ValueError("row-too-large")
    temporary: str | None = None
    try:
        for _ in range(8):
            candidate = ".receipt-" + secrets.token_hex(12)
            try:
                temporary_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_fd,
                )
                temporary = candidate
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError("temporary receipt name collision")
        with os.fdopen(temporary_fd, "wb") as stream:
            stream.write(encoded)
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(
            temporary,
            filename,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=directory_fd)
        temporary = None
        os.fsync(directory_fd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
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


def _transport_raw(receipt: Any) -> tuple[bytes, int | None, str, bool] | None:
    """Extract exact transport evidence; a decoded body is never a raw substitute."""
    if not isinstance(receipt, dict):
        return None
    raw_value = receipt.get("rawBody")
    if "rawBody" in receipt and not isinstance(raw_value, bytes):
        return None
    raw: bytes | None = raw_value
    encoded = receipt.get("rawBodyBase64")
    decoded: bytes | None = None
    if "rawBodyBase64" in receipt and not isinstance(encoded, str):
        return None
    if isinstance(encoded, str):
        if len(encoded) > _MAX_RAW_BASE64:
            return None
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            return None
        if len(decoded) > _MAX_RAW_BYTES:
            return None
    if raw is not None and decoded is not None:
        if raw != decoded:
            return None
    elif raw is None:
        raw = decoded
    if raw is None:
        return None
    if len(raw) > _MAX_RAW_BYTES:
        return None
    body_bytes = receipt.get("bodyBytes")
    raw_body_bytes = receipt.get("rawBodyBytes")
    if "bodyBytes" in receipt and (type(body_bytes) is not int or body_bytes != len(raw)):
        return None
    if "rawBodyBytes" in receipt and (
        type(raw_body_bytes) is not int or raw_body_bytes != len(raw)
    ):
        return None
    status = receipt.get("status")
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        return None
    complete = receipt.get("complete")
    content_type = receipt.get("contentType")
    if type(complete) is not bool or not isinstance(content_type, str):
        return None
    return raw, status, content_type, complete


def _discard_raw_fields(row: dict[str, Any]) -> None:
    for key in ("rawBody", "rawBodyBase64", "rawBodyBytes", "bodyBytes"):
        row.pop(key, None)


def _has_raw_fields(receipt: Any) -> bool:
    return isinstance(receipt, dict) and any(
        key in receipt
        for key in ("rawBody", "rawBodyBase64", "rawBodyBytes", "bodyBytes", "contentType")
    )


def _raw_matches_row(journal: RawJournal, binding: dict[str, Any], row: dict[str, Any]) -> bool:
    """Ensure complete raw JSON remains bound to its compact receipt."""
    if binding.get("contentType", "").split(";", 1)[0].strip().lower() != "application/json":
        return False
    fd = os.open(binding["path"], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=journal._fd)
    try:
        with os.fdopen(fd, "rb") as stream:
            encoded = stream.read(_MAX_RAW_BYTES + 1)
    except BaseException:  # noqa: BLE001 -- close the descriptor on any read failure.
        try:
            os.close(fd)
        except OSError:
            pass
        return False
    if len(encoded) > _MAX_RAW_BYTES:
        return False
    try:
        parsed = json.loads(
            encoded,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeError, ValueError, RecursionError):
        return False
    if binding.get("phase") == "observation" and binding.get("index") == 2:
        view = journal.semantic_view(binding)
        body = row.get("body")
        return (
            "difference" not in view
            and isinstance(view.get("documents"), list)
            and isinstance(body, dict)
            and view["documents"] == body.get("documents")
        )
    return parsed == row.get("body")


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
    output_fd: int | None = None
    parent_fd: int | None = None
    raw_journal: RawJournal | None = None
    raw_bindings: list[dict[str, Any]] = []
    raw_failures: list[str] = []
    try:
        parent_fd = os.open(
            output.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        os.mkdir(output.name, mode=0o700, dir_fd=parent_fd)
        output_fd = os.open(
            output.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    except Exception as error:  # noqa: BLE001 -- report local recording failure.
        persistence_complete = False
        persistence_failures.append(f"output-init:{type(error).__name__}")

    def persist(filename: str, value: Any) -> None:
        nonlocal persistence_complete
        if not persistence_complete and persistence_failures:
            return
        try:
            if output_fd is None:
                raise OSError("output directory is not owned")
            _publish(output_fd, filename, value)
        except Exception as error:  # noqa: BLE001 -- preserve rows and cleanup responsibility.
            persistence_complete = False
            persistence_failures.append(f"{filename}:{type(error).__name__}")

    def dispatch(operation: dict[str, Any]) -> dict[str, Any]:
        try:
            received = execute(copy.deepcopy(operation))
            if isinstance(received, dict):
                raw_fields = {
                    key: received[key]
                    for key in ("rawBody", "rawBodyBase64", "rawBodyBytes", "bodyBytes", "contentType")
                    if key in received
                }
                normalized = _normalize(
                    {key: value for key, value in received.items() if key not in raw_fields}
                )
                normalized.update(raw_fields)
                return normalized
            return _normalize(received)
        except Exception as error:  # noqa: BLE001 -- ambiguous calls require recovery.
            return {
                "complete": False,
                "failure": f"local-executor:{type(error).__name__}",
            }

    def publish_raw(phase: str, index: int, receipt: dict[str, Any], row: dict[str, Any]) -> None:
        nonlocal raw_journal
        evidence = _transport_raw(receipt)
        if evidence is None:
            if _has_raw_fields(receipt):
                raw_failures.append(f"{phase}-{index}:response-bytes-unavailable")
            return
        try:
            if raw_journal is None:
                raw_journal = RawJournal(output / "raw")
            raw, status, content_type, complete = evidence
            binding = raw_journal.add(
                phase, index, status, raw, complete=complete, content_type=content_type
            )
            row["raw"] = copy.deepcopy(binding)
            raw_bindings.append({"phase": phase, "index": index, **copy.deepcopy(binding)})
            for key in ("rawBody", "rawBodyBase64", "rawBodyBytes", "bodyBytes"):
                row.pop(key, None)
            if complete:
                try:
                    row["semanticView"] = raw_journal.semantic_view(binding)
                except ValueError as error:
                    row["semanticView"] = {"difference": f"raw-view:{type(error).__name__}"}
        except Exception as error:  # noqa: BLE001 -- retain compact evidence and report raw failure.
            raw_failures.append(f"{phase}-{index}:raw-publication-{type(error).__name__}")
        else:
            pass
        finally:
            _discard_raw_fields(row)

    # Without an owned journal directory, no wire result can be retained.
    if output_fd is None or not persistence_complete:
        result = {
            "productionExecuted": False,
            "localOnly": True,
            "acquisitionValidated": False,
            "promotionReady": False,
            "recordingComplete": False,
            "cleanupComplete": False,
            "completed": False,
            "rows": [],
            "cleanup": [],
            "resourceAbsence": {plan["document"]: False},
            "attemptedResources": [],
            "semanticMismatches": [],
            "infrastructureFailures": persistence_failures,
            "persistenceComplete": False,
        }
        if output_fd is not None:
            os.close(output_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        return result

    rows: list[dict[str, Any]] = []
    semantic: list[dict[str, Any]] = []
    infrastructure: list[str] = []
    attempted = False
    create_proven = False
    created_update_time: str | None = None
    created_create_time: str | None = None
    stop_observation = False
    for index, declared in enumerate(plan["observation"]):
        if stop_observation:
            break
        operation = copy.deepcopy(declared)
        if operation["kind"] == "create-only-patch":
            attempted = True
        receipt = dispatch(operation)
        if operation["kind"] == "create-only-patch":
            create_proven = _owned(receipt, plan["document"], plan["fixtureFields"])
            if create_proven:
                created_update_time = receipt["body"]["updateTime"]
                created_create_time = receipt["body"].get("createTime")
        row = _row(index, operation, receipt)
        publish_raw("observation", index, receipt, row)
        _discard_raw_fields(row)
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
            elif create_proven and _owned_version(
                prior,
                plan["document"],
                plan["fixtureFields"],
                created_update_time or "",
                created_create_time,
            ):
                operation["path"] += "?currentDocument.updateTime=" + quote(
                    prior["body"]["updateTime"], safe=""
                )
                row = _row(index, operation, dispatch(operation))
            else:
                row = _skip(
                    index,
                    operation,
                    ("create-not-proven" if attempted else "unsafe-delete")
                    if not create_proven
                    else "create-version-mismatch",
                )
        else:
            receipt = dispatch(operation)
            row = _row(index, operation, receipt)
        cleanup.append(row)
        if operation["kind"] != "cleanup-conditional-delete" or "skipped" not in row:
            publish_raw("recovery", index, row, row)
        _discard_raw_fields(row)
        persist(f"recovery-{index:02d}.json", row)
        if operation["kind"] != "cleanup-conditional-delete" and not _complete(row):
            infrastructure.append(f"recovery-{index}:incomplete")
        if (
            operation["kind"] == "cleanup-conditional-delete"
            and row.get("skipped")
            in {"unsafe-delete", "create-not-proven", "create-version-mismatch"}
        ):
            semantic.append({"phase": "recovery", "index": index, "reason": row["skipped"]})
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
    raw_semantic_mismatch = False
    if raw_journal is not None:
        reloaded: RawJournal | None = None
        try:
            raw_journal.close()
            reloaded = RawJournal.reload(output / "raw")
            for candidate in [*rows, *cleanup]:
                binding = candidate.get("raw")
                if isinstance(binding, dict):
                    candidate["semanticView"] = reloaded.semantic_view(binding)
                    if binding.get("complete") is True and not _raw_matches_row(
                        reloaded, binding, candidate
                    ):
                        raw_semantic_mismatch = True
            positive = next((row for row in rows if row.get("index") == 2), None)
            if positive is not None:
                view = positive.get("semanticView")
                compact_documents = (
                    positive.get("body", {}).get("documents")
                    if isinstance(positive.get("body"), dict)
                    else None
                )
                raw_semantic_mismatch = raw_semantic_mismatch or not (
                    isinstance(view, dict)
                    and isinstance(view.get("documents"), list)
                    and view["documents"] == compact_documents
                )
        except Exception as error:  # noqa: BLE001 -- compact publication remains available.
            raw_failures.append(f"raw-manifest:reload-{type(error).__name__}")
            raw_semantic_mismatch = True
        finally:
            if reloaded is not None:
                reloaded.close()
    raw_attempted = bool(raw_bindings or raw_failures)
    raw_verified_completed = (
        not raw_attempted
        or (
            len(raw_bindings) == 9
            and all(binding.get("complete") is True for binding in raw_bindings)
            and not raw_failures
            and not raw_semantic_mismatch
        )
    )
    result = {
        "productionExecuted": False,
        "localOnly": True,
        "acquisitionValidated": False,
        "promotionReady": False,
        "recordingComplete": recording_complete and persistence_complete,
        "cleanupComplete": recovery_ok and persistence_complete,
        "completed": recording_complete and recovery_ok and persistence_complete and not infrastructure and raw_verified_completed,
        "rows": rows,
        "cleanup": cleanup,
        "resourceAbsence": {plan["document"]: absence},
        "attemptedResources": [plan["document"]] if attempted else [],
        "semanticMismatches": semantic,
        "infrastructureFailures": infrastructure + persistence_failures,
        "persistenceComplete": persistence_complete,
        "rawBindings": raw_bindings,
        "rawComplete": (
            len(raw_bindings) == 9
            and all(binding.get("complete") is True for binding in raw_bindings)
            and not raw_failures
            and not raw_semantic_mismatch
        ),
        "rawFailures": raw_failures,
        "rawSemanticMismatch": raw_semantic_mismatch,
        "rawVerifiedCompleted": raw_verified_completed,
        "rawManifest": "raw/manifest.json" if raw_bindings else None,
    }
    persist("collection.json", result)
    # Cleanup is an observed fact even when final journal publication fails.
    if not persistence_complete:
        result["persistenceComplete"] = False
        result["recordingComplete"] = False
        result["cleanupComplete"] = recovery_ok
        result["completed"] = False
        result["infrastructureFailures"] = infrastructure + persistence_failures
    if output_fd is not None:
        os.close(output_fd)
    if parent_fd is not None:
        os.close(parent_fd)
    return result
