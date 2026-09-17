"""Bounded, local-only acquisition for the compiled request-byte plan."""

from __future__ import annotations

import base64
import copy
import errno
import hashlib
import json
import os
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from request_bytes_compiler import (
    compact_utf8,
    logical_fields_digest,
    validate_request_bytes_plan,
)

MAX_ROW_BYTES = 131_072
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")


def _valid_timestamp(value: str) -> bool:
    if _TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _raw_matches_body(raw: bytes, body: Any) -> bool:
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return isinstance(body, str) and body == raw.decode("utf-8", errors="replace")
    return type(parsed) is type(body) and parsed == body


def complete(receipt: Any) -> bool:
    return (
        isinstance(receipt, dict)
        and receipt.get("complete") is True
        and receipt.get("failure") is None
        and type(receipt.get("status")) is int
        and 100 <= receipt["status"] <= 599
        and "body" in receipt
    )


def typed_not_found(receipt: Any) -> bool:
    body = receipt.get("body") if isinstance(receipt, dict) else None
    error = body.get("error") if isinstance(body, dict) else None
    return (
        complete(receipt)
        and receipt["status"] == 404
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error.get("code") == 404
        and error.get("status") == "NOT_FOUND"
    )


def _error_status(receipt: Any, status: str) -> bool:
    body = receipt.get("body") if isinstance(receipt, dict) else None
    error = body.get("error") if isinstance(body, dict) else None
    return (
        complete(receipt)
        and receipt["status"] == 400
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error.get("code") == 400
        and error.get("status") == status
    )


def _document_fields(receipt: Any) -> dict[str, Any] | None:
    body = receipt.get("body") if isinstance(receipt, dict) else None
    fields = body.get("fields") if isinstance(body, dict) else None
    return fields if isinstance(fields, dict) else None


def owned_document(
    receipt: Any, resource: str, expected_digest: str, nonce: str
) -> bool:
    body = receipt.get("body") if isinstance(receipt, dict) else None
    fields = _document_fields(receipt)
    return bool(
        complete(receipt)
        and receipt["status"] == 200
        and isinstance(body, dict)
        and body.get("name") == resource
        and isinstance(body.get("updateTime"), str)
        and _valid_timestamp(body["updateTime"])
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
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("updateTime"), str)
            or not _valid_timestamp(item["updateTime"])
        ):
            return None
        if item.get("name", resource) != resource:
            return None
        versions.append(item["updateTime"])
    return versions


def readback_matches(
    receipt: Any, resource: str, expected_digest: str, nonce: str, version: str | None
) -> bool:
    if not owned_document(receipt, resource, expected_digest, nonce):
        return False
    return version is None or receipt["body"].get("updateTime") == version


def validate_schedule(plan: dict[str, Any]) -> None:
    """Reject flat-array dispatch and require the compiler's exact schedule."""
    validate_request_bytes_plan(plan)
    expected = [
        item
        for probe in range(3)
        for item in (
            [
                {"phase": "observation", "index": i}
                for i in range(probe * 35, (probe + 1) * 35)
            ]
            + [
                {"phase": "recovery", "index": i}
                for i in range(probe * 51, (probe + 1) * 51)
            ]
        )
    ]
    if plan.get("executionSchedule") != expected:
        raise ValueError("request-byte execution schedule drift")


def _safe_json(value: Any) -> bytes:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if len(encoded) > MAX_ROW_BYTES:
        raise ValueError("row-too-large")
    return encoded


def _publish(directory: int, name: str, value: Any, *, bounded: bool = True) -> None:
    encoded = (_safe_json(value) if bounded else compact_utf8(value)) + b"\n"
    if "/" in name or name.startswith("."):
        raise ValueError("unsafe output filename")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass
        raise


def _create_output_directory(output: Path) -> int:
    absolute = output.absolute()
    parts = absolute.parts[1:]
    if not parts or any(part in {".", ".."} for part in parts):
        raise ValueError("unsafe output path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(absolute.anchor, flags)
    try:
        for part in parts[:-1]:
            next_directory = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        os.mkdir(parts[-1], 0o700, dir_fd=directory)
        return os.open(parts[-1], flags, dir_fd=directory)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError("symlink or non-directory output ancestor") from error
        raise
    finally:
        os.close(directory)


def _row(
    phase: str,
    index: int,
    operation: dict[str, Any],
    receipt: dict[str, Any],
    status: str,
    *,
    skipped: str | None = None,
) -> dict[str, Any]:
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
        "receipt": {
            key: value
            for key, value in receipt.items()
            if key not in {"body", "rawBody", "rawBodyBase64"}
        },
    }
    if skipped is not None:
        row["skipped"] = skipped
    raw_encoded = receipt.get("rawBodyBase64")
    if isinstance(raw_encoded, str):
        raw = base64.b64decode(raw_encoded, validate=True)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("response exceeds cap")
        row["responseBytes"] = len(raw)
        row["responseSha256"] = hashlib.sha256(raw).hexdigest()
    elif receipt.get("body") is not None:
        row["responseEvidence"] = "unavailable"
    return row


def collect_local(
    plan: dict[str, Any],
    execute: Callable[[dict[str, Any]], dict[str, Any]],
    output: str | Path,
) -> dict[str, Any]:
    """Execute the immutable schedule and persist bounded rows in an exclusive directory."""
    validate_schedule(plan)
    plan = copy.deepcopy(plan)
    output_fd = _create_output_directory(Path(output))
    try:
        for probe in plan["probes"]:
            body = compact_utf8(probe["body"])
            if len(body) != probe["bodyBytes"] or len(body) > MAX_RESPONSE_BYTES * 8:
                # The request bodies are intentionally retained outside bounded rows.
                raise ValueError("unexpected compiled Commit body")
            _publish(
                output_fd,
                f"request-{probe['label']}.json",
                {
                    "probe": probe["label"],
                    "bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                },
            )
            with os.fdopen(
                os.open(
                    f"request-{probe['label']}.body",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=output_fd,
                ),
                "wb",
            ) as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())

        rows: list[dict[str, Any]] = []
        recovery: list[dict[str, Any]] = []
        versions: dict[str, dict[str, str]] = {}
        ownership_reads: dict[tuple[str, str], dict[str, Any]] = {}
        preflight_ok: dict[str, bool] = {
            probe["label"]: True for probe in plan["probes"]
        }
        commit_sent: set[str] = set()
        commit_refused: set[str] = set()
        stopped = False
        dispatches = 0
        failures: list[str] = []
        absence_proofs: dict[str, set[str]] = {
            probe["label"]: set() for probe in plan["probes"]
        }
        for sequence, slot in enumerate(plan["executionSchedule"]):
            phase, index = slot["phase"], slot["index"]
            operation = copy.deepcopy(plan[phase][index])
            probe = operation["probe"]
            kind = operation["kind"]
            resource = operation.get("resource")
            skip = None
            if stopped:
                skip = "earlier-probe-incomplete"
            elif (
                phase == "observation"
                and kind != "preflight-typed-absence"
                and not preflight_ok[probe]
                or kind == "conditional-create-commit"
                and not preflight_ok[probe]
            ):
                skip = "preflight-not-proven"
            elif kind == "cleanup-version-bound-delete":
                prior = ownership_reads.get((probe, resource))
                proved_version = versions.get(probe, {}).get(resource)
                expected_digest = plan["documents"][resource]["fieldsSha256"]
                if (
                    proved_version is None
                    or prior is None
                    or not readback_matches(
                        prior, resource, expected_digest, plan["nonce"], proved_version
                    )
                ):
                    skip = "creation-and-current-version-not-proven"
                else:
                    operation["path"] += "?currentDocument.updateTime=" + quote(
                        proved_version, safe=""
                    )
            if skip:
                row = _row(
                    phase,
                    index,
                    operation,
                    {"complete": False, "failure": "skipped"},
                    "skipped",
                    skipped=skip,
                )
                expected_refusal_skip = (
                    kind == "cleanup-version-bound-delete"
                    and probe in commit_refused
                    and typed_not_found(ownership_reads.get((probe, resource)))
                )
                if not expected_refusal_skip:
                    failures.append(f"{phase}:{index}:{skip}")
            else:
                if kind == "conditional-create-commit":
                    commit_sent.add(probe)
                dispatches += 1
                try:
                    receipt = execute(copy.deepcopy(operation))
                    if not isinstance(receipt, dict):
                        raise TypeError("executor returned non-object")
                    if complete(receipt):
                        encoded = receipt.get("rawBodyBase64")
                        try:
                            raw = (
                                base64.b64decode(encoded, validate=True)
                                if isinstance(encoded, str)
                                else None
                            )
                        except (ValueError, base64.binascii.Error):
                            raw = None
                        if (
                            raw is None
                            or len(raw) > MAX_RESPONSE_BYTES
                            or (
                                "bodyBytes" in receipt
                                and receipt["bodyBytes"] != len(raw)
                            )
                            or (
                                raw is not None
                                and not _raw_matches_body(raw, receipt["body"])
                            )
                        ):
                            receipt = {
                                **receipt,
                                "complete": False,
                                "failure": "response-bytes-unavailable",
                            }
                            receipt.pop("rawBodyBase64", None)
                except Exception as error:  # noqa: BLE001 - lost responses remain recoverable.
                    receipt = {
                        "complete": False,
                        "failure": f"executor:{type(error).__name__}",
                    }
                status = (
                    "complete" if complete(receipt) else "infrastructure-incomplete"
                )
                if kind == "cleanup-ownership-read":
                    ownership_reads[(probe, resource)] = receipt
                row = _row(phase, index, operation, receipt, status)
                raw_encoded = receipt.get("rawBodyBase64")
                if isinstance(raw_encoded, str):
                    raw = base64.b64decode(raw_encoded, validate=True)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise ValueError("response exceeds cap")
                    sidecar = f"response-{sequence:03d}.body"
                    fd = os.open(
                        sidecar,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=output_fd,
                    )
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    row["responseBodyFile"] = sidecar
                if kind == "preflight-typed-absence" and not typed_not_found(receipt):
                    preflight_ok[probe] = False
                    failures.append(f"{phase}:{index}:preflight-not-absent")
                elif kind == "conditional-create-commit":
                    probe_resources = next(
                        item["resources"]
                        for item in plan["probes"]
                        if item["label"] == probe
                    )
                    found = commit_versions(receipt, probe_resources)
                    if found is not None and probe != "over":
                        versions[probe] = dict(zip(probe_resources, found))
                    elif probe == "over" and _error_status(receipt, "INVALID_ARGUMENT"):
                        commit_refused.add(probe)
                    else:
                        failures.append(f"{probe}:commit-proof-missing")
                elif kind == "probe-readback":
                    expected_digest = plan["documents"][resource]["fieldsSha256"]
                    matched = (
                        typed_not_found(receipt)
                        if probe == "over"
                        else readback_matches(
                            receipt,
                            resource,
                            expected_digest,
                            plan["nonce"],
                            versions.get(probe, {}).get(resource),
                        )
                        and resource in versions.get(probe, {})
                    )
                    if not matched:
                        failures.append(f"{phase}:{index}:readback-mismatch")
                elif kind == "cleanup-ownership-read":
                    expected_digest = plan["documents"][resource]["fieldsSha256"]
                    if not (
                        typed_not_found(receipt)
                        or owned_document(
                            receipt, resource, expected_digest, plan["nonce"]
                        )
                    ):
                        failures.append(f"{phase}:{index}:unsafe-ownership-read")
                elif kind == "cleanup-version-bound-delete" and not (
                    complete(receipt) and receipt["status"] == 200
                ):
                    failures.append(f"{phase}:{index}:delete-failure")
                elif kind == "cleanup-verify-absence":
                    if typed_not_found(receipt):
                        absence_proofs[probe].add(resource)
                    else:
                        failures.append(f"{phase}:{index}:cleanup-not-absent")
                if not complete(receipt):
                    failures.append(f"{phase}:{index}:incomplete")
            (rows if phase == "observation" else recovery).append(row)
            _publish(output_fd, f"row-{sequence:03d}.json", row)
            next_slot = (
                plan["executionSchedule"][sequence + 1]
                if sequence + 1 < len(plan["executionSchedule"])
                else None
            )
            if (
                next_slot is not None
                and next_slot["phase"] == "observation"
                and phase == "recovery"
            ):
                probe_resources = next(
                    item["resources"]
                    for item in plan["probes"]
                    if item["label"] == probe
                )
                if (
                    failures
                    or set(probe_resources) != absence_proofs[probe]
                    or (
                        probe in commit_sent
                        and probe not in versions
                        and probe not in commit_refused
                    )
                    or not preflight_ok[probe]
                ):
                    stopped = True
        all_resources = {
            item for probe in plan["probes"] for item in probe["resources"]
        }
        absence = all_resources == set().union(*absence_proofs.values())
        result = {
            "productionExecuted": False,
            "localOnly": True,
            "formalCompatibilityClaim": False,
            "rawHttpMetricStatus": "observation hypothesis",
            "canonicalRequestBytesMeasuredLocally": True,
            "planDigest": hashlib.sha256(compact_utf8(plan)).hexdigest(),
            "rowCount": len(rows),
            "recoveryRowCount": len(recovery),
            "requestCount": dispatches,
            "resourceAbsence": absence,
            "cleanupComplete": absence and not failures,
            "completed": not failures,
            "failures": failures,
        }
        _publish(output_fd, "result.json", result)
        return result
    finally:
        os.close(output_fd)
