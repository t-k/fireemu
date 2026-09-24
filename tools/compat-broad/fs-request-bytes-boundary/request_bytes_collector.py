"""Bounded, local-only acquisition for the compiled request-byte plan."""

from __future__ import annotations

import base64
import copy
import errno
import hashlib
import json
import math
import os
import re
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from request_bytes_compiler import (
    compact_utf8,
    logical_fields_digest,
    validate_request_bytes_plan,
    validate_request_bytes_sentinel_plan,
)
from request_bytes_remote_transport import MAX_SENTINEL_REQUEST_BYTES

MAX_ROW_BYTES = 131_072
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$")
SEMANTIC_ONLY_FAILURES = frozenset({"over:unexpected-success"})
SEMANTIC_OUTCOMES = frozenset(
    {
        "typed-over-refusal",
        "unexpected-over-success",
        "unknown-over-outcome",
        "sentinel-accepted",
        "sentinel-typed-refusal",
        "sentinel-inconclusive",
    }
)


def _valid_timestamp(value: str) -> bool:
    if _TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("nonfinite JSON constant")


def _same_json_value(left: Any, right: Any) -> bool:
    """Python equality conflates nested booleans, integers and floats."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _same_json_value(value, right[key]) for key, value in left.items()
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same_json_value(a, b) for a, b in zip(left, right, strict=True)
        )
    if isinstance(left, float):
        return (
            math.isfinite(left) and math.isfinite(right) and left.hex() == right.hex()
        )
    return left == right


def _raw_matches_body(raw: bytes, body: Any) -> bool:
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (ValueError, UnicodeDecodeError):
        # A non-JSON response remains diagnostic data, not a typed API proof.
        return isinstance(body, str) and body == raw.decode("utf-8", errors="replace")
    except RecursionError:
        return False
    try:
        return _same_json_value(parsed, body)
    except RecursionError:
        return False


def complete(receipt: Any) -> bool:
    return (
        isinstance(receipt, dict)
        and receipt.get("complete") is True
        and receipt.get("failure") is None
        and type(receipt.get("status")) is int
        and 100 <= receipt["status"] <= 599
        and "body" in receipt
    )


def cleanup_safety_complete(result: Any) -> bool:
    """Recompute safe retirement from owned-state evidence, not compatibility."""
    if not isinstance(result, dict) or result.get("resourceAbsence") is not True:
        return False
    failures = result.get("failures")
    return isinstance(failures, list) and all(
        isinstance(failure, str) and failure in SEMANTIC_ONLY_FAILURES
        for failure in failures
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


def typed_over_refusal(receipt: Any) -> bool:
    """Accept only a complete canonical over-boundary refusal envelope."""
    body = receipt.get("body") if isinstance(receipt, dict) else None
    error = body.get("error") if isinstance(body, dict) else None
    return (
        complete(receipt)
        and receipt["status"] in {400, 413}
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error.get("code") == receipt["status"]
        and error.get("status") == "INVALID_ARGUMENT"
    )


_FIRESTORE_ERROR_STATUSES = frozenset(
    {
        "CANCELLED",
        "UNKNOWN",
        "INVALID_ARGUMENT",
        "DEADLINE_EXCEEDED",
        "NOT_FOUND",
        "ALREADY_EXISTS",
        "PERMISSION_DENIED",
        "RESOURCE_EXHAUSTED",
        "FAILED_PRECONDITION",
        "ABORTED",
        "OUT_OF_RANGE",
        "UNAUTHENTICATED",
        "INTERNAL",
        "UNAVAILABLE",
        "DATA_LOSS",
    }
)


def typed_firestore_refusal(receipt: Any) -> bool:
    """Recognize a complete, status-bound Firestore API error envelope."""
    body = receipt.get("body") if isinstance(receipt, dict) else None
    error = body.get("error") if isinstance(body, dict) else None
    return (
        complete(receipt)
        and 400 <= receipt["status"] < 600
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error["code"] == receipt["status"]
        and isinstance(error.get("status"), str)
        and error["status"] in _FIRESTORE_ERROR_STATUSES
    )


def over_refusal_classification(receipt: Any) -> str | None:
    if not typed_over_refusal(receipt):
        return None
    return "expected" if receipt["status"] == 400 else "semantic-discrepancy"


#: The invariant the two inline bounds below exist to keep:
#:
#:   **the final result must be publishable whatever the remote answers.**
#:
#: A response may be anything up to `MAX_RESPONSE_BYTES`, while `result.json` is
#: published under `MAX_ROW_BYTES`, which is sixteen times smaller. Any field
#: copied from a response into the final result therefore has to be bounded
#: where it is written, not merely expected to be short. Getting this wrong does
#: not fail early: the run completes every request, proves every resource
#: absent, and is then lost at the moment of publication. `_guard_publishable`
#: below is the tripwire for the next field that forgets.

#: Bytes of a refusal message retained inline in the final result.
MESSAGE_EXCERPT_BYTES = 1024


def refusal_message_fields(message: Any, sidecar: Any) -> dict[str, Any]:
    """Describe a refusal message without letting its size govern the result.

    A truncated excerpt is never presented as the message. `messageSha256` is
    taken over the whole text, so a comparison can still be exact when the
    excerpt is not.
    """
    if not isinstance(message, str):
        return {
            "message": None,
            "messageBytes": None,
            "messageSha256": None,
            "messageTruncated": False,
            "responseBodyFile": sidecar,
        }
    encoded = message.encode("utf-8")
    truncated = len(encoded) > MESSAGE_EXCERPT_BYTES
    fields: dict[str, Any] = {
        "messageBytes": len(encoded),
        "messageSha256": hashlib.sha256(encoded).hexdigest(),
        "messageTruncated": truncated,
        "responseBodyFile": sidecar,
    }
    if truncated:
        # No `message` key at all when it would be a partial value: a reader
        # that finds one is entitled to treat it as the whole message.
        fields["messageExcerpt"] = encoded[:MESSAGE_EXCERPT_BYTES].decode(
            "utf-8", errors="replace"
        )
    else:
        fields["message"] = message
    return fields


#: Bytes of a non-typed refusal body retained inline, under the same invariant.
#: The full bytes are always in the run's `response-*.body` sidecar; this is the
#: adjudication excerpt.
UNTYPED_BODY_INLINE_BYTES = 8192


def untyped_transport_refusal(receipt: Any) -> bool:
    """A complete non-success response that is not Firestore's typed refusal.

    A front-end HTML 413 or any other intermediary answer belongs here. It is
    deliberately *not* a refusal proof: it grants no cleanup ownership, leaves
    the refusal shape unproven, and keeps recovery read-only. Recording it
    separately turns an otherwise wasted run into something an owner can
    adjudicate, without letting an intermediary speak for Firestore.
    """
    if not complete(receipt) or typed_over_refusal(receipt):
        return False
    status = receipt.get("status")
    return type(status) is int and 400 <= status < 600


def untyped_refusal_observation(receipt: Any) -> dict[str, Any] | None:
    """Record a non-typed refusal verbatim, bounded, and without any claim."""
    if not untyped_transport_refusal(receipt):
        return None
    encoded = receipt.get("rawBodyBase64")
    raw = b""
    if isinstance(encoded, str):
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error):
            raw = b""
    headers = receipt.get("headers")
    content_type = ""
    if isinstance(headers, dict):
        value = headers.get("content-type")
        content_type = value[:128] if isinstance(value, str) else ""
    observation = {
        "classification": "untyped-transport-refusal",
        "httpStatus": receipt["status"],
        "contentType": content_type,
        "bodyBytes": len(raw),
        "bodySha256": hashlib.sha256(raw).hexdigest(),
        "bodyBase64": base64.b64encode(raw[:UNTYPED_BODY_INLINE_BYTES]).decode("ascii"),
        "bodyTruncated": len(raw) > UNTYPED_BODY_INLINE_BYTES,
        "refusalShapeProven": False,
        "grantsCleanupOwnership": False,
        "recoveryAuthority": "read-only",
        "note": "Not a Firestore typed refusal. The boundary question stays unanswered; the post-state readback and absence proofs still stand.",
    }
    return observation


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
    if plan.get("caseMode") == "single-exploratory-sentinel":
        validate_request_bytes_sentinel_plan(plan)
        return
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


def _publish(directory: int, name: str, value: Any, *, bounded: bool = True) -> bytes:
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
    return encoded


def _journal_digest(entries: list[dict[str, Any]]) -> str:
    encoded = json.dumps(
        entries, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


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


def _guard_publishable(result: dict[str, Any]) -> None:
    """Refuse to lose a completed run, and say which field grew.

    Every field the result copies from a response is bounded where it is
    written. This is the tripwire for the next one that is not: without it a
    new inline field fails as an opaque `row-too-large` after the whole run has
    succeeded, and only in a run whose remote happened to answer at length.
    With it the same mistake names itself the first time a test drives a large
    response through.
    """

    # Measured with the unbounded encoder on purpose: `_safe_json` raises the
    # opaque failure this guard exists to replace, so it cannot be used to
    # measure something already too large.
    def size(value: Any) -> int:
        return len(
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        )

    total = size(result)
    if total <= MAX_ROW_BYTES:
        return
    largest = max(
        ((key, size(value)) for key, value in result.items()),
        key=lambda item: item[1],
        default=("<empty>", 0),
    )
    raise ValueError(
        "final result is not publishable: "
        f"{total} bytes exceeds the {MAX_ROW_BYTES}-byte limit; "
        f"largest field is {largest[0]!r} at {largest[1]} bytes. "
        "A field copied from a response must be bounded where it is written."
    )


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


def _validated_response(receipt):
    if not isinstance(receipt, dict):
        raise TypeError("executor returned non-object")
    encoded = receipt.get("rawBodyBase64")
    raw = None
    if isinstance(encoded, str) and len(encoded) <= 4 * ((MAX_RESPONSE_BYTES + 2) // 3):
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error):
            pass
    raw_invalid = encoded is not None and (
        raw is None
        or len(raw) > MAX_RESPONSE_BYTES
        or (
            "bodyBytes" in receipt
            and (
                type(receipt["bodyBytes"]) is not int
                or receipt["bodyBytes"] != len(raw)
            )
        )
    )
    if raw_invalid or (
        complete(receipt)
        and (raw is None or not _raw_matches_body(raw, receipt["body"]))
    ):
        receipt = {
            **receipt,
            "complete": False,
            "failure": "response-bytes-unavailable",
        }
        receipt.pop("rawBodyBase64", None)
    return receipt


def sentinel_response_capture(
    receipt: dict[str, Any],
    operation: dict[str, Any],
    row: dict[str, Any],
    classification: str,
) -> dict[str, Any]:
    """Retain bounded response metadata while the complete bytes live in a sidecar."""
    raw_encoded = receipt.get("rawBodyBase64")
    raw = None
    if isinstance(raw_encoded, str):
        try:
            raw = base64.b64decode(raw_encoded, validate=True)
        except (ValueError, base64.binascii.Error):
            raw = None
    headers = receipt.get("headers")
    content_type = (
        headers.get("content-type", "")[:128]
        if isinstance(headers, dict) and isinstance(headers.get("content-type"), str)
        else ""
    )
    body = receipt.get("body")
    error = body.get("error") if isinstance(body, dict) else None
    typed_error = None
    if (
        isinstance(error, dict)
        and type(error.get("code")) is int
        and isinstance(error.get("status"), str)
    ):
        typed_error = {
            "code": error["code"],
            "status": error["status"],
            **refusal_message_fields(error.get("message"), row.get("responseBodyFile")),
        }
    request_body = compact_utf8(operation["body"])
    return {
        "classification": classification,
        "complete": complete(receipt),
        "failure": receipt.get("failure"),
        "httpStatus": receipt.get("status"),
        "contentType": content_type,
        "responseBytes": len(raw) if raw is not None else None,
        "responseSha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
        "responseBodyFile": row.get("responseBodyFile"),
        "typedError": typed_error,
        "requestBytes": len(request_body),
        "requestSha256": hashlib.sha256(request_body).hexdigest(),
    }


def collect_local(
    plan: dict[str, Any],
    execute: Callable[..., dict[str, Any]],
    output: str | Path,
    *,
    gate=None,
) -> dict[str, Any]:
    """Execute the immutable schedule and persist bounded rows in an exclusive directory.

    When ``gate`` is supplied, every wire operation is charged through that
    already-created probe Gate and every zero-wire recovery slot advances its cursor
    through ``skip_scheduled_slot``. The local shadow path keeps its historical
    direct callback when no Gate is supplied.
    """
    validate_schedule(plan)
    plan = copy.deepcopy(plan)
    phase_deadlines = None
    if gate is not None:
        # Read the immutable campaign origin once, before any dispatch. The
        # published recovery reserve may be stricter than an older Gate plan.
        import request_bytes_descriptor as campaign

        snapshot = next(iter(gate.values())).snapshot()
        started = snapshot["started"]
        phase_deadlines = {
            "observation": started
            + min(
                snapshot["plan"]["wallSeconds"] - snapshot["plan"]["recoverySeconds"],
                campaign.campaign_seconds() - campaign.recovery_seconds(),
            ),
            "recovery": started
            + min(snapshot["plan"]["wallSeconds"], campaign.campaign_seconds()),
        }
    output_fd = _create_output_directory(Path(output))
    try:
        journal_rows: list[dict[str, Any]] = []
        journal_sidecars: list[dict[str, Any]] = []
        for probe in plan["probes"]:
            body = compact_utf8(probe["body"])
            body_cap = (
                MAX_SENTINEL_REQUEST_BYTES
                if plan.get("caseMode") == "single-exploratory-sentinel"
                else MAX_RESPONSE_BYTES * 8
            )
            if len(body) != probe["bodyBytes"] or len(body) > body_cap:
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
        over_refusal_observation: dict[str, Any] | None = None
        untyped_over_refusal: dict[str, Any] | None = None
        sentinel_response: dict[str, Any] | None = None
        sentinel_outcome = "sentinel-inconclusive"
        is_sentinel = plan.get("caseMode") == "single-exploratory-sentinel"
        abandoned_observation: set[str] = set()
        stopped = False
        observation_stopped = False
        dispatches = 0
        failures: list[str] = []
        absence_proofs: dict[str, set[str]] = {
            probe["label"]: set() for probe in plan["probes"]
        }
        for sequence, slot in enumerate(plan["executionSchedule"]):
            phase, index = slot["phase"], slot["index"]
            operation = copy.deepcopy(plan[phase][index])
            probe = operation["probe"]
            probe_gate = gate[probe] if gate is not None else None
            if probe_gate is not None:
                operation.pop("versionFrom", None)
            kind = operation["kind"]
            resource = operation.get("resource")
            skip = None
            if stopped or (observation_stopped and phase == "observation"):
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
                if probe_gate is not None:
                    if phase == "observation":
                        if probe not in abandoned_observation:
                            probe_gate.abandon_observation(skip)
                            abandoned_observation.add(probe)
                    else:
                        probe_gate.skip_scheduled_slot(
                            copy.deepcopy(operation), True, skip
                        )
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
                    operation_copy = copy.deepcopy(operation)
                    if gate is None:
                        receipt = execute(operation_copy)
                    else:
                        wire_receipt = None

                        def send_wire(current_operation=operation_copy):
                            nonlocal wire_receipt
                            wire_receipt = _validated_response(
                                execute(current_operation, deadline=deadline)  # noqa: B023 -- dispatch invokes synchronously.
                            )
                            if not isinstance(wire_receipt, dict):
                                raise TypeError("executor returned non-object")
                            if not complete(wire_receipt):
                                raise ValueError("incomplete production response")
                            return wire_receipt["status"], wire_receipt.get("body")

                        cap = (
                            campaign.transport_deadline_seconds(plan.get("caseId"))
                            if operation_copy.get("body") is not None
                            else campaign.small_request_timeout_seconds()
                        )
                        deadline = min(time.monotonic() + cap, phase_deadlines[phase])
                        probe_gate.dispatch(
                            operation_copy, phase == "recovery", send_wire
                        )
                        receipt = wire_receipt
                    if not isinstance(receipt, dict):
                        raise TypeError("executor returned non-object")
                    receipt = _validated_response(receipt)
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
                    try:
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
                        journal_sidecars.append(
                            {
                                "name": sidecar,
                                "bytes": len(raw),
                                "sha256": hashlib.sha256(raw).hexdigest(),
                                "sequence": sequence,
                            }
                        )
                    except Exception as error:  # noqa: BLE001 - recording must not bypass recovery.
                        try:
                            os.unlink(sidecar, dir_fd=output_fd)
                        except OSError:
                            pass
                        failures.append(
                            f"recording:response-{sequence:03d}.body:{type(error).__name__}"
                        )
                        observation_stopped = True
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
                    if found is not None:
                        versions[probe] = dict(zip(probe_resources, found))
                        if is_sentinel:
                            sentinel_outcome = "sentinel-accepted"
                            sentinel_response = sentinel_response_capture(
                                receipt, operation, row, "sentinel-accepted"
                            )
                        elif probe == "over":
                            failures.append("over:unexpected-success")
                    elif is_sentinel and typed_firestore_refusal(receipt):
                        commit_refused.add(probe)
                        sentinel_outcome = "sentinel-typed-refusal"
                        sentinel_response = sentinel_response_capture(
                            receipt, operation, row, "sentinel-typed-refusal"
                        )
                    elif is_sentinel:
                        refusal = untyped_refusal_observation(receipt)
                        classification = (
                            "sentinel-untyped-refusal"
                            if refusal is not None
                            else "sentinel-inconclusive"
                        )
                        sentinel_response = sentinel_response_capture(
                            receipt, operation, row, classification
                        )
                        failures.append(f"{probe}:commit-proof-missing")
                    elif probe == "over" and typed_over_refusal(receipt):
                        commit_refused.add(probe)
                        body = receipt["body"]
                        error = body["error"]
                        # The message is part of the refusal shape a reader
                        # compares against production, so it is recorded here
                        # rather than left in the row sidecar. It is bound to
                        # the response digest: `typed_over_refusal` only accepts
                        # a complete receipt whose raw bytes agree with the
                        # parsed body, so this message is the one on the wire.
                        raw_refusal = base64.b64decode(
                            receipt.get("rawBodyBase64") or "", validate=True
                        )
                        over_refusal_observation = {
                            "httpStatus": receipt["status"],
                            "errorCode": error["code"],
                            "errorStatus": error["status"],
                            **refusal_message_fields(
                                error.get("message"), row.get("responseBodyFile")
                            ),
                            "responseBytes": len(raw_refusal),
                            "responseSha256": hashlib.sha256(raw_refusal).hexdigest(),
                            "classification": over_refusal_classification(receipt),
                        }
                    else:
                        failures.append(f"{probe}:commit-proof-missing")
                        if probe == "over":
                            untyped_over_refusal = untyped_refusal_observation(receipt)
                elif kind == "probe-readback":
                    expected_digest = plan["documents"][resource]["fieldsSha256"]
                    matched = (
                        typed_not_found(receipt)
                        if (is_sentinel or probe == "over") and probe not in versions
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
            try:
                row_name = f"row-{sequence:03d}.json"
                encoded_row = _publish(output_fd, row_name, row)
                journal_rows.append(
                    {
                        "name": row_name,
                        "bytes": len(encoded_row),
                        "sha256": hashlib.sha256(encoded_row).hexdigest(),
                        "sequence": sequence,
                    }
                )
            except Exception as error:  # noqa: BLE001 - recording must not bypass recovery.
                failures.append(
                    f"recording:row-{sequence:03d}.json:{type(error).__name__}"
                )
                observation_stopped = True
            if probe_gate is not None and (
                kind == "preflight-typed-absence"
                and not preflight_ok[probe]
                or kind == "conditional-create-commit"
                and probe not in versions
                and probe not in commit_refused
            ):
                break
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
                    if probe_gate is not None:
                        break
        all_resources = {
            item for probe in plan["probes"] for item in probe["resources"]
        }
        absence = all_resources == set().union(*absence_proofs.values())
        if "over:unexpected-success" in failures:
            semantic_outcome = "unexpected-over-success"
        elif is_sentinel:
            semantic_outcome = sentinel_outcome
        elif over_refusal_observation is not None:
            semantic_outcome = "typed-over-refusal"
        else:
            semantic_outcome = "unknown-over-outcome"
        plan_digest = hashlib.sha256(compact_utf8(plan)).hexdigest()
        request_bindings = {}
        for operation in plan["observation"]:
            if operation.get("kind") == "conditional-create-commit":
                body = compact_utf8(operation["body"])
                request_bindings[operation["probe"]] = {
                    "bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                }
        expected_slots = len(plan["executionSchedule"])
        capture_rows_complete = (
            len(journal_rows) == expected_slots
            and len(rows) + len(recovery) == expected_slots
        )
        if is_sentinel:
            actual_rows = [row for row in rows + recovery if row["status"] != "skipped"]
            capture_complete = (
                capture_rows_complete
                and len(actual_rows) == dispatches
                and len(journal_sidecars) == dispatches
                and all("responseBodyFile" in row for row in actual_rows)
            )
        else:
            actual_rows = [row for row in rows + recovery if row["status"] != "skipped"]
            skipped_rows = [
                row for row in rows + recovery if row["status"] == "skipped"
            ]
            permitted_skips = all(
                row["kind"] == "cleanup-version-bound-delete"
                and row["probe"] == "over"
                and row.get("skipped") == "creation-and-current-version-not-proven"
                for row in skipped_rows
            )
            capture_complete = (
                capture_rows_complete
                and permitted_skips
                and len(actual_rows) == dispatches
                and len(journal_sidecars) == dispatches
                and all("responseBodyFile" in row for row in actual_rows)
            )
        skip_counts: dict[tuple[str, str, str], int] = {}
        for row in rows + recovery:
            if row["status"] != "skipped":
                continue
            category = (row["probe"], row["kind"], row["skipped"])
            skip_counts[category] = skip_counts.get(category, 0) + 1
        skipped_summary = [
            {"probe": probe, "kind": kind, "reason": reason, "count": count}
            for (probe, kind, reason), count in sorted(skip_counts.items())
        ]
        local_journal = {
            "schemaVersion": 1,
            "planDigest": plan_digest,
            "rowCount": len(journal_rows),
            "sidecarCount": len(journal_sidecars),
            "skippedCount": sum(skip_counts.values()),
            "skippedSummary": skipped_summary,
            "rowEntries": journal_rows,
            "sidecarEntries": journal_sidecars,
            "requestBindings": request_bindings,
            "entryDigest": _journal_digest(journal_rows + journal_sidecars),
            "captureComplete": capture_complete,
        }
        result = {
            "productionExecuted": False,
            "localOnly": True,
            "formalCompatibilityClaim": False,
            "rawHttpMetricStatus": "observation hypothesis",
            "canonicalRequestBytesMeasuredLocally": True,
            "planDigest": plan_digest,
            "rowCount": len(rows),
            "recoveryRowCount": len(recovery),
            "requestCount": dispatches,
            "resourceAbsence": absence,
            "cleanupComplete": absence and not failures,
            "cleanupSafetyComplete": cleanup_safety_complete(
                {"resourceAbsence": absence, "failures": failures}
            ),
            "completed": not failures,
            "failures": failures,
            "semanticOutcome": semantic_outcome,
            "localJournal": local_journal,
        }
        if over_refusal_observation is not None:
            result["overRefusal"] = over_refusal_observation
        if untyped_over_refusal is not None:
            # Deliberately a separate key. It is never a typed refusal and must
            # not be readable as one by anything consuming `overRefusal`.
            result["untypedOverRefusal"] = untyped_over_refusal
        if sentinel_response is not None:
            result["sentinelResponse"] = sentinel_response
        _guard_publishable(result)
        _publish(output_fd, "result.json", result)
        return result
    finally:
        os.close(output_fd)
