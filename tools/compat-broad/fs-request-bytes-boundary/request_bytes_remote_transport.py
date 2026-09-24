"""Fixed-origin, bounded REST transport for the request-byte boundary.

This module binds every call to an independently validated frozen plan slot. It
does not acquire credentials, admit a campaign, persist tokens, or retry. Tests
may inject a low-level exchange; the default exchange is the production HTTPS
origin and is intentionally not used by the test suite.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import json
import math
import re
import sys
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "o8-core"))

from o8_admission import authorize_transport
from request_bytes_compiler import (
    RAW_16MIB_OVER_BYTES,
    validate_request_bytes_plan,
    validate_request_bytes_sentinel_plan,
)
from request_bytes_process_exchange import _run_process_exchange

ORIGIN = "https://firestore.googleapis.com"
MAX_REQUEST_BYTES = 11_534_337
MAX_SENTINEL_REQUEST_BYTES = RAW_16MIB_OVER_BYTES
RESPONSE_BYTES = 2 * 1024 * 1024
# One total wire deadline covering connection setup, TLS, the upload, server
# processing and the response. It is sized for the 11,534,337-byte boundary
# Commit, not for a kilobyte request.
#
#   upload            92,274,696 bits at a conservative 5 Mbit/s sustained   18.5 s
#   DNS, TCP and TLS 1.3 setup                                                1.5 s
#   server processing of one 17-document conditional-create Commit            8.0 s
#   response read, bounded at 2 MiB                                           0.5 s
#   ------------------------------------------------------------------------------
#   derived requirement                                                      28.5 s
#
# 60 s is that requirement with roughly a 2x margin. At 60 s, reserving 10 s for
# setup, processing and the response leaves 50 s for the body, so the slowest
# link that can complete a boundary probe sustains about 1.85 Mbit/s upstream.
# At 60 s the slowest usable upstream rate is about 1.85 Mbit/s. A slower link
# yields an incomplete receipt and an uncertain Commit; see
# `request_bytes_campaign.TRANSPORT_DEADLINE` for the consequence that binds.
TIMEOUT = 60.0
SENTINEL_TIMEOUT = 80.0
SMALL_REQUEST_TIMEOUT = 2.5
#: Bits in the largest compiled request body, used by the derivation above.
BOUNDARY_REQUEST_BITS = MAX_REQUEST_BYTES * 8
#: Seconds of the deadline reserved for everything that is not the upload.
NON_UPLOAD_RESERVE_SECONDS = 10.0
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]{1,8192}=*")
_VERSION = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z")
_DIAGNOSTIC_LIMIT = 512
_WORKER_SHA256 = "33b7853d2dc9ae08ef28aeb3a4229abce33e8a58ae09b8ba8ed450d44a927c08"

Exchange = Callable[[str, str, bytes | None, dict[str, str], float, int], Any]
Clock = Callable[[], float]


def _compact(value: Any) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _token(value: Any) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise ValueError("invalid credential shape")
    return value


def _operation_for_slot(
    plan: dict[str, Any], phase: str, index: int, operation: dict[str, Any]
) -> dict[str, Any]:
    if phase not in {"observation", "recovery"} or type(index) is not int:
        raise ValueError("invalid request operation position")
    if not isinstance(operation, dict):
        raise TypeError("request operation required")
    operations = plan.get(phase)
    if not isinstance(operations, list) or not 0 <= index < len(operations):
        raise ValueError("request operation outside plan")
    expected = copy.deepcopy(operations[index])
    version_from = expected.pop("versionFrom", None)
    if version_from is not None:
        prefix = expected["path"] + "?currentDocument.updateTime="
        path = operation.get("path")
        if not isinstance(path, str) or not path.startswith(prefix):
            raise ValueError("resolved cleanup version required")
        version = unquote(path[len(prefix) :])
        try:
            datetime.fromisoformat(version.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("invalid cleanup version binding") from None
        if _VERSION.fullmatch(version) is None or path != prefix + quote(
            version, safe=""
        ):
            raise ValueError("invalid cleanup version binding")
        expected["path"] = path
    if _compact(operation) != _compact(expected):
        raise ValueError("request operation differs from frozen plan slot")
    return expected


def prepare(
    plan: dict[str, Any],
    phase: str,
    index: int,
    operation: dict[str, Any],
    token: str,
) -> tuple[str, str, bytes | None, dict[str, str]]:
    """Validate and prepare one exact frozen REST operation without I/O."""
    if not isinstance(plan, dict):
        raise TypeError("request plan required")
    snapshot = copy.deepcopy(plan)
    try:
        _validate_plan(snapshot)
    except (TypeError, ValueError, KeyError) as error:
        raise ValueError(
            f"request plan validation failed: {type(error).__name__}"
        ) from None
    expected = _operation_for_slot(snapshot, phase, index, operation)
    credential = _token(token)
    body = None if expected["body"] is None else _compact(expected["body"])
    request_limit = (
        MAX_SENTINEL_REQUEST_BYTES
        if plan.get("caseMode") == "single-exploratory-sentinel"
        else MAX_REQUEST_BYTES
    )
    if body is not None and len(body) > request_limit:
        raise ValueError("request exceeds bounded byte ceiling")
    headers = {
        "Authorization": "Bearer " + credential,
        "x-goog-user-project": snapshot["project"],
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    return ORIGIN + expected["path"], expected["method"], body, headers


def _header(headers: Any, name: str) -> str:
    if not hasattr(headers, "get"):
        return ""
    value = headers.get(name, "")
    return value if isinstance(value, str) else str(value)


def _diagnostic(raw: bytes) -> str:
    return raw[:_DIAGNOSTIC_LIMIT].decode("utf-8", errors="replace")


def _read_bounded(
    response: Any,
    cap: int,
    deadline: float | None = None,
    clock: Clock = time.monotonic,
) -> tuple[bytes, str | None]:
    declared = _header(getattr(response, "headers", {}), "Content-Length")
    if declared:
        try:
            if int(declared) > cap:
                declared_failure = "response-oversize"
            else:
                declared_failure = None
        except ValueError:
            return b"", "invalid-content-length"
    else:
        declared_failure = None
    chunks: list[bytes] = []
    total = 0
    while True:
        if deadline is not None and clock() >= deadline:
            return b"".join(chunks), "response-timeout"
        remaining = None if deadline is None else max(0.001, deadline - clock())
        socket = getattr(
            getattr(getattr(response, "fp", None), "raw", None), "_sock", None
        )
        if socket is not None and remaining is not None:
            socket.settimeout(remaining)
        try:
            chunk = response.read(min(64 * 1024, cap + 1 - total))
        except http.client.IncompleteRead as incomplete:
            partial = (
                incomplete.partial if isinstance(incomplete.partial, bytes) else b""
            )
            payload = b"".join(chunks) + partial
            return payload[:cap], "response-incomplete"
        except TimeoutError:
            return b"".join(chunks), "response-timeout"
        except OSError:
            return b"".join(chunks), "transport-error"
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            return (b"".join(chunks) + chunk)[:cap], "response-oversize"
        chunks.append(chunk)
    body = b"".join(chunks)
    if declared_failure is not None:
        return body, declared_failure
    if declared and int(declared) != len(body):
        return body, "response-incomplete"
    return body, None


def _process_exchange(
    url: str,
    method: str,
    body: bytes | None,
    headers: dict[str, str],
    deadline: float,
    response_cap: int,
) -> tuple[int | None, Any, bytes, str | None]:
    if not url.startswith(ORIGIN + "/") or url.count(ORIGIN) != 1:
        raise ValueError("invalid fixed origin")
    path = url[len(ORIGIN) :]
    project = headers["x-goog-user-project"]
    if not path.startswith("/v1/projects/" + project + "/"):
        raise ValueError("invalid project path")
    if method not in {"GET", "POST", "DELETE"} or set(headers) not in (
        {"Authorization", "x-goog-user-project"},
        {"Authorization", "x-goog-user-project", "Content-Type"},
    ):
        raise ValueError("invalid worker request")
    if (body is None) != (method != "POST"):
        raise ValueError("invalid worker body")
    if body is not None and headers.get("Content-Type") != "application/json":
        raise ValueError("invalid worker content type")
    source = Path(__file__).with_name("request_bytes_https_worker.py").read_bytes()
    if hashlib.sha256(source).hexdigest() != _WORKER_SHA256:
        raise ValueError("fixed worker digest mismatch")
    message = {
        "method": method,
        "path": path,
        "authorization": headers["Authorization"],
        "project": project,
        "bodyBytes": len(body or b""),
        "deadline": deadline,
    }
    payload = _compact(message) + b"\n" + (body or b"")
    if time.monotonic() >= deadline:
        return None, {}, b"", "timeout"
    status, content_type, raw, failure = _run_process_exchange(
        worker_source=source,
        worker_sha256=_WORKER_SHA256,
        request_payload=payload,
        deadline=deadline,
        response_cap=response_cap,
    )
    return status, {"Content-Type": content_type}, raw, failure


def _result(
    status: int,
    headers: Any,
    body: bytes,
    body_failure: str | None,
    request_body: bytes | None,
) -> dict[str, Any]:
    if 300 <= status < 400:
        return _failure("redirect", status, body)
    if body_failure is not None:
        return _failure(
            "timeout" if body_failure == "response-timeout" else body_failure,
            status,
            body,
        )
    result = {
        "kind": "typed-receipt",
        "complete": True,
        "failure": None,
        "status": status,
        "contentType": _header(headers, "Content-Type")[:128],
        "bodyBytes": len(body),
        "rawBodyBytes": len(body),
        "rawBodySha256": hashlib.sha256(body).hexdigest(),
        "rawBodyBase64": base64.b64encode(body).decode("ascii"),
        "body": _parse_body(body),
        "diagnostic": _diagnostic(body),
        "requestBytes": len(request_body or b""),
        "requestSha256": hashlib.sha256(request_body or b"").hexdigest(),
    }
    return result


def _parse_body(body: bytes) -> Any:
    try:
        return json.loads(body)
    except (UnicodeDecodeError, ValueError):
        return _diagnostic(body)


def _failure(reason: str, status: int, body: bytes) -> dict[str, Any]:
    return {
        "kind": "typed-receipt",
        "complete": False,
        "failure": reason,
        "status": status,
        "contentType": "",
        "bodyBytes": len(body),
        "rawBodyBytes": len(body),
        "rawBodySha256": hashlib.sha256(body).hexdigest(),
        "rawBodyBase64": base64.b64encode(body).decode("ascii"),
        "body": _parse_body(body),
        "diagnostic": _diagnostic(body),
    }


def _transport_failure(reason: str) -> dict[str, Any]:
    return {
        "kind": "transport-failure",
        "complete": False,
        "failure": reason,
        "status": None,
        "rawBodyBytes": 0,
        "rawBodySha256": hashlib.sha256(b"").hexdigest(),
        "rawBodyBase64": "",
    }


def _status(value: Any) -> int:
    if type(value) is not int or not 100 <= value <= 599:
        raise ValueError("invalid HTTP status")
    return value


def _validate_plan(plan: dict[str, Any]) -> None:
    if plan.get("caseMode") == "single-exploratory-sentinel":
        validate_request_bytes_sentinel_plan(plan)
    else:
        validate_request_bytes_plan(plan)


def _operation_timeout(plan: dict[str, Any], operation: dict[str, Any]) -> float:
    if operation.get("body") is None:
        return SMALL_REQUEST_TIMEOUT
    return (
        SENTINEL_TIMEOUT
        if plan.get("caseMode") == "single-exploratory-sentinel"
        else TIMEOUT
    )


def _plan_timeout_ceiling(plan: dict[str, Any]) -> float:
    return (
        SENTINEL_TIMEOUT
        if plan.get("caseMode") == "single-exploratory-sentinel"
        else TIMEOUT
    )


def _request_impl(
    plan: dict[str, Any],
    phase: str,
    index: int,
    operation: dict[str, Any],
    token: str,
    *,
    exchange: Exchange | None = None,
    timeout: float | None = None,
    deadline: float | None = None,
    clock: Clock = time.monotonic,
    capability=None,
    binding=None,
    binding_digest=None,
) -> dict[str, Any]:
    """Time one operation and return its receipt.

    The elapsed figure spans the whole slot: request preparation, the worker
    process, the connection, the upload and the bounded response read. That is
    the boundary a per-slot reservation has to pay for, so it is measured here
    rather than inside the worker.

    This wrapper is additive. It does not look at the receipt, so it cannot
    change a refusal classification, and it does not touch the deadline, which
    `_dispatch` still computes and enforces on its own.
    """
    started = clock()
    receipt = _dispatch(
        plan,
        phase,
        index,
        operation,
        token,
        exchange=exchange,
        timeout=timeout,
        deadline=deadline,
        clock=clock,
        capability=capability,
        binding=binding,
        binding_digest=binding_digest,
    )
    if isinstance(receipt, dict) and "elapsedSeconds" not in receipt:
        receipt["elapsedSeconds"] = clock() - started
    return receipt


def _dispatch(
    plan: dict[str, Any],
    phase: str,
    index: int,
    operation: dict[str, Any],
    token: str,
    *,
    exchange: Exchange | None = None,
    timeout: float | None = None,
    deadline: float | None = None,
    clock: Clock = time.monotonic,
    capability=None,
    binding=None,
    binding_digest=None,
) -> dict[str, Any]:
    """Send one fixed-origin operation, or return a typed transport failure.

    ``clock`` is the monotonic time source used for the one total wire
    deadline. It exists so tests can drive the deadline with simulated time;
    production always uses ``time.monotonic``.
    """
    ceiling = _plan_timeout_ceiling(plan)
    if timeout is None:
        timeout = ceiling
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError(f"timeout must be a finite number in 0..{ceiling:g} seconds")
    if not math.isfinite(timeout) or not 0 < timeout <= ceiling:
        raise ValueError(f"timeout must be a finite number in 0..{ceiling:g} seconds")
    cap = _operation_timeout(plan, operation)
    local_deadline = clock() + min(timeout, cap)
    if deadline is not None:
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ValueError("finite absolute deadline required")
        local_deadline = min(local_deadline, deadline)
    deadline = local_deadline
    if exchange is None:
        if capability is None:
            raise ValueError("active O7 production capability required")
        authorize_transport(
            capability,
            binding=binding,
            binding_digest=binding_digest,
        )
    if clock() >= deadline:
        return _transport_failure("timeout")
    url, method, body, headers = prepare(plan, phase, index, operation, token)
    if clock() >= deadline:
        return _transport_failure("timeout")
    try:
        if exchange is None:
            status, response_headers, raw_body, failure = _process_exchange(
                url, method, body, headers, deadline, RESPONSE_BYTES
            )
        else:
            response = exchange(
                url,
                method,
                body,
                headers,
                max(0.001, deadline - clock()),
                RESPONSE_BYTES,
            )
            try:
                status = _status(getattr(response, "status", None))
                response_headers = getattr(response, "headers", {})
                raw_body, failure = _read_bounded(
                    response, RESPONSE_BYTES, deadline, clock
                )
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
    except TimeoutError:
        return _transport_failure("timeout")
    except http.client.IncompleteRead:
        return _transport_failure("response-incomplete")
    except OSError:
        return _transport_failure("transport-error")
    if status is None:
        return _transport_failure(failure or "transport-error")
    status = _status(status)
    if clock() >= deadline and failure is None:
        failure = "response-timeout"
    receipt = _result(status, response_headers, raw_body, failure, body)
    receipt["requestBytes"] = len(body or b"")
    receipt["requestSha256"] = hashlib.sha256(body or b"").hexdigest()
    return receipt


def request(
    plan: dict[str, Any],
    phase: str,
    index: int,
    operation: dict[str, Any],
    token: str,
    *,
    timeout: float = TIMEOUT,
    deadline: float | None = None,
    capability=None,
    binding=None,
    binding_digest=None,
) -> dict[str, Any]:
    """Send one fixed-origin operation using the production HTTPS exchange."""
    if capability is None:
        raise ValueError("active O7 production capability required")
    authorize_transport(
        capability,
        binding=binding,
        binding_digest=binding_digest,
    )
    return _request_impl(
        plan,
        phase,
        index,
        operation,
        token,
        timeout=timeout,
        deadline=deadline,
        exchange=None,
        capability=capability,
        binding=binding,
        binding_digest=binding_digest,
    )
