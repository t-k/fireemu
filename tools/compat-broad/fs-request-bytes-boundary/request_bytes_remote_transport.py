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
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime
from typing import Any
from urllib.parse import quote, unquote

from request_bytes_compiler import validate_request_bytes_plan

ORIGIN = "https://firestore.googleapis.com"
MAX_REQUEST_BYTES = 10_485_761
RESPONSE_BYTES = 2 * 1024 * 1024
TIMEOUT = 12.0
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]{1,8192}=*")
_VERSION = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z")
_DIAGNOSTIC_LIMIT = 512

Exchange = Callable[[str, str, bytes | None, dict[str, str], float, int], Any]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


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
        validate_request_bytes_plan(snapshot)
    except (TypeError, ValueError, KeyError) as error:
        raise ValueError(
            f"request plan validation failed: {type(error).__name__}"
        ) from None
    expected = _operation_for_slot(snapshot, phase, index, operation)
    credential = _token(token)
    body = None if expected["body"] is None else _compact(expected["body"])
    if body is not None and len(body) > MAX_REQUEST_BYTES:
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
    response: Any, cap: int, deadline: float | None = None
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
        if deadline is not None and time.monotonic() >= deadline:
            return b"".join(chunks), "response-timeout"
        remaining = (
            None if deadline is None else max(0.001, deadline - time.monotonic())
        )
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


def _urllib_exchange(
    url: str,
    method: str,
    body: bytes | None,
    headers: dict[str, str],
    deadline: float,
    response_cap: int,
) -> tuple[int | None, Any, bytes, str | None]:
    request_object = urllib.request.Request(
        url, data=body, headers=headers, method=method
    )
    opener = urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.ProxyHandler({}),
    )
    try:
        remaining = max(0.001, deadline - time.monotonic())
        response = opener.open(request_object, timeout=remaining)
    except urllib.error.HTTPError as error:
        with error:
            payload, failure = _read_bounded(error, response_cap, deadline)
            return error.code, error.headers, payload, failure
    except (OSError, TimeoutError, urllib.error.URLError):
        return (
            None,
            {},
            b"",
            "timeout" if time.monotonic() >= deadline else "transport-error",
        )
    with response:
        payload, failure = _read_bounded(response, response_cap, deadline)
        return response.status, response.headers, payload, failure


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


def _request_impl(
    plan: dict[str, Any],
    phase: str,
    index: int,
    operation: dict[str, Any],
    token: str,
    *,
    exchange: Exchange | None = None,
    timeout: float = TIMEOUT,
) -> dict[str, Any]:
    """Send one fixed-origin operation, or return a typed transport failure."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a finite number in 0..12 seconds")
    if not math.isfinite(timeout) or not 0 < timeout <= TIMEOUT:
        raise ValueError("timeout must be a finite number in 0..12 seconds")
    url, method, body, headers = prepare(plan, phase, index, operation, token)
    deadline = time.monotonic() + timeout
    try:
        if exchange is None:
            status, response_headers, raw_body, failure = _urllib_exchange(
                url, method, body, headers, deadline, RESPONSE_BYTES
            )
        else:
            response = exchange(
                url,
                method,
                body,
                headers,
                max(0.001, deadline - time.monotonic()),
                RESPONSE_BYTES,
            )
            try:
                status = _status(getattr(response, "status", None))
                response_headers = getattr(response, "headers", {})
                raw_body, failure = _read_bounded(response, RESPONSE_BYTES, deadline)
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
    except TimeoutError:
        return _transport_failure("timeout")
    except http.client.IncompleteRead:
        return _transport_failure("response-incomplete")
    except (OSError, urllib.error.URLError):
        return _transport_failure("transport-error")
    if status is None:
        return _transport_failure(failure or "transport-error")
    status = _status(status)
    if time.monotonic() >= deadline and failure is None:
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
) -> dict[str, Any]:
    """Send one fixed-origin operation using the production HTTPS exchange."""
    return _request_impl(
        plan, phase, index, operation, token, timeout=timeout, exchange=None
    )
