"""Local-only bounded HTTP transport for the limits compiler's request plans."""

from __future__ import annotations

import http.client
import json
import math
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from broad_contract import local_origin

MAX_CAP = 2 * 1024 * 1024


def _decode_json_response(payload: bytes) -> Any:
    """Decode one finite UTF-8 JSON value without silently replacing keys.

    A fully received HTTP body can still be unusable as typed API evidence.
    Keep this helper self-contained: this file is also a standalone worker
    (and the limits transport is included in the closed O8 archive).
    """
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON response key")
            result[key] = value
        return result

    def finite_float(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("non-finite JSON response number")
        return parsed

    def reject_constant(_value):
        raise ValueError("non-standard JSON response constant")

    return json.loads(
        payload.decode("utf-8"), object_pairs_hook=unique_object,
        parse_float=finite_float, parse_constant=reject_constant,
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, "redirect forbidden", headers, fp
        )


def _cap(value: Any, name: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > MAX_CAP
    ):
        raise ValueError(f"{name} must be an integer in 1..{MAX_CAP}")
    return value


def _read_bounded(response: Any, cap: int) -> tuple[bytes, str | None]:
    """Bound the body and require one unambiguous HTTP message boundary.

    Keep at most ``cap`` bytes for diagnosis. Even equal duplicate lengths are
    refused by this closed observer, as are unsupported transfer encodings.
    A valid JSON prefix is not evidence that an HTTP response completed.
    """
    payload = b""
    try:
        lengths = response.headers.get_all("Content-Length", [])
        codings = response.headers.get_all("Transfer-Encoding", [])
        if codings and (lengths or len(codings) != 1 or codings[0].lower() != "chunked"):
            return payload, "partial"
        expected = None
        if lengths:
            value = lengths[0].strip(" \t")
            if len(lengths) != 1 or not value or any(c not in "0123456789" for c in value):
                return payload, "partial"
            expected = int(value)
        payload = response.read(cap + 1)
        if len(payload) > cap:
            return payload[:cap], "truncated"
        if expected is not None and expected != len(payload):
            return payload, "partial"
    except (http.client.IncompleteRead, OSError, TimeoutError, ValueError) as error:
        return bytes(getattr(error, "partial", payload))[:cap], "partial"
    return payload, None


def _validate(origin, operation, request_byte_limit, response_byte_limit, timeout):
    origin = local_origin(origin)
    request_cap = _cap(request_byte_limit, "request_byte_limit")
    _cap(response_byte_limit, "response_byte_limit")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > 12
    ):
        raise ValueError("timeout must be positive and at most 12")
    path = operation.get("path")
    if (
        not isinstance(path, str)
        or not path.startswith("/v1/")
        or path.startswith("//")
        or "#" in path
        or ("?" not in path and operation.get("method") == "PATCH")
    ):
        raise ValueError("malformed compiled request path")
    body = operation.get("body")
    data = (
        b""
        if body is None
        else json.dumps(
            body, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    )
    if len(data) > request_cap:
        raise ValueError("request exceeds request_byte_limit before I/O")
    return data


def _perform(
    origin: str,
    operation: dict[str, Any],
    request_cap: int,
    response_cap: int,
    timeout: float,
) -> dict[str, Any]:
    data = _validate(origin, operation, request_cap, response_cap, timeout)
    body = operation.get("body")
    url = origin + operation["path"]
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if operation.get("privileged"):
        headers["Authorization"] = "Bearer owner"
    return _exchange(
        url,
        operation.get("method", "GET"),
        data if body is not None else None,
        headers,
        response_cap,
        timeout,
    )


def _exchange(url, method, data, headers, response_cap, timeout):
    """Shared bounded I/O mechanics; callers validate their distinct origins/admission."""
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    started = time.monotonic()
    try:
        response = opener.open(req, timeout=min(timeout, 12.0))
    except urllib.error.HTTPError as error:
        try:
            payload, failure = _read_bounded(error, response_cap)
            status, headers_obj = error.code, error.headers
        finally:
            error.close()
    except (urllib.error.URLError, TimeoutError, OSError):
        return {"kind": "transport-error", "complete": False}
    else:
        with response:
            status, headers_obj, payload, failure = (
                response.status,
                response.headers,
                *_read_bounded(response, response_cap),
            )
    elapsed = time.monotonic() - started
    if 300 <= status < 400:
        failure = "redirect"
    content_type = headers_obj.get("Content-Type", "")[:512]
    observation: dict[str, Any] = {
        "status": status,
        "headers": {"content-type": content_type},
        "bodyBytes": len(payload),
        "complete": failure is None,
        "elapsedSeconds": elapsed,
    }
    if failure:
        observation.update(
            kind=failure,
            failure=failure,
            body=payload.decode("utf-8", errors="replace"),
        )
        return observation
    try:
        parsed = _decode_json_response(payload)
    except (ValueError, UnicodeDecodeError, RecursionError):
        observation.update(
            kind="non-json", body=payload.decode("utf-8", errors="replace")
        )
    else:
        observation.update(kind="api-error" if status >= 400 else "json", body=parsed)
    return observation


def request(
    origin: str,
    operation: dict[str, Any],
    *,
    request_byte_limit: int,
    response_byte_limit: int,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """Execute one compiled request via a hard-deadline stdin worker."""
    _validate(origin, operation, request_byte_limit, response_byte_limit, timeout)
    request_cap, response_cap = request_byte_limit, response_byte_limit
    payload = json.dumps(
        {
            "origin": origin,
            "operation": operation,
            "request_cap": request_cap,
            "response_cap": response_cap,
            "timeout": timeout,
        },
        separators=(",", ":"),
    )
    try:
        environment = {
            key: os.environ[key]
            for key in ("PATH", "SYSTEMROOT", "LANG")
            if key in os.environ
        }
        environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        completed = subprocess.run(
            [sys.executable, __file__, "--worker"],
            input=payload,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        return {"kind": "deadline-exceeded", "complete": False}
    if completed.returncode != 0:
        return {"kind": "worker-error", "complete": False, "error": "worker failed"}
    return json.loads(completed.stdout)


if __name__ == "__main__" and sys.argv[1:] == ["--worker"]:
    value = json.load(sys.stdin)
    local_origin(value["origin"])
    _cap(value["request_cap"], "request_cap")
    _cap(value["response_cap"], "response_cap")
    print(
        json.dumps(
            _perform(
                value["origin"],
                value["operation"],
                value["request_cap"],
                value["response_cap"],
                value["timeout"],
            ),
            separators=(",", ":"),
        )
    )
