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
    try:
        payload = response.read(cap + 1)
    except (http.client.IncompleteRead, OSError, TimeoutError, ValueError) as error:
        payload = getattr(error, "partial", b"")
        return bytes(payload)[:cap], "partial"
    if len(payload) > cap:
        return payload[:cap], "truncated"
    length = response.headers.get("Content-Length")
    if length is not None and int(length) != len(payload):
        return payload, "partial"
    return payload, None


def _perform(
    origin: str,
    operation: dict[str, Any],
    request_cap: int,
    response_cap: int,
    timeout: float,
) -> dict[str, Any]:
    body = operation.get("body")
    data = (
        b""
        if body is None
        else json.dumps(
            body, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    )
    url = origin + operation["path"]
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if operation.get("privileged"):
        headers["Authorization"] = "Bearer owner"
    req = urllib.request.Request(
        url,
        data=data if body is not None else None,
        headers=headers,
        method=operation.get("method", "GET"),
    )
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
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return {"kind": "transport-error", "complete": False, "error": str(error)}
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
        parsed = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
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
    origin = local_origin(origin)
    request_cap = _cap(request_byte_limit, "request_byte_limit")
    response_cap = _cap(response_byte_limit, "response_byte_limit")
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
