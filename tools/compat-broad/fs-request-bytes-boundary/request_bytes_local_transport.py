"""Loopback-only bounded transport for the request-byte campaign.

This module records the canonical request bytes passed to urllib.  It does not
claim to observe bytes at a server or network boundary.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from broad_contract import local_origin

HERE = Path(__file__).resolve().parent
_SHARED = HERE.parent / "fs-write-limits" / "transport.py"
_SPEC = importlib.util.spec_from_file_location(
    "request_bytes_shared_transport", _SHARED
)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - installation error
    raise ImportError("unable to load bounded shared transport")
_shared = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_shared)

MAX_REQUEST_BYTES = 10_485_761
RESPONSE_BYTES = 2 * 1024 * 1024
REQUEST_TARGETS = (10_485_759, 10_485_760, 10_485_761)


def _request_cap(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > MAX_REQUEST_BYTES
    ):
        raise ValueError(
            f"request_byte_limit must be an integer in 1..{MAX_REQUEST_BYTES}"
        )
    return value


def _canonical_body(operation: dict[str, Any]) -> bytes:
    body = operation.get("body")
    if body is None:
        return b""
    return json.dumps(
        body, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _validate(
    operation: dict[str, Any], request_limit: int, response_limit: int
) -> bytes:
    if not isinstance(operation, dict):
        raise TypeError("operation must be an object")
    if operation.get("service") != "firestore":
        raise ValueError("request-byte transport only accepts Firestore operations")
    if operation.get("form") is not False or operation.get("privileged") is not True:
        raise ValueError("request-byte operation admission drift")
    if operation.get("method") not in {"GET", "POST", "DELETE"}:
        raise ValueError("unsupported request-byte method")
    path = operation.get("path")
    if (
        not isinstance(path, str)
        or not path.startswith("/v1/")
        or path.startswith("//")
        or "#" in path
    ):
        raise ValueError("malformed compiled request path")
    kind = operation.get("kind")
    resource = operation.get("resource")
    if kind == "conditional-create-commit":
        if not re.fullmatch(
            r"/v1/projects/[A-Za-z0-9_-]+/databases/(?:\(default\)|[A-Za-z0-9_-]+)/documents:commit",
            path,
        ):
            raise ValueError("invalid Commit path")
    elif kind in {
        "preflight-typed-absence",
        "probe-readback",
        "cleanup-ownership-read",
        "cleanup-verify-absence",
        "cleanup-version-bound-delete",
    }:
        if not isinstance(resource, str) or not re.fullmatch(
            r"projects/[A-Za-z0-9_-]+/databases/(?:\(default\)|[A-Za-z0-9_-]+)/documents/oracle/[0-9a-f]{32}/request-bytes-0[1-3]/probe-[ueo][0-9]{2}/items/(?:control|payload-[0-9]{2})",
            resource,
        ):
            raise ValueError("invalid resource")
        base = "/v1/" + resource
        if kind == "cleanup-version-bound-delete":
            if operation.get("method") != "DELETE" or not re.fullmatch(
                re.escape(base) + r"\?currentDocument\.updateTime=[A-Za-z0-9%._:-]+",
                path,
            ):
                raise ValueError("unbound cleanup delete")
        elif path != base or operation.get("method") != "GET":
            raise ValueError("resource path drift")
    else:
        raise ValueError("unknown operation kind")
    if response_limit != RESPONSE_BYTES:
        raise ValueError(f"response_byte_limit must equal {RESPONSE_BYTES}")
    body = _canonical_body(operation)
    if len(body) > request_limit:
        raise ValueError("request exceeds request_byte_limit before I/O")
    if operation.get("kind") == "conditional-create-commit":
        if operation.get("method") != "POST" or len(body) not in REQUEST_TARGETS:
            raise ValueError(
                "Commit body is outside the approved request-byte boundary"
            )
    elif body:
        raise ValueError("only Commit operations may carry a body")
    return body


def _perform(
    origin: str,
    operation: dict[str, Any],
    request_limit: int,
    response_limit: int,
    timeout: float,
) -> dict[str, Any]:
    local_origin(origin)
    body = _validate(operation, request_limit, response_limit)
    headers = {"Content-Type": "application/json"} if body else {}
    if operation.get("privileged"):
        headers["Authorization"] = "Bearer owner"
    req = urllib.request.Request(
        origin + operation["path"],
        data=body or None,
        headers=headers,
        method=operation["method"],
    )
    opener = urllib.request.build_opener(
        _shared.NoRedirect(), urllib.request.ProxyHandler({})
    )
    started = time.monotonic()
    try:
        response = opener.open(req, timeout=min(timeout, 12.0))
    except urllib.error.HTTPError as error:
        with error:
            payload, failure = _shared._read_bounded(error, response_limit)
            status, headers_obj = error.code, error.headers
    except (urllib.error.URLError, TimeoutError, OSError):
        return {
            "kind": "transport-error",
            "complete": False,
            "failure": "transport-error",
        }
    else:
        with response:
            payload, failure = _shared._read_bounded(response, response_limit)
            status, headers_obj = response.status, response.headers
    if 300 <= status < 400:
        failure = "redirect"
    result = {
        "status": status,
        "headers": {"content-type": headers_obj.get("Content-Type", "")[:512]},
        "bodyBytes": len(payload),
        "rawBodyBase64": base64.b64encode(payload).decode("ascii"),
        "complete": failure is None,
        "failure": failure,
        "elapsedSeconds": time.monotonic() - started,
    }
    if failure:
        result.update(kind=failure, body=payload.decode("utf-8", errors="replace"))
    else:
        try:
            result.update(
                kind="api-error" if status >= 400 else "json", body=json.loads(payload)
            )
        except (ValueError, UnicodeDecodeError):
            result.update(
                kind="non-json", body=payload.decode("utf-8", errors="replace")
            )
    result["requestBytes"] = len(body)
    result["requestSha256"] = hashlib.sha256(body).hexdigest()
    result["rawHttpMetricStatus"] = "observation hypothesis"
    return result


def request(
    origin: str,
    operation: dict[str, Any],
    *,
    request_byte_limit: int = MAX_REQUEST_BYTES,
    response_byte_limit: int = RESPONSE_BYTES,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """Execute one admitted compiled operation against a numeric loopback origin."""
    local_origin(origin)
    request_limit = _request_cap(request_byte_limit)
    _validate(operation, request_limit, response_byte_limit)
    payload = json.dumps(
        {
            "origin": origin,
            "operation": operation,
            "request_cap": request_limit,
            "response_cap": response_byte_limit,
            "timeout": timeout,
        },
        separators=(",", ":"),
    )
    environment = {
        key: os.environ[key]
        for key in ("PATH", "SYSTEMROOT", "LANG")
        if key in os.environ
    }
    environment["PYTHONPATH"] = str(HERE.parent)
    try:
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--worker"],
            input=payload,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        return {
            "kind": "deadline-exceeded",
            "complete": False,
            "rawHttpMetricStatus": "observation hypothesis",
        }
    if completed.returncode != 0:
        return {
            "kind": "worker-error",
            "complete": False,
            "rawHttpMetricStatus": "observation hypothesis",
        }
    return json.loads(completed.stdout)


if __name__ == "__main__" and sys.argv[1:] == ["--worker"]:
    value = json.load(sys.stdin)
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
