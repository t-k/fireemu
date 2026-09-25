"""Finite HTTP transport for the partition/cursor lane: loopback and fixed host.

The fixed child retains exact bounded bytes. Its parent enforces one post-spawn
request deadline, including body reception and child exit. No retry exists. OS
process creation, kill/reap and kernel stalls are not bounded.

Two closed modes share the child. The local mode addresses a numeric loopback
origin with an explicit port and a placeholder bearer. The production mode
addresses exactly one fixed origin, `https://firestore.googleapis.com`, with the
owner's bearer token delivered on the child's stdin, never on its command line.
A loopback origin is refused in production mode and a non-loopback origin is
refused in local mode, so neither mode can be steered at the other's target.
"""
from __future__ import annotations

import base64
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from batch_wire import NoRedirect, _decode_json_response, _read_bounded_response

MAX_RAW_BYTES = 65536
MAX_INPUT_BYTES = 262144
MAX_OUTPUT_BYTES = 90000
REQUEST_SECONDS = 20.0
# The one production origin this lane can address. Exact string, no port, no
# path: the child compares it before it opens a socket, and the parent before
# it spawns the child.
PRODUCTION_ORIGIN = "https://firestore.googleapis.com"
PRODUCTION_USER_PROJECT = "fireemu-35fe6"
# Whole-worker ceiling for one production request: spawn, TLS, body and exit.
# The owned documents are tiny, so a request that needs longer is a failure the
# collector records, never a reason to wait.
PRODUCTION_REQUEST_SECONDS = 5.0
MAX_BEARER_BYTES = 8192
MODES = ("local", "production")
_LOCAL_INPUT_KEYS = frozenset({"origin", "path", "method", "body", "seconds"})
_PRODUCTION_INPUT_KEYS = _LOCAL_INPUT_KEYS | {"mode", "bearer", "userProject"}


def validate_origin(origin: Any) -> None:
    """An origin has no credentials, query, fragment, DNS or implicit port."""
    if (not isinstance(origin, str) or not origin or len(origin) > 8192
            or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in origin)):
        raise PermissionError("numeric loopback origin with explicit port required")
    try:
        parsed = urllib.parse.urlsplit(origin)
        port = parsed.port
    except ValueError:
        raise PermissionError("numeric loopback origin with explicit port required") from None
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"}
            or port is None or not 1 <= port <= 65535
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or "?" in origin or "#" in origin):
        raise PermissionError("numeric loopback origin with explicit port required")


def validate_production_origin(origin: Any) -> None:
    """Only the fixed production origin; a loopback or any other host is refused."""
    if not isinstance(origin, str) or origin != PRODUCTION_ORIGIN:
        raise PermissionError("fixed production origin required")


def _bearer(value: Any) -> str:
    """A bounded, printable-ASCII bearer token; never logged, never in argv."""
    if (not isinstance(value, str) or not 0 < len(value) <= MAX_BEARER_BYTES
            or not value.isascii()
            or any(ord(c) < 33 or ord(c) == 127 for c in value)):
        raise ValueError("bounded bearer token required")
    return value


def same_json(left: Any, right: Any) -> bool:
    """Preserve nested JSON types; bool/int/float are not interchangeable."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_json(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    if isinstance(left, float):
        return math.isfinite(left) and math.isfinite(right) and left.hex() == right.hex()
    return left == right


def decode_response(raw: bytes) -> Any:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_RAW_BYTES:
        raise ValueError("bounded UTF-8 JSON response required")
    value = _decode_json_response(raw)
    if not isinstance(value, (dict, list)):
        raise ValueError("object or stream-array response required")
    return value


def validate_receipt(value: Any) -> Any:
    """Verify transport bytes before they can grant versions or typed absence."""
    if not isinstance(value, dict):
        raise ValueError("transport receipt required")
    status, raw, count, media = (value.get(k) for k in ("status", "rawBody", "byteCount", "contentType"))
    if (type(status) is not int or not 200 <= status <= 599 or 300 <= status < 400
            or value.get("complete") is not True or type(count) is not int
            or not isinstance(raw, bytes) or count != len(raw)
            or not isinstance(media, str) or len(media) > 512
            or media.split(";", 1)[0].strip().lower() != "application/json"):
        raise ValueError("incomplete or malformed transport receipt")
    decoded = decode_response(raw)
    if not same_json(decoded, value.get("body")):
        raise ValueError("decoded body differs from transport bytes")
    return decoded


def _duration(value: Any) -> float:
    if type(value) not in (int, float):
        raise ValueError("bounded request duration required")
    try:
        seconds = float(value)
    except OverflowError:
        raise ValueError("bounded request duration required") from None
    if not math.isfinite(seconds) or not 0 < seconds <= REQUEST_SECONDS:
        raise ValueError("bounded request duration required")
    return seconds


def _input(origin: str, request: dict, seconds: float, *, mode: str = "local",
           bearer: Any = None, user_project: Any = None) -> bytes:
    if mode not in MODES:
        raise ValueError("closed transport mode required")
    if mode == "production":
        validate_production_origin(origin)
        _bearer(bearer)
        if user_project != PRODUCTION_USER_PROJECT:
            raise ValueError("fixed quota project required")
    else:
        validate_origin(origin)
        if bearer is not None or user_project is not None:
            raise ValueError("local mode carries no credential")
    seconds = _duration(seconds)
    if not isinstance(request, dict):
        raise ValueError("local request required")
    method, path = request.get("method"), request.get("path")
    if (method not in {"GET", "POST", "PATCH", "DELETE"} or not isinstance(path, str)
            or not path.startswith("/v1/projects/") or len(path) > 8192 or "#" in path
            or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in path)
            or any(segment in {".", ".."} for segment in path.split("?", 1)[0].split("/"))):
        raise ValueError("local Firestore request required")
    body = request.get("body")
    if body is not None and not isinstance(body, dict):
        raise ValueError("object request body required")
    # Encoding also snapshots all caller-owned mutable values before admission.
    value: dict[str, Any] = {"origin": origin.rstrip("/"), "method": method, "path": path,
                             "body": body, "seconds": seconds}
    if mode == "production":
        value.update(mode="production", bearer=bearer, userProject=user_project)
    payload = json.dumps(value, allow_nan=False).encode("utf-8")
    if len(payload) > MAX_INPUT_BYTES:
        raise ValueError("local request exceeds bound")
    return payload


def _spawn(payload: bytes, timeout: float) -> dict:
    """Run the fixed child once on this file; the payload never touches argv."""
    env = {k: os.environ[k] for k in ("PATH", "LANG", "SYSTEMROOT") if k in os.environ}
    try:
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve())],
                                input=payload, capture_output=True, timeout=_duration(timeout),
                                env=env, check=False)
    except subprocess.TimeoutExpired:
        raise ValueError("local partition request deadline exceeded") from None
    except OSError:
        raise ValueError("local partition worker unavailable") from None
    return _receipt(result)


def _receipt(result: subprocess.CompletedProcess) -> dict:
    try:
        if result.returncode != 0 or not 0 < len(result.stdout) <= MAX_OUTPUT_BYTES:
            raise ValueError("worker failed")
        value = _decode_json_response(result.stdout)
        if not isinstance(value, dict) or set(value) != {"status", "contentType", "raw"}:
            raise ValueError("invalid worker envelope")
        raw = base64.b64decode(value["raw"], validate=True)
        receipt = {"status": value["status"], "contentType": value["contentType"],
                   "complete": True, "rawBody": raw, "byteCount": len(raw), "body": decode_response(raw)}
        validate_receipt(receipt)
        return receipt
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("unusable local partition response") from None


def request(origin: str, operation: dict, *, timeout: float = REQUEST_SECONDS) -> dict:
    """One local-mode exchange against a numeric loopback origin."""
    return _spawn(_input(origin, operation, timeout), timeout)


def production_request(operation: dict, bearer: str, *, origin: str = PRODUCTION_ORIGIN,
                       timeout: float = PRODUCTION_REQUEST_SECONDS,
                       deadline: float | None = None) -> dict:
    """One production-mode exchange against the fixed origin only.

    `deadline` is an absolute `time.monotonic()` instant the whole exchange must
    finish by; the worker ceiling is the smaller of it and `timeout`. A loopback
    origin is refused here before any file or process exists.
    """
    validate_production_origin(origin)
    seconds = _duration(timeout)
    if seconds > PRODUCTION_REQUEST_SECONDS:
        raise ValueError("production request ceiling exceeded")
    if deadline is not None:
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise ValueError("finite absolute deadline required")
        import time

        seconds = min(seconds, deadline - time.monotonic())
        if seconds <= 0:
            raise ValueError("production request deadline")
    payload = _input(origin, operation, seconds, mode="production", bearer=bearer,
                     user_project=PRODUCTION_USER_PROJECT)
    return _spawn(payload, seconds)


def _exchange(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) not in (_LOCAL_INPUT_KEYS, _PRODUCTION_INPUT_KEYS):
        raise ValueError("invalid worker input")
    production = "mode" in value
    _input(value["origin"], value, value["seconds"],
           mode="production" if production else "local",
           bearer=value.get("bearer"), user_project=value.get("userProject"))
    body = value["body"]
    data = None if body is None else json.dumps(body, allow_nan=False).encode("utf-8")
    headers = {"Authorization": "Bearer owner",
               "Content-Type": "application/json", "Accept": "application/json"}
    if production:
        headers["Authorization"] = "Bearer " + value["bearer"]
        headers["x-goog-user-project"] = value["userProject"]
    message = urllib.request.Request(value["origin"] + value["path"], data=data,
                                    method=value["method"], headers=headers)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        response = opener.open(message, timeout=min(value["seconds"], 10.0))
    except urllib.error.HTTPError as error:
        response = error
    with response:
        media = response.headers.get_all("Content-Type", [])
        if (type(response.status) is not int or not 200 <= response.status <= 599
                or 300 <= response.status < 400 or len(media) != 1 or len(media[0]) > 512
                or media[0].split(";", 1)[0].strip().lower() != "application/json"):
            raise ValueError("invalid response envelope")
        raw, failure = _read_bounded_response(response, value["method"])
        if failure is not None:
            raise ValueError("incomplete HTTP response")
        decode_response(raw)
        return {"status": response.status, "contentType": media[0],
                "raw": base64.b64encode(raw).decode("ascii")}


def main() -> None:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("oversized worker input")
    value = _exchange(_decode_json_response(raw))
    sys.stdout.buffer.write(json.dumps(value, allow_nan=False).encode("utf-8"))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(2)  # Never emit server bodies, credentials or exception strings.
