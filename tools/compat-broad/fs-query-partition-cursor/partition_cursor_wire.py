"""Finite numeric-loopback HTTP transport for the local partition/cursor lane.

The fixed child retains exact bounded bytes. Its parent enforces one post-spawn
request deadline, including body reception and child exit. No retry or production
entry exists. OS process creation, kill/reap and kernel stalls are not bounded.
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


def _input(origin: str, request: dict, seconds: float) -> bytes:
    validate_origin(origin)
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
    payload = json.dumps({"origin": origin.rstrip("/"), "method": method, "path": path,
                          "body": body, "seconds": seconds}, allow_nan=False).encode("utf-8")
    if len(payload) > MAX_INPUT_BYTES:
        raise ValueError("local request exceeds bound")
    return payload


def request(origin: str, operation: dict, *, timeout: float = REQUEST_SECONDS) -> dict:
    payload = _input(origin, operation, timeout)
    env = {k: os.environ[k] for k in ("PATH", "LANG", "SYSTEMROOT") if k in os.environ}
    try:
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve())],
                                input=payload, capture_output=True, timeout=_duration(timeout),
                                env=env, check=False)
    except subprocess.TimeoutExpired:
        raise ValueError("local partition request deadline exceeded") from None
    except OSError:
        raise ValueError("local partition worker unavailable") from None
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


def _exchange(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != {"origin", "path", "method", "body", "seconds"}:
        raise ValueError("invalid worker input")
    _input(value["origin"], value, value["seconds"])
    body = value["body"]
    data = None if body is None else json.dumps(body, allow_nan=False).encode("utf-8")
    message = urllib.request.Request(value["origin"] + value["path"], data=data,
                                    method=value["method"], headers={"Authorization": "Bearer owner",
                                    "Content-Type": "application/json", "Accept": "application/json"})
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
