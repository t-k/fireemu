"""Bounded local AUTH-CREDENTIAL HTTP worker; never production.

The parent deadline covers worker execution after spawn, not OS process creation
or kill/reap under a stalled kernel. Secrets travel through stdin, not argv.
"""
from __future__ import annotations

import base64
import json
import math
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from batch_wire import NoRedirect, _decode_json_response, _read_bounded_response

MAX_BODY_BYTES = 65536
MAX_INPUT_BYTES = 131072
MAX_OUTPUT_BYTES = 90000
MAX_SECONDS = 5.0
LOOPBACK_HOSTS = ("127.0.0.1", "::1")


def validate_url(url: str) -> urllib.parse.SplitResult:
    """No DNS, proxy, userinfo, URL fragments or implicit ports."""
    if (not isinstance(url, str) or not url or len(url) > 8192
            or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url)):
        raise ValueError("non-loopback or malformed local target")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ValueError("non-loopback or malformed local target") from None
    if (parsed.scheme != "http" or parsed.hostname not in LOOPBACK_HOSTS
            or port is None or not 1 <= port <= 65535
            or parsed.username is not None or parsed.password is not None
            or "#" in url or not parsed.path.startswith("/")
            or parsed.path.startswith("//")):
        raise ValueError("non-loopback or malformed local target")
    return parsed


def target(base: str, path: str) -> str:
    if (not isinstance(base, str) or not isinstance(path, str)
            or (path and (not path.startswith(("/", ":")) or path.startswith("//")))):
        raise ValueError("non-loopback or malformed local target")
    # A securetoken base already contains its complete path and query.
    if path and ("?" in base or "#" in base):
        raise ValueError("ambiguous local target")
    url = base + path
    validate_url(url)
    return url


def duration(value: Any) -> float:
    if type(value) not in (float, int):
        raise ValueError("bounded request duration required")
    try:
        seconds = float(value)
    except OverflowError:
        raise ValueError("bounded request duration required") from None
    if not math.isfinite(seconds) or not 0 < seconds <= MAX_SECONDS:
        raise ValueError("bounded request duration required")
    return seconds


def response_body(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_BODY_BYTES:
        raise ValueError("invalid or oversized local JSON response")
    try:
        body = _decode_json_response(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid local JSON response") from None
    if not isinstance(body, dict):
        raise ValueError("local JSON object response required")
    return body


def _payload(url: str, body: dict[str, Any], owner: bool, seconds: float) -> bytes:
    validate_url(url)
    duration(seconds)
    if type(owner) is not bool or not isinstance(body, dict):
        raise ValueError("typed local request required")
    try:
        encoded = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        response_body(encoded)  # Also rejects key collisions after JSON encoding.
        raw = json.dumps({"url": url, "body": encoded.decode("utf-8"),
                          "owner": owner, "seconds": seconds},
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("invalid or oversized local request") from None
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("local request envelope exceeds bound")
    return raw


def request(url: str, body: dict[str, Any], owner: bool, seconds: float) -> tuple[int, bytes]:
    """Exactly one fixed worker. Timeout kills and waits for this direct child."""
    raw = _payload(url, body, owner, seconds)
    env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "LANG") if k in os.environ}
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve())],
            input=raw, capture_output=True, timeout=duration(seconds), env=env, check=False,
        )
    except subprocess.TimeoutExpired:
        raise ValueError("local credential request deadline exceeded") from None
    except OSError:
        raise ValueError("local credential worker could not start") from None
    try:
        if result.returncode != 0 or not 0 < len(result.stdout) <= MAX_OUTPUT_BYTES:
            raise ValueError("invalid worker result")
        value = _decode_json_response(result.stdout)
        if (not isinstance(value, list) or len(value) != 2
                or type(value[0]) is not int or not 200 <= value[0] <= 599
                or 300 <= value[0] < 400 or not isinstance(value[1], str)):
            raise ValueError("invalid worker result")
        body_bytes = base64.b64decode(value[1], validate=True)
        response_body(body_bytes)
        return value[0], body_bytes
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("local credential HTTP response was not usable") from None


def _exchange(value: Any) -> tuple[int, bytes]:
    if (not isinstance(value, dict) or set(value) != {"url", "body", "owner", "seconds"}
            or not isinstance(value["body"], str)):
        raise ValueError("invalid worker input")
    body = response_body(value["body"].encode("utf-8"))
    _payload(value["url"], body, value["owner"], value["seconds"])
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if value["owner"]:
        headers["Authorization"] = "Bearer owner"
    req = urllib.request.Request(value["url"], data=value["body"].encode("utf-8"),
                                 headers=headers, method="POST")
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        response = opener.open(req, timeout=value["seconds"])
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status = response.status
        media = response.headers.get_all("Content-Type", [])
        if (type(status) is not int or not 200 <= status <= 599 or 300 <= status < 400
                or len(media) != 1 or len(media[0]) > 512
                or media[0].split(";", 1)[0].strip().lower() != "application/json"):
            raise ValueError("invalid response envelope")
        raw, failure = _read_bounded_response(response, "POST")
        if failure is not None:
            raise ValueError("incomplete local response")
        response_body(raw)
        return status, raw


def main() -> None:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("worker input exceeds bound")
    status, body = _exchange(_decode_json_response(raw))
    sys.stdout.buffer.write(json.dumps([status, base64.b64encode(body).decode("ascii")]).encode())


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never serialize server bodies, request secrets or exception text.
        sys.exit(2)
