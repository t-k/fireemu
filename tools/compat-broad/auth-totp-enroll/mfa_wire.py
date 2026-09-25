"""One MFA-local HTTP request. Parent owns the whole-request deadline.

Only the fixed worker is spawned, with secrets on stdin rather than argv. The
worker's socket timeout is not itself a total request deadline; the parent kills
and waits for this direct child when subprocess.run's deadline expires.
"""
from __future__ import annotations

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

# Also works under -I -S -B. Bind this exact dependency in mfa_provenance.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from batch_wire import NoRedirect, _decode_json_response, _read_bounded_response

MAX_REQUEST_BYTES = 65536
MAX_INPUT_BYTES = 131072
MAX_TOKEN_BYTES = 8192
REQUEST_SECONDS = 20.0


def validate_url(url: str) -> urllib.parse.SplitResult:
    """Numeric loopback, explicit unprivileged port, no credentials or fragment."""
    if not isinstance(url, str) or not url or len(url) > 8192 or any(
        ord(char) <= 32 or ord(char) == 127 for char in url
    ):
        raise ValueError("numeric loopback URL required")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ValueError("numeric loopback URL required") from None
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or port is None or not 1024 <= port <= 65535
        or parsed.username is not None or parsed.password is not None
        or parsed.fragment or "#" in url
        or not parsed.path.startswith("/") or parsed.path.startswith("//")
    ):
        raise ValueError("numeric loopback URL required")
    return parsed


def origin(value: str, *, control: bool = False) -> str:
    """Validate an owned origin before it can be combined with a request path."""
    if not isinstance(value, str):
        raise ValueError("owned loopback origin required")
    parsed = validate_url(value.rstrip("/") + "/")
    allowed = {"/", "/v1/"} if control else {"/"}
    if parsed.path not in allowed or parsed.query:
        raise ValueError("owned loopback origin required")
    return f"{parsed.scheme}://{parsed.netloc}"


def _duration(value: Any) -> float:
    if type(value) not in (int, float):
        raise ValueError("bounded MFA request duration required")
    try:
        duration = float(value)
    except OverflowError:
        raise ValueError("bounded MFA request duration required") from None
    if not math.isfinite(duration) or not 0 < duration <= REQUEST_SECONDS:
        raise ValueError("bounded MFA request duration required")
    return duration


def _payload(url: str, body: Any, token: str | None, timeout: float) -> bytes:
    validate_url(url)
    duration = _duration(timeout)
    if token is not None and (
        not isinstance(token, str) or not token or not token.isascii()
        or len(token) > MAX_TOKEN_BYTES or any(ord(c) < 33 or ord(c) > 126 for c in token)
    ):
        raise ValueError("invalid local authorization value")
    try:
        encoded = None if body is None else json.dumps(
            body, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        )
        if encoded is not None:
            raw = encoded.encode("utf-8")
            if len(raw) > MAX_REQUEST_BYTES:
                raise ValueError("request exceeds local bound")
            _decode_json_response(raw)
        envelope = json.dumps(
            {"url": url, "body": encoded, "token": token, "timeout": duration},
            ensure_ascii=False, allow_nan=False, separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise ValueError("invalid or oversized local MFA request") from None
    if len(envelope) > MAX_INPUT_BYTES:
        raise ValueError("local MFA input exceeds bound")
    return envelope


def call(url: str, body: Any = None, token: str | None = None, *,
         timeout: float = REQUEST_SECONDS) -> tuple[int, dict]:
    """No retries; the post-spawn deadline covers headers, body and child exit.

    OS process creation, kill/reap and a stalled kernel cannot be hard-bounded
    by subprocess.run; this is not an OS-level execution sandbox.
    """
    data = _payload(url, body, token, timeout)
    environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "LANG") if key in os.environ}
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve())],
            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, timeout=_duration(timeout), check=False,
        )
    except subprocess.TimeoutExpired:
        raise ValueError("local MFA request deadline exceeded") from None
    except OSError:
        raise ValueError("local MFA worker could not start") from None
    if result.returncode != 0:
        raise ValueError("local MFA HTTP response was not usable")
    try:
        if len(result.stdout) > 393216:
            raise ValueError("oversized worker output")
        value = _decode_json_response(result.stdout)
        if (not isinstance(value, list) or len(value) != 2 or type(value[0]) is not int
                or not 200 <= value[0] <= 599 or not isinstance(value[1], dict)):
            raise ValueError("invalid worker output")
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ValueError("invalid local MFA worker output") from None
    return value[0], value[1]


def _exchange(value: dict) -> tuple[int, dict]:
    if not isinstance(value, dict) or set(value) != {"url", "body", "token", "timeout"}:
        raise ValueError("invalid worker input")
    url, encoded, token = value["url"], value["body"], value["token"]
    if encoded is not None and not isinstance(encoded, str):
        raise ValueError("invalid body")
    body = None if encoded is None else _decode_json_response(encoded.encode("utf-8"))
    _payload(url, body, token, value["timeout"])
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if encoded is not None:
        headers["Content-Type"] = "application/json"
    method = "GET" if encoded is None else "POST"
    request = urllib.request.Request(
        url, data=None if encoded is None else encoded.encode("utf-8"), headers=headers, method=method,
    )
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=min(value["timeout"], 10.0))
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status = response.status
        media_types = response.headers.get_all("Content-Type", [])
        if (type(status) is not int or not 200 <= status <= 599 or 300 <= status < 400
                or len(media_types) != 1 or len(media_types[0]) > 512
                or media_types[0].split(";", 1)[0].strip().lower() != "application/json"):
            raise ValueError("invalid response envelope")
        raw, failure = _read_bounded_response(response, method)
        if failure is not None:
            raise ValueError("incomplete local response")
        decoded = _decode_json_response(raw)
        if not isinstance(decoded, dict):
            raise ValueError("object response required")
        return status, decoded


def main() -> None:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds bound")
    result = _exchange(_decode_json_response(raw))
    sys.stdout.buffer.write(json.dumps(result, ensure_ascii=False, allow_nan=False).encode("utf-8"))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Neither credentials, server bodies nor exception strings leave this worker.
        sys.exit(2)
