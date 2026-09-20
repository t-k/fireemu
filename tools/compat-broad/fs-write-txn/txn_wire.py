"""Single-use local Transaction HTTP worker with a post-spawn wall deadline.

Secrets are stdin-only. The first bounded output frame records observed HTTP
status before reading a potentially stalled body, so an incomplete 401/403
still stops the collector. This is not a production transport or an emulator
identity assertion. Process creation and kernel kill/reap stalls are not bounded.
"""
from __future__ import annotations

import base64
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from batch_wire import NoRedirect, _decode_json_response, _read_bounded_response

MAX_REQUEST_BYTES = 8192
MAX_RESPONSE_BYTES = 65536
MAX_INPUT_BYTES = 65536
MAX_OUTPUT_BYTES = 90000
MAX_SECONDS = 120


def duration(value):
    if type(value) not in (int, float):
        raise ValueError("finite local request duration required")
    try:
        valid = math.isfinite(value) and 0 < value <= MAX_SECONDS
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError("finite local request duration required")
    return float(value)


def _bound(value, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("invalid local byte limit")
    return value


def _target(url, method):
    if (not isinstance(url, str) or len(url) > 32768
            or any(ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url)):
        raise ValueError("invalid numeric loopback target")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "::1")
            or parsed.port is None or not 1 <= parsed.port <= 65535
            or parsed.username is not None or parsed.password is not None or "#" in url):
        raise ValueError("invalid numeric loopback target")
    control = parsed.path in ("/v1/sessions/default", "/v1/sessions/default/resources")
    advance = parsed.path == "/v1/sessions/default/clock:advance"
    data = re.fullmatch(r"/v1/projects/[^/?#%\\]+/databases/[^/?#%\\]+/documents(.*)", parsed.path)
    suffix = data.group(1) if data else None
    allowed = (
        (method == "GET" and control and not parsed.query)
        or (method == "POST" and advance and not parsed.query)
        or (method == "GET" and suffix is not None and suffix.startswith("/")
            and not suffix.startswith("//"))
        or (method == "POST" and suffix in (":beginTransaction", ":commit", ":rollback")
            and not parsed.query)
    )
    if not allowed:
        raise ValueError("request outside local Transaction routes")
    if parsed.query:
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        if len(query) != 1 or query[0][0] != "transaction" or not query[0][1]:
            raise ValueError("invalid local transaction selector")


def _validate(value):
    keys = {"url", "method", "payload", "token", "seconds", "requestLimit", "responseLimit"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("invalid worker request")
    _target(value["url"], value["method"])
    duration(value["seconds"])
    request_limit = _bound(value["requestLimit"], MAX_REQUEST_BYTES)
    _bound(value["responseLimit"], MAX_RESPONSE_BYTES)
    token = value["token"]
    if (not isinstance(token, str) or not 1 <= len(token) <= 8192
            or any(not 33 <= ord(c) <= 126 for c in token)):
        raise ValueError("invalid local authorization value")
    if value["method"] == "GET":
        if value["payload"] is not None:
            raise ValueError("GET payload forbidden")
    else:
        if not isinstance(value["payload"], str):
            raise ValueError("POST object required")
        raw = value["payload"].encode("utf-8")
        if len(raw) > request_limit or not isinstance(_decode_json_response(raw), dict):
            raise ValueError("POST object exceeds limit or is invalid")


def _header(raw):
    """Only a complete first status frame is trusted, never any response body."""
    try:
        if not isinstance(raw, bytes) or b"\n" not in raw or len(raw) > MAX_OUTPUT_BYTES:
            return None
        first = raw.split(b"\n", 1)[0]
        if len(first) > 128:
            return None
        value = _decode_json_response(first)
        status = value.get("status") if isinstance(value, dict) else None
        if (set(value) != {"kind", "status"} or value["kind"] != "headers"
                or type(status) is not int or not 200 <= status <= 599):
            return None
        return status
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return None


def _incomplete(status, failure):
    return {"httpStatus": status, "complete": False, "rawBody": b"", "failure": failure}


def _result(raw, returncode):
    status = _header(raw)
    if returncode != 0 or status is None:
        return _incomplete(status, "worker-result-invalid")
    try:
        frames = raw.split(b"\n")
        if len(frames) != 3 or frames[-1] != b"":
            raise ValueError("frame count")
        body = _decode_json_response(frames[1])
        if (not isinstance(body, dict) or set(body) != {"kind", "status", "complete", "failure", "body"}
                or body["kind"] != "body" or type(body["status"]) is not int
                or body["status"] != status or type(body["complete"]) is not bool
                or not isinstance(body["body"], str)):
            raise ValueError("body frame")
        payload = base64.b64decode(body["body"], validate=True)
        if len(payload) > MAX_RESPONSE_BYTES:
            raise ValueError("body too large")
        if body["complete"] is not True or body["failure"] is not None or 300 <= status < 400:
            return _incomplete(status, "response-incomplete")
        return {"httpStatus": status, "complete": True, "rawBody": payload, "failure": None}
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return _incomplete(status, "worker-result-invalid")


def request(url, *, method, payload=None, token="owner", seconds=10,
            request_limit=MAX_REQUEST_BYTES, response_limit=MAX_RESPONSE_BYTES):
    """No retry. subprocess.run kills/waits for its fixed direct child on timeout."""
    value = {"url": url, "method": method, "payload": payload, "token": token,
             "seconds": duration(seconds), "requestLimit": request_limit, "responseLimit": response_limit}
    _validate(value)
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("local worker request exceeds envelope")
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT") if k in os.environ}
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve())],
            input=raw, capture_output=True, timeout=value["seconds"], env=env, check=False,
        )
    except subprocess.TimeoutExpired as error:
        return _incomplete(_header(error.stdout), "request-deadline-exceeded")
    except OSError:
        return _incomplete(None, "worker-start-failed")
    outcome = _result(result.stdout, result.returncode)
    if len(outcome["rawBody"]) > response_limit:
        return _incomplete(outcome["httpStatus"], "response-exceeds-bound")
    return outcome


def _emit(value):
    sys.stdout.buffer.write(json.dumps(value, separators=(",", ":"), allow_nan=False).encode() + b"\n")
    sys.stdout.buffer.flush()


def _exchange(value):
    _validate(value)
    payload = None if value["payload"] is None else value["payload"].encode("utf-8")
    req = urllib.request.Request(
        value["url"], data=payload, method=value["method"],
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "Authorization": "Bearer " + value["token"],
                 "Origin": "http://127.0.0.1"},
    )
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        response = opener.open(req, timeout=value["seconds"])
    except urllib.error.HTTPError as error:
        response = error
    status = response.status
    if type(status) is not int or not 200 <= status <= 599:
        response.close()
        raise ValueError("invalid HTTP status")
    # Preserve a received authority refusal even if read/close is killed later.
    _emit({"kind": "headers", "status": status})
    raw, failure = b"", None
    try:
        with response:
            media = response.headers.get_all("Content-Type", [])
            if (300 <= status < 400 or len(media) != 1 or len(media[0]) > 512
                    or media[0].split(";", 1)[0].strip().lower() != "application/json"):
                raise ValueError("invalid media or redirect")
            raw, failure = _read_bounded_response(response, value["method"])
            if len(raw) > value["responseLimit"]:
                failure = "response-exceeds-bound"
    except Exception:
        failure = "response-read-failed"
    # Never relay exception text, URLs or credentials; body is private IPC only.
    _emit({"kind": "body", "status": status, "complete": failure is None,
           "failure": None if failure is None else "response-incomplete",
           "body": base64.b64encode(raw[:MAX_RESPONSE_BYTES]).decode("ascii")})


def main():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise ValueError("worker input exceeds bound")
    _exchange(_decode_json_response(raw))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(2)
