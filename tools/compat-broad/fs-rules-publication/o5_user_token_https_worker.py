"""Isolated, bounded HTTPS worker for the O5 user-token transport.

The parent transport owns plan validation and O8 authorization. This process
owns only one HTTP exchange. Secrets arrive in the bounded envelope on stdin,
never on argv, and no response or exception text is logged.
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SECONDS = 12.0
FIXED_ORIGINS = {
    "https://firestore.googleapis.com",
    "https://identitytoolkit.googleapis.com",
    "https://firebaserules.googleapis.com",
}
ALLOWED_HEADERS = {"authorization", "content-type", "x-goog-user-project"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any):
        raise ValueError("redirect refused")


def _json(value: Any, *, error: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(error)  # noqa: TRY004 - sanitize all malformed envelopes alike
    return value


def _origin(url: str, fixture_origin: str | None) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    allowed = set(FIXED_ORIGINS)
    if fixture_origin is not None:
        fixture = urllib.parse.urlsplit(fixture_origin)
        if (
            fixture.scheme != "http"
            or fixture.hostname not in {"127.0.0.1", "::1"}
            or not fixture.port
        ):
            raise ValueError("fixture origin refused")
        allowed.add(fixture_origin.rstrip("/"))
    if origin not in allowed or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("fixed service origin required")
    if not parsed.path.startswith("/"):
        raise ValueError("query shape refused")
    return origin, urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))


def _bounded_body(value: Any) -> bytes | None:
    if value is None:
        return None
    encoded = json.dumps(
        value, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    if len(encoded) > MAX_REQUEST_BYTES:
        raise ValueError("request body exceeds bound")
    return encoded


def exchange(
    envelope: dict[str, Any], *, fixture_origin: str | None = None
) -> dict[str, Any]:
    if set(envelope) != {"url", "method", "headers", "body", "seconds"}:
        raise ValueError("closed worker envelope required")
    url = envelope["url"]
    method = envelope["method"]
    headers = envelope["headers"]
    if (
        not isinstance(url, str)
        or not isinstance(method, str)
        or method not in {"GET", "POST", "PATCH", "DELETE"}
    ):
        raise ValueError("closed worker request required")
    if (
        not isinstance(headers, dict)
        or not headers
        or {str(key).lower() for key in headers} - ALLOWED_HEADERS
    ):
        raise ValueError("closed worker headers required")
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in headers.items()
    ):
        raise ValueError("closed worker headers required")
    if "authorization" not in {key.lower() for key in headers}:
        raise ValueError("authorization header required")
    seconds = envelope["seconds"]
    if type(seconds) not in (int, float) or not 0 < seconds <= MAX_SECONDS:
        raise ValueError("bounded worker deadline required")
    origin, target = _origin(url, fixture_origin)
    body = _bounded_body(envelope["body"])
    if method == "GET" and body is not None:
        raise ValueError("GET body refused")
    if method != "GET" and body is None:
        raise ValueError("request body required")
    request_headers = {key: value for key, value in headers.items()}
    if body is not None:
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        origin + target,
        data=body,
        headers=request_headers,
        method=method,
    )
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({}))
    started = time.monotonic()
    try:
        with opener.open(request, timeout=float(seconds)) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("response body exceeds bound")
            parsed = json.loads(raw) if raw else {}
            return {
                "status": int(response.status),
                "body": _json(parsed, error="object response required"),
            }
    except urllib.error.HTTPError as error:
        raw = error.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("response body exceeds bound") from None
        parsed = json.loads(raw) if raw else {}
        return {
            "status": int(error.code),
            "body": _json(parsed, error="object response required"),
        }
    except (
        OSError,
        TimeoutError,
        http.client.HTTPException,
        json.JSONDecodeError,
    ) as error:
        raise ValueError("bounded worker exchange failed") from error
    finally:
        if time.monotonic() - started > float(seconds) + 0.5:
            raise ValueError("worker walltime exceeded")


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--fixture-origin")
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("worker envelope exceeds bound")
        envelope = _json(json.loads(raw), error="worker envelope required")
        result = exchange(envelope, fixture_origin=args.fixture_origin)
        sys.stdout.write(json.dumps(result, separators=(",", ":"), allow_nan=False))
        return 0
    except Exception as error:  # noqa: BLE001 - only sanitized type crosses process boundary
        sys.stderr.write(type(error).__name__)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
