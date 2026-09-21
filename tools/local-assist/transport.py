"""Loopback-only HTTP transport for the OpenAI-compatible chat endpoint.

The opener carries no proxy handlers, so proxy environment variables are
ignored, and it refuses redirects so a misconfigured server cannot forward a
prompt anywhere else. Errors carry a status word and a short reason; bodies
are never included in exceptions or logs.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable

from packet import validate_loopback_url

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
USER_AGENT = "fireemu-local-assist/1"

# A transport takes (method, url, body-or-None, timeout) and returns the decoded
# JSON object. Tests can substitute an in-memory function.
Transport = Callable[[str, str, "dict | None", float], dict]


class TransportError(Exception):
    """A request failed. `status` is a finishStatus word, `reason` is short."""

    def __init__(self, status: str, reason: str):
        super().__init__(f"{status}: {reason}")
        self.status = status
        self.reason = reason


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def http_json(method: str, url: str, body: dict | None, timeout: float) -> dict:
    """Send one request to a loopback URL and decode the JSON reply."""
    validate_loopback_url(url)
    data = None
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _opener().open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise TransportError(
                "server-error", f"redirect refused (HTTP {error.code})"
            )
        if error.code in (429, 503):
            raise TransportError("busy", f"server reported HTTP {error.code}")
        raise TransportError("server-error", f"HTTP {error.code}")
    except urllib.error.URLError as error:
        reason = error.reason
        if isinstance(reason, TimeoutError):
            raise TransportError("timeout", "request deadline exceeded")
        raise TransportError(
            "server-error", f"connection failed ({type(reason).__name__})"
        )
    except TimeoutError:
        raise TransportError("timeout", "request deadline exceeded")
    except OSError as error:
        raise TransportError(
            "server-error", f"connection failed ({type(error).__name__})"
        )
    if len(raw) > MAX_RESPONSE_BYTES:
        raise TransportError("server-error", "response larger than the byte cap")
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TransportError("server-error", "response body is not JSON")
    if not isinstance(decoded, dict):
        raise TransportError("server-error", "response body is not a JSON object")
    return decoded
