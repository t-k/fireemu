"""Loopback-only HTTP transport for the OpenAI-compatible chat endpoint.

Built on a socket we own with http.client parsing the reply: it never
consults proxy environment variables, never follows redirects (a 3xx is
refused), and the deadline is a true wall-clock cutoff. The body is read in
bounded chunks and each read is given only the time that remains; when the
deadline passes the connection is closed and the request abandoned. Errors
carry a status word and a short reason; bodies are never included in
exceptions or logs.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from local_assist.packet import validate_loopback_url

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
USER_AGENT = "fireemu-local-assist/1"

# A transport takes (method, url, body-or-None, timeout) and returns the decoded
# JSON object. Tests can substitute an in-memory function.
Transport = Callable[[str, str, "dict | None", float], dict]


class TransportError(Exception):
    """A request failed. `status` is a finishStatus word, `reason` is short.

    `inflight` is True when the request had already been sent and no complete
    response came back, so the server may still be working on it.
    """

    def __init__(self, status: str, reason: str, inflight: bool = False):
        super().__init__(f"{status}: {reason}")
        self.status = status
        self.reason = reason
        self.inflight = inflight


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportError("timeout", "request deadline exceeded")
    return remaining


def _read_body(sock: socket.socket, response, deadline: float) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        sock.settimeout(_remaining(deadline))
        # read1 returns after one recv; read(n) would wait for n bytes.
        chunk = response.read1(READ_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise TransportError("server-error", "response larger than the byte cap")
        chunks.append(chunk)
    return b"".join(chunks)


def http_json(
    method: str,
    url: str,
    body: dict | None,
    timeout: float,
    api_key: str | None = None,
) -> dict:
    """Send one request to a loopback URL and decode the JSON reply.

    `api_key`, when given, is sent as a bearer token; it is never logged.
    """
    validate_loopback_url(url)
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or 80
    path = parts.path or "/"
    data = b""
    headers = [
        ("Host", f"[{host}]:{port}" if ":" in host else f"{host}:{port}"),
        ("Connection", "close"),
        ("Accept", "application/json"),
        ("User-Agent", USER_AGENT),
    ]
    if api_key:
        headers.append(("Authorization", f"Bearer {api_key}"))
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers.append(("Content-Type", "application/json"))
    headers.append(("Content-Length", str(len(data))))
    head = f"{method} {path} HTTP/1.1\r\n" + "".join(
        f"{k}: {v}\r\n" for k, v in headers
    )
    deadline = time.monotonic() + timeout
    sock = None
    sent = False
    try:
        # The socket is ours: http.client only parses over it, so every read
        # below gets exactly the time that remains and close() abandons the
        # request whatever the server is still doing.
        sock = socket.create_connection((host, port), timeout=_remaining(deadline))
        sock.settimeout(_remaining(deadline))
        sock.sendall(head.encode("ascii") + b"\r\n" + data)
        sent = True
        response = http.client.HTTPResponse(sock, method=method)
        sock.settimeout(_remaining(deadline))
        response.begin()
        if 300 <= response.status < 400:
            raise TransportError(
                "server-error", f"redirect refused (HTTP {response.status})"
            )
        if response.status in (401, 403):
            raise TransportError(
                "server-error",
                f"server refused the credential (HTTP {response.status})",
            )
        if response.status in (429, 503):
            raise TransportError("busy", f"server reported HTTP {response.status}")
        if response.status != 200:
            raise TransportError("server-error", f"HTTP {response.status}")
        raw = _read_body(sock, response, deadline)
    except TransportError as error:
        if error.status == "timeout":
            error.inflight = sent
        raise
    except (TimeoutError, socket.timeout):  # noqa: UP041 - socket.timeout is distinct on 3.9
        raise TransportError("timeout", "request deadline exceeded", inflight=sent)
    except (OSError, http.client.HTTPException) as error:
        raise TransportError(
            "server-error", f"connection failed ({type(error).__name__})", inflight=sent
        )
    finally:
        if sock is not None:
            sock.close()
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TransportError("server-error", "response body is not JSON")
    if not isinstance(decoded, dict):
        raise TransportError("server-error", "response body is not a JSON object")
    return decoded
