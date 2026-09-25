"""Loopback-only HTTP transport for the OpenAI-compatible chat endpoint.

Built on a socket we own with http.client parsing the reply: it never
consults proxy environment variables, never follows redirects (a 3xx is
refused), and the deadline is a true wall-clock cutoff. One deadline covers
connect, send, status line, headers and body: every socket read, including
the ones http.client makes while parsing the head, is given only the time
that remains, and when the deadline passes the socket is closed and the
request abandoned. A reply counts only when the HTTP response was received
in full (the declared Content-Length, or the terminating chunk); JSON that
happens to parse from a truncated body is refused. Errors carry a status word
and a short reason; bodies are never included in exceptions or logs.
"""

from __future__ import annotations

import http.client
import io
import ipaddress
import json
import math
import re
import socket
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from local_assist.packet import MAX_DEADLINE_SECONDS, validate_loopback_url

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
USER_AGENT = "fireemu-local-assist/1"
MAX_API_KEY_BYTES = 512
_METHOD = re.compile(r"^[A-Z]{3,10}$")
# A bearer credential is a single line of printable ASCII: anything else could
# split the request head or is not a token the server hands out.
_API_KEY = re.compile(r"^[\x21-\x7e]+$")

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


class _DeadlineReader(io.RawIOBase):
    """Raw reads over our socket, each bounded by the time left to the deadline.

    http.client parses the status line and headers with buffered reads over
    the file object this yields; a socket timeout set once would restart on
    every fragment, so the timeout is re-derived from the deadline on every
    underlying recv instead. Closing this object does not close the socket:
    the caller owns it and closes it exactly once.
    """

    def __init__(self, sock: socket.socket, deadline: float):
        super().__init__()
        self._sock = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        self._sock.settimeout(_remaining(self._deadline))
        return self._sock.recv_into(buffer)

    def makefile(self, mode: str = "rb", *_args, **_kwargs) -> io.BufferedReader:
        # HTTPResponse asks the "socket" for a binary file object.
        assert mode == "rb"
        return io.BufferedReader(self, READ_CHUNK_BYTES)


class _StrictResponse(http.client.HTTPResponse):
    """HTTPResponse that treats EOF inside the chunked trailer as truncation.

    The standard parser tolerates a server that closes right after the `0`
    size line without the final CRLF; for this transport a chunked reply is
    complete only when its terminator was received in full.
    """

    def _read_and_discard_trailer(self) -> None:  # standard-library hook
        while True:
            line = self.fp.readline(http.client._MAXLINE + 1)
            if len(line) > http.client._MAXLINE:
                raise http.client.LineTooLong("trailer line")
            if not line:
                raise http.client.IncompleteRead(b"")
            if line in (b"\r\n", b"\n"):
                break


def _check_framing(response: http.client.HTTPResponse) -> None:
    """Refuse replies whose body length is declared ambiguously.

    Exactly one framing is accepted: one Content-Length, or a single
    `Transfer-Encoding: chunked`, or neither (delimited by close).
    """
    lengths = response.headers.get_all("Content-Length") or []
    encodings = response.headers.get_all("Transfer-Encoding") or []
    if len(lengths) > 1:
        raise TransportError("server-error", "duplicate Content-Length")
    if len(encodings) > 1:
        raise TransportError("server-error", "duplicate Transfer-Encoding")
    if encodings and encodings[0].strip().lower() != "chunked":
        raise TransportError("server-error", "unsupported transfer encoding")
    if encodings and lengths:
        raise TransportError("server-error", "conflicting body framing")
    if lengths and not re.fullmatch(r"\d{1,12}", lengths[0].strip()):
        raise TransportError("server-error", "invalid Content-Length")


def _connect(host: str, port: int, timeout: float) -> socket.socket:
    """Open the loopback connection without a resolver.

    `localhost` is bound to 127.0.0.1 explicitly and IPv6 loopback is given
    as `[::1]`; either way the address is a literal, so no DNS lookup, proxy
    variable or ambient credential can take part.
    """
    literal = "127.0.0.1" if host == "localhost" else host
    address = ipaddress.ip_address(literal)
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((literal, port))
    except BaseException:
        sock.close()
        raise
    return sock


def _validate_call(method: str, url: str, timeout: object, api_key: str | None) -> int:
    """Check the arguments that must never reach a socket when wrong."""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TransportError("server-error", "timeout must be a number")
    try:
        seconds = float(timeout)
    except OverflowError:
        raise TransportError("server-error", "timeout out of range") from None
    if not math.isfinite(seconds) or seconds <= 0 or seconds > MAX_DEADLINE_SECONDS:
        raise TransportError("server-error", "timeout out of range")
    if not isinstance(method, str) or not _METHOD.fullmatch(method):
        raise TransportError("server-error", "invalid HTTP method")
    if api_key is not None and (
        not isinstance(api_key, str)
        or not _API_KEY.fullmatch(api_key)
        or len(api_key) > MAX_API_KEY_BYTES
    ):
        raise TransportError("server-error", "invalid api key")
    validate_loopback_url(url)
    try:
        port = urlsplit(url).port
    except ValueError:
        raise TransportError("server-error", "invalid port") from None
    if port is None or not 1 <= port <= 65535:
        raise TransportError("server-error", "invalid port")
    return port


def _read_body(response: http.client.HTTPResponse) -> bytes:
    """Read the whole body; refuse it unless the response was received in full.

    `response.length` is the Content-Length still to come (None when chunked or
    delimited by close). At EOF a fixed-length body must have delivered every
    declared byte and a chunked body must have ended with the terminating
    chunk, which http.client reports by closing its file object. Timing is
    enforced by the reader underneath, so no per-read timeout is set here.
    """
    declared = response.length
    if declared is not None and declared > MAX_RESPONSE_BYTES:
        raise TransportError("server-error", "response larger than the byte cap")
    chunks: list[bytes] = []
    total = 0
    while True:
        # read1 returns after one recv; read(n) would wait for n bytes.
        chunk = response.read1(READ_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise TransportError("server-error", "response larger than the byte cap")
        chunks.append(chunk)
    # The request went out and no complete answer came back: the server's
    # state is unknown, exactly as after a timeout.
    if declared is not None and total != declared:
        raise TransportError("server-error", "incomplete body", inflight=True)
    if response.chunked and not response.isclosed():
        raise TransportError("server-error", "incomplete body", inflight=True)
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
    port = _validate_call(method, url, timeout, api_key)
    parts = urlsplit(url)
    host = parts.hostname or ""
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
        # request whatever the server is still doing. sendall is bounded as a
        # whole by the timeout it is given.
        sock = _connect(host, port, _remaining(deadline))
        sock.settimeout(_remaining(deadline))
        sock.sendall(head.encode("ascii") + b"\r\n" + data)
        sent = True
        response = _StrictResponse(_DeadlineReader(sock, deadline), method=method)
        response.begin()
        _check_framing(response)
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
        raw = _read_body(response)
    except TransportError as error:
        if error.status == "timeout":
            error.inflight = sent
        raise
    except (TimeoutError, socket.timeout):  # noqa: UP041 - socket.timeout is distinct on 3.9
        raise TransportError("timeout", "request deadline exceeded", inflight=sent)
    except http.client.IncompleteRead:
        # http.client noticed the truncation first (EOF inside a chunk).
        raise TransportError("server-error", "incomplete body", inflight=sent)
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
