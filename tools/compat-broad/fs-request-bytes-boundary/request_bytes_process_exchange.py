"""Bounded, cancellable process exchange for an offline transport worker.

This module does not select a worker or send production requests. The caller
supplies verified worker bytes and the already encoded private request message.
"""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import subprocess
import sys
import time

_MAX_SOURCE = 96 * 1024
_MAX_REQUEST = 16_777_217 + 8192 + 4096 + 8
_MAX_FRAME = 16 * 1024
_MAX_HEADER = 512
_MAX_FAILURE = 128
_FAILURE_CODES = frozenset(
    {
        "timeout",
        "transport-error",
        "response-incomplete",
        "response-oversize",
        "invalid-content-length",
        "worker-failure",
    }
)


def _run_process_exchange(
    *,
    worker_source: bytes,
    request_payload: bytes,
    deadline: float,
    response_cap: int,
    worker_sha256: str,
) -> tuple[int | None, str, bytes, str | None]:
    """Run exact verified worker bytes and retain only complete response frames."""
    if not isinstance(worker_source, bytes) or len(worker_source) > _MAX_SOURCE:
        raise ValueError("invalid worker source")
    if hashlib.sha256(worker_source).hexdigest() != worker_sha256:
        raise ValueError("worker digest mismatch")
    if not isinstance(request_payload, bytes) or len(request_payload) > _MAX_REQUEST:
        raise ValueError("invalid request payload")
    if type(response_cap) is not int or not 0 < response_cap <= 2 * 1024 * 1024:
        raise ValueError("invalid response cap")
    source = worker_source.decode("utf-8")
    if time.monotonic() >= deadline:
        return None, "", b"", "timeout"
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-B", "-c", source],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env={"PATH": os.defpath},
    )
    selector: selectors.BaseSelector | None = None
    status: int | None = None
    content_type = ""
    body = bytearray()
    pending = bytearray()
    sent = 0
    wire = 0
    # A one-byte B frame costs six wire bytes. Permit the worst legal
    # fragmentation, one header, and the terminal frame.
    wire_cap = 6 * response_cap + 1024
    terminal: str | None = None
    failure: str | None = None
    try:
        assert process.stdin is not None and process.stdout is not None
        selector = selectors.DefaultSelector()
        os.set_blocking(process.stdin.fileno(), False)
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        if request_payload:
            selector.register(process.stdin, selectors.EVENT_WRITE)
        else:
            process.stdin.close()
        while terminal is None and failure is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timeout"
                break
            events = selector.select(remaining)
            if not events:
                failure = "timeout"
                break
            for key, _ in events:
                if time.monotonic() >= deadline:
                    failure = "timeout"
                    break
                if key.fileobj is process.stdin:
                    try:
                        count = os.write(
                            process.stdin.fileno(), request_payload[sent : sent + 16384]
                        )
                    except (BrokenPipeError, OSError):
                        selector.unregister(process.stdin)
                        process.stdin.close()
                        continue
                    sent += count
                    if sent == len(request_payload):
                        selector.unregister(process.stdin)
                        process.stdin.close()
                else:
                    try:
                        chunk = os.read(
                            process.stdout.fileno(), min(16384, wire_cap + 1 - wire)
                        )
                    except OSError:
                        failure = "ipc-error"
                        break
                    if not chunk:
                        failure = "ipc-incomplete"
                        break
                    wire += len(chunk)
                    crossed_wire_cap = wire > wire_cap
                    pending.extend(chunk)
                    while len(pending) >= 5:
                        kind = pending[0]
                        length = int.from_bytes(pending[1:5], "big")
                        if (
                            (kind == ord("H") and length > _MAX_HEADER)
                            or (
                                kind == ord("B")
                                and (length == 0 or length > _MAX_FRAME)
                            )
                            or (kind == ord("E") and length != 0)
                            or (kind == ord("F") and length > _MAX_FAILURE)
                            or kind not in b"HBEF"
                        ):
                            failure = "ipc-malformed"
                            break
                        if len(pending) < 5 + length:
                            break
                        payload = bytes(pending[5 : 5 + length])
                        del pending[: 5 + length]
                        if kind == ord("H"):
                            if status is not None:
                                failure = "ipc-malformed"
                                break
                            try:
                                header = json.loads(payload)
                                value = header["status"]
                                content = header["contentType"]
                                if (
                                    type(value) is not int
                                    or not 100 <= value <= 599
                                    or not isinstance(content, str)
                                    or len(content.encode()) > 128
                                ):
                                    raise ValueError
                                status, content_type = value, content
                            except (
                                KeyError,
                                ValueError,
                                TypeError,
                                UnicodeDecodeError,
                            ):
                                failure = "ipc-malformed"
                                break
                        elif kind == ord("B"):
                            if status is None or len(body) + length > response_cap:
                                failure = (
                                    "ipc-oversize"
                                    if status is not None
                                    else "ipc-malformed"
                                )
                                break
                            body.extend(payload)
                        elif kind == ord("E"):
                            if status is None or pending:
                                failure = "ipc-malformed"
                            else:
                                terminal = "complete"
                            break
                        else:
                            if pending:
                                failure = "ipc-malformed"
                            else:
                                try:
                                    code = payload.decode("ascii")
                                except UnicodeDecodeError:
                                    code = ""
                                if code not in _FAILURE_CODES:
                                    failure = "ipc-malformed"
                                else:
                                    terminal = "failure"
                                    failure = code
                            break
                    if crossed_wire_cap and failure is None:
                        failure = "ipc-oversize"
                    if failure or terminal:
                        break
            if process.poll() is not None and terminal is None and not events:
                failure = "ipc-incomplete"
        if time.monotonic() >= deadline:
            failure = "timeout"
        return status, content_type, bytes(body), failure
    finally:
        try:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            for stream in (process.stdin, process.stdout):
                if stream is not None and not stream.closed:
                    stream.close()
        finally:
            process.wait()
            if selector is not None:
                selector.close()
