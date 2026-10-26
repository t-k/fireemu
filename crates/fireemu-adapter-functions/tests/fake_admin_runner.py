#!/usr/bin/env python3
"""A runner that asks the daemon App Check verification questions over its own stdio pipe.

An `invoke` whose event carries `requests` (a list of {requestId, projectId, token}) or `raw`
(frames sent verbatim) makes this runner write one `appCheck:verify` frame per entry, read back
`expect` verdict frames (default: one per request) with a bounded wait, and answer the invoke
with the collected verdicts as JSON in the result's `error` text. A runner that never gets a
verdict reports `timeout` for the missing ones.
"""
import json
import os
import select
import sys
import time


def send(msg):
    payload = json.dumps(msg).encode()
    sys.stdout.buffer.write(f"{len(payload)}\n".encode())
    sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


_buffer = bytearray()


def _fill(timeout):
    """Reads at least one more byte from fd 0 (None on EOF, "timeout" when none came)."""
    if timeout is not None:
        ready, _, _ = select.select([0], [], [], timeout)
        if not ready:
            return "timeout"
    chunk = os.read(0, 65536)
    if not chunk:
        return None
    _buffer.extend(chunk)
    return True


def read_frame(timeout=None):
    """One frame, reading raw bytes so `select` and the buffer never disagree."""
    deadline = None if timeout is None else time.time() + timeout
    while True:
        newline = _buffer.find(b"\n")
        if newline >= 0:
            length = int(_buffer[:newline])
            if len(_buffer) >= newline + 1 + length:
                body = bytes(_buffer[newline + 1 : newline + 1 + length])
                del _buffer[: newline + 1 + length]
                return json.loads(body)
        remaining = None if deadline is None else max(deadline - time.time(), 0)
        got = _fill(remaining)
        if got is None:
            return None
        if got == "timeout":
            return "timeout"


send(
    {
        "type": "hello",
        "runner": "node",
        "manifest": {"functions": []},
        "adminAppCheck": {"instrumentation": "ok", "firebaseAdminVersion": "14.3.0"},
    }
)

while True:
    frame = read_frame()
    if frame is None or frame.get("type") == "shutdown":
        break
    if frame.get("type") != "invoke":
        continue
    event = frame.get("event", {})
    for request in event.get("requests", []):
        send({"type": "appCheck:verify", **request})
    for raw in event.get("raw", []):
        send(raw)
    if event.get("closeStdin"):
        # Stop reading but stay alive: the daemon's verdict write must fail and retire us.
        os.close(0)
        time.sleep(4)
        break
    expect = event.get("expect", len(event.get("requests", [])))
    wait = event.get("waitSeconds", 10)
    verdicts = []
    deadline = time.time() + wait
    while len(verdicts) < expect:
        remaining = deadline - time.time()
        got = read_frame(max(remaining, 0)) if remaining > 0 else "timeout"
        if got == "timeout" or got is None:
            verdicts.append({"requestId": None, "timeout": True})
            break
        if got.get("type") == "appCheck:verdict":
            verdicts.append(got)
    send(
        {
            "type": "result",
            "invocationId": frame["invocationId"],
            "ok": False,
            "error": json.dumps(verdicts),
        }
    )
