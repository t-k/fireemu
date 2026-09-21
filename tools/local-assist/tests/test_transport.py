"""Transport tests: response completeness and the wall-clock deadline.

Every scenario runs `http_json` against the scripted loopback server with a
byte-exact `wire` reply, so both the HTTP framing and the timing are under the
test's control. Nothing here talks to a real model server.
"""

from __future__ import annotations

import json
import os
import threading
import time

import pytest
from local_assist.transport import TransportError, http_json
from local_assist_fake_server import FakeLlamaServer

CONTENT = {"findings": [], "unknowns": []}
BODY = json.dumps({"choices": [{"message": {"content": json.dumps(CONTENT)}}]}).encode()


@pytest.fixture
def server():
    fake = FakeLlamaServer().start()
    yield fake
    fake.stop()


def _post(server: FakeLlamaServer, timeout: float = 2.0) -> dict:
    return http_json("POST", server.endpoint, {"messages": []}, timeout)


def _fixed_length(body: bytes, declared: int) -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Content-Length: " + str(declared).encode() + b"\r\n\r\n" + body
    )


def _chunked(body: bytes, terminated: bool) -> bytes:
    head = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
    )
    chunk = f"{len(body):x}".encode() + b"\r\n" + body + b"\r\n"
    return head + chunk + (b"0\r\n\r\n" if terminated else b"")


def _open_fds() -> int:
    return len(os.listdir("/dev/fd"))


def _wait_for_idle(server: FakeLlamaServer) -> None:
    # The handler thread finishes on its own once the client is gone; wait for
    # it so the descriptor count below is not racing the server's close().
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        handlers = [
            thread
            for thread in threading.enumerate()
            if thread is not threading.current_thread() and thread is not server._thread
        ]
        if not handlers:
            return
        time.sleep(0.01)
    raise AssertionError(f"server handler threads still alive: {handlers}")


def test_a_complete_fixed_length_response_is_accepted(server):
    server.replies.append(
        {"__raw__": {"wire": [{"bytes": _fixed_length(BODY, len(BODY))}]}}
    )
    reply = _post(server)
    assert reply == json.loads(BODY)


def test_a_complete_chunked_response_is_accepted(server):
    server.replies.append({"__raw__": {"wire": [{"bytes": _chunked(BODY, True)}]}})
    reply = _post(server)
    assert reply == json.loads(BODY)


def test_valid_json_short_of_the_declared_content_length_is_refused(server):
    # The body parses as JSON, but the server closed 64 bytes early: the HTTP
    # response was never fully received, so it must not count as an answer.
    server.replies.append(
        {"__raw__": {"wire": [{"bytes": _fixed_length(BODY, len(BODY) + 64)}]}}
    )
    with pytest.raises(TransportError) as raised:
        _post(server)
    assert raised.value.status == "server-error"
    assert raised.value.reason == "incomplete body"
    assert raised.value.inflight is True


def test_a_chunked_response_without_the_terminating_chunk_is_refused(server):
    server.replies.append({"__raw__": {"wire": [{"bytes": _chunked(BODY, False)}]}})
    with pytest.raises(TransportError) as raised:
        _post(server)
    assert raised.value.status == "server-error"
    assert raised.value.reason == "incomplete body"
    assert raised.value.inflight is True


def test_a_declared_length_above_the_byte_cap_is_refused_before_reading(server):
    server.replies.append(
        {"__raw__": {"wire": [{"bytes": _fixed_length(BODY, 8 * 1024 * 1024 + 1)}]}}
    )
    with pytest.raises(TransportError) as raised:
        _post(server)
    assert raised.value.status == "server-error"
    assert raised.value.reason == "response larger than the byte cap"


def _fragments(prefix: bytes, count: int, interval: float, tail: bytes) -> list:
    fragments = [{"bytes": prefix}]
    fragments += [{"bytes": b"x", "delay": interval} for _ in range(count)]
    fragments.append({"bytes": tail, "delay": interval})
    return fragments


TRICKLE_PREFIXES = {
    "status-line": (b"HTTP/1.1 200 OK", b"\r\nX-Test: "),
    "header-value": (b"HTTP/1.1 200 OK\r\nX-Test: ", b""),
}


@pytest.mark.parametrize("phase", sorted(TRICKLE_PREFIXES))
def test_trickling_headers_cannot_hold_the_request_past_the_deadline(server, phase):
    # 25 fragments 20 ms apart would keep a per-read socket timeout alive for
    # about half a second; the deadline is 80 ms and must win.
    first, second = TRICKLE_PREFIXES[phase]
    tail = second + b"\r\nContent-Length: " + str(len(BODY)).encode() + b"\r\n\r\n"
    fragments = [{"bytes": first}]
    fragments += [{"bytes": b"x", "delay": 0.02} for _ in range(25)]
    fragments.append({"bytes": tail + BODY, "delay": 0.02})
    server.replies.append({"__raw__": {"wire": fragments}})
    threads_before = set(threading.enumerate())
    fds_before = _open_fds()
    started = time.monotonic()
    with pytest.raises(TransportError) as raised:
        _post(server, timeout=0.08)
    elapsed = time.monotonic() - started
    assert raised.value.status == "timeout"
    assert raised.value.inflight is True
    assert elapsed < 0.08 + 0.15, elapsed
    # The abandoned socket is closed at the deadline: the server's next write
    # fails, its handler thread exits, and nothing of ours is left behind.
    _wait_for_idle(server)
    assert server.abandoned == 1
    assert set(threading.enumerate()) == threads_before
    assert _open_fds() == fds_before


def test_a_trickling_body_within_the_deadline_is_accepted(server):
    head = _fixed_length(b"", len(BODY))
    fragments = [{"bytes": head}]
    fragments += [
        {"bytes": BODY[offset : offset + 16], "delay": 0.01}
        for offset in range(0, len(BODY), 16)
    ]
    server.replies.append({"__raw__": {"wire": fragments}})
    reply = _post(server, timeout=2.0)
    assert reply == json.loads(BODY)


def test_a_trickling_body_slower_than_the_deadline_is_a_timeout(server):
    head = _fixed_length(b"", len(BODY))
    fragments = [{"bytes": head}]
    fragments += [
        {"bytes": BODY[offset : offset + 1], "delay": 0.02}
        for offset in range(len(BODY))
    ]
    server.replies.append({"__raw__": {"wire": fragments}})
    threads_before = set(threading.enumerate())
    fds_before = _open_fds()
    started = time.monotonic()
    with pytest.raises(TransportError) as raised:
        _post(server, timeout=0.08)
    elapsed = time.monotonic() - started
    assert raised.value.status == "timeout"
    assert raised.value.inflight is True
    assert elapsed < 0.08 + 0.15, elapsed
    _wait_for_idle(server)
    assert server.abandoned == 1
    assert set(threading.enumerate()) == threads_before
    assert _open_fds() == fds_before
