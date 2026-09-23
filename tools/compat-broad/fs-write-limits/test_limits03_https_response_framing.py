"""Loopback regressions for the Limits-03 HTTP response framing boundary."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import socket
import threading
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
WORKER = HERE / "limits_03_https_worker.py"
EXCHANGE = HERE.parent / "fs-request-bytes-boundary/request_bytes_process_exchange.py"
spec = importlib.util.spec_from_file_location("limits03_framing_exchange", EXCHANGE)
assert spec is not None and spec.loader is not None
exchange = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exchange)

PROJECT = "fireemu-35fe6"
PATH = f"/v1/projects/{PROJECT}/databases/(default)/documents/oracle/{'a' * 32}/limits-03/check"


def _observe(monkeypatch, headers, body=b"{}", *, status=200):
    packet = (
        f"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\n".encode()
        + b"".join(name + b": " + value + b"\r\n" for name, value in headers)
        + b"Connection: close\r\n\r\n"
        + body
    )
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(3)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        request.extend(conn.recv(4096))
                    conn.sendall(packet)
                    conn.shutdown(socket.SHUT_WR)
                    while conn.recv(4096):
                        pass
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        source = WORKER.read_bytes()
        encoded = base64.b64encode(source).decode("ascii")
        wrapper = f'''\
import base64, http.client
ns = {{"__name__": "_worker"}}
exec(compile(base64.b64decode({encoded!r}), "worker", "exec"), ns)
def route(host, *, timeout):
    assert host == "firestore.googleapis.com"
    return http.client.HTTPConnection("127.0.0.1", {port}, timeout=timeout)
http.client.HTTPSConnection = route
ns["run"]()
'''.encode()
        deadline = time.monotonic() + 4
        message = {
            "method": "GET", "path": PATH,
            "authorization": "Bearer synthetic-test-token", "project": PROJECT,
            "bodyBytes": 0, "deadline": deadline,
        }
        result = exchange._run_process_exchange(
            worker_source=wrapper,
            worker_sha256=hashlib.sha256(wrapper).hexdigest(),
            request_payload=json.dumps(message).encode() + b"\n",
            deadline=deadline,
            response_cap=65_536,
        )
        thread.join(timeout=4)
        assert not thread.is_alive()
        assert not errors, errors
        return result


@pytest.mark.parametrize(
    "headers,body",
    [
        ([(b"Content-Length", b"2"), (b"Transfer-Encoding", b"chunked")], b"2\r\n{}\r\n0\r\n\r\n"),
        ([(b"Transfer-Encoding", b"chunked"), (b"Content-Length", b"2")], b"2\r\n{}\r\n0\r\n\r\n"),
        ([(b"Transfer-Encoding", b"gzip")], b"{}"),
        ([(b"Transfer-Encoding", b"gzip, chunked")], b"{}"),
        ([(b"Transfer-Encoding", b"chunked"), (b"Transfer-Encoding", b"chunked")], b"{}"),
    ],
)
def test_ambiguous_response_framing_is_never_a_complete_observation(monkeypatch, headers, body):
    status, _, raw, failure = _observe(monkeypatch, headers, body)
    assert status == 200
    assert failure == "response-incomplete"
    assert raw == b""


@pytest.mark.parametrize("lengths", [[b"+2"], [b"0_2"], [b"-2"], [b"2, 2"], [b"2", b"2"], [b"2", b"3"]])
def test_non_decimal_or_duplicate_lengths_are_rejected(monkeypatch, lengths):
    headers = [(b"Content-Length", value) for value in lengths]
    status, _, raw, failure = _observe(monkeypatch, headers)
    assert status == 200
    assert failure == "invalid-content-length"
    assert raw == b""


@pytest.mark.parametrize("coding", [b"gzip", b"br", b"identity"])
def test_content_encoded_responses_are_not_complete_observations(monkeypatch, coding):
    status, _, _, failure = _observe(
        monkeypatch, [(b"Content-Encoding", coding)], b"compressed bytes"
    )
    assert status == 200
    assert failure == "response-incomplete"


@pytest.mark.parametrize("status", [101, 204, 205, 304])
@pytest.mark.parametrize("body", [b"", b"{}"])
def test_bodyless_status_is_outside_the_observation_contract(
    monkeypatch, status, body
):
    actual, _, _, failure = _observe(monkeypatch, [], body, status=status)
    assert actual == status
    assert failure == "response-incomplete"


@pytest.mark.parametrize("coding", [b" chunked", b"chunked \t"])
def test_chunked_transfer_coding_allows_optional_whitespace(monkeypatch, coding):
    status, _, raw, failure = _observe(
        monkeypatch,
        [(b"Transfer-Encoding", coding)],
        b"2\r\n{}\r\n0\r\n\r\n",
    )
    assert (status, raw, failure) == (200, b"{}", None)
