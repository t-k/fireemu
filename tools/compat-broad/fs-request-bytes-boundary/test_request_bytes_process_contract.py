"""Fail-first contract for a bounded, per-request process exchange.

The fixture worker talks only to a local socket. These tests intentionally stay
red until the production transport has a process cancellation boundary.
"""

import base64
import hashlib
import inspect
import json
import os
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest
import request_bytes_process_exchange as transport
import request_bytes_remote_transport as receipts

WORKER = r"""
import http.client
import json
import os
import socket
import struct
import sys

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
assert sys.argv[0] == "-c" and "__file__" not in globals()
request = json.loads(sys.stdin.buffer.readline())
with open(request["pid_file"], "w", encoding="ascii") as stream:
    stream.write(str(os.getpid()))
connection = http.client.HTTPConnection("127.0.0.1", request["port"], timeout=10)
connection.request("GET", "/")
response = connection.getresponse()

def frame(kind, payload):
    sys.stdout.buffer.write(kind + struct.pack(">I", len(payload)) + payload)
    sys.stdout.buffer.flush()

frame(b"H", json.dumps({"status": response.status, "contentType":
    response.getheader("Content-Type", "")}).encode())
while True:
    chunk = response.read1(1)
    if not chunk:
        break
    frame(b"B", chunk)
frame(b"E", b"")
"""

FLOOD_WORKER = r"""
import json
import os
import struct
import sys

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
assert sys.argv[0] == "-c" and "__file__" not in globals()
request = json.loads(sys.stdin.buffer.readline())
with open(request["pid_file"], "w", encoding="ascii") as stream:
    stream.write(str(os.getpid()))
header = b'{"status":200,"contentType":"text/plain"}'
sys.stdout.buffer.write(b"H" + struct.pack(">I", len(header)) + header)
sys.stdout.buffer.flush()
frame = b"B" + struct.pack(">I", 1) + b"x"
while True:
    sys.stdout.buffer.write(frame)
    sys.stdout.buffer.flush()
"""


def _server(chunks: list[tuple[float, bytes]]):
    ready = threading.Event()
    done = threading.Event()
    port = []

    def serve():
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(1)
                port.append(listener.getsockname()[1])
                ready.set()
                try:
                    peer, _ = listener.accept()
                except TimeoutError:
                    return
                with peer:
                    peer.settimeout(2)
                    peer.recv(4096)
                    for delay, data in chunks:
                        time.sleep(delay)
                        try:
                            peer.sendall(data)
                        except (BrokenPipeError, ConnectionResetError):
                            break
        finally:
            done.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(1)
    return port[0], done, thread


def _exchange(tmp_path: Path, port: int, timeout: float, worker_source=WORKER):
    worker = tmp_path / "fixture_worker.py"
    worker.write_text(worker_source, encoding="utf-8")
    verified_source = worker.read_bytes()
    verified_digest = hashlib.sha256(verified_source).hexdigest()
    worker.write_text(
        'raise SystemExit("changed worker source must not run")\n', encoding="utf-8"
    )
    pid_file = tmp_path / "worker.pid"
    payload = json.dumps({"port": port, "pid_file": str(pid_file)}).encode() + b"\n"
    start = time.monotonic()
    result = transport._run_process_exchange(
        worker_source=verified_source,
        request_payload=payload,
        deadline=start + timeout,
        response_cap=1024,
        worker_sha256=verified_digest,
    )
    elapsed = time.monotonic() - start
    assert pid_file.exists()
    pid = int(pid_file.read_text(encoding="ascii"))
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    return result, elapsed


def test_header_drip_is_interrupted_at_one_absolute_deadline(tmp_path):
    header = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"
    chunks = [(0.03, bytes([byte])) for byte in header]
    port, done, thread = _server(chunks)
    try:
        result, elapsed = _exchange(tmp_path, port, 0.5)
        assert result == (None, "", b"", "timeout")
        assert elapsed < 0.9
    finally:
        assert done.wait(3)
        thread.join(1)


def test_partial_body_frames_remain_evidence_on_timeout(tmp_path):
    chunks = [
        (
            0,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n",
        ),
        (0, b"abc"),
        (1.0, b"def"),
    ]
    port, done, thread = _server(chunks)
    try:
        result, elapsed = _exchange(tmp_path, port, 0.5)
        status, content_type, raw, failure = result
        assert (status, content_type, raw, failure) == (
            200,
            "application/json",
            b"abc",
            "timeout",
        )
        receipt = receipts._result(
            status, {"Content-Type": content_type}, raw, failure, None
        )
        assert receipt["complete"] is False
        assert receipt["rawBodyBytes"] == 3
        assert receipt["rawBodySha256"] == hashlib.sha256(b"abc").hexdigest()
        assert receipt["rawBodyBase64"] == base64.b64encode(b"abc").decode("ascii")
        assert elapsed < 0.9
    finally:
        assert done.wait(2)
        thread.join(1)


def test_stdout_flood_is_stopped_at_wire_cap_and_worker_reaped(tmp_path, monkeypatch):
    original_read = os.read
    read_total = 0

    def counted_read(fd, size):
        nonlocal read_total
        caller = inspect.currentframe().f_back
        from_exchange = caller is not None and caller.f_code.co_filename.endswith(
            "request_bytes_process_exchange.py"
        )
        if from_exchange:
            assert size <= 16_384
        data = original_read(fd, size)
        if from_exchange:
            read_total += len(data)
        return data

    monkeypatch.setattr(transport.os, "read", counted_read)
    result, elapsed = _exchange(tmp_path, 0, 2.0, FLOOD_WORKER)
    assert read_total <= 6 * 1024 + 1025
    status, content_type, raw, failure = result
    assert status == 200
    assert content_type == "text/plain"
    assert failure == "ipc-oversize"
    assert 0 < len(raw) <= 1024
    assert elapsed < 1.0


def test_immediate_response_completes_and_reaps_worker(tmp_path):
    port, done, thread = _server(
        [(0, b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno")]
    )
    try:
        result, _ = _exchange(tmp_path, port, 1.0)
        assert result == (403, "", b"no", None)
    finally:
        assert done.wait(2)
        thread.join(1)


def test_chunked_body_drip_stops_at_deadline_with_partial_evidence(tmp_path):
    chunks = [(0, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")]
    chunks.extend((0.06, b"1\r\nx\r\n") for _ in range(20))
    port, done, thread = _server(chunks)
    try:
        result, elapsed = _exchange(tmp_path, port, 0.5)
        assert result[0] == 200
        assert result[2]
        assert result[3] == "timeout"
        assert elapsed < 0.9
    finally:
        assert done.wait(3)
        thread.join(1)


def test_malformed_frame_fails_closed_and_reaps_worker(tmp_path):
    worker = """
import json, os, sys
request = json.loads(sys.stdin.buffer.readline())
with open(request["pid_file"], "w") as stream: stream.write(str(os.getpid()))
sys.stdout.buffer.write(b"B\\x00\\x00\\x00\\x01x")
sys.stdout.buffer.flush()
"""
    result, _ = _exchange(tmp_path, 0, 1.0, worker)
    assert result == (None, "", b"", "ipc-malformed")


def test_worker_crash_is_incomplete_and_reaped(tmp_path):
    worker = """
import json, os, sys
request = json.loads(sys.stdin.buffer.readline())
with open(request["pid_file"], "w") as stream: stream.write(str(os.getpid()))
raise SystemExit(7)
"""
    result, _ = _exchange(tmp_path, 0, 1.0, worker)
    assert result == (None, "", b"", "ipc-incomplete")


def test_worker_failure_cannot_echo_secret_into_result(tmp_path):
    worker = """
import json, os, struct, sys
request = json.loads(sys.stdin.buffer.readline())
with open(request["pid_file"], "w") as stream: stream.write(str(os.getpid()))
payload = b"secret-test-credential"
sys.stdout.buffer.write(b"F" + struct.pack(">I", len(payload)) + payload)
sys.stdout.buffer.flush()
"""
    result, _ = _exchange(tmp_path, 0, 1.0, worker)
    assert result == (None, "", b"", "ipc-malformed")


def test_one_byte_frames_up_to_body_cap_are_valid(tmp_path):
    worker = """
import json, os, struct, sys
request = json.loads(sys.stdin.buffer.readline())
with open(request["pid_file"], "w") as stream: stream.write(str(os.getpid()))
header = b'{"status":200,"contentType":"text/plain"}'
sys.stdout.buffer.write(b"H" + struct.pack(">I", len(header)) + header)
for _ in range(600):
    sys.stdout.buffer.write(b"B\\x00\\x00\\x00\\x01x")
sys.stdout.buffer.write(b"E\\x00\\x00\\x00\\x00")
sys.stdout.buffer.flush()
"""
    result, _ = _exchange(tmp_path, 0, 1.0, worker)
    assert result == (200, "text/plain", b"x" * 600, None)


def test_selector_construction_failure_reaps_spawned_worker(monkeypatch):
    spawned = []
    original_popen = subprocess.Popen

    def capture_process(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        spawned.append(process)
        return process

    def reject_selector():
        raise OSError("selector unavailable")

    monkeypatch.setattr(transport.subprocess, "Popen", capture_process)
    monkeypatch.setattr(transport.selectors, "DefaultSelector", reject_selector)
    source = b"import time\ntime.sleep(10)\n"
    with pytest.raises(OSError, match="selector unavailable"):
        transport._run_process_exchange(
            worker_source=source,
            request_payload=b"private-token\n",
            deadline=time.monotonic() + 2,
            response_cap=1024,
            worker_sha256=hashlib.sha256(source).hexdigest(),
        )
    assert len(spawned) == 1
    process = spawned[0]
    assert process.poll() is not None
    assert process.stdin is not None and process.stdin.closed
    assert process.stdout is not None and process.stdout.closed


def test_process_frame_admits_the_bounded_sentinel_request_payload():
    source = b"""import json, struct, sys
sys.stdin.buffer.readline()
sys.stdin.buffer.read()
header = b'{\"status\":200,\"contentType\":\"application/json\"}'
sys.stdout.buffer.write(b'H' + struct.pack('>I', len(header)) + header)
sys.stdout.buffer.write(b'E' + struct.pack('>I', 0))
sys.stdout.buffer.flush()
"""
    body_bytes = 16_777_217
    overhead = 8192 + 4096 + 8
    payload = b"{}\n" + b"x" * (body_bytes + overhead - 3)

    result = transport._run_process_exchange(
        worker_source=source,
        request_payload=payload,
        deadline=time.monotonic() + 20,
        response_cap=1024,
        worker_sha256=hashlib.sha256(source).hexdigest(),
    )

    assert result == (200, "application/json", b"", None)


def test_process_frame_rejects_one_byte_above_the_sentinel_request_cap():
    source = b"raise SystemExit(0)\n"
    payload = b"x" * (16_777_217 + 8192 + 4096 + 8 + 1)
    with pytest.raises(ValueError, match="invalid request payload"):
        transport._run_process_exchange(
            worker_source=source,
            request_payload=payload,
            deadline=time.monotonic() + 20,
            response_cap=1024,
            worker_sha256=hashlib.sha256(source).hexdigest(),
        )
