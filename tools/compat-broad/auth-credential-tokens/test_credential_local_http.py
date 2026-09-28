"""Real bounded loopback worker and the public credential POST contract."""
from __future__ import annotations

import contextlib
import json
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import credential_shadow as shadow
import credential_wire as wire
from credential_collector import new_budget


@contextlib.contextmanager
def server(response, *, drip=False):
    calls = []
    finished = threading.Event()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            raw = b""
            try:
                while b"\r\n\r\n" not in raw:
                    chunk = self.request.recv(65536)
                    if not chunk:
                        return
                    raw += chunk
                    if len(raw) > 131072:
                        return
                calls.append(raw)
                if drip:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10000\r\n\r\n{")
                    for _ in range(100):
                        self.request.sendall(b" ")
                        time.sleep(.02)
                else:
                    self.request.sendall(response)
            except (OSError, TimeoutError):
                pass
            finally:
                finished.set()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": .005}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", calls, finished
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def response(body=b"{}", status=200, headers=None):
    headers = headers if headers is not None else [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
    return f"HTTP/1.1 {status} test\r\n".encode() + b"".join(f"{k}: {v}\r\n".encode() for k, v in headers) + b"\r\n" + body


def budget():
    return new_budget(10, 60, 0.0, started_monotonic=time.monotonic())


BAD_JSON = [b"", b"[]", b"null", b"false", b'"text"', b'{"users":[],"users":[]}',
            b'{"x":{"sub":1,"sub":2}}', b'{"x":NaN}', b'{"x":Infinity}',
            b'{"x":1e999}', '{}'.encode('utf-16'), b'{"x":"\xff"}', b'{']


@pytest.mark.parametrize("raw", BAD_JSON)
def test_injected_raw_response_is_not_silently_coerced_to_empty_object(raw):
    b = budget()
    with pytest.raises(shadow.ShadowError):
        shadow.post(b, "http://127.0.0.1:1", "/accounts:lookup", {}, sender=lambda *args: (200, raw))
    assert b["requests"] == 1


@pytest.mark.parametrize("raw", BAD_JSON)
def test_real_worker_rejects_unusable_json(raw):
    with server(response(raw)) as (base, calls, _):
        with pytest.raises(shadow.ShadowError):
            shadow.post(budget(), base, "/identitytoolkit.googleapis.com/v1/accounts:lookup", {})
        assert len(calls) == 1


@pytest.mark.parametrize("raw,status", [(b'{"users":[]}',200), (b'{"kind":"identitytoolkit#GetAccountInfoResponse"}',200),
    (b'{"error":{"message":"TOKEN_EXPIRED"}}',400), (b'{"x":"\xe6\x97\xa5\xe6\x9c\xac"}',200),
    (b'{"x":' + b'"' + b'a' * 65528 + b'"}',200)])
def test_real_worker_keeps_success_and_typed_api_refusal(raw, status):
    with server(response(raw, status)) as (base, calls, _):
        actual_status, parsed = shadow.post(budget(), base, "/accounts:lookup", {}, owner=True)
        assert actual_status == status and parsed == json.loads(raw)
        assert len(calls) == 1 and b"Authorization: Bearer owner" in calls[0]


@pytest.mark.parametrize("headers,body", [
    ([("Content-Type", "text/html"), ("Content-Length", "2")], b"{}"),
    ([("Content-Type", "application/json"), ("Content-Length", "90")], b"{}"),
    ([("Content-Type", "application/json"), ("Content-Length", "2"), ("Content-Length", "2")], b"{}"),
    ([("Content-Type", "application/json"), ("Content-Type", "application/json"), ("Content-Length", "2")], b"{}"),
    ([("Content-Type", "application/json"), ("Content-Length", "2"), ("Transfer-Encoding", "chunked")], b"{}"),
    ([("Content-Type", "application/json"), ("Content-Length", "65537")], b"{" + b" " * 65535 + b"}"),
])
def test_real_worker_rejects_ambiguous_framing_or_oversized_body(headers, body):
    with server(response(body, headers=headers)) as (base, calls, _):
        with pytest.raises(shadow.ShadowError):
            shadow.post(budget(), base, "/accounts:lookup", {})
        assert len(calls) == 1


def test_redirect_is_not_followed():
    with server(response(status=302, headers=[("Location", "http://example.invalid/"), ("Content-Length", "0")], body=b"")) as (base, calls, _):
        with pytest.raises(shadow.ShadowError):
            shadow.post(budget(), base, "/accounts:lookup", {})
        assert len(calls) == 1


@pytest.mark.parametrize("base", ["http://localhost:8123", "https://127.0.0.1:8123", "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:8123@external.invalid", "http://127.0.0.1.evil:8123", "http://10.0.0.1:8123", "http://127.0.0.1:8123#fragment", "http://127.0.0.1:8123\n", "http://[::1]:8123#", "http://127.0.0.1:8123\\evil"])
def test_invalid_origin_is_rejected_before_budget_or_sender(base):
    b = budget()
    called = []
    with pytest.raises(shadow.ShadowError):
        shadow.post(b, base, "/accounts:lookup", {}, sender=lambda *a: called.append(a))
    assert called == [] and b["requests"] == 0


@pytest.mark.parametrize("base,path", [("http://[::1]:8123", "/accounts:lookup"),
    ("http://127.0.0.1:8123/identitytoolkit.googleapis.com/v1/projects/demo-app", ":createSessionCookie"),
    ("http://127.0.0.1:8123/securetoken.googleapis.com/v1/token?key=local", "")])
def test_numeric_loopback_and_existing_rpc_path_shapes_remain_supported(base, path):
    status, body = shadow.post(budget(), base, path, {}, sender=lambda *a: (200,b"{}"))
    assert status == 200 and body == {}


@pytest.mark.parametrize("status", [True, False, 200.0, "200", 0, 199, 600, 302])
def test_injected_http_status_is_typed(status):
    with pytest.raises(shadow.ShadowError):
        shadow.post(budget(), "http://127.0.0.1:1", "/accounts:lookup", {}, sender=lambda *a: (status,b"{}"))


def test_drip_is_stopped_by_whole_request_deadline_and_worker_is_reaped(monkeypatch):
    original = wire.subprocess.Popen
    processes = []
    def capture(*args, **kwargs):
        process = original(*args, **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(wire.subprocess, "Popen", capture)
    monkeypatch.setattr(shadow, "REQUEST_TIMEOUT_SECONDS", .25)
    with server(None, drip=True) as (base, calls, finished):
        started = time.monotonic()
        with pytest.raises(shadow.ShadowError):
            shadow.post(budget(), base, "/accounts:lookup", {})
        assert time.monotonic() - started < 2
        assert len(calls) == 1 and len(processes) == 1
        assert processes[0].poll() is not None
        assert finished.wait(2)


def test_worker_has_no_ambient_credentials_or_secret_argv(monkeypatch):
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/private/credential.json")
    monkeypatch.setenv("HTTP_PROXY", "http://external.invalid:80")
    monkeypatch.setenv("PYTHONPATH", "/private/hooks")
    calls = []
    original = wire.subprocess.run
    def capture(command, **kwargs):
        calls.append((command, kwargs))
        return original(command, **kwargs)
    monkeypatch.setattr(wire.subprocess, "run", capture)
    with server(response()) as (base, _, _):
        shadow.post(budget(), base, "/accounts:lookup", {"idToken": "private-token"})
    command, kwargs = calls[0]
    assert command[1:4] == ["-I", "-S", "-B"]
    assert "private-token" not in repr(command)
    assert b"private-token" in kwargs["input"]
    assert not {"GOOGLE_APPLICATION_CREDENTIALS", "HTTP_PROXY", "PYTHONPATH"} & set(kwargs["env"])


def test_worker_dependency_is_bound():
    from credential_collector import module_digests
    sources = module_digests()
    assert {"credential_wire.py", "credential_process.py", "../batch_wire.py"} <= set(sources)
    assert all(len(sources[name]) == 64 for name in ("credential_wire.py", "credential_process.py", "../batch_wire.py"))
