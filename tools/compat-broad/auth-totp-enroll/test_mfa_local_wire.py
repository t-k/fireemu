"""Real loopback/worker regressions; no Firebase or native artifact required."""
from __future__ import annotations

import contextlib
import json
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import mfa_local_shadow as shadow
import mfa_wire as wire


@contextlib.contextmanager
def server(response, *, drip=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    result = {"calls": 0, "request": b"", "closed": False}
    stop = threading.Event()
    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(2)
                result["calls"] += 1
                while b"\r\n\r\n" not in result["request"]:
                    block = conn.recv(4096)
                    if not block:
                        return
                    result["request"] += block
                headers, body = result["request"].split(b"\r\n\r\n", 1)
                length = next((int(x.split(b":", 1)[1]) for x in headers.split(b"\r\n")
                               if x.lower().startswith(b"content-length:")), 0)
                while len(body) < length:
                    block = conn.recv(4096)
                    if not block:
                        return
                    result["request"] += block
                    body += block
                if drip:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 900\r\n\r\n")
                    # Inactivity never reaches the socket timeout. Only the parent
                    # deadline can interrupt this continuously arriving body.
                    while not stop.wait(0.025):
                        conn.sendall(b" ")
                else:
                    conn.sendall(response)
        except (OSError, ValueError):
            pass
        finally:
            result["closed"] = True
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}/test", result
    finally:
        stop.set()
        listener.close()
        thread.join(4)
        assert not thread.is_alive()


def reply(body=b"{}", *, status=200, headers=None):
    if headers is None:
        headers = [b"Content-Type: application/json", b"Content-Length: " + str(len(body)).encode()]
    return f"HTTP/1.1 {status} Test\r\n".encode() + b"\r\n".join(headers) + b"\r\n\r\n" + body


@pytest.mark.parametrize("status", [200, 400, 401, 403, 404, 429, 500])
def test_typed_api_success_and_refusal_keep_their_status(status):
    value = {"uid": "日本語"} if status == 200 else {"error": {"code":status, "message":"REFUSED"}}
    with server(reply(json.dumps(value, ensure_ascii=False).encode(), status=status)) as (url, observed):
        assert shadow._call(url) == (status, value)
        assert observed["calls"] == 1


@pytest.mark.parametrize("body", [
    b"", b"null", b"[]", b'"text"', b"true", b"42", b"{", b'{"users":[],"users":[]}',
    b'{"u\\u0073ers":[],"users":[]}', b'{"n":NaN}', b'{"n":Infinity}', b'{"n":1e999}',
    '{"users":[]}'.encode("utf-16"), b'{"bad":"\xff"}', b'{"x":"' + b'a'*65536 + b'"}',
])
def test_unusable_response_is_rejected_without_returning_a_false_empty_object(body):
    with server(reply(body)) as (url, _), pytest.raises(ValueError, match="usable"):
        shadow._call(url)


@pytest.mark.parametrize("headers,body", [
    ([b"Content-Type: application/json", b"Content-Length: 900"], b'{}'),
    ([b"Content-Type: application/json", b"Content-Length: 2", b"Content-Length: 2"], b'{}'),
    ([b"Content-Type: application/json", b"Content-Length: -2"], b'{}'),
    ([b"Content-Type: application/json", b"Content-Length: +2"], b'{}'),
    ([b"Content-Type: application/json", b"Content-Length: 2", b"Transfer-Encoding: chunked"], b'2\r\n{}\r\n0\r\n\r\n'),
    ([b"Content-Type: application/json", b"Transfer-Encoding: gzip"], b'{}'),
    ([b"Content-Type: text/html", b"Content-Length: 2"], b'{}'),
    ([b"Content-Length: 2"], b'{}'),
    ([b"Content-Type: application/json", b"Content-Type: text/html", b"Content-Length: 2"], b'{}'),
])
def test_http_completeness_and_content_type_are_not_inferred_from_parseable_json(headers, body):
    with server(reply(body, headers=headers)) as (url, _), pytest.raises(ValueError):
        shadow._call(url)


@pytest.mark.parametrize("headers,body", [
    ([b"Content-Type: application/json", b"Transfer-Encoding: chunked"], b'2\r\n{}\r\n0\r\n\r\n'),
    ([b"Content-Type: application/json"], b'{}'),
    ([b"Content-Type: application/json; charset=utf-8", b"Content-Length: 2"], b'{}'),
])
def test_supported_framing_remains_usable(headers, body):
    with server(reply(body, headers=headers)) as (url, _):
        assert shadow._call(url) == (200, {})


def test_redirect_is_not_followed():
    with server(reply(status=302, headers=[b"Location: http://external.invalid/SECRET"])) as (url, _):
        with pytest.raises(ValueError) as caught:
            shadow._call(url)
        assert "SECRET" not in str(caught.value)


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:9099/x", "http://localhost:9099/x", "http://127.0.0.1/x",
    "http://127.0.0.1:80/x", "http://127.0.0.1:9099/x#fragment",
    "http://secret@127.0.0.1:9099/x", "http://127.0.0.1:9099//x",
    "http://127.0.0.1:9099/x\n", "http://127.0.0.1:9099/x#", "http://[::1]:bad/x",
    "http://external.invalid:9099/x",
])
def test_invalid_destination_is_rejected_before_spawn(monkeypatch, url):
    monkeypatch.setattr(wire.subprocess, "run", lambda *a, **k: pytest.fail("spawn"))
    with pytest.raises(ValueError, match="loopback"):
        shadow._call(url)


@pytest.mark.parametrize("timeout", [True, False, 0, -1, 21, "1", float("nan"), float("inf"), 10**1000])
def test_caller_cannot_disable_or_expand_deadline(monkeypatch, timeout):
    monkeypatch.setattr(wire.subprocess, "run", lambda *a, **k: pytest.fail("spawn"))
    with pytest.raises(ValueError):
        wire.call("http://127.0.0.1:9099/x", timeout=timeout)


@pytest.mark.parametrize("body,token", [
    ({"n":float("nan")}, None), ({1:"a", "1":"b"}, None), ({"x":"a"*65536}, None),
    ({}, "secret\r\nX: bad"), ({}, ""), ({}, 123), ({}, "a"*8193), ({}, "日本"),
])
def test_invalid_inputs_do_not_reach_worker(monkeypatch, body, token):
    monkeypatch.setattr(wire.subprocess, "run", lambda *a, **k: pytest.fail("spawn"))
    with pytest.raises(ValueError):
        shadow._call("http://127.0.0.1:9099/x", body, token)


def test_secrets_are_stdin_only_and_ambient_hooks_are_removed(monkeypatch):
    for key in ["GOOGLE_APPLICATION_CREDENTIALS", "HTTPS_PROXY", "PYTHONPATH", "PYTHONSTARTUP", "NODE_OPTIONS"]:
        monkeypatch.setenv(key, "PRIVATE-AMBIENT")
    original = wire.subprocess.run
    seen = {}
    def capture(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        return original(argv, **kwargs)
    monkeypatch.setattr(wire.subprocess, "run", capture)
    with server(reply()) as (url, result):
        assert shadow._call(url, {"password":"PRIVATE-PASSWORD"}, "PRIVATE-TOKEN") == (200, {})
        assert b"PRIVATE-TOKEN" in result["request"]
        assert b"PRIVATE-PASSWORD" in result["request"]
    assert seen["argv"][1:4] == ["-I", "-S", "-B"]
    assert "PRIVATE" not in repr(seen["argv"]) + repr(seen["env"])
    assert b"PRIVATE" in seen["input"]
    assert seen["timeout"] == 20


def test_slow_continuous_body_is_killed_and_waited_not_retried(monkeypatch):
    children = []
    original = wire.subprocess.Popen
    def spawned(*args, **kwargs):
        process = original(*args, **kwargs)
        children.append(process)
        return process
    monkeypatch.setattr(wire.subprocess, "Popen", spawned)
    with server(b"", drip=True) as (url, record):
        start = time.monotonic()
        with pytest.raises(ValueError, match="deadline"):
            wire.call(url, timeout=0.65)
        elapsed = time.monotonic() - start
        assert 0.4 <= elapsed < 3
        assert record["calls"] == 1
        assert len(children) == 1 and children[0].poll() is not None


def test_emulator_inspection_is_charged_in_the_same_counter(monkeypatch):
    calls = []
    monkeypatch.setattr(shadow, "_call", lambda *args, **kw: (calls.append((args,kw)) or (200, {})))
    instance = shadow.Instance("http://127.0.0.1:9099", "http://127.0.0.1:9100/v1", "CONTROL")
    instance.emulator("/verificationCodes")
    instance.admin("/v1/x", {})
    assert instance.requests == len(calls) == 2
    assert calls[0][0][2] == "CONTROL"
    with pytest.raises(ValueError):
        instance.send("http://127.0.0.1:9101/x", {})
    assert instance.requests == 2


def test_failed_http_attempt_stays_charged(monkeypatch):
    def failed(*a, **kw):
        raise ValueError("transport failed")
    monkeypatch.setattr(shadow, "_call", failed)
    instance = shadow.Instance("http://127.0.0.1:9099", "http://127.0.0.1:9100/v1", "CONTROL")
    with pytest.raises(ValueError):
        instance.emulator("/verificationCodes")
    assert instance.requests == 1


def test_validated_ipv6_origin_does_not_need_hostname_resolution():
    instance = shadow.Instance("http://[::1]:9099", "http://[::1]:9100/v1/", "CONTROL")
    assert instance.origin == "http://[::1]:9099"
    assert instance.control == "http://[::1]:9100"
