"""The remote Limits-03 receipt must use the local lane's JSON evidence contract.

HTTP and IPC are real in the wire cases. Only the worker's TLS connection is
redirected to an owned loopback HTTP socket; no production capability is used.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import json
import socket
import sys
import threading
import time
import types
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REMOTE = load_file("_test_limits03_remote_json", HERE / "limits_03_remote_transport.py")
LOCAL = load_file("_test_limits03_local_json", HERE / "transport.py")

BAD = [
    ("duplicate-code", b'{"error":{"code":403,"code":404,"status":"NOT_FOUND"}}'),
    (
        "duplicate-error",
        b'{"error":{"code":403,"status":"PERMISSION_DENIED"},"error":{"code":404,"status":"NOT_FOUND"}}',
    ),
    (
        "duplicate-equal",
        b'{"error":{"code":404,"status":"NOT_FOUND","status":"NOT_FOUND"}}',
    ),
    (
        "duplicate-escaped",
        b'{"error":{"code":403,"\\u0063ode":404,"status":"NOT_FOUND"}}',
    ),
    ("duplicate-nested", b'{"nested":[{"x":1,"x":2}]}'),
    ("duplicate-name", b'{"name":"foreign","name":"owned","fields":{}}'),
    ("nan", b'{"diagnostic":NaN}'),
    ("positive-infinity", b'{"diagnostic":Infinity}'),
    ("negative-infinity", b'{"nested":[-Infinity]}'),
    ("overflow", b'{"nested":[1e9999]}'),
    ("negative-overflow", b'{"nested":[-1e9999]}'),
    ("utf16", '{"error":{"code":404,"status":"NOT_FOUND"}}'.encode("utf-16")),
    ("utf32", '{"error":{"code":404,"status":"NOT_FOUND"}}'.encode("utf-32")),
    ("invalid-utf8", b'{"text":"\xff"}'),
    ("utf8-bom", b'\xef\xbb\xbf{"error":{"code":404,"status":"NOT_FOUND"}}'),
    ("truncated-json", b'{"error":'),
    ("two-json-values", b"{}{}"),
    ("deep-json", b"[" * 10000 + b"0" + b"]" * 10000),
]
GOOD = [
    ("absence", b'{"error":{"code":404,"status":"NOT_FOUND"}}'),
    ("permission-error", b'{"error":{"code":403,"status":"PERMISSION_DENIED"}}'),
    ("document", b'{"name":"owned","fields":{"v":{"integerValue":"9"}}}'),
    (
        "firestore-special-floats",
        b'{"fields":{"a":{"doubleValue":"NaN"},"b":{"doubleValue":"Infinity"},"c":{"doubleValue":"-Infinity"}}}',
    ),
    ("sibling-keys", b'{"left":{"same":1},"right":{"same":2}}'),
    ("array-keys", b'[{"same":1},{"same":2}]'),
    ("number-types", b'{"integer":404,"float":404.0,"bool":true,"negativeZero":-0.0}'),
    ("unicode", '{"unicode":"東京","escaped":"\\u0061"}'.encode()),
    ("finite-large", b'{"finite":1e300}'),
    ("empty-array", b"[]"),
    ("null", b"null"),
    ("text", b'"text"'),
    ("whitespace", b' \r\n\t{ "v": 1 }\n'),
]


def canonical(value):
    return json.dumps(value, sort_keys=True, allow_nan=False)


def assert_retained(receipt, raw, status, request_body=None, failure=None):
    assert receipt["status"] == status
    assert receipt["complete"] is (failure is None)
    assert receipt["failure"] == failure
    assert receipt["rawBodyBytes"] == receipt["bodyBytes"] == len(raw)
    assert receipt["rawBodySha256"] == hashlib.sha256(raw).hexdigest()
    assert base64.b64decode(receipt["rawBodyBase64"], validate=True) == raw
    assert receipt["requestBytes"] == len(request_body or b"")
    assert receipt["requestSha256"] == hashlib.sha256(request_body or b"").hexdigest()
    assert receipt["diagnostic"] == raw[:512].decode("utf-8", errors="replace")
    # A malformed wire number must not make the receipt itself unrecordable.
    canonical(receipt)


@pytest.mark.parametrize("label,raw", BAD, ids=[x[0] for x in BAD])
def test_unusable_json_is_diagnostic_not_typed_evidence(label, raw):
    with pytest.raises((ValueError, UnicodeDecodeError, RecursionError)):
        LOCAL._decode_json_response(raw)
    receipt = REMOTE._receipt(404, "application/json", raw, None, b'{"request":1}')
    assert_retained(receipt, raw, 404, b'{"request":1}')
    assert isinstance(receipt["body"], str), label
    assert receipt["body"] == receipt["diagnostic"]


@pytest.mark.parametrize("label,raw", GOOD, ids=[x[0] for x in GOOD])
def test_usable_json_preserves_types_and_agrees_with_local_decoder(label, raw):
    receipt = REMOTE._receipt(200, "application/json", raw, None, None)
    assert_retained(receipt, raw, 200)
    assert canonical(receipt["body"]) == canonical(LOCAL._decode_json_response(raw)), (
        label
    )
    assert canonical(receipt["body"]) == canonical(json.loads(raw.decode("utf-8")))


@pytest.mark.parametrize("status", [200, 400, 403, 404, 409, 429, 500])
def test_valid_api_outcomes_are_not_overwritten(status):
    raw = json.dumps({"error": {"code": status, "status": "TEST_STATUS"}}).encode()
    receipt = REMOTE._receipt(status, "application/json", raw, None, None)
    assert_retained(receipt, raw, status)
    assert receipt["body"]["error"]["code"] == status


@pytest.mark.parametrize(
    "failure",
    ["timeout", "response-incomplete", "response-oversize", "invalid-content-length"],
)
def test_transport_failures_keep_their_original_disposition(failure):
    raw = b'{"error":{"code":404,"code":404,"status":"NOT_FOUND"}}'
    receipt = REMOTE._receipt(404, "application/json", raw, failure, None)
    assert_retained(receipt, raw, 404, failure=failure)
    assert isinstance(receipt["body"], str)


def test_missing_status_and_redirect_still_fail_transport():
    for status, failure in [(None, "transport-error"), (302, "redirect")]:
        raw = b"{}"
        receipt = REMOTE._receipt(status, "application/json", raw, None, None)
        assert_retained(receipt, raw, status, failure=failure)


def test_empty_body_retains_existing_none_representation():
    receipt = REMOTE._receipt(204, "", b"", None, None)
    assert_retained(receipt, b"", 204)
    assert receipt["body"] is None


def test_decoder_is_loaded_by_path_not_an_ambient_transport_module(monkeypatch):
    poisoned = types.ModuleType("transport")
    poisoned._decode_json_response = lambda _raw: {"unexpected": "ambient"}
    monkeypatch.setitem(sys.modules, "transport", poisoned)
    module = load_file(
        "_test_limits03_poisoned_json_import", HERE / "limits_03_remote_transport.py"
    )
    result = module._parse_body(BAD[0][1])
    assert isinstance(result, str)
    assert sys.modules["transport"] is poisoned


def test_public_request_still_requires_a_production_capability(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("no preparation or exchange is allowed without a capability")

    monkeypatch.setattr(REMOTE, "prepare", forbidden)
    monkeypatch.setattr(REMOTE, "_exchange", forbidden)
    with pytest.raises(ValueError, match="active O7 production capability required"):
        REMOTE.request(
            {}, "observation", 0, {}, "not-a-credential", deadline=time.monotonic() + 5
        )


@contextlib.contextmanager
def raw_response(raw, status):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(6)
    address = listener.getsockname()
    requests, errors = [], []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(6)
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = connection.recv(4096)
                    if not chunk:
                        raise RuntimeError("request terminated before its headers")
                    request += chunk
                    if len(request) > 32768:
                        raise RuntimeError("unexpected request size")
                requests.append(request)
                header = (
                    f"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(raw)}\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                connection.sendall(header + raw)
        except (OSError, RuntimeError) as error:
            errors.append(repr(error))
        finally:
            listener.close()

    thread = threading.Thread(target=serve, name="limits03-json-wire")
    thread.start()
    try:
        yield address, requests
    finally:
        thread.join(8)
        if thread.is_alive():
            listener.close()
            thread.join(1)
        assert not thread.is_alive(), "owned HTTP thread leaked"
        assert listener.fileno() == -1
        assert not errors, errors
        assert len(requests) == 1
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.25)
            assert probe.connect_ex(address) != 0, "owned listener remains open"


def worker_to_loopback(source, port):
    marker = b'if __name__ == "__main__":'
    assert source.count(marker) == 1
    bootstrap = f"""# Test-only routing; leave the worker parser and framing untouched.
_http_connection = http.client.HTTPConnection
def _owned_loopback(host, *, timeout):
    if host != "firestore.googleapis.com":
        raise ValueError("unexpected worker host")
    return _http_connection("127.0.0.1", {port}, timeout=timeout)
http.client.HTTPSConnection = _owned_loopback

""".encode()
    return source.replace(marker, bootstrap + marker)


WIRE = [
    ("valid-absence", GOOD[0][1], 404, True),
    ("duplicate-absence", BAD[1][1], 404, False),
    ("duplicate-create", BAD[5][1], 200, False),
    ("overflow", BAD[9][1], 200, False),
    ("utf16-absence", BAD[11][1], 404, False),
    ("deep-json", BAD[17][1], 200, False),
    ("firestore-nan-string", GOOD[3][1], 200, True),
    ("valid-permission-denial", GOOD[1][1], 403, True),
]


@pytest.mark.parametrize("label,raw,status,valid", WIRE, ids=[x[0] for x in WIRE])
def test_real_worker_ipc_and_receipt_use_the_same_json_contract(
    monkeypatch, label, raw, status, valid
):
    # Source is fetched and hash-checked by the production module, including
    # any independently integrated 047 framing repair. Only routing is replaced.
    worker = REMOTE.worker_source()
    processes = []
    popen = REMOTE._process_exchange.subprocess.Popen

    def tracked_popen(*args, **kwargs):
        process = popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(REMOTE._process_exchange.subprocess, "Popen", tracked_popen)
    with raw_response(raw, status) as (address, requests):
        effective_worker = worker_to_loopback(worker, address[1])
        monkeypatch.setattr(REMOTE, "worker_source", lambda: effective_worker)
        monkeypatch.setattr(
            REMOTE, "_WORKER_SHA256", hashlib.sha256(effective_worker).hexdigest()
        )
        path = (
            "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
            + "a" * 32
            + "/limits-03/test"
        )
        received_status, content_type, received, failure = REMOTE._exchange(
            REMOTE.ORIGIN + path,
            "GET",
            None,
            {
                "Authorization": "Bearer test-only",
                "x-goog-user-project": REMOTE.PROJECT,
            },
            time.monotonic() + 5,
            65536,
        )
    assert failure is None, (label, failure)
    assert received_status == status
    assert received == raw
    assert requests[0].startswith(("GET " + path + " HTTP/1.1\r\n").encode())
    assert len(processes) == 1
    process = processes[0]
    assert process.poll() is not None
    assert process.stdin.closed and process.stdout.closed
    receipt = REMOTE._receipt(received_status, content_type, received, failure, None)
    assert_retained(receipt, raw, status)
    if valid:
        assert canonical(receipt["body"]) == canonical(LOCAL._decode_json_response(raw))
    else:
        assert isinstance(receipt["body"], str), label
