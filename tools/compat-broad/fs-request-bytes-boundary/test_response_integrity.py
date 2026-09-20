"""Keep byte identity, recursive JSON types and HTTP framing distinct."""
from __future__ import annotations

import base64
import io
import json
from email.message import Message
from types import SimpleNamespace

import pytest

import request_bytes_collector as collector
import request_bytes_local_transport as local_transport
from request_bytes_compiler import compile_request_bytes_plan, document_size_bytes


@pytest.mark.parametrize(("raw", "body"), [
    (b'{"error":{"code":404.0,"status":"NOT_FOUND"}}', {"error": {"code": 404, "status": "NOT_FOUND"}}),
    (b'{"value":true}', {"value": 1}),
    (b'{"value":false}', {"value": 0}),
    (b'{"value":[[1]]}', {"value": [[True]]}),
    (b'{"value":1}', {"value": 1.0}),
    (b'{"value":1.0}', {"value": 1}),
    (b'{"value":-0.0}', {"value": 0.0}),
    (b'{"value":1,"value":2}', {"value": 2}),
    (b'{"nested":{"x":1,"x":1}}', {"nested": {"x": 1}}),
    (b'{"value":Infinity}', {"value": float("inf")}),
    (b'{"value":1e400}', {"value": float("inf")}),
    ('{"a":1}'.encode('utf-16'), {"a": 1}),
    (b'{"v":[1]}', {"v": (1,)}),
])
def test_raw_binding_rejects_typed_or_ambiguous_substitution(raw, body):
    assert collector._raw_matches_body(raw, body) is False


@pytest.mark.parametrize(("raw", "body"), [
    (b'{"x":[1,true,null,1.0],"y":{}}', {"y": {}, "x": [1, True, None, 1.0]}),
    ('{"v":"日本語"}'.encode(), {"v": "日本語"}),
    (b'{ "b":2, "a":1 }', {"a": 1, "b": 2}),
    (b'not-json', 'not-json'),
    (b'"a"', 'a'),
])
def test_valid_wire_binding_preserves_field_order_independence(raw, body):
    assert collector._raw_matches_body(raw, body) is True


@pytest.mark.parametrize("headers", [
    [("Content-Length", "2"), ("Content-Length", "2")],
    [("Content-Length", "2"), ("Content-Length", "4")],
    [("Content-Length", "+2")],
    [("Content-Length", "٢")],
    [("Content-Length", "\v2")],
    [("Content-Length", "2"), ("Transfer-Encoding", "chunked")],
    [("Transfer-Encoding", "gzip")],
    [("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "chunked")],
])
def test_shared_limits_reader_rejects_ambiguous_framing(headers):
    message = Message()
    for key, value in headers:
        message[key] = value
    response = SimpleNamespace(headers=message, read=io.BytesIO(b"{}").read)
    _payload, failure = local_transport._shared._read_bounded(response, 20)
    assert failure is not None


@pytest.mark.parametrize("length", ["two", "-1", "2,2", "", "9" * 5000],
                         ids=["word", "negative", "comma", "empty", "huge"])
def test_malformed_length_is_recorded_as_incomplete_not_an_uncaught_error(length):
    message = Message()
    message["Content-Length"] = length
    response = SimpleNamespace(headers=message, read=io.BytesIO(b"{}").read)
    payload, failure = local_transport._shared._read_bounded(response, 20)
    assert failure is not None
    assert len(payload) <= 20


@pytest.mark.parametrize("headers", [[], [("Content-Length", "2")],
    [("Content-Length", "\t2 ")], [("Transfer-Encoding", "chunked")]])
def test_supported_framing_still_accepts_bounded_body(headers):
    message = Message()
    for key, value in headers:
        message[key] = value
    response = SimpleNamespace(headers=message, read=io.BytesIO(b"{}").read)
    assert local_transport._shared._read_bounded(response, 20) == (b"{}", None)


@pytest.mark.parametrize(("project", "database"), [
    ("documents", "(default)"), ("demo", "documents"),
    ("documents", "documents"), ("databases", "databases"),
])
def test_document_charge_does_not_include_namespace(project, database):
    fields = {"f": {"stringValue": "日"}}
    # Document a/b: 16+2+2; document overhead 32; field name 2; value 4.
    assert document_size_bytes(
        f"projects/{project}/databases/{database}/documents/a/b", fields,
    ) == 58


@pytest.mark.parametrize("resource", [
    "anything/documents/a/b", "projects//databases/d/documents/a/b",
    "projects/p/databases//documents/a/b", "projects/p/wrong/d/documents/a/b",
])
def test_invalid_namespace_is_not_measurable_document(resource):
    with pytest.raises(ValueError):
        document_size_bytes(resource, {})


def test_nested_numeric_substitution_cannot_authorize_commit(tmp_path):
    plan = compile_request_bytes_plan("demo-integrity", "(default)", "b" * 32)
    calls = []

    def execute(operation):
        calls.append(operation)
        # This is syntactically valid JSON, but code is a floating-point value.
        # It cannot be replaced by an integer in the body bound to these bytes.
        raw = b'{"error":{"code":404.0,"status":"NOT_FOUND"}}'
        return {"complete": True, "failure": None, "status": 404,
                "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
                "rawBodyBase64": base64.b64encode(raw).decode(), "bodyBytes": len(raw)}

    result = collector.collect_local(plan, execute, tmp_path / "run")
    assert result["completed"] is False
    assert not any(op["kind"] == "conditional-create-commit" for op in calls)


@pytest.mark.parametrize("header_lines", [
    b"Content-Length: 2\r\nContent-Length: 2\r\n",
    b"Content-Length: 2\r\nContent-Length: 900\r\n",
    b"Content-Length: +2\r\n",
    b"Content-Length: 900\r\n",
], ids=["duplicate-equal", "duplicate-conflicting", "signed", "truncated"])
def test_ambiguous_real_http_does_not_become_a_complete_receipt(header_lines):
    import socketserver
    import threading

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            request = b""
            while b"\r\n\r\n" not in request:
                data = self.request.recv(4096)
                if not data:
                    return
                request += data
            self.request.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
                                 b"Content-Type: application/json\r\n" + header_lines + b"\r\n{}")

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            receipt = local_transport._shared.request(
                f"http://127.0.0.1:{server.server_address[1]}",
                {"method": "GET", "path": "/v1/probe"},
                request_byte_limit=100, response_byte_limit=1000,
            )
            assert receipt["complete"] is False
        finally:
            server.shutdown()
            thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.parametrize("length_type", ["float", "string", "wrong-integer"])
def test_invalid_retained_length_cannot_authorize_commit(tmp_path, length_type):
    plan = compile_request_bytes_plan("demo-integrity", "(default)", "b" * 32)
    calls = []
    def execute(operation):
        calls.append(operation)
        raw = b'{"error":{"code":404,"status":"NOT_FOUND"}}'
        size = {"float": float(len(raw)), "string": str(len(raw)),
                "wrong-integer": len(raw) + 1}[length_type]
        return {"complete": True, "failure": None, "status": 404,
                "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
                "rawBodyBase64": base64.b64encode(raw).decode(), "bodyBytes": size}
    result = collector.collect_local(plan, execute, tmp_path / "run")
    assert result["completed"] is False
    assert not any(op["kind"] == "conditional-create-commit" for op in calls)
