import json
import sys
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import ClassVar

import pytest

sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
sys.path.insert(0, "tools/compat-broad")

from request_bytes_compiler import (
    RAW_16MIB_OVER_BYTES,
    compact_utf8,
    compile_request_bytes_plan,
    compile_request_bytes_sentinel_plan,
)
from request_bytes_local_transport import (
    MAX_REQUEST_BYTES,
    MAX_SENTINEL_REQUEST_BYTES,
    RESPONSE_BYTES,
    request,
)


class Handler(BaseHTTPRequestHandler):
    received: ClassVar[list[bytes]] = []
    requests: ClassVar[list[tuple[str, str]]] = []

    def do_GET(self):
        self.requests.append((self.command, self.path))
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self):
        self.requests.append((self.command, self.path))
        size = int(self.headers.get("Content-Length", "0"))
        self.received.append(self.rfile.read(size))
        body = json.dumps(
            {"writeResults": [{"updateTime": "2026-01-01T00:00:00.000000Z"}] * 17}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@pytest.fixture()
def origin():
    Handler.received.clear()
    Handler.requests.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_three_compiled_sizes_round_trip_over_loopback(origin):
    plan = compile_request_bytes_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    operation = plan["observation"][17]
    for probe in plan["probes"]:
        operation = next(
            row
            for row in plan["observation"]
            if row.get("probe") == probe["label"]
            and row["kind"] == "conditional-create-commit"
        )
        result = request(origin, operation)
        assert result["complete"] is True
        assert result["requestBytes"] == probe["bodyBytes"]
        assert result["rawHttpMetricStatus"] == "observation hypothesis"
        assert (
            Handler.received[-1]
            == json.dumps(
                operation["body"], separators=(",", ":"), ensure_ascii=False
            ).encode()
        )


def test_cap_above_approved_range_and_non_loopback_are_rejected(origin):
    plan = compile_request_bytes_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    operation = plan["observation"][17]
    with pytest.raises(ValueError):
        request(origin, operation, request_byte_limit=MAX_SENTINEL_REQUEST_BYTES + 1)
    with pytest.raises(ValueError):
        request("https://example.com", operation)
    assert RESPONSE_BYTES == 2 * 1024 * 1024


def test_transport_preserves_exact_response_bytes(origin):
    import base64

    plan = compile_request_bytes_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    operation = next(
        row for row in plan["observation"] if row["kind"] == "conditional-create-commit"
    )
    result = request(origin, operation)
    raw = base64.b64decode(result["rawBodyBase64"], validate=True)
    assert (
        raw
        == json.dumps(
            {"writeResults": [{"updateTime": "2026-01-01T00:00:00.000000Z"}] * 17}
        ).encode()
    )
    assert result["bodyBytes"] == len(raw)


def test_transport_rejects_unbound_delete(origin):
    plan = compile_request_bytes_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    operation = next(
        row for row in plan["recovery"] if row["kind"] == "cleanup-version-bound-delete"
    )
    with pytest.raises(ValueError, match="unbound cleanup delete"):
        request(origin, operation)


def test_compiled_sentinel_preflight_and_exact_commit_round_trip(origin):
    plan = compile_request_bytes_sentinel_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    preflight = next(
        row for row in plan["observation"] if row["kind"] == "preflight-typed-absence"
    )
    commit = next(
        row for row in plan["observation"] if row["kind"] == "conditional-create-commit"
    )

    read = request(origin, preflight)
    assert read["status"] == 404
    assert Handler.requests[-1] == ("GET", preflight["path"])

    result = request(origin, commit, request_byte_limit=MAX_SENTINEL_REQUEST_BYTES)
    canonical = json.dumps(
        commit["body"], separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert result["complete"] is True
    assert result["requestBytes"] == RAW_16MIB_OVER_BYTES
    assert len(canonical) == RAW_16MIB_OVER_BYTES
    assert Handler.received[-1] == canonical


@pytest.mark.parametrize("delta", [-1, 1])
def test_sentinel_rejects_neighboring_body_sizes(origin, delta):
    plan = compile_request_bytes_sentinel_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    commit = next(
        row for row in plan["observation"] if row["kind"] == "conditional-create-commit"
    )
    altered = deepcopy(commit)
    blob = altered["body"]["writes"][-1]["update"]["fields"]["blob"]["stringValue"]
    altered["body"]["writes"][-1]["update"]["fields"]["blob"]["stringValue"] = (
        blob[:-1] if delta < 0 else blob + "x"
    )

    expected_error = "request_byte_limit" if delta > 0 else "sentinel"
    with pytest.raises(ValueError, match=expected_error):
        request(
            origin,
            altered,
            request_byte_limit=(
                MAX_SENTINEL_REQUEST_BYTES + 1
                if delta > 0
                else MAX_SENTINEL_REQUEST_BYTES
            ),
        )
    assert Handler.requests == []


def test_sentinel_rejects_non_compiled_body_with_same_size(origin):
    plan = compile_request_bytes_sentinel_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    commit = next(
        row for row in plan["observation"] if row["kind"] == "conditional-create-commit"
    )
    altered = deepcopy(commit)
    owner = altered["body"]["writes"][0]["update"]["fields"]["_owner"]["stringValue"]
    altered["body"]["writes"][0]["update"]["fields"]["_owner"]["stringValue"] = (
        "f" + owner[1:]
    )

    with pytest.raises(ValueError, match="sentinel"):
        request(origin, altered, request_byte_limit=MAX_SENTINEL_REQUEST_BYTES)
    assert Handler.requests == []


def test_sentinel_rejects_neighboring_resource_and_non_loopback(origin):
    plan = compile_request_bytes_sentinel_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    preflight = next(
        row for row in plan["observation"] if row["kind"] == "preflight-typed-absence"
    )
    neighboring = deepcopy(preflight)
    neighboring["resource"] = neighboring["resource"].replace(
        "/probe-r16m1/", "/probe-r16m2/"
    )
    neighboring["path"] = neighboring["path"].replace("/probe-r16m1/", "/probe-r16m2/")
    with pytest.raises(ValueError, match="invalid resource"):
        request(origin, neighboring, request_byte_limit=MAX_SENTINEL_REQUEST_BYTES)
    with pytest.raises(ValueError):
        request("https://example.com", preflight)
    assert Handler.requests == []


def test_strict_commit_boundary_sizes_are_admitted_with_the_extended_cap(origin):
    plan = compile_request_bytes_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    commits = [
        row for row in plan["observation"] if row["kind"] == "conditional-create-commit"
    ]
    assert [len(compact_utf8(commit["body"])) for commit in commits] == [
        11_534_335,
        11_534_336,
        11_534_337,
    ]
    assert MAX_REQUEST_BYTES == 11_534_337
    for commit in commits:
        result = request(origin, commit, request_byte_limit=MAX_REQUEST_BYTES)
        assert result["requestBytes"] == len(compact_utf8(commit["body"]))
        assert Handler.requests[-1] == ("POST", commit["path"])
