import base64
import copy
import hashlib
import http.client
import json
import sys
import time

import pytest

sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")

from request_bytes_collector import collect_local
from request_bytes_compiler import compile_request_bytes_plan
from request_bytes_compiler import validate_request_bytes_plan as validate_plan
from request_bytes_remote_transport import (
    MAX_REQUEST_BYTES,
    ORIGIN,
    RESPONSE_BYTES,
    _request_impl,
)
from request_bytes_remote_transport import (
    request as production_request,
)

NONCE = "0123456789abcdef0123456789abcdef"


def request(*args, exchange=None, **kwargs):
    if exchange is None:
        return production_request(*args, **kwargs)
    return _request_impl(*args, exchange=exchange, **kwargs)


class FakeResponse:
    def __init__(self, status, headers, body, *, error=None):
        self.status = status
        self.headers = headers
        self._body = body
        self._error = error
        self._offset = 0
        self.closed = False

    def read(self, size=-1):
        if self._error is not None and self._offset >= len(self._body):
            error, self._error = self._error, None
            raise error
        if size < 0:
            size = len(self._body) - self._offset
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def close(self):
        self.closed = True


def response(status, headers, body, *, error=None):
    return FakeResponse(status, headers, body, error=error)


def plan_and_commit():
    plan = compile_request_bytes_plan("fireemu-35fe6", "(default)", NONCE)
    return plan, next(
        row for row in plan["observation"] if row["kind"] == "conditional-create-commit"
    )


def test_request_binds_exact_plan_slot_and_canonical_commit_bytes():
    plan, operation = plan_and_commit()
    calls = []
    responses = []

    def exchange(url, method, body, headers, timeout, response_cap):
        calls.append((url, method, body, headers, timeout, response_cap))
        current = response(
            401, {"Content-Type": "application/json"}, b'{"error":"unauthenticated"}'
        )
        responses.append(current)
        return current

    receipt = request(plan, "observation", 17, operation, "token", exchange=exchange)

    assert receipt["kind"] == "typed-receipt"
    assert receipt["status"] == 401
    assert receipt["rawBodyBytes"] == len(b'{"error":"unauthenticated"}')
    assert (
        receipt["rawBodySha256"]
        == hashlib.sha256(b'{"error":"unauthenticated"}').hexdigest()
    )
    assert receipt["complete"] is True
    assert receipt["failure"] is None
    assert receipt["bodyBytes"] == receipt["rawBodyBytes"]
    assert (
        receipt["rawBodyBase64"]
        == base64.b64encode(b'{"error":"unauthenticated"}').decode()
    )
    assert receipt["body"] == {"error": "unauthenticated"}
    assert "requestBodyBase64" not in receipt
    assert calls[0][0] == ORIGIN + operation["path"]
    assert calls[0][1] == "POST"
    assert receipt["requestBytes"] == len(calls[0][2])
    assert receipt["requestSha256"] == hashlib.sha256(calls[0][2]).hexdigest()
    assert calls[0][5] == RESPONSE_BYTES
    assert responses[0].closed is True


@pytest.mark.parametrize(
    "mutation",
    [
        lambda op: {**op, "path": op["path"] + "?forged=1"},
        lambda op: {**op, "method": "PUT"},
        lambda op: {**op, "body": {"writes": []}},
    ],
)
def test_request_rejects_forged_operation_path_method_or_body(mutation):
    plan, operation = plan_and_commit()
    with pytest.raises(ValueError):
        request(
            plan,
            "observation",
            17,
            mutation(operation),
            "token",
            exchange=lambda *_: None,
        )


def test_request_rejects_plan_mutation_before_exchange():
    plan, operation = plan_and_commit()
    forged = copy.deepcopy(plan)
    forged["probes"][0]["path"] += "?forged=1"
    with pytest.raises(ValueError, match="plan"):
        request(forged, "observation", 17, operation, "token", exchange=lambda *_: None)


def test_request_freezes_plan_before_validation(monkeypatch):
    plan, operation = plan_and_commit()
    operation = copy.deepcopy(operation)
    original_path = operation["path"]

    def validate_then_mutate(snapshot):
        validate_plan(snapshot)
        plan["project"] = "attacker-project"
        plan["observation"][17]["path"] = "/attacker"

    monkeypatch.setattr(
        "request_bytes_remote_transport.validate_request_bytes_plan",
        validate_then_mutate,
    )
    calls = []
    request(
        plan,
        "observation",
        17,
        operation,
        "token",
        exchange=lambda url, *_args: calls.append(url) or response(401, {}, b"error"),
    )
    assert calls == [ORIGIN + original_path]


@pytest.mark.parametrize("status", [400, 413, 403])
def test_http_errors_are_typed_receipts(status):
    plan, operation = plan_and_commit()

    receipt = request(
        plan,
        "observation",
        17,
        operation,
        "token",
        exchange=lambda *_: response(status, {}, b"error"),
    )

    assert receipt["kind"] == "typed-receipt"
    assert receipt["status"] == status
    assert receipt["complete"] is True


@pytest.mark.parametrize(
    "response",
    [
        response(200, {"Content-Length": str(RESPONSE_BYTES + 1)}, b"x"),
        response(200, {"Content-Length": "4"}, b"x"),
        response(302, {"Location": "https://attacker.invalid"}, b""),
    ],
)
def test_oversized_incomplete_or_redirect_response_is_transport_failure(response):
    plan, operation = plan_and_commit()
    result = request(
        plan, "observation", 17, operation, "token", exchange=lambda *_: response
    )
    assert result["kind"] == "typed-receipt"
    assert result["complete"] is False


def test_timeout_is_transport_failure_and_does_not_retry():
    plan, operation = plan_and_commit()
    calls = 0

    def exchange(*_args):
        nonlocal calls
        calls += 1
        raise TimeoutError

    result = request(plan, "observation", 17, operation, "token", exchange=exchange)
    assert result["kind"] == "transport-failure"
    assert result["failure"] == "timeout"
    assert calls == 1


def test_trickle_response_obeys_one_total_wire_deadline():
    plan, operation = plan_and_commit()
    started = time.monotonic()
    result = request(
        plan,
        "observation",
        17,
        operation,
        "token",
        timeout=0.01,
        exchange=lambda *_: (
            time.sleep(0.02) or response(200, {"Content-Length": "1"}, b"x")
        ),
    )
    assert result["complete"] is False
    assert time.monotonic() - started < 1


def test_incomplete_read_is_transport_failure_with_partial_bytes():
    plan, operation = plan_and_commit()
    result = request(
        plan,
        "observation",
        17,
        operation,
        "token",
        exchange=lambda *_: response(
            200,
            {"Content-Length": "8"},
            b"partial",
            error=http.client.IncompleteRead(b"partial", 3),
        ),
    )
    assert result["failure"] == "response-incomplete"
    assert result["rawBodyBase64"]


def test_413_oversize_retains_status_and_observed_size():
    plan, operation = plan_and_commit()
    body = b"x" * (RESPONSE_BYTES + 1)
    result = request(
        plan,
        "observation",
        17,
        operation,
        "token",
        exchange=lambda *_: response(413, {}, body),
    )
    assert result["status"] == 413
    assert result["failure"] == "response-oversize"
    assert result["rawBodyBytes"] == RESPONSE_BYTES


def test_request_byte_ceiling_is_approved_maximum():
    assert MAX_REQUEST_BYTES == 10_485_761
    assert RESPONSE_BYTES == 2 * 1024 * 1024


@pytest.mark.parametrize("status", [99, 600, True, "200"])
def test_rejects_status_outside_strict_http_range(status):
    plan, operation = plan_and_commit()
    with pytest.raises(ValueError, match="HTTP status"):
        request(
            plan,
            "observation",
            17,
            operation,
            "token",
            exchange=lambda *_: response(status, {}, b""),
        )


def test_oserror_after_status_preserves_bounded_receipt():
    plan, operation = plan_and_commit()
    result = request(
        plan,
        "observation",
        17,
        operation,
        "token",
        exchange=lambda *_: response(
            503, {"Content-Length": "9"}, b"partial", error=OSError("socket closed")
        ),
    )
    assert result["status"] == 503
    assert result["complete"] is False
    assert result["failure"] == "transport-error"
    assert result["rawBodyBase64"] == base64.b64encode(b"partial").decode()


def test_default_exchange_uses_one_deadline_for_open_and_body(monkeypatch):
    plan, operation = plan_and_commit()
    clock = iter([100.0, 100.0, 108.0, 108.0, 113.0, 113.0, 113.0])
    seen = {}

    class Opener:
        def open(self, _request, *, timeout):
            seen["timeout"] = timeout
            return response(200, {"Content-Length": "1"}, b"x")

    monkeypatch.setattr(
        "request_bytes_remote_transport.time.monotonic", lambda: next(clock)
    )
    monkeypatch.setattr(
        "request_bytes_remote_transport.urllib.request.build_opener",
        lambda *_args: Opener(),
    )
    result = request(plan, "observation", 17, operation, "token", timeout=12)
    assert seen["timeout"] == 12
    assert result["status"] == 200
    assert result["failure"] == "timeout"


def test_collector_accepts_incomplete_receipt_and_persists_bounded_sidecar(tmp_path):
    plan, _operation = plan_and_commit()

    def execute(current):
        for phase in ("observation", "recovery"):
            for index, planned in enumerate(plan[phase]):
                if current == planned:
                    return request(
                        plan,
                        phase,
                        index,
                        current,
                        "token",
                        exchange=lambda *_: response(
                            503, {"Content-Length": "9"}, b"partial", error=OSError()
                        ),
                    )
        raise AssertionError("collector dispatched an unknown operation")

    collected = collect_local(
        plan,
        execute,
        tmp_path / "receipts",
    )
    assert collected["completed"] is False
    row = json.loads((tmp_path / "receipts" / "row-000.json").read_text())
    assert row["receipt"]["status"] == 503
    assert row["receipt"]["failure"] == "transport-error"
    assert (tmp_path / "receipts" / row["responseBodyFile"]).read_bytes() == b"partial"
