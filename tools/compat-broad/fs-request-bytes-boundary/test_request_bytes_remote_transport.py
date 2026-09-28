import base64
import copy
import hashlib
import http.client
import http.server
import json
import pathlib
import sys
import threading
import time

import pytest

sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")

import request_bytes_remote_transport
from request_bytes_collector import collect_local
from request_bytes_compiler import REQUEST_TARGETS, compile_request_bytes_plan
from request_bytes_compiler import (
    RAW_16MIB_OVER_BYTES,
    compile_request_bytes_sentinel_plan,
)
from request_bytes_compiler import validate_request_bytes_plan as validate_plan
from request_bytes_remote_transport import (
    MAX_REQUEST_BYTES,
    NON_UPLOAD_RESERVE_SECONDS,
    ORIGIN,
    RESPONSE_BYTES,
    TIMEOUT,
    _dispatch,
    _request_impl,
)
from request_bytes_remote_transport import (
    request as production_request,
)

HERE = pathlib.Path(__file__).resolve().parent
NONCE = "0123456789abcdef0123456789abcdef"
# Generous wall-clock ceiling for the one real-time deadline smoke test.
WIRE_SMOKE_BUDGET_SECONDS = 30.0


def request(*args, exchange=None, **kwargs):
    if exchange is None:
        if "capability" in kwargs:
            return production_request(*args, **kwargs)
        return _request_impl(*args, exchange=_fixture_exchange, **kwargs)
    return _request_impl(*args, exchange=exchange, **kwargs)


def test_public_production_request_requires_o7_capability():
    plan, operation = plan_and_commit()
    with pytest.raises(ValueError, match="active O7 production capability"):
        production_request(plan, "observation", 17, operation, "token")


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


def _fixture_exchange(url, method, body, headers, timeout, response_cap):
    status, response_headers, raw, failure = request_bytes_remote_transport._process_exchange(
        url,
        method,
        body,
        headers,
        time.monotonic() + timeout,
        response_cap,
    )
    error = OSError(failure) if failure else None
    return FakeResponse(status or 500, response_headers, raw, error=error)


class FakeClock:
    """Monotonic clock that only advances when a test says it does."""

    def __init__(self, start=1_000.0):
        self._start = start
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds

    def elapsed(self):
        return self.now - self._start


class TrickleResponse(FakeResponse):
    """Response that yields one byte per read and burns simulated wire time."""

    def __init__(self, status, headers, body, *, clock, chunk_cost):
        super().__init__(status, headers, body)
        self._clock = clock
        self._chunk_cost = chunk_cost
        self.reads = 0

    def read(self, size=-1):
        self.reads += 1
        self._clock.advance(self._chunk_cost)
        return super().read(1)


def response(status, headers, body, *, error=None):
    return FakeResponse(status, headers, body, error=error)


@pytest.fixture
def loopback_server():
    """A plaintext loopback HTTP server that counts the bytes it receives.

    It exists so the boundary body can travel the real process exchange and the
    real worker logic without TLS and without leaving this machine.
    """
    received = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _consume(self):
            length = int(self.headers.get("Content-Length") or 0)
            digest = hashlib.sha256()
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            received["bytes"] = length - remaining
            received["sha256"] = digest.hexdigest()
            return length - remaining

        def do_POST(self):
            count = self._consume()
            payload = json.dumps({"received": count}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            payload = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_DELETE(self):
            received["method"] = self.command
            received["path"] = self.path
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f"{host}:{port}", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        assert not thread.is_alive()


def plan_and_commit():
    plan = compile_request_bytes_plan("fireemu-35fe6", "(default)", NONCE)
    return plan, next(
        row for row in plan["observation"] if row["kind"] == "conditional-create-commit"
    )


def test_sentinel_body_reaches_exchange_with_its_case_specific_deadline():
    plan = compile_request_bytes_sentinel_plan(
        "fireemu-35fe6", "(default)", NONCE
    )
    operation = next(
        row for row in plan["observation"] if row["kind"] == "conditional-create-commit"
    )
    seen = {}

    def exchange(url, method, body, headers, timeout, response_cap):
        seen.update(
            url=url,
            method=method,
            body_bytes=len(body),
            body_digest=hashlib.sha256(body).hexdigest(),
            timeout=timeout,
        )
        return response(200, {"Content-Type": "application/json"}, b"{}")

    receipt = request(
        plan, "observation", 20, operation, "token", exchange=exchange
    )

    assert receipt["complete"] is True
    assert receipt["requestBytes"] == RAW_16MIB_OVER_BYTES
    assert seen["body_bytes"] == RAW_16MIB_OVER_BYTES
    assert seen["body_digest"] == receipt["requestSha256"]
    assert seen["timeout"] > 75
    assert seen["timeout"] <= 80


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


# Steps are binary-exact fractions of the wire budget so the simulated clock
# accumulates without rounding and the expected read count is exact.
@pytest.mark.parametrize("chunk_cost", [0.25, 0.125, 0.0625])
def test_trickle_response_obeys_one_total_wire_deadline(chunk_cost):
    plan, operation = plan_and_commit()
    clock = FakeClock()
    timeout = 0.5
    trickle = TrickleResponse(
        200, {"Content-Length": "100"}, b"x" * 100, clock=clock, chunk_cost=chunk_cost
    )
    budgets = []

    def exchange(_url, _method, _body, _headers, budget, _cap):
        budgets.append(budget)
        return trickle

    result = request(
        plan,
        "observation",
        17,
        operation,
        "token",
        timeout=timeout,
        exchange=exchange,
        clock=clock,
    )

    # The deadline is enforced on simulated time only: the read loop stops
    # after exactly as many trickled chunks as fit inside the wire budget.
    expected_reads = int(timeout / chunk_cost)
    assert trickle.reads == expected_reads
    assert result["kind"] == "typed-receipt"
    assert result["complete"] is False
    assert result["failure"] == "timeout"
    assert result["rawBodyBytes"] == expected_reads
    assert budgets == [timeout]
    assert clock.elapsed() == pytest.approx(timeout)
    assert trickle.closed is True


def test_trickle_response_wire_deadline_smoke_uses_real_time():
    # Real-time smoke check for the same property. The budget is generous by
    # design: it only proves the call returns promptly relative to a stalled
    # wire, so a loaded host cannot turn it into a flake.
    plan, operation = plan_and_commit()
    timeout = 0.01
    started = time.monotonic()
    result = request(
        plan,
        "observation",
        17,
        operation,
        "token",
        timeout=timeout,
        exchange=lambda *_: (
            time.sleep(timeout * 2) or response(200, {"Content-Length": "1"}, b"x")
        ),
    )
    assert result["complete"] is False
    assert time.monotonic() - started < WIRE_SMOKE_BUDGET_SECONDS


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
    assert MAX_REQUEST_BYTES == 11_534_337
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


def test_default_exchange_uses_verified_worker_and_one_deadline(monkeypatch):
    plan, operation = plan_and_commit()
    seen = {}

    def process(**kwargs):
        seen.update(kwargs)
        return 403, "application/json", b"{}", None

    monkeypatch.setattr("request_bytes_remote_transport._run_process_exchange", process)
    receipt = request(plan, "observation", 17, operation, "secret-test-credential")
    assert receipt["status"] == 403
    assert receipt["complete"] is True
    assert seen["deadline"] - time.monotonic() <= TIMEOUT
    assert hashlib.sha256(seen["worker_source"]).hexdigest() == seen["worker_sha256"]
    assert b"secret-test-credential" in seen["request_payload"]
    assert b"secret-test-credential" not in seen["worker_source"]
    assert (
        seen["request_payload"].split(b"\n", 1)[1]
        == json.dumps(
            operation["body"], separators=(",", ":"), ensure_ascii=False
        ).encode()
    )


def test_changed_worker_source_is_rejected_before_exchange(monkeypatch):
    plan, operation = plan_and_commit()
    from pathlib import Path

    from request_bytes_remote_transport import _WORKER_SHA256

    original = Path.read_bytes

    def changed(path):
        if path.name == "request_bytes_https_worker.py":
            return original(path) + b"\n# mutation"
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", changed)
    monkeypatch.setattr(
        "request_bytes_remote_transport._run_process_exchange",
        lambda **_kwargs: pytest.fail("mutated worker executed"),
    )
    with pytest.raises(ValueError, match="digest"):
        request(plan, "observation", 17, operation, "token")
    assert len(_WORKER_SHA256) == 64


def test_fixed_worker_rejects_forged_path_without_network():
    from pathlib import Path

    from request_bytes_process_exchange import _run_process_exchange
    from request_bytes_remote_transport import _WORKER_SHA256

    source = Path(
        "tools/compat-broad/fs-request-bytes-boundary/request_bytes_https_worker.py"
    ).read_bytes()
    payload = (
        json.dumps(
            {
                "method": "GET",
                "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents/other",
                "authorization": "Bearer secret-test-credential",
                "project": "fireemu-35fe6",
                "bodyBytes": 0,
                "deadline": time.monotonic() + 2,
            }
        ).encode()
        + b"\n"
    )
    assert _run_process_exchange(
        worker_source=source,
        worker_sha256=_WORKER_SHA256,
        request_payload=payload,
        deadline=time.monotonic() + 2,
        response_cap=RESPONSE_BYTES,
    ) == (None, "", b"", "worker-failure")


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


# --- Boundary-size deadline coverage -----------------------------------------
#
# The production transport carries an 11,534,337-byte body through a single total
# deadline. These tests exercise that path at boundary size: one through the
# injected-exchange seam, one through the real process exchange and the real
# worker logic with TLS replaced by loopback plaintext. No production request is
# sent and no credential is used.


def test_deadline_derivation_leaves_the_upload_a_usable_rate():
    """The published ceiling must admit a link a real operator could have."""
    reserve = NON_UPLOAD_RESERVE_SECONDS
    assert TIMEOUT > reserve
    upload_seconds = TIMEOUT - reserve
    bits = MAX_REQUEST_BYTES * 8
    required_bits_per_second = bits / upload_seconds
    # Anything above a few Mbit/s would make the ceiling unreachable in practice.
    assert required_bits_per_second < 2_000_000
    # And the ceiling must still be short enough to bound a stuck run.
    assert TIMEOUT <= 120


def test_boundary_body_reaches_the_exchange_intact_within_one_deadline():
    plan, operation = plan_and_commit()
    seen = {}

    def exchange(url, method, body, headers, timeout, response_cap):
        seen["bytes"] = len(body)
        seen["sha256"] = hashlib.sha256(body).hexdigest()
        # The budget handed to the exchange is what remains of the one total
        # deadline, so it must still cover the upload at this size.
        seen["budget"] = timeout
        return response(200, {"Content-Type": "application/json"}, b"{}")

    receipt = request(plan, "observation", 17, operation, "token", exchange=exchange)
    body = json.dumps(
        operation["body"], separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert len(body) == REQUEST_TARGETS[0]
    assert seen["bytes"] == len(body)
    assert seen["sha256"] == hashlib.sha256(body).hexdigest()
    assert receipt["requestBytes"] == len(body)
    assert receipt["requestSha256"] == hashlib.sha256(body).hexdigest()
    assert receipt["complete"] is True
    assert seen["budget"] > TIMEOUT - 5


def test_the_deadline_starts_before_the_upload_not_after_it():
    """A slow upload must consume the deadline, not be granted a fresh one."""
    plan, operation = plan_and_commit()
    clock = FakeClock()

    def exchange(url, method, body, headers, timeout, response_cap):
        # Simulate an upload that eats the whole budget before any response.
        clock.advance(TIMEOUT)
        return response(200, {"Content-Type": "application/json"}, b"{}")

    receipt = _request_impl(
        plan,
        "observation",
        17,
        operation,
        "token",
        exchange=exchange,
        timeout=TIMEOUT,
        clock=clock,
    )
    assert receipt["complete"] is False
    # The remaining budget is already spent when the response is read, so the
    # read is refused rather than granted a second full deadline.
    assert receipt["failure"] in {"timeout", "response-timeout"}


def _loopback_worker_source(host: str) -> bytes:
    """The real worker with TLS swapped for a loopback plaintext origin.

    Only the connection class and the fixed host literal change. The deadline
    re-check, the request validation, the framing, the response caps and the
    failure codes are the same bytes the production worker runs, so this
    exercises the timing path rather than a re-implementation of it. The host is
    substituted into the source because the process exchange launches the worker
    with an empty environment, so it cannot be passed at run time.
    """
    source = (HERE / "request_bytes_https_worker.py").read_text()
    patched = source.replace(
        "connection = http.client.HTTPSConnection(",
        "connection = http.client.HTTPConnection(",
    ).replace('_HOST = "firestore.googleapis.com"', f"_HOST = {host!r}")
    assert patched.count("HTTPConnection(") == 1
    assert "HTTPSConnection" not in patched
    assert "firestore.googleapis.com" not in patched
    return patched.encode()


def test_boundary_body_survives_the_real_process_exchange_and_worker(loopback_server):
    """Push 11,534,337 bytes through the exchange and worker the campaign uses."""
    from request_bytes_process_exchange import _run_process_exchange

    host, received = loopback_server
    source = _loopback_worker_source(host)
    body = b"x" * MAX_REQUEST_BYTES
    message = (
        json.dumps(
            {
                "method": "POST",
                "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents:commit",
                "authorization": "Bearer loopback-test-token",
                "project": "fireemu-35fe6",
                "bodyBytes": len(body),
                "deadline": time.monotonic() + TIMEOUT,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    started = time.monotonic()
    status, _content_type, raw, failure = _run_process_exchange(
        worker_source=source,
        request_payload=message + body,
        deadline=time.monotonic() + TIMEOUT,
        response_cap=RESPONSE_BYTES,
        worker_sha256=hashlib.sha256(source).hexdigest(),
    )
    elapsed = time.monotonic() - started
    assert failure is None, failure
    assert status == 200
    assert json.loads(raw) == {"received": MAX_REQUEST_BYTES}
    # The server counted exactly the boundary body; nothing was truncated by the
    # exchange's framing, its request cap, or the worker's own validation.
    assert received["bytes"] == MAX_REQUEST_BYTES
    assert received["sha256"] == hashlib.sha256(body).hexdigest()
    assert elapsed < TIMEOUT


def test_sentinel_body_survives_the_real_worker_and_exact_case_route(loopback_server):
    from request_bytes_process_exchange import _run_process_exchange

    host, received = loopback_server
    source = _loopback_worker_source(host)
    plan = compile_request_bytes_sentinel_plan(
        "fireemu-35fe6", "(default)", NONCE
    )
    operation = next(
        row for row in plan["observation"] if row["kind"] == "conditional-create-commit"
    )
    body = json.dumps(
        operation["body"], separators=(",", ":"), ensure_ascii=False
    ).encode()
    assert len(body) == RAW_16MIB_OVER_BYTES
    message = (
        json.dumps(
            {
                "method": "POST",
                "path": operation["path"],
                "authorization": "Bearer loopback-test-token",
                "project": "fireemu-35fe6",
                "bodyBytes": len(body),
                "deadline": time.monotonic() + 80,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )

    status, _content_type, raw, failure = _run_process_exchange(
        worker_source=source,
        request_payload=message + body,
        deadline=time.monotonic() + 80,
        response_cap=RESPONSE_BYTES,
        worker_sha256=hashlib.sha256(source).hexdigest(),
    )

    assert failure is None, failure
    assert status == 200
    assert json.loads(raw) == {"received": RAW_16MIB_OVER_BYTES}
    assert received["bytes"] == RAW_16MIB_OVER_BYTES
    assert received["sha256"] == hashlib.sha256(body).hexdigest()


def test_real_worker_rejects_one_byte_above_sentinel_body_ceiling(loopback_server):
    from request_bytes_process_exchange import _run_process_exchange

    host, _ = loopback_server
    source = _loopback_worker_source(host)
    message = (
        json.dumps(
            {
                "method": "POST",
                "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents:commit",
                "authorization": "Bearer loopback-test-token",
                "project": "fireemu-35fe6",
                "bodyBytes": RAW_16MIB_OVER_BYTES + 1,
                "deadline": time.monotonic() + 80,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )

    result = _run_process_exchange(
        worker_source=source,
        request_payload=message,
        deadline=time.monotonic() + 80,
        response_cap=RESPONSE_BYTES,
        worker_sha256=hashlib.sha256(source).hexdigest(),
    )

    assert result == (None, "", b"", "worker-failure")


def test_real_worker_path_is_closed_to_the_twenty_sentinel_resources():
    import request_bytes_https_worker as worker

    valid = (
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
        + NONCE
        + "/request-bytes-02/probe-r16m1/items/payload-18"
        "?currentDocument.updateTime=2026-09-23T01%3A02%3A03Z"
    )
    invalid = valid.replace("payload-18", "payload-19")

    assert worker._PATH.fullmatch(valid)
    assert worker._PATH.fullmatch(invalid) is None


@pytest.mark.parametrize(
    "route",
    [
        "request-bytes-01/probe-u01/items/control",
        "request-bytes-01/probe-u01/items/payload-00",
        "request-bytes-02/probe-r16m1/items/control",
        "request-bytes-02/probe-r16m1/items/payload-18",
    ],
)
def test_real_worker_owns_only_compiled_request_byte_routes(route):
    import request_bytes_https_worker as worker

    path = (
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
        + NONCE
        + "/"
        + route
    )
    assert worker._PATH.fullmatch(path)
    assert worker._PATH.fullmatch(
        path + "?currentDocument.updateTime=2026-09-23T01%3A02%3A03Z"
    )


@pytest.mark.parametrize(
    "route",
    [
        "request-bytes-01/probe-u01/items/control",
        "request-bytes-01/probe-u01/items/payload-00",
        "request-bytes-02/probe-r16m1/items/control",
        "request-bytes-02/probe-r16m1/items/payload-18",
    ],
)
def test_real_worker_accepts_version_bound_delete_for_owned_routes(route):
    import request_bytes_https_worker as worker

    path = (
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
        + NONCE
        + "/"
        + route
        + "?currentDocument.updateTime=2026-09-23T01%3A02%3A03Z"
    )
    assert worker._PATH.fullmatch(path)


@pytest.mark.parametrize(
    "route",
    [
        "request-bytes-01/probe-x01/items/control",
        "request-bytes-01/probe-u01/items/payload-16",
        "request-bytes-02/probe-r16m1/items/payload-19",
        "request-bytes-03/probe-u01/items/control",
        "request-bytes-01/probe-u01/items/control/child",
    ],
)
def test_real_worker_rejects_sibling_request_byte_routes(route):
    import request_bytes_https_worker as worker

    path = (
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
        + NONCE
        + "/"
        + route
        + "?currentDocument.updateTime=2026-09-23T01%3A02%3A03Z"
    )
    assert worker._PATH.fullmatch(path) is None


def _run_loopback_worker_request(host, method, path):
    from request_bytes_process_exchange import _run_process_exchange

    source = _loopback_worker_source(host)
    message = (
        json.dumps(
            {
                "method": method,
                "path": path,
                "authorization": "Bearer loopback-test-token",
                "project": "fireemu-35fe6",
                "bodyBytes": 0,
                "deadline": time.monotonic() + 2,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    return _run_process_exchange(
        worker_source=source,
        request_payload=message,
        deadline=time.monotonic() + 2,
        response_cap=RESPONSE_BYTES,
        worker_sha256=hashlib.sha256(source).hexdigest(),
    )


@pytest.mark.parametrize(
    "path",
    [
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
        + NONCE
        + "/request-bytes-01/probe-u01/items/control",
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
        + NONCE
        + "/request-bytes-01/probe-u01/items/control?currentDocument.updateTime=2026-09-23T01:02:03Z",
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
        + NONCE
        + "/request-bytes-02/probe-r16m1/items/control?currentDocument.updateTime=2026-99-99T01%3A02%3A03Z",
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
        + NONCE
        + "/request-bytes-02/probe-r16m1/items/control?currentDocument.updateTime=2026-09-23T01%3A02%3A03Z&other=1",
    ],
)
def test_real_worker_refuses_delete_without_canonical_version(loopback_server, path):
    host, received = loopback_server

    result = _run_loopback_worker_request(host, "DELETE", path)

    assert result == (None, "", b"", "worker-failure")
    assert "method" not in received


@pytest.mark.parametrize(
    "route",
    [
        "request-bytes-01/probe-u01/items/control",
        "request-bytes-01/probe-u01/items/payload-00",
        "request-bytes-02/probe-r16m1/items/control",
        "request-bytes-02/probe-r16m1/items/payload-18",
    ],
)
def test_real_worker_sends_only_version_bound_delete_for_owned_routes(
    loopback_server, route
):
    host, received = loopback_server
    path = (
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
        + NONCE
        + "/"
        + route
        + "?currentDocument.updateTime=2026-09-23T01%3A02%3A03Z"
    )

    status, content_type, body, failure = _run_loopback_worker_request(
        host, "DELETE", path
    )

    assert (status, content_type, body, failure) == (200, "", b"", None)
    assert received["method"] == "DELETE"
    assert received["path"] == path


def test_the_real_worker_refuses_a_deadline_above_the_published_ceiling(
    loopback_server,
):
    from request_bytes_process_exchange import _run_process_exchange

    host, _ = loopback_server
    source = _loopback_worker_source(host)
    message = (
        json.dumps(
            {
                "method": "GET",
                "path": (
                    "/v1/projects/fireemu-35fe6/databases/(default)/documents"
                    "/oracle/" + NONCE + "/request-bytes-01/probe-u01/items/control"
                ),
                "authorization": "Bearer loopback-test-token",
                "project": "fireemu-35fe6",
                "bodyBytes": 0,
                "deadline": time.monotonic() + TIMEOUT + 30,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )
    status, _content_type, _raw, failure = _run_process_exchange(
        worker_source=source,
        request_payload=message,
        deadline=time.monotonic() + TIMEOUT,
        response_cap=RESPONSE_BYTES,
        worker_sha256=hashlib.sha256(source).hexdigest(),
    )
    assert status is None
    assert failure == "worker-failure"


# --- Per-request elapsed time -------------------------------------------------
#
# The O8 runner reserves a number of seconds per schedule slot. The production
# transport recorded no duration at all, so nothing in the tree measured what a
# slot actually costs. These cover the recording, not a production figure.


def test_the_receipt_carries_the_elapsed_time_of_the_whole_slot():
    plan, operation = plan_and_commit()
    clock = FakeClock()

    def exchange(url, method, body, headers, timeout, response_cap):
        clock.advance(3.5)
        return response(200, {"Content-Type": "application/json"}, b"{}")

    receipt = _request_impl(
        plan,
        "observation",
        17,
        operation,
        "token",
        exchange=exchange,
        timeout=TIMEOUT,
        clock=clock,
    )
    assert receipt["complete"] is True
    assert receipt["elapsedSeconds"] == pytest.approx(3.5)


def test_a_transport_failure_is_timed_too():
    """A timeout's duration is exactly the figure a reservation needs."""
    plan, operation = plan_and_commit()
    clock = FakeClock()

    def exchange(url, method, body, headers, timeout, response_cap):
        clock.advance(TIMEOUT)
        raise TimeoutError

    receipt = _request_impl(
        plan,
        "observation",
        17,
        operation,
        "token",
        exchange=exchange,
        timeout=TIMEOUT,
        clock=clock,
    )
    assert receipt["complete"] is False
    assert receipt["failure"] == "timeout"
    assert receipt["elapsedSeconds"] == pytest.approx(TIMEOUT)


def test_timing_does_not_change_a_refusal_or_the_deadline(monkeypatch):
    """The wrapper must be additive.

    Compared against the untimed dispatch path through the same exchange, not
    against a stripped copy of itself: the timed receipt minus its one new key
    has to equal what the transport produced before the wrapper existed.
    """
    plan, operation = plan_and_commit()
    body = json.dumps(
        {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}, separators=(",", ":")
    ).encode()

    def process(**kwargs):
        return 400, "application/json", body, None

    monkeypatch.setattr("request_bytes_remote_transport._run_process_exchange", process)
    timed = request(plan, "observation", 17, operation, "secret-test-credential")
    untimed = _dispatch(
        plan,
        "observation",
        17,
        operation,
        "secret-test-credential",
        exchange=_fixture_exchange,
    )
    assert timed["status"] == 400
    assert timed["complete"] is True
    assert json.loads(base64.b64decode(timed["rawBodyBase64"])) == json.loads(body)
    assert timed["elapsedSeconds"] >= 0
    assert "elapsedSeconds" not in untimed
    assert {k: v for k, v in timed.items() if k != "elapsedSeconds"} == untimed


def test_a_real_loopback_request_is_timed_end_to_end(loopback_server, monkeypatch):
    """A real socket, a real worker process, through the production path."""
    from request_bytes_process_exchange import _run_process_exchange

    host, _received = loopback_server
    source = _loopback_worker_source(host)
    plan, operation = plan_and_commit()

    def process(**kwargs):
        assert kwargs["deadline"] > time.monotonic()
        return _run_process_exchange(
            worker_source=source,
            request_payload=kwargs["request_payload"],
            deadline=kwargs["deadline"],
            response_cap=kwargs["response_cap"],
            worker_sha256=hashlib.sha256(source).hexdigest(),
        )

    monkeypatch.setattr("request_bytes_remote_transport._run_process_exchange", process)
    started = time.monotonic()
    receipt = request(plan, "observation", 17, operation, "loopback-test-token")
    wall = time.monotonic() - started
    assert receipt["status"] == 200
    assert receipt["complete"] is True
    # A real measurement: positive, no larger than the wall clock around it, and
    # inside the deadline the transport enforces.
    assert 0 < receipt["elapsedSeconds"] <= wall
    assert receipt["elapsedSeconds"] < TIMEOUT
