"""Exercise the real bounded HTTP worker against owned loopback sockets.

No Firebase, credentials, DNS lookup of external hosts, or production transport is
used. In particular a JSON-decodable prefix is not a complete HTTP response.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
from urllib.parse import quote

import pytest

import batch_wire
import shared_gate
from broad_contract import digest

WORKER = Path(batch_wire.__file__).resolve()
ABSENT = {"error": {"code": 404, "status": "NOT_FOUND"}}
NONCE = "e" * 32
RESOURCE = f"projects/p/databases/(default)/documents/campaign/{NONCE}/items/a"
VERSION = "2026-09-19T00:00:00Z"


@contextlib.contextmanager
def raw_server(response: bytes):
    """One request, one response, no reusable port or surviving worker thread."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(4)
    requests: list[bytes] = []
    failures: list[BaseException] = []

    def serve():
        try:
            client, _ = listener.accept()
            with client:
                client.settimeout(4)
                request = b""
                while b"\r\n\r\n" not in request:
                    block = client.recv(4096)
                    if not block:
                        raise AssertionError("worker closed before request headers")
                    request += block
                    if len(request) > 65536:
                        raise AssertionError("test request bound exceeded")
                headers, body = request.split(b"\r\n\r\n", 1)
                lengths = [line.split(b":", 1)[1].strip() for line in headers.split(b"\r\n")
                           if line.lower().startswith(b"content-length:")]
                length = int(lengths[0]) if lengths else 0
                while len(body) < length:
                    block = client.recv(min(4096, length - len(body)))
                    if not block:
                        raise AssertionError("worker closed before request body")
                    body += block
                requests.append(headers + b"\r\n\r\n" + body)
                try:
                    client.sendall(response)
                    client.shutdown(socket.SHUT_WR)
                except (BrokenPipeError, ConnectionResetError):
                    # The client is allowed to reject framing before reading a body.
                    pass
        except BaseException as error:
            failures.append(error)
        finally:
            listener.close()

    port = listener.getsockname()[1]
    thread = threading.Thread(target=serve, name="owned-wire-fixture", daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", requests
    finally:
        thread.join(5)
        listener.close()
        assert not thread.is_alive(), "owned socket thread survived the test"
        assert not failures, failures
        assert len(requests) == 1, "redirect/retry or missing request"


def frame(payload, *, status=200, headers=None):
    headers = list(headers) if headers is not None else [
        ("Content-Length", str(len(payload))),
    ]
    return (f"HTTP/1.1 {status} Fixture\r\n".encode()
            + b"Content-Type: application/json\r\nConnection: close\r\n"
            + b"".join(f"{key}: {value}\r\n".encode() for key, value in headers)
            + b"\r\n" + payload)


def exchange(response, *, receipt=False, operation=None, extra_env=None):
    operation = operation or {"method": "GET", "path": "/owned", "body": None}
    with raw_server(response) as (origin, requests):
        value = {
            "url": origin + operation["path"], "method": operation["method"],
            "body": None if operation.get("body") is None else json.dumps(operation["body"]),
            "headers": {"Content-Type": "application/json"}, "receipt": receipt,
        }
        # Do not inherit cloud credentials, proxies, startup hooks, or user config.
        env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "LANG") if key in os.environ}
        env.update(extra_env or {})
        result = subprocess.run(
            [sys.executable, str(WORKER)], input=json.dumps(value), text=True,
            capture_output=True, timeout=5, check=False, env=env,
        )
    assert requests[0].split(b" ", 2)[:2] == [
        operation["method"].encode(), operation["path"].encode(),
    ]
    return result


def assert_incomplete(result, receipt):
    assert result.stderr == ""
    if not receipt:
        assert result.returncode == 2
        assert result.stdout == ""
        return
    assert result.returncode == 0
    evidence = json.loads(result.stdout)["http"]
    assert evidence["complete"] is False
    assert evidence["failure"] == "body-interrupted"
    assert evidence["digestScope"] == "prefix"


@pytest.mark.parametrize("receipt", [False, True])
@pytest.mark.parametrize("status,body", [
    (200, {"ok": True}), (400, {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}),
    (404, ABSENT), (200, {"unicode": "大森駅🦀"}),
])
def test_complete_response_preserves_exact_status_and_json(receipt, status, body):
    payload = json.dumps(body, ensure_ascii=False).encode()
    result = exchange(frame(payload, status=status), receipt=receipt)
    assert result.returncode == 0
    assert result.stderr == ""
    observed = json.loads(result.stdout)
    if receipt:
        assert observed["body"] == body
        assert observed["http"]["status"] == status
        assert observed["http"]["complete"] is True
        assert observed["http"]["failure"] is None
        assert observed["http"]["bodySha256"] == hashlib.sha256(payload).hexdigest()
        assert observed["http"]["receivedBytes"] == len(payload)
        assert observed["http"]["digestScope"] == "full"
    else:
        assert observed == [status, body, "application/json"]


@pytest.mark.parametrize("receipt", [False, True])
@pytest.mark.parametrize("status,body", [(200, {"ok": True}), (404, ABSENT), (200, [1, 2, 3])])
def test_valid_json_prefix_cannot_hide_content_length_truncation(receipt, status, body):
    payload = json.dumps(body).encode()
    result = exchange(frame(payload, status=status, headers=[
        ("Content-Length", str(len(payload) + 20)),
    ]), receipt=receipt)
    assert_incomplete(result, receipt)
    if receipt:
        evidence = json.loads(result.stdout)
        assert evidence["body"] == body  # Diagnostic prefix, NOT a completed response.
        assert evidence["http"]["bodySha256"] == hashlib.sha256(payload).hexdigest()
        assert evidence["http"]["receivedBytes"] == len(payload)


@pytest.mark.parametrize("receipt", [False, True])
@pytest.mark.parametrize("length", ["abc", "-1", "+2", "2, 2", "2, 9", "", "\v2"])
def test_invalid_content_length_is_never_a_complete_response(receipt, length):
    assert_incomplete(exchange(frame(b"{}", headers=[("Content-Length", length)]), receipt=receipt), receipt)


@pytest.mark.parametrize("receipt", [False, True])
@pytest.mark.parametrize("lengths", [("2", "9"), ("9", "2"), ("2", "2")])
def test_duplicate_content_lengths_fail_closed(receipt, lengths):
    # The closed observer deliberately rejects duplicates, even equal values.
    assert_incomplete(exchange(frame(b"{}", headers=[("Content-Length", v) for v in lengths]), receipt=receipt), receipt)


@pytest.mark.parametrize("receipt", [False, True])
@pytest.mark.parametrize("headers", [
    [("Transfer-Encoding", "chunked"), ("Content-Length", "2")],
    [("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "chunked")],
    [("Transfer-Encoding", "identity")],
    [("Transfer-Encoding", "gzip, chunked")],
])
def test_ambiguous_or_unsupported_transfer_framing_is_not_complete(receipt, headers):
    payload = b"2\r\n{}\r\n0\r\n\r\n" if headers[0][1] == "chunked" else b"{}"
    assert_incomplete(exchange(frame(payload, headers=headers), receipt=receipt), receipt)


@pytest.mark.parametrize("receipt", [False, True])
@pytest.mark.parametrize("headers,payload", [
    ([], b"{}"),
    ([("Transfer-Encoding", "chunked")], b"1\r\n{\r\n1\r\n}\r\n0\r\n\r\n"),
    ([("Content-Length", "0002")], b"{}"),
])
def test_supported_close_delimited_and_chunked_framing_remains_usable(receipt, headers, payload):
    result = exchange(frame(payload, headers=headers), receipt=receipt)
    assert result.returncode == 0
    evidence = json.loads(result.stdout)
    if receipt:
        assert evidence["body"] == {}
        assert evidence["http"]["complete"] is True
        assert evidence["http"]["bodySha256"] == hashlib.sha256(b"{}").hexdigest()
    else:
        assert evidence[:2] == [200, {}]


@pytest.mark.parametrize("receipt", [False, True])
@pytest.mark.parametrize("payload", [b"2\r\n{}\r\n", b"4\r\n{}", b"2\r\n{}"])
def test_incomplete_chunked_messages_never_complete(receipt, payload):
    assert_incomplete(exchange(frame(payload, headers=[("Transfer-Encoding", "chunked")]), receipt=receipt), receipt)


@pytest.mark.parametrize("receipt", [False, True])
@pytest.mark.parametrize("size", [65535, 65536, 65537])
def test_response_byte_limit_is_unchanged(receipt, size):
    payload = b'"' + b"x" * (size - 2) + b'"'
    result = exchange(frame(payload), receipt=receipt)
    if receipt:
        assert result.returncode == 0
        evidence = json.loads(result.stdout)["http"]
        assert evidence["complete"] is (size <= 65536)
        assert evidence["failure"] == (None if size <= 65536 else "size-limit")
        assert evidence["retainedBytes"] == min(size, 65536)
        assert evidence["receivedBytes"] == size
        assert evidence["bodySha256"] == hashlib.sha256(payload[:65536]).hexdigest()
    else:
        assert result.returncode == (0 if size <= 65536 else 2)
        if size <= 65536:
            assert json.loads(result.stdout)[1] == "x" * (size - 2)
        else:
            assert result.stdout == ""


@pytest.mark.parametrize("receipt", [False, True])
def test_environment_proxy_cannot_redirect_the_owned_request(receipt):
    result = exchange(frame(b"{}"), receipt=receipt, extra_env={
        "HTTP_PROXY": "http://127.0.0.1:1", "http_proxy": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1",
        "NO_PROXY": "", "no_proxy": "",
    })
    assert result.returncode == 0


def _worker_send(operation, status, body, *, short=False):
    payload = json.dumps(body).encode()
    result = exchange(frame(payload, status=status, headers=[
        ("Content-Length", str(len(payload) + (20 if short else 0))),
    ]), operation=operation)
    if result.returncode != 0:
        raise ValueError("bounded transport failed")
    code, value, _ = json.loads(result.stdout)
    return code, value


def _gate_and_ledger(tmp_path, scheduled):
    sys.path.insert(0, str(Path(shared_gate.__file__).parent / "production-admission"))
    from reservations import Ledger

    read = {"service": "firestore", "method": "GET", "path": "/v1/" + RESOURCE, "body": None}
    setup = {**read, "method": "PATCH", "path": read["path"] + "?currentDocument.exists=false",
             "body": {"fields": {"_sharedOwner": {"referenceValue": RESOURCE}}}}
    job = {"resources": [RESOURCE], "observation": [setup],
           "recovery": [read, {**read, "method": "DELETE", "versionFrom": 0}, read]}
    if scheduled:
        job["schedule"] = [{"phase": "observation", "index": 0, "creates": True},
                           *[{"phase": "recovery", "index": i, "creates": False} for i in range(3)]]
    plan = {"contract": "shared-local-v2", "nonce": NONCE, "wallSeconds": 300,
            "recoverySeconds": 120, "observationRequests": 1, "requestCostMicrousd": 1,
            "costMicrousd": 20, "intervalSeconds": 0.25, "jobs": {"wire": job}}
    claim = {"campaignId": "FS-DATA-WRITE-LIMITS-02", "gateJob": "wire", "manifestDigest": digest("wire-local-only"),
             "nonceDigest": digest(NONCE), "gatePath": str((tmp_path / "gate").resolve()),
             "gatePlanDigest": digest(plan), "locks": [{"key": "project/p/firestore/(default)/documents/campaign", "mode": "WRITE"}],
             "budget": {"requests": 4, "accounts": 0, "resources": 1, "costMicrousd": 20}, "durationSeconds": 300}
    envelope = {"permissionDigest": "a" * 64, "issuedAt": 1000, "expiresAt": 10000,
                "limits": {"requests": 10, "accounts": 0, "resources": 2, "costMicrousd": 40},
                "concurrency": 1, "scopes": [{"key": "project/p", "mode": "EXCLUSIVE"}]}
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(envelope, claim, plan, now=1100)
    shared_gate.create(tmp_path / "gate", plan)
    gate = shared_gate.Gate(tmp_path / "gate", "wire")
    gate.claim()
    doc = {"name": RESOURCE, "fields": setup["body"]["fields"], "updateTime": VERSION}
    return gate, ledger, ticket, job, doc, envelope, claim


@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize("short", [False, True])
def test_actual_worker_final_absence_controls_ledger_release(tmp_path, scheduled, short):
    gate, ledger, ticket, job, doc, envelope, claim = _gate_and_ledger(tmp_path, scheduled)
    setup = job["observation"][0]
    gate.dispatch(setup, False, lambda: _worker_send(setup, 200, doc))
    initial, declared_delete, final = job["recovery"]
    gate.dispatch(initial, True, lambda: _worker_send(initial, 200, doc))
    delete = {key: value for key, value in declared_delete.items() if key != "versionFrom"}
    delete["path"] += "?currentDocument.updateTime=" + quote(VERSION, safe="")
    gate.dispatch(delete, True, lambda: _worker_send(delete, 200, {}))
    if short:
        with pytest.raises(ValueError, match="bounded transport failed"):
            gate.dispatch(final, True, lambda: _worker_send(final, 404, ABSENT, short=True))
        with pytest.raises(ValueError):
            gate.finish()
        with pytest.raises(ValueError):
            ledger.finish(ticket)
        state = gate.snapshot()
        assert RESOURCE not in state["jobs"]["wire"]["absent"]
        assert state["events"][-1]["completed"] is False
        assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
    else:
        gate.dispatch(final, True, lambda: _worker_send(final, 404, ABSENT))
        gate.finish()
        ledger.finish(ticket)
        assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "released"
    assert ledger.snapshot()["envelopes"][digest(envelope)]["allocated"] == claim["budget"]


@pytest.mark.parametrize("scheduled", [False, True])
def test_truncated_create_acknowledgement_remains_unknown_after_cleanup(tmp_path, scheduled):
    gate, ledger, ticket, job, doc, *_ = _gate_and_ledger(tmp_path, scheduled)
    setup = job["observation"][0]
    with pytest.raises(ValueError, match="bounded transport failed"):
        gate.dispatch(setup, False, lambda: _worker_send(setup, 200, doc, short=True))
    assert shared_gate.unconfirmed_creates(gate.snapshot(), "wire") == 1
    for declared in job["recovery"]:
        operation = copy.deepcopy(declared)
        operation.pop("versionFrom", None)
        # The middle conditional DELETE is skipped: there is no creation proof.
        gate.dispatch(operation, True, lambda op=operation: _worker_send(op, 404, ABSENT))
    with pytest.raises(ValueError):
        gate.finish()
    with pytest.raises(ValueError):
        ledger.finish(ticket)
    assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "held"
