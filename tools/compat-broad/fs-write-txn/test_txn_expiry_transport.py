"""The fixed transport reaches only the campaign's routes and normalizes like the rehearsal."""

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import txn_expiry_collector as collector
import txn_expiry_descriptor as campaign
import txn_expiry_o8 as launcher
import txn_expiry_plan as plan_module
import txn_expiry_remote_transport as remote
from broad_contract import digest

NONCE = "d" * 32
PROJECT = "fireemu-35fe6"
NAME = f"projects/{PROJECT}/databases/(default)/documents/oracle/{NONCE}/txn-expiry-04/control"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("network forbidden")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def request(rpc, **overrides):
    value = {
        "rpc": rpc,
        "database": "(default)",
        "projectId": PROJECT,
        "name": NAME if rpc == "GetDocument" else None,
        "body": None if rpc == "GetDocument" else {"transaction": "AAAA"},
        "query": None,
        "maxResponseBytes": plan_module.MAX_RESPONSE_BYTES,
        "maxRequestBytes": plan_module.MAX_REQUEST_BYTES,
        "timeoutSeconds": 10,
        "site": "fixture",
    }
    value.update(overrides)
    return value


def test_the_worker_source_is_pinned_by_digest():
    source = remote.worker_source()
    assert hashlib.sha256(source).hexdigest() == remote.WORKER_SHA256
    assert campaign.worker_binding() == (source, remote.WORKER_SHA256)
    with pytest.raises(ValueError, match="differs from the reviewed transport"):
        campaign.verify_worker_binding(
            source + b"\n", hashlib.sha256(source + b"\n").hexdigest(), None
        )
    with pytest.raises(ValueError, match="frozen inputs"):
        campaign.verify_worker_binding(
            source, remote.WORKER_SHA256, {campaign.WORKER_ENTRY: "0" * 64}
        )


def test_build_maps_every_rpc_onto_its_fixed_route():
    assert remote.build(request("GetDocument")) == ("GET", "/v1/" + NAME, None)
    assert remote.build(request("GetDocument", query={"transaction": "AA=="})) == (
        "GET",
        "/v1/" + NAME + "?transaction=AA%3D%3D",
        None,
    )
    method, path, payload = remote.build(request("Rollback"))
    assert (method, path, payload) == (
        "POST",
        f"/v1/projects/{PROJECT}/databases/(default)/documents:rollback",
        b'{"transaction":"AAAA"}',
    )
    assert remote.build(request("BeginTransaction", body={"options": {}}))[1].endswith(
        ":beginTransaction"
    )
    assert remote.build(request("Commit", body={"writes": []}))[1].endswith(":commit")


@pytest.mark.parametrize(
    "damage",
    [
        {"projectId": "other-project"},
        {"database": "other"},
        {"maxRequestBytes": 0},
        {
            "name": f"projects/{PROJECT}/databases/(default)/documents/other/{NONCE}/txn-expiry-04/control"
        },
        {
            "name": f"projects/{PROJECT}/databases/(default)/documents/oracle/{NONCE}/txn-expiry-04/stray"
        },
        {"name": NAME + "/sub/doc"},
        {"name": NAME.replace(NONCE, "not-a-nonce")},
        {"query": {"readTime": "x"}},
        {"timeoutSeconds": 121},
        {"maxResponseBytes": plan_module.MAX_RESPONSE_BYTES + 1},
        {"body": {"x": 1}},
    ],
    ids=[
        "project",
        "database",
        "request-bound",
        "collection",
        "role",
        "subdocument",
        "nonce",
        "query",
        "timeout",
        "bound",
        "get-body",
    ],
)
def test_build_refuses_requests_outside_the_campaign(damage):
    with pytest.raises(ValueError):
        remote.build(request("GetDocument", **damage))


def test_build_refuses_an_oversized_or_named_rpc_body():
    with pytest.raises(ValueError, match="rpc vocabulary"):
        remote.build(request("RunQuery"))
    with pytest.raises(ValueError, match="exceeds bound"):
        remote.build(
            request("Commit", body={"writes": ["x" * plan_module.MAX_REQUEST_BYTES]})
        )
    with pytest.raises(ValueError, match="names no document"):
        remote.build(request("Rollback", name=NAME))


def test_the_worker_refuses_routes_outside_the_campaign_before_connecting(tmp_path):
    """The worker's own route check runs before any socket exists."""
    for path in (
        f"/v1/projects/{PROJECT}/databases/(default)/documents/oracle/{NONCE}/other/control",
        f"/v1/projects/{PROJECT}/databases/(default)/documents:batchWrite",
        f"/v1/projects/{PROJECT}/databases/other/documents:commit",
    ):
        message = {
            "method": "GET" if "documents/" in path else "POST",
            "path": path,
            "authorization": "Bearer x",
            "project": PROJECT,
            "bodyBytes": 0 if "documents/" in path else 2,
            "deadline": time.monotonic() + 5,
        }
        payload = (
            json.dumps(message).encode()
            + b"\n"
            + (b"" if "documents/" in path else b"{}")
        )
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", remote.worker_source().decode()],
            input=payload,
            capture_output=True,
            timeout=20,
            check=False,
            env={"PATH": os.defpath},
        )
        assert result.stdout == b"F" + (14).to_bytes(4, "big") + b"worker-failure", path


def _exchange(status, body, *, content_type="application/json", failure=None):
    raw = json.dumps(body).encode() if body is not None else b""

    def exchange(method, path, payload, deadline, cap):
        return status, content_type, raw, failure

    return exchange


def test_request_normalizes_like_the_rehearsal_transport():
    """One normalizer for both sides, so a production row and a rehearsal row agree by construction."""
    import txn_expiry_shadow as shadow

    assert remote.STATUS_TO_CODE == shadow.STATUS_TO_CODE
    value = {"request": request("Rollback"), "token": "tok"}
    ok = remote.request(
        value, deadline=time.monotonic() + 5, exchange=_exchange(200, {})
    )
    assert (ok["complete"], ok["code"], ok["status"], ok["httpStatus"]) == (
        True,
        0,
        "OK",
        200,
    )
    assert ok["wire"]["rawBodySha256"] == hashlib.sha256(b"{}").hexdigest()
    refused = remote.request(
        value,
        deadline=time.monotonic() + 5,
        exchange=_exchange(
            409, {"error": {"code": 409, "status": "ABORTED", "message": "expired"}}
        ),
    )
    assert (
        refused["complete"],
        refused["code"],
        refused["status"],
        refused["message"],
    ) == (True, 10, "ABORTED", "expired")
    mismatched = remote.request(
        value,
        deadline=time.monotonic() + 5,
        exchange=_exchange(409, {"error": {"code": 400, "status": "ABORTED"}}),
    )
    assert (
        mismatched["complete"] is False
        and mismatched["message"] == "error-status-not-confirmed"
    )
    html = remote.request(
        value,
        deadline=time.monotonic() + 5,
        exchange=_exchange(502, None, content_type="text/html"),
    )
    assert html["complete"] is False and html["httpStatus"] == 502
    lost = remote.request(
        value,
        deadline=time.monotonic() + 5,
        exchange=_exchange(None, None, failure="timeout"),
    )
    assert (
        lost["complete"] is False
        and lost["httpStatus"] is None
        and lost["message"] == "timeout"
    )
    for response in (ok, refused, mismatched, html, lost):
        assert "tok" not in json.dumps(response)


def test_request_without_a_capability_never_reaches_the_worker(monkeypatch):
    spawned = []
    monkeypatch.setattr(
        remote,
        "_run_process_exchange",
        lambda **kwargs: spawned.append(kwargs) or (None, "", b"", "timeout"),
    )
    with pytest.raises(ValueError, match="capability required"):
        remote.request(
            {"request": request("Rollback"), "token": "tok"},
            deadline=time.monotonic() + 5,
        )
    with pytest.raises(ValueError, match="closed transaction wire call"):
        remote.request({"request": request("Rollback")}, deadline=time.monotonic() + 5)
    assert spawned == []


def test_the_bounded_deadline_is_the_earliest_of_request_slot_and_maximum():
    def clock():
        return 1000.0

    assert (
        remote._bounded_deadline(
            request("Rollback", timeoutSeconds=10), deadline=1003.0, clock=clock
        )
        == 1003.0
    )
    assert (
        remote._bounded_deadline(
            request("Rollback", timeoutSeconds=10), deadline=1100.0, clock=clock
        )
        == 1010.0
    )
    assert (
        remote._bounded_deadline(
            request("Rollback", timeoutSeconds=120), deadline=1500.0, clock=clock
        )
        == 1120.0
    )
    with pytest.raises(ValueError):
        remote._bounded_deadline(
            request("Rollback"), deadline=float("inf"), clock=clock
        )


def test_the_credential_handoff_is_read_from_a_private_descriptor(tmp_path):
    permission = {"kind": "fixture"}
    handoff = json.dumps(
        {
            "kind": launcher.HANDOFF_KIND,
            "permissionDigest": digest(permission),
            "token": "tok",
        }
    ).encode()
    reader, writer = os.pipe()
    os.write(writer, handoff)
    os.close(writer)
    args = launcher.build_parser().parse_args(
        [
            "--inputs",
            "i",
            "--approval",
            "a",
            "--manifest",
            "m",
            "--permission",
            "p",
            "--source",
            "s",
            "--artifact",
            "x",
            "--ledger",
            "l",
            "--output",
            "o",
            "--credential-fd",
            str(reader),
        ]
    )
    assert launcher.validate_handoff(launcher._read_handoff(args), permission) == "tok"
    os.close(reader)
    # A world-readable regular file is refused.
    exposed = tmp_path / "handoff.json"
    exposed.write_bytes(handoff)
    exposed.chmod(0o644)
    with pytest.raises(ValueError, match="private credential descriptor"):
        launcher._read_private_fd(os.open(exposed, os.O_RDONLY))
    # An oversized handoff is refused before it is parsed.
    reader, writer = os.pipe()
    os.write(writer, b"x" * (launcher.MAX_HANDOFF_BYTES + 1))
    os.close(writer)
    with pytest.raises(ValueError, match="bounded private credential handoff"):
        launcher._read_private_fd(reader)
    os.close(reader)


def test_a_refused_launcher_exits_two_without_touching_anything(tmp_path):
    code = launcher.main(
        [
            "--inputs",
            str(tmp_path / "missing.json"),
            "--approval",
            "a",
            "--manifest",
            "m",
            "--permission",
            "p",
            "--source",
            "s",
            "--artifact",
            "x",
            "--ledger",
            "l",
            "--output",
            str(tmp_path / "out"),
            "--credential-fd",
            "3",
        ]
    )
    assert code == 2
    assert not (tmp_path / "out").exists()


def test_collector_requests_from_the_rehearsal_are_all_buildable():
    """Every request the collector emits under production options maps onto a route."""
    from test_txn_expiry_collector import Endpoint, advances

    plan = campaign.execution_plan(campaign.plan_compiler(NONCE))
    options = {
        **campaign.collector_options(plan, target="local", host="127.0.0.1", port=1),
        "timing": collector.CONTROL_CLOCK,
    }
    endpoint = Endpoint()
    collector.Collection(
        options, plan, endpoint, advance=advances([]), monotonic=lambda: 0.0
    ).run()
    assert endpoint.calls
    for call in endpoint.calls:
        method, path, _payload = remote.build(call)
        assert method in ("GET", "POST") and path.startswith(
            "/v1/projects/fireemu-35fe6/"
        )
