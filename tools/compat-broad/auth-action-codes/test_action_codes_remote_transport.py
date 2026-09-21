"""Tests for the closed AUTH-ACTION production transport wrapper."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
import sys

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "auth-credential-tokens"))
sys.path.insert(0, str(HERE.parent / "o8-core"))

import action_codes_remote_transport as action_remote
import credential_remote_transport as credential_remote
import o8_admission


NONCE = "0123456789abcdef0123456789abcdef"
PROJECT = "demo-auth-action"


class _Echo(BaseHTTPRequestHandler):
    requests: list[dict] = []

    def do_POST(self):  # noqa: N802 - stdlib handler API
        size = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(size))
        self.requests.append(
            {
                "path": self.path,
                "body": payload,
                "authorization": self.headers.get("Authorization"),
            }
        )
        response = {"kind": "fixture", "email": payload.get("email")}
        encoded = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        pass


@pytest.fixture
def fixture_origin():
    _Echo.requests = []
    server = HTTPServer(("127.0.0.1", 0), _Echo)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _capability(transport):
    source, source_digest = credential_remote.worker_binding()
    now = time.time()
    capability = o8_admission.ProductionWireCapability(
        o8_admission._CAPABILITY_TOKEN,
        binding=source,
        binding_digest=source_digest,
        campaign_id=action_remote.CAMPAIGN_ID,
        window_seconds=30,
        inputs_digest="a" * 64,
        ledger_root=str(Path("/tmp/action-test-ledger").resolve()),
        window_starts_at=now - 1,
        window_expires_at=now + 60,
        approval_digest="b" * 64,
        transport_bound=transport,
    )
    capability._consume(
        campaign_id=action_remote.CAMPAIGN_ID,
        inputs_digest="a" * 64,
        ledger_root=str(Path("/tmp/action-test-ledger").resolve()),
    )
    return capability, source, source_digest


def test_admin_action_slot_reaches_loopback_fixture_with_exact_shape(fixture_origin):
    origin, _server = fixture_origin
    transport = action_remote.make_transport(fixture_origin=origin)
    capability, source, source_digest = _capability(transport)
    body = {
        "requestType": "PASSWORD_RESET",
        "email": f"o1-oob-{NONCE}-absent@example.invalid",
        "returnOobLink": True,
    }

    status, response = action_remote.send(
        capability,
        stage_id="link-generate-unknown-email",
        project=PROJECT,
        nonce=NONCE,
        body=body,
        token="owner-token",
        api_key="web-key",
        deadline=time.monotonic() + 10,
        binding=source,
        binding_digest=source_digest,
    )

    assert status == 200
    assert response["kind"] == "fixture"
    request = _Echo.requests == [
        {
            "path": f"/identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:sendOobCode",
            "body": body,
            "authorization": "Bearer owner-token",
        }
    ]
    assert request


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("stage_id", "not-a-stage", "unknown Action stage"),
        ("project", "other/project", "project differs"),
        ("nonce", "not-32-hex", "nonce"),
    ],
)
def test_malformed_action_slot_is_rejected_before_wire(field, value, message):
    transport = action_remote.make_transport()
    capability, source, source_digest = _capability(transport)
    kwargs = {
        "stage_id": "link-generate-unknown-email",
        "project": PROJECT,
        "nonce": NONCE,
        "body": {
            "requestType": "PASSWORD_RESET",
            "email": f"o1-oob-{NONCE}-absent@example.invalid",
            "returnOobLink": True,
        },
        "token": "owner-token",
        "api_key": "web-key",
        "deadline": time.monotonic() + 10,
        "binding": source,
        "binding_digest": source_digest,
    }
    kwargs[field] = value
    with pytest.raises(ValueError, match=message):
        action_remote.send(capability, **kwargs)


def test_extra_operation_is_rejected_before_wire(fixture_origin):
    origin, _server = fixture_origin
    transport = action_remote.make_transport(fixture_origin=origin)
    capability, source, source_digest = _capability(transport)
    body = {
        "requestType": "PASSWORD_RESET",
        "email": f"o1-oob-{NONCE}-absent@example.invalid",
        "returnOobLink": True,
        "unexpected": True,
    }
    with pytest.raises(ValueError, match="body shape"):
        action_remote.send(
            capability,
            stage_id="link-generate-unknown-email",
            project=PROJECT,
            nonce=NONCE,
            body=body,
            token="owner-token",
            api_key="web-key",
            deadline=time.monotonic() + 10,
            binding=source,
            binding_digest=source_digest,
        )


def test_mutated_source_binding_is_rejected_before_wire(fixture_origin):
    origin, _server = fixture_origin
    transport = action_remote.make_transport(fixture_origin=origin)
    capability, source, source_digest = _capability(transport)
    body = {
        "requestType": "PASSWORD_RESET",
        "email": f"o1-oob-{NONCE}-absent@example.invalid",
        "returnOobLink": True,
    }
    with pytest.raises(ValueError, match="capability binding differs"):
        action_remote.send(
            capability,
            stage_id="link-generate-unknown-email",
            project=PROJECT,
            nonce=NONCE,
            body=body,
            token="owner-token",
            api_key="web-key",
            deadline=time.monotonic() + 10,
            binding=source,
            binding_digest=hashlib.sha256(source + b"mutated").hexdigest(),
        )


def test_production_transport_does_not_accept_a_loopback_origin_without_fixture():
    transport = action_remote.make_transport()
    with pytest.raises(ValueError, match="loopback fixture is test-only"):
        transport({"fixtureOrigin": "http://127.0.0.1:1234"}, binding=b"x", binding_digest="x", capability=object())
