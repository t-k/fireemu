"""The bound HTTPS transport, exercised against a loopback fixture only."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import credential_remote_transport as remote
from credential_gate import IDENTITY, SECURE
import credential_https_worker as worker


class _Echo(BaseHTTPRequestHandler):
    status = 200

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        body = {
            "path": self.path,
            "contentType": self.headers.get("Content-Type"),
            "authorization": self.headers.get("Authorization"),
            "quotaProject": self.headers.get("x-goog-user-project"),
            "body": raw.decode("utf-8"),
        }
        if self.path.endswith(":signBlob"):
            body = {"keyId": "fixture-key", "signedBlob": base64.b64encode(b"fixture-signature").decode()}
        encoded = json.dumps(body).encode()
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):  # noqa: N802 - stdlib handler API
        encoded = json.dumps({"path": self.path, "email": "owner@example.test", "scope": "scope"}).encode()
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        pass


@pytest.fixture
def fixture_origin():
    server = HTTPServer(("127.0.0.1", 0), _Echo)
    server.status = 200
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_the_pinned_worker_digest_is_the_worker_on_disk() -> None:
    source, observed = remote.worker_binding()
    assert observed == remote.WORKER_SHA256 == hashlib.sha256(source).hexdigest()
    remote.verify_worker_binding(source, observed, None)
    with pytest.raises(ValueError, match="differs from the reviewed transport"):
        remote.verify_worker_binding(source + b"\n", hashlib.sha256(source + b"\n").hexdigest(), None)
    with pytest.raises(ValueError, match="differs from the frozen inputs"):
        remote.verify_worker_binding(source, observed, {"other": observed})


def test_a_client_call_carries_the_key_and_no_bearer(fixture_origin) -> None:
    origin, _server = fixture_origin
    status, body = remote.request(
        origin + "/" + IDENTITY + "/accounts:signUp?key=k%20ey",
        {"email": "a@b.invalid", "password": "p"},
        headers={},
        seconds=5,
        fixture_origin=origin,
    )
    assert status == 200
    assert body["path"].endswith("accounts:signUp?key=k%20ey")
    assert body["authorization"] is None and body["quotaProject"] is None
    assert body["contentType"] == "application/json"
    assert json.loads(body["body"]) == {"email": "a@b.invalid", "password": "p"}


def test_a_secure_token_exchange_is_form_encoded(fixture_origin) -> None:
    origin, _server = fixture_origin
    status, body = remote.request(
        origin + "/" + SECURE + "?key=k",
        {"grant_type": "refresh_token", "refresh_token": "rt"},
        headers={},
        seconds=5,
        form=True,
        fixture_origin=origin,
    )
    assert status == 200
    assert body["contentType"] == "application/x-www-form-urlencoded"
    assert body["body"] == "grant_type=refresh_token&refresh_token=rt"


def test_an_owner_call_carries_the_bearer_and_the_quota_project(fixture_origin) -> None:
    origin, _server = fixture_origin
    status, body = remote.request(
        origin + "/" + IDENTITY + "/projects/fireemu-35fe6/accounts:lookup",
        {"localId": ["u"]},
        headers={"Authorization": "Bearer secret-token", "x-goog-user-project": "fireemu-35fe6"},
        seconds=5,
        fixture_origin=origin,
    )
    assert status == 200
    assert body["authorization"] == "Bearer secret-token"
    assert body["quotaProject"] == "fireemu-35fe6"


def test_a_refusal_status_is_returned_as_data(fixture_origin) -> None:
    origin, server = fixture_origin
    server.status = 400
    status, body = remote.request(origin + "/" + IDENTITY + "/accounts:lookup?key=k", {"idToken": "x"}, headers={}, seconds=5, fixture_origin=origin)
    assert status == 400 and body["path"].endswith("accounts:lookup?key=k")


def test_the_worker_refuses_any_host_outside_the_allowlist_in_production_mode() -> None:
    for url in (
        "https://example.com/v1/accounts:lookup",
        "http://identitytoolkit.googleapis.com/v1/accounts:lookup",
        "https://identitytoolkit.googleapis.com:8443/v1/accounts:lookup",
        "http://127.0.0.1:9/v1/accounts:lookup",
        "https://user:pw@identitytoolkit.googleapis.com/v1/accounts:lookup",
    ):
        envelope = json.dumps({"url": url, "body": "{}", "headers": {}, "seconds": 2.0}).encode()
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(HERE / remote.WORKER_ENTRY)],
            input=envelope, capture_output=True, timeout=10, check=False,
        )
        assert result.returncode == 2, url
        assert result.stdout == b"" and result.stderr == b""


def test_tokeninfo_uses_only_the_documented_oauth_route() -> None:
    exact = worker.validate_target(
        "https://oauth2.googleapis.com/tokeninfo?access_token=opaque", fixture=False
    )
    assert exact.hostname == "oauth2.googleapis.com" and exact.path == "/tokeninfo"
    for url in (
        "https://oauth2.googleapis.com/oauth2/v1/tokeninfo?access_token=opaque",
        "https://oauth2.googleapis.com/tokeninfo?access_token=opaque&extra=x",
        "https://oauth2.googleapis.com/tokeninfo",
    ):
        with pytest.raises(ValueError, match="token-info route"):
            worker.validate_target(url, fixture=False)


def test_bootstrap_routes_are_closed_to_the_four_documented_operations() -> None:
    accepted = (
        "https://oauth2.googleapis.com/token",
        "https://oauth2.googleapis.com/tokeninfo?access_token=opaque",
        "https://cloudresourcemanager.googleapis.com/v1/projects/fireemu-35fe6",
        "https://identitytoolkit.googleapis.com/admin/v2/projects/fireemu-35fe6/config",
    )
    for url in accepted:
        worker.validate_target(url, fixture=False)
    for url in (
        "https://oauth2.googleapis.com/oauth2/v1/tokeninfo?access_token=opaque",
        "https://oauth2.googleapis.com/token?extra=x",
        "https://cloudresourcemanager.googleapis.com/v1/projects/other",
        "https://identitytoolkit.googleapis.com/v1/projects/fireemu-35fe6/config",
        "https://identitytoolkit.googleapis.com/admin/v2/projects/other/config",
    ):
        with pytest.raises(ValueError):
            worker.validate_target(url, fixture=False)


def test_lifecycle_result_proves_worker_reaped(fixture_origin) -> None:
    origin, _server = fixture_origin
    result = remote.request_with_lifecycle(
        origin + "/" + IDENTITY + "/accounts:lookup",
        {"localId": ["u"]},
        headers={},
        seconds=5,
        fixture_origin=origin,
    )
    assert result.status == 200
    assert result.worker_reaped is True


def test_the_worker_refuses_a_non_loopback_target_even_as_a_fixture_worker() -> None:
    envelope = json.dumps({"url": "http://example.com/x", "body": "{}", "headers": {}, "seconds": 2.0}).encode()
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", str(HERE / remote.WORKER_ENTRY), "--fixture-worker"],
        input=envelope, capture_output=True, timeout=10, check=False,
    )
    assert result.returncode == 2 and result.stdout == b""


def test_a_deadline_already_passed_never_spawns_a_worker(monkeypatch) -> None:
    spawned = []
    monkeypatch.setattr(remote.subprocess, "run", lambda *a, **k: spawned.append(a))
    with pytest.raises(ValueError, match="deadline already passed"):
        remote._seconds(time.monotonic() - 1)
    assert spawned == []


def test_transmit_refuses_without_an_admitted_capability() -> None:
    declared = {"path": IDENTITY + "/accounts:lookup", "owner": False, "form": False}
    with pytest.raises(ValueError, match="unadmitted O7 production capability"):
        remote.transmit(declared, {"idToken": "x"}, token="t", api_key="k", deadline=time.monotonic() + 5, capability=object(), binding=b"x", binding_digest="y")


def test_sign_custom_token_builds_a_compact_rs256_token_from_signblob(fixture_origin, monkeypatch) -> None:
    origin, _server = fixture_origin
    monkeypatch.setattr(remote, "authorize_transport", lambda *a, **k: None)
    source, observed = remote.worker_binding()
    account = "fireemu-oracle@fireemu-35fe6.iam.gserviceaccount.com"
    payload = {"aud": "a", "iss": account, "sub": account, "uid": "u", "claims": {}, "iat": 1, "exp": 3601}
    token, public = remote.sign_custom_token(
        payload, service_account=account, token="bearer", deadline=time.monotonic() + 5,
        capability=None, binding=source, binding_digest=observed, fixture_origin=origin,
    )
    header, body, signature = token.split(".")
    assert json.loads(base64.urlsafe_b64decode(header + "==")) == {"alg": "RS256", "typ": "JWT"}
    assert json.loads(base64.urlsafe_b64decode(body + "==")) == payload
    assert base64.urlsafe_b64decode(signature + "==") == b"fixture-signature"
    assert public["kind"] == "custom-token-signature-v1"
    assert public["signatureBytes"] == len(b"fixture-signature") and public["keyIdPresent"] is True
    assert "signedBlob" not in json.dumps(public) and token not in json.dumps(public)
    with pytest.raises(ValueError, match="must name the signing account"):
        remote.sign_custom_token(
            {**payload, "iss": "other@example.invalid"}, service_account=account, token="bearer",
            deadline=time.monotonic() + 5, capability=None, binding=source, binding_digest=observed, fixture_origin=origin,
        )
