"""Fixture-only tests for the bounded Auth bootstrap contract."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import credential_bootstrap as bootstrap
import credential_gate as gate_module

ADC = {
    "type": "authorized_user",
    "client_id": "client-1",
    "client_secret": "fixture-secret",
    "refresh_token": "fixture-refresh",
}


class _Fixture(BaseHTTPRequestHandler):
    requests = []

    def do_POST(self):
        self.__class__.requests.append(self.path)
        if self.path == "/oauth2.googleapis.com/token":
            body = {"access_token": "fixture-access", "expires_in": 3600, "token_type": "Bearer"}
        elif self.path.startswith("/oauth2.googleapis.com/tokeninfo"):
            body = {
                "azp": "client-1",
                "aud": "client-1",
                "sub": "subject-1",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "expires_in": 3600,
            }
        else:
            body = self._metadata()
        self._reply(body)

    def do_GET(self):
        self.__class__.requests.append(self.path)
        if self.path.startswith("/oauth2.googleapis.com/tokeninfo"):
            self._reply({
                "azp": "client-1",
                "aud": "client-1",
                "sub": "subject-1",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "expires_in": 3600,
            })
        else:
            self._reply(self._metadata())

    def _metadata(self):
        if self.path.endswith("/config"):
            return {"name": "projects/592603257417/config", "mfa": {"state": "DISABLED"}}
        return {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}

    def _reply(self, value):
        raw = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args):
        pass


@pytest.fixture
def fixture_origin():
    _Fixture.requests = []
    server = HTTPServer(("127.0.0.1", 0), _Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", _Fixture.requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _permission():
    return {
        "kind": bootstrap.PERMISSION_KIND,
        "permissionDigest": "permission-digest",
        "authorizedUserDigest": bootstrap.digest(ADC),
        "credentialPrincipal": {"clientId": "client-1", "subject": "subject-1", "requiredScopes": [bootstrap.SCOPE]},
        "project": bootstrap.PROJECT,
        "projectNumber": bootstrap.PROJECT_NUMBER,
        "nonce": "a" * 32,
    }


def test_fixture_bootstrap_charges_exact_four_requests_and_returns_private_handoff(fixture_origin):
    origin, requests = fixture_origin
    result = bootstrap.prepare(_permission(), adc=ADC, api_key="api-key", fixture_origin=origin)
    assert requests == ["/oauth2.googleapis.com/token", "/oauth2.googleapis.com/tokeninfo?access_token=fixture-access", "/cloudresourcemanager.googleapis.com/v1/projects/fireemu-35fe6", "/identitytoolkit.googleapis.com/admin/v2/projects/fireemu-35fe6/config"]
    assert result.prepared == {
        "token": "fixture-access",
        "apiKey": "api-key",
        "signing": {"serviceAccount": bootstrap.SERVICE_ACCOUNT},
    }
    observation_digest = "a" * 64
    assert bootstrap.finalize_handoff(result.prepared, observation_digest, result.proof) == {
        "kind": bootstrap.HANDOFF_KIND,
        "permissionDigest": observation_digest,
        "token": "fixture-access",
        "apiKey": "api-key",
        "signing": {"serviceAccount": bootstrap.SERVICE_ACCOUNT},
    }
    assert result.proof["project"] == {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}
    assert result.proof["authConfigDigest"] == bootstrap.digest({"name": "projects/592603257417/config", "mfa": {"state": "DISABLED"}})
    assert result.charged_requests == 4


def test_prepare_uses_real_gate_and_pinned_loopback_worker_without_retry(fixture_origin, tmp_path):
    origin, requests = fixture_origin
    permission = _permission()
    plan = gate_module.bootstrap_plan(
        gate_module.gate_plan(
            bootstrap.PROJECT,
            permission["nonce"],
            signing=False,
            wall_seconds=600,
            recovery_seconds=90,
            cost_microusd=200,
            observation_window_seconds=510,
        ),
        permission_digest=bootstrap.digest(permission),
    )
    plan["permissionExpiresAt"] = __import__("time").time() + 3600
    gate_path = tmp_path / "gate"
    gate_module.create(gate_path, plan)
    gate = gate_module.CredentialGate(gate_path)
    gate.claim()
    result = bootstrap.prepare(
        permission, adc=ADC, api_key="api-key", fixture_origin=origin, gate=gate
    )
    assert result.charged_requests == len(gate.snapshot()["managementEvents"]) == 4
    assert [path.split("?", 1)[0] for path in requests] == [
        "/oauth2.googleapis.com/token",
        "/oauth2.googleapis.com/tokeninfo",
        "/cloudresourcemanager.googleapis.com/v1/projects/fireemu-35fe6",
        "/identitytoolkit.googleapis.com/admin/v2/projects/fireemu-35fe6/config",
    ]
    journal = (gate_path / "state.json").read_text()
    assert "fixture-access" not in journal and "fixture-secret" not in journal
    with pytest.raises(ValueError, match="closed management sequence"):
        bootstrap.prepare(
            permission, adc=ADC, api_key="api-key", fixture_origin=origin, gate=gate
        )
    assert len(requests) == 4


def test_bootstrap_rejects_foreign_principal_before_network(fixture_origin):
    origin, requests = fixture_origin
    permission = _permission()
    permission["credentialPrincipal"]["clientId"] = "foreign-client"
    with pytest.raises(ValueError, match="principal"):
        bootstrap.prepare(permission, adc=ADC, api_key="api-key", fixture_origin=origin)
    assert requests == []


def test_production_bootstrap_requires_gate_before_any_wire_call():
    with pytest.raises(ValueError, match="Gate"):
        bootstrap.prepare(_permission(), adc=ADC, api_key="api-key")


def test_bootstrap_rejects_budget_or_deadline_mutation():
    with pytest.raises(ValueError, match="budget"):
        bootstrap.BootstrapBudget(max_requests=5, max_seconds=600, cost_microusd=50_000).validate()
    with pytest.raises(ValueError, match="budget"):
        bootstrap.BootstrapBudget(max_requests=60, max_seconds=601, cost_microusd=50_000).validate()
    with pytest.raises(ValueError, match="budget"):
        bootstrap.BootstrapBudget(max_requests=60, max_seconds=600, cost_microusd=50_001).validate()
    with pytest.raises(ValueError, match="deadline"):
        bootstrap.validate_deadline(bootstrap.PREP_REQUEST_SECONDS - 1)
