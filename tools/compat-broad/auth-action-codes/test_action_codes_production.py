"""Real local O7/O8, Ledger, Gate and bounded-worker Action execution."""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import action_codes_admission as admission
import action_codes_descriptor as descriptor
import action_codes_production as production
import action_codes_plan as plan_module
import reservations

from broad_contract import digest
from test_action_codes_admission import _artifacts


NONCE = "b" * 32


class _ActionFixture(BaseHTTPRequestHandler):
    calls: list[dict] = []
    recovery_status: int = 200
    recovery_body: dict = {"users": []}
    fail_first_response = False

    def do_POST(self):  # noqa: N802 - stdlib handler API
        size = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(size))
        self.__class__.calls.append({"path": self.path, "body": body})
        if self.__class__.fail_first_response and len(self.__class__.calls) == 1:
            encoded = b"not-json"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return
        route = self.path.split("?", 1)[0]
        if route.endswith("accounts:signUp"):
            suffix = "a" if body["email"].endswith("-a@example.invalid") else "b"
            response = {"localId": "uid-" + suffix, "idToken": "token-" + suffix, "refreshToken": "refresh-" + suffix}
        elif route.endswith("accounts:lookup"):
            response = self.recovery_body
        elif route.endswith("accounts:sendOobCode"):
            response = {"oobCode": "code-" + str(len(self.calls))}
        else:
            response = {}
        encoded = json.dumps(response).encode()
        self.send_response(self.recovery_status if route.endswith("accounts:lookup") else 200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        pass


def _bindings():
    manifest = plan_module.campaign_manifest(NONCE, project=descriptor.AUTHORIZED_PROJECT)
    result: dict[str, dict[str, str]] = {}

    def names(value):
        if isinstance(value, str) and value.startswith("$binding:"):
            return {value.removeprefix("$binding:")}
        if isinstance(value, dict):
            found = set()
            for item in value.values():
                found.update(names(item))
            return found
        if isinstance(value, list):
            found = set()
            for item in value:
                found.update(names(item))
            return found
        return set()

    for stage in (*manifest["stages"], *manifest["recovery"]):
        values = {}
        for name in names(stage["body"]):
            if name.endswith(".email"):
                suffix = "absent" if name == "unknownEmail" else name.split(".", 1)[0][-1].lower()
                values[name] = f"o1-oob-{NONCE}-{suffix}@example.invalid"
            elif name.endswith(".localId"):
                values[name] = "uid-" + name.split(".", 1)[0][-1].lower()
            elif name == "weakPassword":
                values[name] = "a"
            elif name == "wrongCode":
                values[name] = "wrong-code"
            else:
                values[name] = "secret-" + name.replace(".", "-")
        result[stage["id"]] = values
    return result


def _handoff(permission):
    return {
        "token": "fixture-owner-token",
        "apiKey": "fixture-api-key",
        "permissionDigest": digest(permission),
        "principal": "owner@example.test",
        "scope": descriptor.IDENTITY_SCOPE,
    }


def _verify_handoff(handoff, permission):
    if handoff != _handoff(permission):
        raise ValueError("fixture handoff differs")


@pytest.fixture
def fixture_origin():
    _ActionFixture.calls = []
    _ActionFixture.recovery_status = 200
    _ActionFixture.recovery_body = {"users": []}
    _ActionFixture.fail_first_response = False
    server = HTTPServer(("127.0.0.1", 0), _ActionFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_full_action_bridge_runs_26_plus_6_through_o8_ledger_gate_and_worker(tmp_path, fixture_origin):
    descriptor_, inputs, permission, manifest, manifest_bytes, manifest_path, artifact, launcher, approval = _artifacts(tmp_path)
    ledger_root = tmp_path / "ledger"
    reservations.Ledger.create(ledger_root)
    worker = (ROOT / descriptor.WORKER_ENTRY).read_bytes()
    capability = admission.issue_production_capability(
        inputs=inputs,
        approval=approval,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_path=manifest_path,
        permission=permission,
        ledger_root=ledger_root,
        artifact_path=artifact,
        launcher_path=launcher,
        binding=worker,
        binding_digest=hashlib.sha256(worker).hexdigest(),
    )
    result = production.execute(
        capability=capability,
        inputs=inputs,
        permission=permission,
        ledger_root=ledger_root,
        output=tmp_path / "output",
        bindings=_bindings(),
        credential_handoff=_handoff(permission),
        verify_handoff=_verify_handoff,
        fixture_origin=fixture_origin,
    )
    assert result["requests"] == 34
    assert result["observation"] == 28
    assert result["recovery"] == 6
    assert result["reservation"] == "released"
    assert len(_ActionFixture.calls) == 32
    gate_state = json.loads((tmp_path / "output" / "gate" / "state.json").read_bytes())
    assert gate_state["managementUsed"] == [
        "observation:oauth-tokeninfo",
        "observation:auth-project-readback",
    ]
    assert all(event["completed"] and event["workerReaped"] for event in gate_state["managementEvents"])
    frozen_plan = plan_module.campaign_manifest(NONCE, project=descriptor.AUTHORIZED_PROJECT)
    expected_paths = [
        row["path"].format(project=descriptor.AUTHORIZED_PROJECT).lstrip("/")
        for row in (*frozen_plan["stages"], *frozen_plan["recovery"])
    ]
    actual_paths = [call["path"].split("?", 1)[0].lstrip("/") for call in _ActionFixture.calls]
    assert actual_paths == expected_paths
    assert _ActionFixture.calls[0]["body"] == {
        "email": f"o1-oob-{NONCE}-a@example.invalid",
        "password": "secret-accountA-password",
        "returnSecureToken": True,
    }
    serialized = json.dumps(result) + json.dumps(reservations.Ledger(ledger_root).snapshot())
    for secret in ("fixture-owner-token", "fixture-api-key", "token-a", "refresh-a"):
        assert secret not in serialized


@pytest.mark.parametrize(
    ("status", "body"),
    [(400, {"error": {"message": "bad"}}), (200, {"unexpected": True})],
)
def test_recovery_error_is_not_typed_absence(tmp_path, fixture_origin, status, body):
    _ActionFixture.recovery_status = status
    _ActionFixture.recovery_body = body
    descriptor_, inputs, permission, manifest, manifest_bytes, manifest_path, artifact, launcher, approval = _artifacts(tmp_path)
    ledger_root = tmp_path / "ledger"
    reservations.Ledger.create(ledger_root)
    worker = (ROOT / descriptor.WORKER_ENTRY).read_bytes()
    capability = admission.issue_production_capability(
        inputs=inputs, approval=approval, manifest=manifest,
        manifest_bytes=manifest_bytes, manifest_path=manifest_path,
        permission=permission, ledger_root=ledger_root,
        artifact_path=artifact, launcher_path=launcher,
        binding=worker, binding_digest=hashlib.sha256(worker).hexdigest(),
    )
    with pytest.raises(ValueError, match="typed Auth absence|cleanup incomplete"):
        production.execute(
            capability=capability, inputs=inputs, permission=permission,
            ledger_root=ledger_root, output=tmp_path / "output",
            bindings=_bindings(), credential_handoff=_handoff(permission),
            verify_handoff=_verify_handoff, fixture_origin=fixture_origin,
        )
    state = reservations.Ledger(ledger_root).snapshot()
    rows = list(state["reservations"].values())
    assert len(rows) == 1 and rows[0]["state"] == "held"


def test_observation_failure_attempts_all_known_cleanup_and_holds_unknown_signup(
    tmp_path, fixture_origin
):
    _ActionFixture.fail_first_response = True
    descriptor_, inputs, permission, manifest, manifest_bytes, manifest_path, artifact, launcher, approval = _artifacts(tmp_path)
    ledger_root = tmp_path / "ledger"
    reservations.Ledger.create(ledger_root)
    worker = (ROOT / descriptor.WORKER_ENTRY).read_bytes()
    capability = admission.issue_production_capability(
        inputs=inputs, approval=approval, manifest=manifest,
        manifest_bytes=manifest_bytes, manifest_path=manifest_path,
        permission=permission, ledger_root=ledger_root,
        artifact_path=artifact, launcher_path=launcher,
        binding=worker, binding_digest=hashlib.sha256(worker).hexdigest(),
    )
    with pytest.raises(ValueError):
        production.execute(
            capability=capability, inputs=inputs, permission=permission,
            ledger_root=ledger_root, output=tmp_path / "output",
            bindings=_bindings(), credential_handoff=_handoff(permission),
            verify_handoff=_verify_handoff, fixture_origin=fixture_origin,
        )
    state = reservations.Ledger(ledger_root).snapshot()
    rows = list(state["reservations"].values())
    assert len(rows) == 1 and rows[0]["state"] == "held"
    assert len(_ActionFixture.calls) == 7
    expected_recovery_paths = [
        row["path"].format(project=descriptor.AUTHORIZED_PROJECT).lstrip("/")
        for row in plan_module.campaign_manifest(NONCE, project=descriptor.AUTHORIZED_PROJECT)["recovery"]
    ]
    assert [call["path"].split("?", 1)[0].lstrip("/") for call in _ActionFixture.calls[1:]] == expected_recovery_paths
