"""Real local O7/O8, Ledger, Gate and bounded-worker Action execution."""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import action_codes_admission as admission
import action_codes_descriptor as descriptor
import action_codes_plan as plan_module
import action_codes_production as production
import reservations
from action_codes_remote_transport import _tokeninfo_valid

from broad_contract import digest
from test_action_codes_admission import FIXTURE_PRINCIPAL, _artifacts


NONCE = "b" * 32


def test_recovery_deadline_uses_remaining_owner_window():
    assert production._operation_deadline(
        299.0, 0.0, is_recovery=False, wall_seconds=300, recovery_seconds=180
    ) == 300.0
    assert production._operation_deadline(
        301.0, 0.0, is_recovery=True, wall_seconds=300, recovery_seconds=180
    ) == 309.0
    assert production._operation_deadline(
        479.0, 0.0, is_recovery=True, wall_seconds=300, recovery_seconds=180
    ) == 480.0


@pytest.mark.parametrize("email_verified", [True, "1", "false", None, 1])
def test_tokeninfo_requires_modern_string_email_verified(email_verified):
    body = {
        "email": FIXTURE_PRINCIPAL["verifiedEmail"],
        "email_verified": email_verified,
        "scope": "https://www.googleapis.com/auth/identitytoolkit",
        "expires_in": "600",
        "azp": FIXTURE_PRINCIPAL["clientId"],
        "aud": FIXTURE_PRINCIPAL["clientId"],
    }
    valid, _expires = _tokeninfo_valid(
        200,
        body,
        principal={
            "clientId": FIXTURE_PRINCIPAL["clientId"],
            "verifiedEmail": FIXTURE_PRINCIPAL["verifiedEmail"],
        },
        scope="https://www.googleapis.com/auth/identitytoolkit",
        required_seconds=480,
    )
    assert valid is False


@pytest.mark.parametrize(
    "mutation",
    [
        {"azp": "foreign-client"},
        {"aud": "foreign-client"},
        {"email": "foreign@example.test"},
        {"scope": "other-scope"},
    ],
)
def test_tokeninfo_rejects_foreign_principal_or_scope(mutation):
    body = {
        "email": FIXTURE_PRINCIPAL["verifiedEmail"],
        "email_verified": "true",
        "scope": descriptor.IDENTITY_SCOPE,
        "expires_in": "600",
        "azp": FIXTURE_PRINCIPAL["clientId"],
        "aud": FIXTURE_PRINCIPAL["clientId"],
    }
    body.update(mutation)
    valid, _expires = _tokeninfo_valid(
        200,
        body,
        principal={
            "clientId": FIXTURE_PRINCIPAL["clientId"],
            "verifiedEmail": FIXTURE_PRINCIPAL["verifiedEmail"],
        },
        scope=descriptor.IDENTITY_SCOPE,
        required_seconds=480,
    )
    assert valid is False


class _ActionFixture(BaseHTTPRequestHandler):
    calls: list[dict] = []
    recovery_status: int = 200
    recovery_body: dict = {"users": []}
    fail_first_response = False

    def do_POST(self):  # noqa: N802 - stdlib handler API
        self._serve_action_request()

    def do_GET(self):  # noqa: N802 - stdlib handler API
        self._serve_action_request()

    def _serve_action_request(self):
        size = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(size)
        body = json.loads(raw) if raw else {}
        self.__class__.calls.append({"path": self.path, "body": body})
        if self.__class__.fail_first_response and len(self.__class__.calls) == 3:
            encoded = b"not-json"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return
        route = self.path.split("?", 1)[0]
        if route.endswith("/tokeninfo"):
            response = {"email": FIXTURE_PRINCIPAL["verifiedEmail"], "email_verified": "true", "scope": "https://www.googleapis.com/auth/identitytoolkit", "expires_in": "600", "azp": FIXTURE_PRINCIPAL["clientId"], "aud": FIXTURE_PRINCIPAL["clientId"]}
        elif route.endswith("/admin/v2/projects/fireemu-35fe6/config"):
            response = {"projectId": "fireemu-35fe6"}
        elif route.endswith("accounts:signUp"):
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
        "principal": FIXTURE_PRINCIPAL["verifiedEmail"],
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
    receipt = json.loads(
        (tmp_path / "output" / "production-receipt.json").read_text()
    )
    assert receipt["kind"] == "auth-action-production-receipt-v1"
    assert receipt["requests"] == 34
    assert receipt["cleanup"]["complete"] is True
    assert "token" not in json.dumps(receipt)
    assert len(_ActionFixture.calls) == 34
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
    management_paths = [call["path"].split("?", 1)[0].lstrip("/") for call in _ActionFixture.calls[:2]]
    assert management_paths == ["tokeninfo", "admin/v2/projects/fireemu-35fe6/config"]
    actual_paths = [call["path"].split("?", 1)[0].lstrip("/") for call in _ActionFixture.calls[2:]]
    assert actual_paths == expected_paths
    assert _ActionFixture.calls[2]["body"] == {
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
    # The Gate records the uncertain observation before the worker response;
    # recovery skips unowned deletes without opening additional wire calls.
    assert len(_ActionFixture.calls) == 7
    expected_recovery_paths = [
        row["path"].format(project=descriptor.AUTHORIZED_PROJECT).lstrip("/")
        for row in plan_module.campaign_manifest(NONCE, project=descriptor.AUTHORIZED_PROJECT)["recovery"]
    ]
    assert _ActionFixture.calls[2]["path"].split("?", 1)[0].lstrip("/") == "identitytoolkit.googleapis.com/v1/accounts:signUp"
    actual_recovery_paths = [
        call["path"].split("?", 1)[0].lstrip("/")
        for call in _ActionFixture.calls[3:]
    ]
    assert actual_recovery_paths
    assert all(path in expected_recovery_paths for path in actual_recovery_paths)
    assert not any(path.endswith("accounts:delete") for path in actual_recovery_paths)


# F4: all post-observation terminal failures use the same bounded receipt path.
class _F4TerminalHarness:
    def __init__(self, tmp_path, failure):
        self.failure = failure
        self.released = False
        self.gate_finished = False
        self.remote_forgotten = False
        self.transport_open = False
        self.output = tmp_path / "output"
        self.ledger_root = tmp_path / "ledger"
        self.ledger_root.mkdir(parents=True)
        (self.ledger_root / "state.json").write_text("{}")

        harness = self

        class Capability:
            def _consume(self, **_kwargs):
                return None

        class Ledger:
            def __init__(self, _path):
                pass

            def reserve(self, *_args, **_kwargs):
                return {"reservation": "f4-reservation"}

            def finish(self, _ticket):
                if harness.failure == "ledger-finish":
                    raise ValueError("ledger-finish-refused")
                harness.released = True

            def snapshot(self):
                return {
                    "reservations": {
                        "f4-reservation": {
                            "state": "released" if harness.released else "held"
                        }
                    }
                }

        class Gate:
            def __init__(self, _path, _job):
                if harness.failure == "gate-construct":
                    raise ValueError("gate-constructor-refused")
                self.observation = 0
                self.recovery = 0

            def claim(self):
                if harness.failure == "gate-claim":
                    raise ValueError("gate-claim-refused")
                return None

            def management_dispatch(self, _phase, _slot, send):
                if harness.failure == "management-preflight":
                    raise ValueError("management-preflight-refused")
                return send(999.0)

            def dispatch(self, operation, recovery, send):
                if recovery and harness.failure == "recovery-timeout":
                    raise TimeoutError("recovery-response-lost")
                if recovery:
                    self.recovery += 1
                else:
                    self.observation += 1
                return send()

            def abandon_observation(self, _reason):
                return None

            def finish(self):
                if harness.failure == "gate-finish":
                    raise ValueError("gate-finish-refused")
                harness.gate_finished = True

            def snapshot(self):
                return {
                    "total": self.observation + self.recovery + 2,
                    "observation": self.observation + 2,
                    "recovery": self.recovery,
                    "jobs": {
                        "auth-action": {
                            "complete": harness.gate_finished,
                            "owned": [],
                            "absent": [],
                        }
                    },
                }

        class Remote:
            GENERATED_BINDINGS = frozenset()

            @staticmethod
            def make_transport(**_kwargs):
                harness.transport_open = True
                if harness.failure == "transport-setup":
                    raise ValueError("transport-setup-refused")
                return None

            @staticmethod
            def management_receipt(**_kwargs):
                return {"complete": True}

            @staticmethod
            def send(_capability, **kwargs):
                if (
                    kwargs["stage_id"] == "observe-one"
                    and harness.failure in {"observation", "observation-transport-forget"}
                ):
                    raise TimeoutError("observation-response-lost")
                if kwargs["stage_id"] == "recover-one":
                    return 200, {"users": []}
                return 200, {"localId": "f4-uid"}

            @staticmethod
            def forget_transport(_inputs_digest):
                if harness.failure in {"transport-forget", "observation-transport-forget"}:
                    raise ValueError("transport-forget-refused")
                harness.transport_open = False
                harness.remote_forgotten = True

        def create_gate(*_args):
            if harness.failure == "gate-create":
                raise ValueError("gate-create-refused")

        self.Capability = Capability
        self.Ledger = Ledger
        self.Gate = Gate
        self.Remote = Remote
        self.create_gate = create_gate


def test_f4_terminal_receipt_retains_primary_failure_and_held_reservation(
    tmp_path, monkeypatch
):
    """Every terminal failure retains one held record and its primary error."""
    expected = {
        "observation": ("observation", "TimeoutError"),
        "recovery-timeout": ("recovery", "TimeoutError"),
        "gate-finish": ("gate-finish", "ValueError"),
        "ledger-finish": ("ledger-finish", "ValueError"),
        "transport-setup": ("preflight", "ValueError"),
        "management-preflight": ("preflight", "ValueError"),
        "binding-setup": ("preflight", "FileNotFoundError"),
        "gate-create": ("gate-setup", "ValueError"),
        "gate-construct": ("gate-setup", "ValueError"),
        "gate-claim": ("gate-setup", "ValueError"),
        "transport-forget": ("complete", None),
        "observation-transport-forget": ("observation", "TimeoutError"),
    }
    for failure, (expected_phase, expected_error) in expected.items():
        case = _F4TerminalHarness(tmp_path / failure, failure)
        worker = case.output.parent / "worker.fixture"
        if failure != "binding-setup":
            worker.write_bytes(b"fixture worker")
        monkeypatch.setattr(production, "ROOT", case.output.parent)
        monkeypatch.setattr(
            production,
            "descriptor",
            SimpleNamespace(
                CAMPAIGN="AUTH-ACTION-OOB-DELIVERY-BOUNDARY-01",
                WORKER_ENTRY="worker.fixture",
                lock_scopes=lambda _plan: [],
            ),
        )
        monkeypatch.setattr(
            production,
            "admission",
            SimpleNamespace(validate_frozen_inputs=lambda _inputs: None),
        )
        monkeypatch.setattr(
            production,
            "o8_admission",
            SimpleNamespace(issued_capability=lambda _capability: True),
        )
        operation = {
            "id": "observe-one",
            "service": "auth",
            "body": {},
        }
        recovery = {
            "id": "recover-one",
            "service": "auth",
            "body": {},
        }
        plan = {
            "nonce": "a" * 32,
            "stages": [operation],
            "recovery": [recovery],
        }
        gate_plan = {
            "jobs": {
                "auth-action": {
                    "resources": [],
                    "observation": [operation],
                    "recovery": [recovery],
                }
            },
            "costMicrousd": 4,
            "wallSeconds": 300,
            "recoverySeconds": 180,
        }
        monkeypatch.setattr(
            production,
            "gate_module",
            SimpleNamespace(
                JOB="auth-action",
                gate_plan=lambda _project, _nonce, frozen_plan=gate_plan: frozen_plan,
                create=case.create_gate,
                ActionGate=case.Gate,
            ),
        )
        monkeypatch.setattr(
            production,
            "reservations",
            SimpleNamespace(Ledger=case.Ledger),
        )
        monkeypatch.setattr(production, "remote", case.Remote)
        monkeypatch.setattr(
            production,
            "_claim",
            lambda *_args, **_kwargs: {"campaignId": "fixture", "inputsDigest": "fixture"},
        )
        monkeypatch.setattr(
            production,
            "_envelope",
            lambda *_args, **_kwargs: {},
        )
        permission = {"projectId": "fireemu-35fe6"}
        inputs = {
            "plan": plan,
            "planDigest": digest(plan),
            "permissionDigest": digest(permission),
            "inputsDigest": "fixture",
        }
        execute_kwargs = {
            "capability": case.Capability(),
            "inputs": inputs,
            "permission": permission,
            "ledger_root": case.ledger_root,
            "output": case.output,
            "bindings": {},
            "credential_handoff": {},
            "verify_handoff": lambda *_args: None,
            "fixture_origin": "http://127.0.0.1:1",
        }
        if failure == "transport-forget":
            result = production.execute(**execute_kwargs)
            assert result["reservation"] == "released"
        else:
            with pytest.raises((TimeoutError, ValueError, FileNotFoundError)):
                production.execute(**execute_kwargs)
        receipt = json.loads((case.output / "production-receipt.json").read_text())
        if failure == "transport-forget":
            assert receipt["error"] is None
            assert receipt["reservationState"] == "released"
            assert receipt["reservationReleased"] is True
            assert receipt["terminal"]["releaseEvidence"] is True
        else:
            assert receipt["reservationState"] == "held"
            assert receipt["reservationReleased"] is False
            assert receipt["terminal"]["releaseEvidence"] is False
        assert receipt["terminal"]["phase"] == expected_phase
        assert receipt["terminal"]["primaryError"] == expected_error
        assert any(
            entry["phase"] == "transport-forget"
            for entry in receipt["terminal"]["cleanupErrors"]
        ) is ("transport-forget" in failure)
        assert case.remote_forgotten is (
            expected_phase != "gate-setup" and "transport-forget" not in failure
        )
        assert case.transport_open is ("transport-forget" in failure)
