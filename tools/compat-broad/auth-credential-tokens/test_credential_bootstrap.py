"""Fixture-only tests for the bounded Auth bootstrap contract."""

from __future__ import annotations

import base64
import copy
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "production-admission"))

import credential_bootstrap as bootstrap
import credential_gate as gate_module

ADC = {
    "type": "authorized_user",
    "client_id": "client-1",
    "client_secret": "fixture-secret",
    "refresh_token": "fixture-refresh",
}


class _Fixture(BaseHTTPRequestHandler):
    requests: ClassVar[list] = []
    before_request = None
    tokeninfo_overrides: ClassVar[dict] = {}
    refresh_status = 200
    service = None
    delay_seconds = 0
    access_token = "fixture-access"

    def do_POST(self):
        if self.__class__.before_request is not None:
            self.__class__.before_request(self.path)
        self.__class__.requests.append(self.path)
        if self.__class__.delay_seconds:
            time.sleep(self.__class__.delay_seconds)
        if self.__class__.service is not None and not self.path.startswith(
            "/oauth2.googleapis.com"
        ):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if "application/x-www-form-urlencoded" in self.headers.get(
                "Content-Type", ""
            ):
                body = dict(urllib.parse.parse_qsl(raw.decode()))
            else:
                body = json.loads(raw)
            if self.path.startswith("/iamcredentials.googleapis.com/"):
                self._reply(
                    {
                        "signedBlob": base64.b64encode(
                            b"fixture-signature" * 16
                        ).decode(),
                        "keyId": "fixture",
                    }
                )
                return
            host, _, path = self.path[1:].partition("/")
            rpc = path.rsplit("/", 1)[-1]
            route = (
                "/" + rpc
                if rpc.startswith("accounts:")
                else ":createSessionCookie"
                if rpc.endswith(":createSessionCookie")
                else ""
            )
            status, response = self.__class__.service["sender"](
                "http://127.0.0.1:1/" + host,
                route,
                body,
                "Authorization" in self.headers,
                5,
            )
            self._reply(json.loads(response), status)
            return
        if self.path == "/oauth2.googleapis.com/token":
            body = {
                "access_token": self.__class__.access_token,
                "expires_in": 3600,
                "token_type": "Bearer",
            }
        elif self.path.startswith("/oauth2.googleapis.com/tokeninfo"):
            body = {
                "azp": "client-1",
                "aud": "client-1",
                "sub": "subject-1",
                "email": "fixture@example.invalid",
                "email_verified": "true",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "expires_in": 3600,
            }
        else:
            body = self._metadata()
        self._reply(
            body, self.__class__.refresh_status if self.path.endswith("/token") else 200
        )

    def do_GET(self):
        if self.__class__.before_request is not None:
            self.__class__.before_request(self.path)
        self.__class__.requests.append(self.path)
        if self.path.startswith("/oauth2.googleapis.com/tokeninfo"):
            self._reply(
                {
                    "azp": "client-1",
                    "aud": "client-1",
                    "sub": "subject-1",
                    "email": "fixture@example.invalid",
                    "email_verified": "true",
                    "scope": "https://www.googleapis.com/auth/cloud-platform",
                    "expires_in": 3600,
                    **self.__class__.tokeninfo_overrides,
                }
            )
        else:
            self._reply(self._metadata())

    def _metadata(self):
        if self.path.endswith("/config"):
            return {
                "name": "projects/592603257417/config",
                "mfa": {"state": "DISABLED"},
            }
        return {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}

    def _reply(self, value, status=200):
        if value.get("email_verified") == "__missing__":
            value = {
                key: item for key, item in value.items() if key != "email_verified"
            }
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except BrokenPipeError:
            pass

    def log_message(self, *_args):
        pass


@pytest.fixture
def fixture_origin():
    _Fixture.requests = []
    _Fixture.before_request = None
    _Fixture.tokeninfo_overrides = {}
    _Fixture.refresh_status = 200
    _Fixture.service = None
    _Fixture.delay_seconds = 0
    _Fixture.access_token = "fixture-access"
    server = HTTPServer(("127.0.0.1", int(os.environ.get("PORT", "0"))), _Fixture)
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
        "credentialPrincipal": {
            "clientId": "client-1",
            "subject": "subject-1",
            "requiredScopes": [bootstrap.SCOPE],
        },
        "project": bootstrap.PROJECT,
        "projectNumber": bootstrap.PROJECT_NUMBER,
        "nonce": "a" * 32,
    }


def test_fixture_bootstrap_charges_exact_four_requests_and_returns_private_handoff(
    fixture_origin,
):
    origin, requests = fixture_origin
    result = bootstrap.prepare(
        _permission(),
        adc=ADC,
        api_key="fixture-bootstrap-api-key",
        fixture_origin=origin,
    )
    assert requests == [
        "/oauth2.googleapis.com/token",
        "/oauth2.googleapis.com/tokeninfo?access_token=fixture-access",
        "/cloudresourcemanager.googleapis.com/v1/projects/fireemu-35fe6",
        "/identitytoolkit.googleapis.com/admin/v2/projects/fireemu-35fe6/config",
    ]
    assert result.prepared == {
        "token": "fixture-access",
        "apiKey": "fixture-bootstrap-api-key",
        "signing": {"serviceAccount": bootstrap.SERVICE_ACCOUNT},
    }
    observation_digest = "a" * 64
    with pytest.raises(ValueError, match="independent observation"):
        bootstrap.finalize_handoff(result.prepared, observation_digest, result.proof)
    assert result.proof["project"] == {
        "projectId": "fireemu-35fe6",
        "projectNumber": "592603257417",
    }
    assert result.proof["authConfigDigest"] == bootstrap.digest(
        {"name": "projects/592603257417/config", "mfa": {"state": "DISABLED"}}
    )
    assert result.charged_requests == 4


def test_prepare_uses_real_gate_and_pinned_loopback_worker_without_retry(
    fixture_origin, tmp_path
):
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
        permission,
        adc=ADC,
        api_key="fixture-bootstrap-api-key",
        fixture_origin=origin,
        gate=gate,
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
            permission,
            adc=ADC,
            api_key="fixture-bootstrap-api-key",
            fixture_origin=origin,
            gate=gate,
        )
    assert len(requests) == 4


def test_bootstrap_rejects_foreign_principal_before_network(fixture_origin):
    origin, requests = fixture_origin
    permission = _permission()
    permission["credentialPrincipal"]["clientId"] = "foreign-client"
    with pytest.raises(ValueError, match="principal"):
        bootstrap.prepare(
            permission,
            adc=ADC,
            api_key="fixture-bootstrap-api-key",
            fixture_origin=origin,
        )
    assert requests == []


def test_production_bootstrap_requires_gate_before_any_wire_call():
    with pytest.raises(ValueError, match="Gate"):
        bootstrap.prepare(_permission(), adc=ADC, api_key="fixture-bootstrap-api-key")


def test_tokeninfo_query_preserves_private_token_delimiters(fixture_origin):
    _Fixture.access_token = "fixture+token&suffix"
    result = bootstrap.prepare(
        _permission(),
        adc=ADC,
        api_key="fixture-bootstrap-api-key",
        fixture_origin=fixture_origin[0],
    )
    assert result.prepared["token"] == _Fixture.access_token
    assert (
        fixture_origin[1][1]
        == "/oauth2.googleapis.com/tokeninfo?access_token=fixture%2Btoken%26suffix"
    )


def test_bootstrap_rejects_budget_or_deadline_mutation():
    with pytest.raises(ValueError, match="budget"):
        bootstrap.BootstrapBudget(
            max_requests=5, max_seconds=600, cost_microusd=50_000
        ).validate()
    with pytest.raises(ValueError, match="budget"):
        bootstrap.BootstrapBudget(
            max_requests=60, max_seconds=601, cost_microusd=50_000
        ).validate()
    with pytest.raises(ValueError, match="budget"):
        bootstrap.BootstrapBudget(
            max_requests=60, max_seconds=600, cost_microusd=50_001
        ).validate()
    with pytest.raises(ValueError, match="deadline"):
        bootstrap.validate_deadline(bootstrap.PREP_REQUEST_SECONDS - 1)


def test_real_preparation_admission_reserves_once_before_four_worker_calls(
    fixture_origin, tmp_path
):
    import credential_admission as admission
    import credential_descriptor as campaign
    import reservations
    from test_credential_admission import Admission

    fixture = Admission(tmp_path, preparation=True, fixture_origin=fixture_origin[0])
    binding, binding_digest = campaign.remote.worker_binding()
    capability = admission.issue_preparation_capability(
        **fixture.bindings(), binding=binding, binding_digest=binding_digest
    )
    origin, requests = fixture_origin

    def before_wire(_path):
        rows = reservations.Ledger(fixture.ledger).snapshot()["reservations"]
        assert len(rows) == 1
        state = json.loads((tmp_path / "prepared" / "gate" / "state.json").read_text())
        assert state["total"] == len(requests) + 1
        assert state["managementEvents"][-1]["completed"] is False

    _Fixture.before_request = before_wire
    result = bootstrap.execute_preparation(
        capability=capability,
        inputs=fixture.inputs,
        permission=fixture.permission,
        source_root=fixture.source,
        ledger_root=fixture.ledger,
        output=tmp_path / "prepared",
        credential_reader=lambda: {"adc": ADC, "apiKey": "fixture-bootstrap-api-key"},
        fixture_origin=origin,
    )
    state = reservations.Ledger(fixture.ledger).snapshot()
    assert len(state["reservations"]) == 1
    row = state["reservations"][result.ticket["reservation"]]
    assert row["state"] == "held"
    assert row["claim"]["budget"]["requests"] == 60
    assert row["claim"]["budget"]["costMicrousd"] == 50_000
    assert row["claim"]["durationSeconds"] == 600
    assert result.proof["reservationDeadline"] == row["deadline"]
    assert result.charged_requests == len(requests) == 4
    assert result.gate.snapshot()["total"] == 4
    assert result.budget["requests"] == 4
    assert (
        result.budget["totalDeadlineMonotonic"]
        == result.proof["reservationMonotonicDeadline"]
    )
    bootstrap.validate_proof(
        result.proof,
        snapshot=result.gate.snapshot(),
        reservation=row,
        inputs=fixture.inputs,
    )
    for field in (
        "authConfigDigest",
        "managementJournalDigest",
        "claimDigest",
        "reservationDeadline",
        "tokeninfoExpiresInSeconds",
    ):
        changed = copy.deepcopy(result.proof)
        changed[field] = (
            0
            if field in {"reservationDeadline", "tokeninfoExpiresInSeconds"}
            else "0" * 64
        )
        with pytest.raises(ValueError, match="proof|evidence"):
            bootstrap.validate_proof(
                changed,
                snapshot=result.gate.snapshot(),
                reservation=row,
                inputs=fixture.inputs,
            )
    import credential_production as production

    with pytest.raises(ValueError, match="independent observation"):
        production.execute_reserved(
            capability=None,
            inputs=None,
            permission=None,
            preparation=result,
            preparation_inputs=fixture.inputs,
            source_root=fixture.source,
            ledger_root=fixture.ledger,
            output=tmp_path / "prepared",
        )
    assert len(requests) == 4
    for path in (tmp_path / "prepared").rglob("*.json"):
        raw = path.read_text()
        assert all(
            secret not in raw
            for secret in (
                "fixture-access",
                "fixture-secret",
                "fixture-refresh",
                '"fixture-bootstrap-api-key"',
            )
        )


@pytest.mark.parametrize(
    "failure,expected_calls", [("key", 0), ("refresh", 1), ("identity", 2)]
)
def test_failed_preparation_retains_real_prefix_and_reservation(
    fixture_origin, tmp_path, failure, expected_calls
):
    import credential_admission as admission
    import credential_descriptor as campaign
    import reservations
    from test_credential_admission import Admission

    fixture = Admission(tmp_path, preparation=True, fixture_origin=fixture_origin[0])
    binding, binding_digest = campaign.remote.worker_binding()
    cap = admission.issue_preparation_capability(
        **fixture.bindings(), binding=binding, binding_digest=binding_digest
    )
    if failure == "refresh":
        _Fixture.refresh_status = 401
    if failure == "identity":
        _Fixture.tokeninfo_overrides = {"email_verified": "false"}
    with pytest.raises(ValueError):
        bootstrap.execute_preparation(
            capability=cap,
            inputs=fixture.inputs,
            permission=fixture.permission,
            source_root=fixture.source,
            ledger_root=fixture.ledger,
            output=tmp_path / "prepared",
            credential_reader=lambda: {
                "adc": ADC,
                "apiKey": "foreign"
                if failure == "key"
                else "fixture-bootstrap-api-key",
            },
            fixture_origin=fixture_origin[0],
        )
    assert len(fixture_origin[1]) == expected_calls
    (row,) = reservations.Ledger(fixture.ledger).snapshot()["reservations"].values()
    assert row["state"] == "held"
    failure_record = json.loads(
        (tmp_path / "prepared" / "preparation-failure.json").read_text()
    )
    assert failure_record["chargedCalls"] == expected_calls
    assert failure_record["coordinatorMustExit"] is True


def test_independent_observation_continues_all_53_calls_on_original_reservation(
    fixture_origin, tmp_path
):
    import credential_admission as admission
    import credential_descriptor as campaign
    import credential_production as production
    import reservations
    from test_credential_admission import Admission, owner_permission
    from test_credential_shadow import _service

    fixture = Admission(tmp_path, preparation=True, fixture_origin=fixture_origin[0])
    binding, binding_digest = campaign.remote.worker_binding()
    cap = admission.issue_preparation_capability(
        **fixture.bindings(), binding=binding, binding_digest=binding_digest
    )
    output = tmp_path / "prepared"
    prepared = bootstrap.execute_preparation(
        capability=cap,
        inputs=fixture.inputs,
        permission=fixture.permission,
        source_root=fixture.source,
        ledger_root=fixture.ledger,
        output=output,
        credential_reader=lambda: {"adc": ADC, "apiKey": "fixture-bootstrap-api-key"},
        fixture_origin=fixture_origin[0],
    )
    original_inputs = fixture.inputs
    original_snapshot = prepared.gate.snapshot()
    time.sleep(1.05)
    fixture.permission = {
        **owner_permission(
            fixture.plan,
            fixture.commit,
            fixture.inputs["artifactSha256"],
            fixture.inputs["sourceInputs"],
        ),
        "credentialPrincipal": fixture.permission["credentialPrincipal"],
        "authConfigDigest": prepared.proof["authConfigDigest"],
        "bootstrap": bootstrap.observation_binding(prepared.proof),
        "fixtureOrigin": fixture_origin[0],
    }
    fixture.permission_path.write_text(json.dumps(fixture.permission))
    fixture.inputs = admission.freeze_inputs(
        fixture.permission_path,
        fixture.plan,
        source_root=fixture.source,
        artifact_path=fixture.artifact_path,
    )
    fixture.descriptor = campaign.descriptor()
    fixture.manifest = {
        "kind": fixture.descriptor.manifest_kind,
        "inputsDigest": fixture.inputs["inputsDigest"],
    }
    fixture.manifest_bytes = json.dumps(fixture.manifest).encode()
    fixture.manifest_path.write_bytes(fixture.manifest_bytes)
    fixture.approval = fixture._approval()
    capability = admission.issue_production_capability(
        **fixture.bindings(), binding=binding, binding_digest=binding_digest
    )
    _Fixture.service = _service(project="fireemu-35fe6")
    result = production.execute_reserved(
        capability=capability,
        inputs=fixture.inputs,
        permission=fixture.permission,
        preparation=prepared,
        preparation_inputs=original_inputs,
        source_root=fixture.source,
        ledger_root=fixture.ledger,
        output=output,
    )
    assert result["failure"] is None
    assert result["reservationReleased"] is True
    assert len(fixture_origin[1]) == result["chargedCalls"] == 53
    final = prepared.gate.snapshot()
    assert final["started"] == original_snapshot["started"]
    assert final["planDigest"] == original_snapshot["planDigest"]
    rows = reservations.Ledger(fixture.ledger).snapshot()["reservations"]
    assert (
        len(rows) == 1
        and rows[prepared.ticket["reservation"]]["deadline"]
        == prepared.proof["reservationDeadline"]
    )
    assert _Fixture.service["accounts"] == {}
    production.verify_saved(
        output,
        expected_inputs_digest=fixture.inputs["inputsDigest"],
        ledger_root=fixture.ledger,
    )


def _failed_preparation_child(directory, origin):
    import credential_admission as admission
    import credential_descriptor as campaign
    from test_credential_admission import Admission

    fixture = Admission(Path(directory), preparation=True, fixture_origin=origin)
    binding, binding_digest = campaign.remote.worker_binding()
    cap = admission.issue_preparation_capability(
        **fixture.bindings(), binding=binding, binding_digest=binding_digest
    )
    try:
        bootstrap.execute_preparation(
            capability=cap,
            inputs=fixture.inputs,
            permission=fixture.permission,
            source_root=fixture.source,
            ledger_root=fixture.ledger,
            output=Path(directory) / "prepared",
            credential_reader=lambda: {
                "adc": ADC,
                "apiKey": "fixture-bootstrap-api-key",
            },
            fixture_origin=origin,
        )
    except ValueError:
        return
    raise AssertionError("fixture refresh rejection expected")


@pytest.mark.parametrize("timeout", [False, True])
def test_no_data_retirement_requires_real_coordinator_exit(
    fixture_origin, tmp_path, timeout
):
    import reservations

    _Fixture.refresh_status = 401
    _Fixture.delay_seconds = 6 if timeout else 0
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); from test_credential_bootstrap import _failed_preparation_child; _failed_preparation_child(sys.argv[2], sys.argv[3])",
            str(HERE),
            str(tmp_path),
            fixture_origin[0],
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert child.returncode == 0, child.stderr.decode()
    receipt = json.loads((tmp_path / "prepared" / "receipt.json").read_text())
    result = bootstrap.retire_no_data(
        tmp_path / "prepared", ledger_root=tmp_path / "ledger"
    )
    assert result["state"] == "aborted-no-data"
    assert len(fixture_origin[1]) == receipt["chargedCalls"] == 1
    ledger = reservations.Ledger(tmp_path / "ledger")
    assert (
        ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]["state"]
        == "aborted-no-data"
    )


@pytest.mark.parametrize(
    "drift", ["missing", "permission", "source", "worker", "ledger", "expiry"]
)
def test_preparation_admission_drift_never_reaches_wire(
    fixture_origin, tmp_path, drift
):
    import credential_admission as admission
    import credential_descriptor as campaign
    import reservations
    from test_credential_admission import Admission

    fixture = Admission(tmp_path, preparation=True, fixture_origin=fixture_origin[0])
    binding, binding_digest = campaign.remote.worker_binding()
    if drift == "worker":
        binding += b"\n"
    if drift == "expiry":
        fixture.approval["windowExpiresAt"] = time.time() - 1
    with pytest.raises(ValueError):
        cap = (
            admission.issue_preparation_capability(
                **fixture.bindings(), binding=binding, binding_digest=binding_digest
            )
            if drift != "missing"
            else None
        )
        if drift == "permission":
            fixture.permission["apiKeyDigest"] = "0" * 64
        if drift == "source":
            source_file = fixture.source / campaign.WORKER_ENTRY
            source_file.write_bytes(source_file.read_bytes() + b"\n")
        target_ledger = fixture.ledger
        if drift == "ledger":
            target_ledger = tmp_path / "other-ledger"
            reservations.Ledger.create(target_ledger)
        bootstrap.execute_preparation(
            capability=cap,
            inputs=fixture.inputs,
            permission=fixture.permission,
            source_root=fixture.source,
            ledger_root=target_ledger,
            output=tmp_path / "prepared",
            credential_reader=lambda: {
                "adc": ADC,
                "apiKey": "fixture-bootstrap-api-key",
            },
            fixture_origin=fixture_origin[0],
        )
    assert fixture_origin[1] == []
    assert reservations.Ledger(fixture.ledger).snapshot()["reservations"] == {}


def _cli_fixture(tmp_path, origin, *, wait_seconds="60"):
    from test_credential_admission import Admission

    fixture = Admission(tmp_path, preparation=True, fixture_origin=origin)
    fixture.launcher_path = HERE / "credential_bootstrap.py"
    fixture.approval = fixture._approval()
    fixture.approval_path.write_text(json.dumps(fixture.approval))
    inputs_path = tmp_path / "prep-inputs.json"
    inputs_path.write_text(json.dumps(fixture.inputs))
    credentials = tmp_path / "synthetic-private-input.json"
    credentials.write_text(
        json.dumps({"adc": ADC, "apiKey": "fixture-bootstrap-api-key"})
    )
    credentials.chmod(0o600)
    observation = tmp_path / "observation"
    observation.mkdir()
    command = [
        sys.executable,
        str(fixture.launcher_path),
        "run",
        "--inputs",
        str(inputs_path),
        "--permission",
        str(fixture.permission_path),
        "--approval",
        str(fixture.approval_path),
        "--manifest",
        str(fixture.manifest_path),
        "--source",
        str(fixture.source),
        "--artifact",
        str(fixture.artifact_path),
        "--ledger",
        str(fixture.ledger),
        "--output",
        str(tmp_path / "prepared"),
        "--credential-file",
        str(credentials),
        "--observation-directory",
        str(observation),
        "--approval-wait-seconds",
        wait_seconds,
    ]
    return fixture, command, observation


def test_actual_coordinator_cli_timeout_publishes_retirable_four_call_prefix(
    fixture_origin, tmp_path
):
    fixture, command, _ = _cli_fixture(tmp_path, fixture_origin[0], wait_seconds="0.1")
    child = subprocess.run(command, capture_output=True, timeout=30, check=False)
    assert child.returncode == 2
    assert len(fixture_origin[1]) == 4
    result = bootstrap.retire_no_data(tmp_path / "prepared", ledger_root=fixture.ledger)
    assert result["state"] == "aborted-no-data"
    assert b"fixture-access" not in child.stdout + child.stderr


@pytest.mark.parametrize("approved", [True, False, "preflight-refused"])
def test_actual_cli_waits_for_independent_final_artifacts(
    fixture_origin, tmp_path, approved
):
    import credential_admission as admission
    import credential_descriptor as campaign
    import credential_production as production
    import reservations
    from test_credential_admission import owner_permission
    from test_credential_shadow import _service

    fixture, command, observation = _cli_fixture(tmp_path, fixture_origin[0])
    _Fixture.tokeninfo_overrides = {"expires_in": "600"}

    def delay_auth_readback(path):
        if path.endswith("/config"):
            time.sleep(1.05)

    _Fixture.before_request = delay_auth_readback
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        proof_path = tmp_path / "prepared" / "preparation-proof.json"
        until = time.monotonic() + 20
        while (
            not proof_path.exists()
            and process.poll() is None
            and time.monotonic() < until
        ):
            time.sleep(0.05)
        assert proof_path.exists()
        proof = json.loads(proof_path.read_text())
        assert proof["tokenLifetime"]["expiresInSeconds"] == 600
        assert proof["tokeninfoExpiresInSeconds"] < 600
        assert (
            proof["tokenLifetime"]
            == proof["managementEvidence"][1]["response"]["body"]["tokenLifetime"]
        )
        assert len(fixture_origin[1]) == 4
        time.sleep(0.25)
        assert len(fixture_origin[1]) == 4
        fixture.permission = {
            **owner_permission(
                fixture.plan,
                fixture.commit,
                fixture.inputs["artifactSha256"],
                fixture.inputs["sourceInputs"],
            ),
            "credentialPrincipal": fixture.permission["credentialPrincipal"],
            "authConfigDigest": proof["authConfigDigest"],
            "bootstrap": bootstrap.observation_binding(proof),
            "fixtureOrigin": fixture_origin[0],
        }
        permission_path = observation / "permission.json"
        permission_path.write_text(json.dumps(fixture.permission))
        fixture.inputs = admission.freeze_inputs(
            permission_path,
            fixture.plan,
            source_root=fixture.source,
            artifact_path=fixture.artifact_path,
        )
        fixture.descriptor = campaign.descriptor()
        fixture.manifest = {
            "kind": campaign.MANIFEST_KIND,
            "inputsDigest": fixture.inputs["inputsDigest"],
        }
        fixture.manifest_bytes = json.dumps(fixture.manifest).encode()
        (observation / "manifest.json").write_bytes(fixture.manifest_bytes)
        (observation / "inputs.json").write_text(json.dumps(fixture.inputs))
        fixture.approval = fixture._approval()
        if approved is False:
            fixture.approval["status"] = "denied"
        if approved == "preflight-refused":
            _Fixture.tokeninfo_overrides["email_verified"] = "false"
        _Fixture.service = _service(project="fireemu-35fe6")
        (observation / "approval.json").write_text(json.dumps(fixture.approval))
        stdout, stderr = process.communicate(timeout=90)
        completed = approved is True
        assert process.returncode == (0 if completed else 2), (stdout, stderr)
        expected_calls = (
            53 if completed else 5 if approved == "preflight-refused" else 4
        )
        assert len(fixture_origin[1]) == expected_calls
        assert (
            b"fixture-access" not in stdout + stderr
            and b"fixture-secret" not in stdout + stderr
        )
        if completed:
            receipt = production.verify_saved(
                tmp_path / "prepared",
                expected_inputs_digest=fixture.inputs["inputsDigest"],
                ledger_root=fixture.ledger,
            )
            assert receipt["ticket"] == proof["ticket"]
            assert receipt["chargedCalls"] == 53
            assert receipt["credentialEvidence"][0]["requiredSeconds"] < 600
        else:
            receipt = json.loads((tmp_path / "prepared" / "receipt.json").read_text())
            snapshot = gate_module.CredentialGate(
                tmp_path / "prepared" / "gate"
            ).snapshot()
            assert receipt["chargedCalls"] == expected_calls
            assert snapshot["events"] == []
            assert all(event["workerReaped"] for event in snapshot["managementEvents"])
            assert (
                bootstrap.retire_no_data(
                    tmp_path / "prepared", ledger_root=fixture.ledger
                )["state"]
                == "aborted-no-data"
            )
        (row,) = reservations.Ledger(fixture.ledger).snapshot()["reservations"].values()
        assert row["deadline"] == proof["reservationDeadline"]
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


@pytest.mark.parametrize("claim", [True, 1, False, "false", None, "__missing__"])
def test_modern_verified_email_rejects_non_string_true_claims(fixture_origin, claim):
    import credential_preflight as preflight

    _Fixture.tokeninfo_overrides = {"email_verified": claim}
    permission = _permission()
    permission["credentialPrincipal"] = {
        "clientId": "client-1",
        "verifiedEmail": "fixture@example.invalid",
        "requiredScopes": [bootstrap.SCOPE],
    }
    with pytest.raises(ValueError, match="principal"):
        bootstrap.prepare(
            permission,
            adc=ADC,
            api_key="fixture-bootstrap-api-key",
            fixture_origin=fixture_origin[0],
        )
    assert len(fixture_origin[1]) == 2
    response = preflight.modern_management_transport(
        "oauth-tokeninfo",
        "fixture-access",
        deadline=time.monotonic() + 5,
        fixture_origin=fixture_origin[0],
    )
    assert response["body"]["verified_email"] is False


def test_lifetime_boundary_covers_original_deadline_including_recovery():
    lifetime = bootstrap.token_lifetime(
        {"expires_in": "600"}, sent_monotonic=100.0, sent_at=1000.0
    )
    bootstrap.require_lifetime(
        lifetime,
        deadline_monotonic=700.0,
        deadline_at=1600.0,
        now_monotonic=130.0,
        now_at=1030.0,
    )
    with pytest.raises(ValueError, match="lifetime"):
        bootstrap.require_lifetime(
            lifetime,
            deadline_monotonic=700.001,
            deadline_at=1600.0,
            now_monotonic=130.0,
            now_at=1030.0,
        )
    with pytest.raises(ValueError, match="lifetime"):
        bootstrap.require_lifetime(
            lifetime,
            deadline_monotonic=700.0,
            deadline_at=1600.001,
            now_monotonic=130.0,
            now_at=1030.0,
        )
    with pytest.raises(ValueError, match="lifetime"):
        bootstrap.require_lifetime(
            lifetime,
            deadline_monotonic=700.0,
            deadline_at=1600.0,
            now_monotonic=700.0,
            now_at=1600.0,
        )


@pytest.mark.parametrize(
    "kind", ["regular", "symlink", "public", "fifo", "oversized", "malformed"]
)
def test_private_input_is_bounded_regular_private_owned_fd(tmp_path, kind):
    path = tmp_path / "private.json"
    value = {"adc": ADC, "apiKey": "fixture-bootstrap-api-key"}
    if kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        path.write_text(json.dumps(value))
        path.chmod(0o600)
    if kind == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(path)
        path = link
    elif kind == "public":
        path.chmod(0o644)
    elif kind == "oversized":
        path.write_bytes(b"x" * 65537)
    elif kind == "malformed":
        path.write_text("fixture-secret invalid JSON")
    if kind == "regular":
        assert bootstrap.read_private_input(path) == value
    else:
        with pytest.raises(ValueError, match="private input"):
            bootstrap.read_private_input(path)
