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
from action_codes_plan import campaign_manifest
from broad_contract import digest


NONCE = "0123456789abcdef0123456789abcdef"
PROJECT = "demo-auth-action"
UNUSED_FIXTURE_ORIGIN = "http://127.0.0.1:65535"


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


def _capability(transport, inputs_digest):
    source, source_digest = credential_remote.worker_binding()
    now = time.time()
    capability = o8_admission.ProductionWireCapability(
        o8_admission._CAPABILITY_TOKEN,
        binding=source,
        binding_digest=source_digest,
        campaign_id=action_remote.CAMPAIGN_ID,
        window_seconds=30,
        inputs_digest=inputs_digest,
        ledger_root=str(Path("/tmp/action-test-ledger").resolve()),
        window_starts_at=now - 1,
        window_expires_at=now + 60,
        approval_digest="b" * 64,
        transport_bound=transport,
    )
    capability._consume(
        campaign_id=action_remote.CAMPAIGN_ID,
        inputs_digest=inputs_digest,
        ledger_root=str(Path("/tmp/action-test-ledger").resolve()),
    )
    return capability, source, source_digest


def _frozen_inputs():
    plan = campaign_manifest(NONCE)
    plan["ownerInputs"]["projectId"] = PROJECT
    permission = {
        "projectId": PROJECT,
        "permissionReference": "fixture-owner-permission",
        "logicalAccounts": {
            "accountA": {
                "resource": f"projects/{PROJECT}/auth/accounts/o1-oob-{NONCE}-a"
            },
            "accountB": {
                "resource": f"projects/{PROJECT}/auth/accounts/o1-oob-{NONCE}-b"
            },
        },
        "credentialPrincipal": {
            "subject": "owner@example.test",
            "requiredScopes": [action_remote.IDENTITY_SCOPE],
        },
    }
    value = {
        "kind": "fixture-frozen-inputs",
        "permission": permission,
        "permissionDigest": digest(permission),
        "plan": plan,
        "planDigest": digest(plan),
        "sourceCommit": "a" * 40,
        "sourceInputs": {"action_codes_remote_transport.py": "b" * 64},
        "artifactSha256": "c" * 64,
    }
    value["inputsDigest"] = digest(value)
    return value


def _bindings():
    plan = campaign_manifest(NONCE)
    result = {}

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

    for stage in plan["stages"]:
        values = {}
        for name in names(stage["body"]):
            if name.endswith(".email") or name.endswith("Email"):
                suffix = "absent" if name == "unknownEmail" else name.removesuffix(".email")[-1].lower()
                values[name] = f"o1-oob-{NONCE}-{suffix}@example.invalid"
            else:
                values[name] = "declared-" + name.replace(".", "-") + "-" + NONCE[:8]
        result[stage["id"]] = values
    for stage in plan["recovery"]:
        values = {}
        for name in names(stage["body"]):
            if name.endswith(".email"):
                suffix = name.removesuffix(".email")[-1].lower()
                values[name] = f"o1-oob-{NONCE}-{suffix}@example.invalid"
            elif name.endswith(".localId"):
                values[name] = "uid-" + name.split(".", 1)[0]
        result[stage["id"]] = values
    return result


def _handoff(permission):
    return {
        "token": "owner-token",
        "apiKey": "web-key",
        "permissionDigest": digest(permission),
        "principal": "owner@example.test",
        "scope": action_remote.IDENTITY_SCOPE,
    }


def _verify_fixture_handoff(handoff, permission):
    if handoff != _handoff(permission):
        raise ValueError("fixture credential handoff verification failed")


def _action_transport(fixture_origin=UNUSED_FIXTURE_ORIGIN):
    inputs = _frozen_inputs()
    transport = action_remote.make_transport(
        frozen_inputs=inputs,
        declared_bindings=_bindings(),
        credential_handoff=_handoff(inputs["permission"]),
        verify_handoff=_verify_fixture_handoff,
        fixture_origin=fixture_origin,
    )
    return inputs, transport


def test_admin_action_slot_reaches_loopback_fixture_with_exact_shape(fixture_origin):
    origin, _server = fixture_origin
    inputs, transport = _action_transport(origin)
    capability, source, source_digest = _capability(transport, inputs["inputsDigest"])
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
        deadline=time.monotonic() + 10,
        binding=source,
        binding_digest=source_digest,
    )

    assert status == 200
    assert response["kind"] == "fixture"
    assert _Echo.requests == [
        {
            "path": f"/identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:sendOobCode",
            "body": body,
            "authorization": "Bearer owner-token",
        }
    ]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("stage_id", "not-a-stage", "unknown Action stage"),
        ("project", "other/project", "project differs"),
        ("nonce", "not-32-hex", "nonce"),
    ],
)
def test_malformed_action_slot_is_rejected_before_wire(field, value, message):
    inputs, transport = _action_transport()
    capability, source, source_digest = _capability(transport, inputs["inputsDigest"])
    kwargs = {
        "stage_id": "link-generate-unknown-email",
        "project": PROJECT,
        "nonce": NONCE,
        "body": {
            "requestType": "PASSWORD_RESET",
            "email": f"o1-oob-{NONCE}-absent@example.invalid",
            "returnOobLink": True,
        },
        "deadline": time.monotonic() + 10,
        "binding": source,
        "binding_digest": source_digest,
    }
    kwargs[field] = value
    with pytest.raises(ValueError, match=message):
        action_remote.send(capability, **kwargs)


def test_extra_operation_is_rejected_before_wire(fixture_origin):
    origin, _server = fixture_origin
    inputs, transport = _action_transport(origin)
    capability, source, source_digest = _capability(transport, inputs["inputsDigest"])
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
            deadline=time.monotonic() + 10,
            binding=source,
            binding_digest=source_digest,
        )
    assert _Echo.requests == []


def test_mutated_source_binding_is_rejected_before_wire(fixture_origin):
    origin, _server = fixture_origin
    inputs, transport = _action_transport(origin)
    capability, source, source_digest = _capability(transport, inputs["inputsDigest"])
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
            deadline=time.monotonic() + 10,
            binding=source,
            binding_digest=hashlib.sha256(source + b"mutated").hexdigest(),
        )
    assert _Echo.requests == []


def test_production_transport_does_not_accept_a_loopback_origin_without_fixture():
    called = False

    def verifier(_handoff, _permission):
        nonlocal called
        called = True

    with pytest.raises(ValueError, match="production hosting is unavailable"):
        action_remote.make_transport(
            frozen_inputs=_frozen_inputs(),
            declared_bindings=_bindings(),
            credential_handoff=_handoff(_frozen_inputs()["permission"]),
            verify_handoff=verifier,
        )
    assert called is False


def test_noncanonical_project_is_rejected_before_fixture_constructor():
    inputs = _frozen_inputs()
    inputs["permission"]["projectId"] = "foreign-project"
    inputs["plan"]["ownerInputs"]["projectId"] = "foreign-project"
    inputs["permissionDigest"] = digest(inputs["permission"])
    inputs["planDigest"] = digest(inputs["plan"])
    unsigned = {key: item for key, item in inputs.items() if key != "inputsDigest"}
    inputs["inputsDigest"] = digest(unsigned)
    with pytest.raises(ValueError, match="noncanonical Action project"):
        action_remote.make_transport(
            frozen_inputs=inputs,
            declared_bindings=_bindings(),
            credential_handoff=_handoff(inputs["permission"]),
            verify_handoff=_verify_fixture_handoff,
            fixture_origin=UNUSED_FIXTURE_ORIGIN,
        )


def test_rehashed_permission_digest_does_not_authorize_mutated_permission():
    inputs = _frozen_inputs()
    inputs["permission"]["projectId"] = PROJECT
    inputs["permission"]["credentialPrincipal"]["subject"] = "other@example.test"
    # Keep the original permissionDigest to model a caller that only rehashes
    # the outer frozen inputs after changing the permission object.
    unsigned = {key: item for key, item in inputs.items() if key != "inputsDigest"}
    inputs["inputsDigest"] = digest(unsigned)
    with pytest.raises(ValueError, match="permission digest"):
        action_remote.make_transport(
            frozen_inputs=inputs,
            declared_bindings=_bindings(),
            credential_handoff=_handoff(inputs["permission"]),
            verify_handoff=_verify_fixture_handoff,
            fixture_origin=UNUSED_FIXTURE_ORIGIN,
        )


def test_valid_foreign_project_and_nonce_are_rejected():
    inputs, transport = _action_transport()
    capability, source, source_digest = _capability(transport, inputs["inputsDigest"])
    body = {
        "requestType": "PASSWORD_RESET",
        "email": f"o1-oob-{NONCE}-absent@example.invalid",
        "returnOobLink": True,
    }
    for project, nonce in (("another-project", NONCE), (PROJECT, "f" * 32)):
        with pytest.raises(ValueError, match="frozen|differs"):
            action_remote.send(
                capability,
                stage_id="link-generate-unknown-email",
                project=project,
                nonce=nonce,
                body=body,
                deadline=time.monotonic() + 10,
                binding=source,
                binding_digest=source_digest,
            )


def test_dynamic_binding_and_credential_scope_or_principal_mutations_are_rejected():
    inputs, transport = _action_transport()
    capability, source, source_digest = _capability(transport, inputs["inputsDigest"])
    body = {
        "requestType": "PASSWORD_RESET",
        "email": f"o1-oob-{NONCE}-absent@example.invalid",
        "returnOobLink": True,
    }
    with pytest.raises(ValueError, match="binding"):
        action_remote.send(
            capability,
            stage_id="link-generate-unknown-email",
            project=PROJECT,
            nonce=NONCE,
            body={**body, "email": f"o1-oob-{NONCE}-a@example.invalid"},
            deadline=time.monotonic() + 10,
            binding=source,
            binding_digest=source_digest,
        )
    reset_body = {"oobCode": "not-the-declared-code"}
    with pytest.raises(ValueError, match="binding"):
        action_remote.send(
            capability,
            stage_id="reset-code-lookup",
            project=PROJECT,
            nonce=NONCE,
            body=reset_body,
            deadline=time.monotonic() + 10,
            binding=source,
            binding_digest=source_digest,
        )
    for field, value in (("scope", "wrong-scope"), ("principal", "other@example.test")):
        handoff = _handoff(inputs["permission"])
        handoff[field] = value
        with pytest.raises(ValueError, match="credential handoff"):
            action_remote.make_transport(
                frozen_inputs=inputs,
                declared_bindings=_bindings(),
                credential_handoff=handoff,
                verify_handoff=_verify_fixture_handoff,
                fixture_origin=UNUSED_FIXTURE_ORIGIN,
            )


def test_six_recovery_operations_use_exact_wire_shapes(fixture_origin):
    origin, _server = fixture_origin
    inputs, transport = _action_transport(origin)
    bindings = _bindings()
    capability, source, source_digest = _capability(transport, inputs["inputsDigest"])
    plan = inputs["plan"]
    for stage in plan["recovery"]:
        body = {}
        for key, value in stage["body"].items():
            if isinstance(value, list):
                body[key] = [bindings[stage["id"]][item.removeprefix("$binding:")] for item in value]
            else:
                body[key] = bindings[stage["id"]][value.removeprefix("$binding:")]
        status, _response = action_remote.send(
            capability,
            stage_id=stage["id"],
            project=PROJECT,
            nonce=NONCE,
            body=body,
            deadline=time.monotonic() + 10,
            binding=source,
            binding_digest=source_digest,
        )
        assert status == 200
    assert [request["path"] for request in _Echo.requests] == [
        f"/identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:lookup",
        f"/identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:delete",
        f"/identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:delete",
        f"/identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:lookup",
        f"/identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:lookup",
        f"/identitytoolkit.googleapis.com/v1/projects/{PROJECT}/accounts:lookup",
    ]


def test_unknown_recovery_uid_is_held_before_wire():
    inputs = _frozen_inputs()
    bindings = _bindings()
    del bindings["recover-delete-accountA"]["accountA.localId"]
    with pytest.raises(ValueError, match="recovery binding"):
        action_remote.make_transport(
            frozen_inputs=inputs,
            declared_bindings=bindings,
            credential_handoff=_handoff(inputs["permission"]),
            verify_handoff=_verify_fixture_handoff,
            fixture_origin=UNUSED_FIXTURE_ORIGIN,
        )


def test_self_consistent_mutated_plan_is_rejected_by_canonical_compiler():
    inputs = _frozen_inputs()
    inputs["plan"]["stages"][0]["body"]["returnSecureToken"] = False
    inputs["planDigest"] = digest(inputs["plan"])
    unsigned = {key: item for key, item in inputs.items() if key != "inputsDigest"}
    inputs["inputsDigest"] = digest(unsigned)
    with pytest.raises(ValueError, match="canonical compiler"):
        action_remote.make_transport(
            frozen_inputs=inputs,
            declared_bindings=_bindings(),
            credential_handoff=_handoff(inputs["permission"]),
            verify_handoff=_verify_fixture_handoff,
        )


def test_mutating_original_inputs_bindings_and_handoff_after_construction_cannot_change_authorization(fixture_origin):
    origin, _server = fixture_origin
    inputs = _frozen_inputs()
    bindings = _bindings()
    handoff = _handoff(inputs["permission"])
    transport = action_remote.make_transport(
        frozen_inputs=inputs,
        declared_bindings=bindings,
        credential_handoff=handoff,
        verify_handoff=_verify_fixture_handoff,
        fixture_origin=origin,
    )
    capability, source, source_digest = _capability(transport, inputs["inputsDigest"])
    inputs["permission"]["projectId"] = "foreign-project"
    inputs["plan"]["nonce"] = "f" * 32
    bindings["link-generate-unknown-email"]["unknownEmail"] = "o1-oob-" + NONCE + "-a@example.invalid"
    handoff["scope"] = "wrong-scope"
    with pytest.raises(ValueError, match="project differs"):
        action_remote.send(
            capability,
            stage_id="link-generate-unknown-email",
            project="foreign-project",
            nonce="f" * 32,
            body={
                "requestType": "PASSWORD_RESET",
                "email": "o1-oob-" + NONCE + "-a@example.invalid",
                "returnOobLink": True,
            },
            deadline=time.monotonic() + 10,
            binding=source,
            binding_digest=source_digest,
        )
    status, _response = action_remote.send(
        capability,
        stage_id="link-generate-unknown-email",
        project=PROJECT,
        nonce=NONCE,
        body={
            "requestType": "PASSWORD_RESET",
            "email": "o1-oob-" + NONCE + "-absent@example.invalid",
            "returnOobLink": True,
        },
        deadline=time.monotonic() + 10,
        binding=source,
        binding_digest=source_digest,
    )
    assert status == 200
