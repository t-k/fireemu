from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import time
from contextlib import nullcontext
from pathlib import Path
from typing import ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import o5_user_token_identity_proof as proof
import o5_user_token_remote_transport as remote
import pytest
from broad_contract import digest
from o5_user_token_case import compile_case
from o5_user_token_collector import _request
from shared_gate import Gate

PORTCTL = os.environ.get("FIREEMU_PORTCTL")


def _segment(value):
    return (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )


def _token(uid="uid-a", provider="password", tenant=None, custom=None):
    now = int(time.time())
    firebase = {"sign_in_provider": provider}
    if tenant is not None:
        firebase["tenant"] = tenant
    payload = {
        "iss": "https://securetoken.google.com/fireemu-35fe6",
        "aud": "fireemu-35fe6",
        "sub": uid,
        "user_id": uid,
        "iat": now - 10,
        "auth_time": now - 10,
        "exp": now + 3600,
        "firebase": firebase,
        **(custom or {}),
    }
    return (
        _segment({"alg": "RS256", "typ": "JWT"}) + "." + _segment(payload) + ".fixture"
    )


class _Handler(http.server.BaseHTTPRequestHandler):
    body: ClassVar[dict] = {}
    requests: ClassVar[list[tuple[str, bytes]]] = []

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.__class__.requests.append((self.path, raw))
        payload = json.dumps(self.__class__.body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


@pytest.fixture
def fixture_origin():
    reservation = None
    if PORTCTL:
        claim = subprocess.run(
            [
                sys.executable,
                PORTCTL,
                "claim",
                "--service",
                "o5-user-token-identity-proof",
                "--preferred",
                "10000",
                "--range",
                "10000-19999",
                "--ttl",
                "10m",
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        reservation = json.loads(claim.stdout)
        server = socketserver.TCPServer(
            ("127.0.0.1", int(reservation["port"])), _Handler
        )
    else:
        server = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = (
            int(reservation["port"])
            if reservation is not None
            else int(server.server_address[1])
        )
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        if reservation is not None:
            subprocess.run(
                [sys.executable, PORTCTL, "release", "--token", reservation["token"]],
                check=True,
                capture_output=True,
                text=True,
            )


def test_closed_issuance_binds_response_and_exact_request(fixture_origin):
    _Handler.requests.clear()
    token = _token()
    _Handler.body = {
        "localId": "uid-a",
        "idToken": token,
        "refreshToken": "private",
        "expiresIn": "3600",
    }
    request = proof.build_request(
        "signin",
        api_key="fixture-key",
        email="a@example.invalid",
        password="pw",
        tenant=None,
    )
    result = proof.issue_proof(
        "owner-a",
        request,
        expected_provider="password",
        expected_tenant=None,
        expected_claims={},
        fixture_origin=fixture_origin,
        now=int(time.time()),
    )
    assert result.trusted() and result.uid == "uid-a"
    assert result.token_hash == __import__("hashlib").sha256(token.encode()).hexdigest()
    assert len(_Handler.requests) == 1


def test_proof_rejects_wrong_identity_and_claims(fixture_origin):
    _Handler.body = {"localId": "uid-a", "idToken": _token(uid="uid-b")}
    request = proof.build_request(
        "signin",
        api_key="fixture-key",
        email="a@example.invalid",
        password="pw",
        tenant=None,
    )
    with pytest.raises(ValueError, match="identity"):
        proof.issue_proof(
            "owner-a",
            request,
            expected_provider="password",
            expected_tenant=None,
            expected_claims={},
            fixture_origin=fixture_origin,
            now=int(time.time()),
        )
    _Handler.body = {"localId": "uid-a", "idToken": _token(custom={"o5role": "viewer"})}
    with pytest.raises(ValueError, match="claims"):
        proof.issue_proof(
            "owner-a",
            request,
            expected_provider="password",
            expected_tenant=None,
            expected_claims={"o5role": "editor"},
            fixture_origin=fixture_origin,
            now=int(time.time()),
        )


@pytest.mark.parametrize(
    "custom",
    [
        {},
        {"o5role": "editor"},
        {"name": "Owner", "picture": "https://example.invalid/owner.png"},
        {"phone_number": "+15551234567"},
    ],
)
def test_standard_email_claims_are_not_developer_claims(fixture_origin, custom):
    token = _token(
        custom={
            "email": "owner@example.invalid",
            "email_verified": False,
            **custom,
        }
    )
    _Handler.body = {"localId": "uid-a", "idToken": token}
    request = proof.build_request(
        "signin",
        api_key="fixture-key",
        email="owner@example.invalid",
        password="pw",
        tenant=None,
    )

    issued = proof.issue_proof(
        "owner-a",
        request,
        expected_provider="password",
        expected_tenant=None,
        expected_claims=custom,
        fixture_origin=fixture_origin,
        now=int(time.time()),
    )

    assert issued.claims_digest == digest(custom)


@pytest.mark.parametrize("field", ["name", "picture", "phone_number"])
def test_proof_rejects_unexpected_profile_claims(fixture_origin, field):
    token = _token(
        custom={
            "email": "owner@example.invalid",
            "email_verified": False,
            field: {
                "name": "Owner",
                "picture": "https://example.invalid/owner.png",
                "phone_number": "+15551234567",
            }[field],
        }
    )
    _Handler.body = {"localId": "uid-a", "idToken": token}
    request = proof.build_request(
        "signin",
        api_key="fixture-key",
        email="owner@example.invalid",
        password="pw",
        tenant=None,
    )

    with pytest.raises(ValueError, match="claims"):
        proof.issue_proof(
            "owner-a",
            request,
            expected_provider="password",
            expected_tenant=None,
            expected_claims={},
            fixture_origin=fixture_origin,
            now=int(time.time()),
        )

def test_caller_cannot_construct_a_trusted_proof():
    with pytest.raises(TypeError):
        proof.IdentityProof(
            "owner-a",
            "token",
            "hash",
            "uid",
            "password",
            None,
            digest({}),
            "iss",
            "aud",
            1,
            1,
            2,
            "request",
            object(),
        )


@pytest.fixture(scope="module")
def acknowledged_setup(tmp_path_factory, request):
    """Actual pinned setup workers and durable Gate, never a fabricated event."""
    import o5_user_token_collector as collector
    import o5_user_token_descriptor as lane
    import o5_user_token_production_bridge as bridge
    import shared_gate
    from o8_admission import revoke_production_capability
    from test_o5_user_token_production import _producer_server, _ProducerHandler
    from test_o5_user_token_remote_transport import _fixture_capability

    directory = tmp_path_factory.mktemp("identity-setup")
    plan = lane.plan_compiler("a" * 32)
    frozen = {"plan": plan, "planDigest": digest(plan)}
    frozen["inputsDigest"] = digest(frozen)
    binding, binding_digest = remote.worker_binding()
    capability = _fixture_capability(plan, binding, binding_digest, frozen)
    gate_path = directory / "gate"
    shared_gate.create(
        gate_path, lane.gate_plan(plan, permission_expires_at=time.time() + 1200)
    )
    gate = Gate(gate_path, plan["campaignId"])
    journal = collector.open_ownership_journal(
        directory / "ownership.jsonl",
        run_id="identity-setup",
        plan_digest=plan["planDigest"],
    )
    server = _producer_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    handoffs = {}
    _ProducerHandler._plan = plan
    _ProducerHandler.requests = []
    _ProducerHandler.setup_uids = {}
    failure_after = getattr(request, "param", None)
    _ProducerHandler.fail_setup_after = failure_after
    try:
        with (
            pytest.raises(ValueError, match="setup") if failure_after else nullcontext()
        ):
            bridge.run_bound_setup(
                plan=plan,
                gate=gate,
                credentials={
                    "administrator": "fixture-admin",
                    "api-key": "fixture-key",
                },
                setup_secrets={
                    row["ref"]: "fixture-password" for row in plan["ownedAccounts"]
                },
                account_bindings={},
                capability=capability,
                fixture_origin=origin,
                binding=binding,
                binding_digest=binding_digest,
                journal=journal,
                ownership={},
                identity_handoffs=handoffs,
            )
        assert len(_ProducerHandler.requests) == (
            failure_after + 1 if failure_after else 19
        )
        yield plan, gate, handoffs, origin, _ProducerHandler
    finally:
        revoke_production_capability(capability)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        _ProducerHandler.fail_setup_after = None


def _mint_arguments(setup, ref="owner-a"):
    import hashlib

    plan, gate, handoffs, origin, _handler = setup
    handoff = handoffs[ref]
    event = handoff["event"]
    account = next(row for row in plan["ownedAccounts"] if row["ref"] == ref)
    token, _response_digest, request_digest = handoff["private"].proof_material()
    return {
        "principal_ref": ref,
        "private_handoff": handoff["private"],
        "setup_receipt": handoff["receipt"],
        "gate_authority": gate,
        "gate_acknowledgment": {
            "kind": "setup-ack",
            "principalRef": ref,
            "uid": handoff["receipt"].local_id,
            "tenant": account["tenant"],
            "tokenHash": hashlib.sha256(token.encode()).hexdigest(),
            "requestDigest": request_digest,
            "responseDigest": event["responseDigest"],
            "eventDigest": digest(event),
            "planDigest": gate.snapshot()["planDigest"],
            "nonce": plan["nonce"],
            "slotId": event["id"],
        },
        "expected_provider": "anonymous"
        if account["kind"] == "anonymous"
        else "password",
        "expected_tenant": account["tenant"],
        "expected_claims": account["claims"],
        "request_digest": request_digest,
        "fixture_origin": origin,
    }


def test_setup_ack_mints_sealed_proof_without_network(acknowledged_setup):
    import o5_user_token_production_bridge as bridge

    plan, gate, handoffs, origin, handler = acknowledged_setup
    before = gate.snapshot()
    proofs = bridge.setup_identity_proofs(plan, gate, handoffs, fixture_origin=origin)
    assert set(proofs) == set(handoffs)
    assert all(issued.trusted() for issued in proofs.values())
    assert proofs["owner-a"].claims_digest == digest(
        next(row["claims"] for row in plan["ownedAccounts"] if row["ref"] == "owner-a")
    )
    assert gate.snapshot() == before
    assert len(handler.requests) == 19


@pytest.mark.parametrize("acknowledged_setup", [1], indirect=True)
def test_setup_ack_signup_before_claim_update_has_only_issued_claims(
    acknowledged_setup,
):
    args = _mint_arguments(acknowledged_setup)
    args["expected_claims"] = {}
    before = args["gate_authority"].snapshot()
    issued = proof.mint_acknowledged_setup_proof(**args)
    assert issued.trusted() and issued.claims_digest == digest({})
    args["expected_claims"] = {"o5role": "editor"}
    with pytest.raises(ValueError, match="subject"):
        proof.mint_acknowledged_setup_proof(**args)
    assert args["gate_authority"].snapshot() == before
    assert len(acknowledged_setup[-1].requests) == 2


def test_acknowledged_setup_ignores_standard_email_claims(acknowledged_setup):
    args = _mint_arguments(acknowledged_setup)
    original = args["private_handoff"]
    _token_value, response_digest, handoff_request_digest = original.proof_material()
    token = _token(
        uid=args["setup_receipt"].local_id,
        provider=args["expected_provider"],
        tenant=args["expected_tenant"],
        custom={
            "email": "owner@example.invalid",
            "email_verified": False,
            **args["expected_claims"],
        },
    )
    args["private_handoff"] = remote.SetupPrivateHandoff._issued(
        id_token=token,
        expires_in=original.expires_in_for_followup(),
        response_digest=response_digest,
        request_digest=handoff_request_digest,
    )
    args["gate_acknowledgment"]["tokenHash"] = hashlib.sha256(
        token.encode()
    ).hexdigest()

    issued = proof.mint_acknowledged_setup_proof(**args)

    assert issued.claims_digest == digest(args["expected_claims"])


@pytest.mark.parametrize("field", ["name", "picture", "phone_number"])
def test_acknowledged_setup_rejects_unexpected_profile_claims(
    acknowledged_setup, field
):
    args = _mint_arguments(acknowledged_setup)
    original = args["private_handoff"]
    _token_value, response_digest, handoff_request_digest = original.proof_material()
    token = _token(
        uid=args["setup_receipt"].local_id,
        provider=args["expected_provider"],
        tenant=args["expected_tenant"],
        custom={
            "email": "owner@example.invalid",
            "email_verified": False,
            field: {
                "name": "Owner",
                "picture": "https://example.invalid/owner.png",
                "phone_number": "+15551234567",
            }[field],
            **args["expected_claims"],
        },
    )
    args["private_handoff"] = remote.SetupPrivateHandoff._issued(
        id_token=token,
        expires_in=original.expires_in_for_followup(),
        response_digest=response_digest,
        request_digest=handoff_request_digest,
    )
    args["gate_acknowledgment"]["tokenHash"] = hashlib.sha256(
        token.encode()
    ).hexdigest()

    with pytest.raises(ValueError, match="claims"):
        proof.mint_acknowledged_setup_proof(**args)


@pytest.mark.parametrize(
    "mutation",
    [
        "principal",
        "nonce",
        "slot",
        "uid",
        "token",
        "request",
        "response",
        "event",
        "plan",
        "claims",
        "foreign-handoff",
        "foreign-receipt",
        "raw-as-wrapper",
    ],
)
def test_setup_ack_rejects_token_or_gate_binding_changes(acknowledged_setup, mutation):
    args = _mint_arguments(acknowledged_setup)
    ack = args["gate_acknowledgment"]
    if mutation == "principal":
        # All caller labels agree; only the real durable event contradicts them.
        args["principal_ref"] = ack["principalRef"] = "other-b"
    elif mutation == "nonce":
        ack["nonce"] = "b" * 32
    elif mutation == "slot":
        ack["slotId"] = "observation:setup/account/other-b/signup"
    elif mutation == "uid":
        ack["uid"] = "foreign-uid"
    elif mutation == "token":
        ack["tokenHash"] = "e" * 64
    elif mutation == "request":
        args["request_digest"] = ack["requestDigest"] = "e" * 64
    elif mutation == "response":
        ack["responseDigest"] = "e" * 64
    elif mutation == "event":
        ack["eventDigest"] = "e" * 64
    elif mutation == "plan":
        ack["planDigest"] = "e" * 64
    elif mutation == "claims":
        args["expected_claims"] = {}
    elif mutation == "foreign-handoff":
        args["private_handoff"] = acknowledged_setup[2]["other-b"]["private"]
        token, _, request_digest = args["private_handoff"].proof_material()
        ack["tokenHash"] = __import__("hashlib").sha256(token.encode()).hexdigest()
        args["request_digest"] = ack["requestDigest"] = request_digest
    elif mutation == "foreign-receipt":
        args["setup_receipt"] = acknowledged_setup[2]["other-b"]["receipt"]
        ack["uid"] = args["setup_receipt"].local_id
    elif mutation == "raw-as-wrapper":
        ack["responseDigest"] = args["private_handoff"].proof_material()[1]
    before = args["gate_authority"].snapshot()
    with pytest.raises(ValueError):
        proof.mint_acknowledged_setup_proof(**args)
    assert args["gate_authority"].snapshot() == before
    assert len(acknowledged_setup[-1].requests) == 19


def test_issuance_proof_binds_the_same_token_before_firestore(fixture_origin):
    token = _token(uid="uid-owner-a", custom={"o5role": "editor"})
    _Handler.body = {"localId": "uid-owner-a", "idToken": token}
    request = proof.build_request(
        "signin",
        api_key="fixture-key",
        email="a@example.invalid",
        password="pw",
        tenant=None,
    )
    issued = proof.issue_proof(
        "owner-a",
        request,
        expected_provider="password",
        expected_tenant=None,
        expected_claims={"o5role": "editor"},
        fixture_origin=fixture_origin,
        now=int(time.time()),
    )
    plan = compile_case("fireemu-35fe6", "(default)", "a" * 32, "tenant1234")
    operation = _request(plan["observation"][0], plan["nonce"])
    bindings = {
        "owner-a": {
            "uid": "uid-owner-a",
            "provider": "password",
            "tenant": None,
            "claimsDigest": digest({"o5role": "editor"}),
        }
    }
    prepared = remote.prepare_request(
        plan,
        operation,
        credentials={"owner-a": token},
        account_bindings=bindings,
        identity_proofs={"owner-a": issued},
    )
    assert prepared["headers"]["Authorization"] == "Bearer " + token
    with pytest.raises(ValueError, match="trusted identity proof"):
        remote.prepare_request(
            plan,
            operation,
            credentials={"owner-a": "different-token"},
            account_bindings=bindings,
            identity_proofs={"owner-a": issued},
        )


def test_fixture_proof_cannot_cross_fixture_or_production_origin(fixture_origin):
    token = _token(uid="uid-owner-a", custom={"o5role": "editor"})
    _Handler.body = {"localId": "uid-owner-a", "idToken": token}
    request = proof.build_request(
        "signin",
        api_key="fixture-key",
        email="a@example.invalid",
        password="pw",
        tenant=None,
    )
    issued = proof.issue_proof(
        "owner-a",
        request,
        expected_provider="password",
        expected_tenant=None,
        expected_claims={"o5role": "editor"},
        fixture_origin=fixture_origin,
        now=int(time.time()),
    )
    plan = compile_case("fireemu-35fe6", "(default)", "a" * 32, "tenant1234")
    with pytest.raises(ValueError, match="origin or mode"):
        remote.make_transport(
            plan,
            credentials={},
            identity_proofs={"owner-a": issued},
            fixture_origin="http://127.0.0.1:19999",
        )
    with pytest.raises(ValueError, match="origin or mode"):
        remote.make_transport(plan, credentials={}, identity_proofs={"owner-a": issued})
