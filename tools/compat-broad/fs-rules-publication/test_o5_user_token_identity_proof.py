from __future__ import annotations

import base64
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import o5_user_token_identity_proof as proof
import o5_user_token_remote_transport as remote
import pytest
from broad_contract import digest
from shared_gate import Gate
from o5_user_token_case import compile_case
from o5_user_token_collector import _request

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
        port = int(reservation["port"]) if reservation is not None else int(server.server_address[1])
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


def test_setup_ack_mints_sealed_proof_without_network(tmp_path):
    token = _token(uid="fresh-uid", custom={"o5role": "editor"})
    request_digest = digest({"setup": "signup"})
    item = {"id": "account/owner-a/signup", "service": "identity", "route": "accounts:signUp", "accountRef": "owner-a", "response": {"localId": "response-bound", "idToken": "response-bound", "expiresIn": "response-bound"}}
    response_body = {"localId": "fresh-uid", "idToken": token, "expiresIn": "3600"}
    setup_result = remote.adapt_setup_result(item, {"status": 200, "body": response_body}, endpoint="fixture", sequence=1, request_digest=request_digest)
    handoff, receipt = setup_result.private, setup_result.receipt
    plan = {"kind": "setup-test-plan"}
    event = {"id": "setup/account/owner-a/signup", "completed": True, "workerReaped": True, "responseDigest": digest(response_body)}
    gate_path = tmp_path / "gate"
    gate_path.mkdir(mode=0o700, exist_ok=True)
    (gate_path / "lock").write_text("")
    (gate_path / "state.json").write_text(json.dumps({"plan": plan, "planDigest": digest(plan), "managementEvents": [event]}))
    os.chmod(gate_path / "lock", 0o600)
    os.chmod(gate_path / "state.json", 0o600)
    gate = Gate(gate_path, {})
    acknowledgment = {
        "kind": "setup-ack",
        "principalRef": "owner-a",
        "uid": "fresh-uid",
        "tenant": None,
        "tokenHash": __import__("hashlib").sha256(token.encode()).hexdigest(),
        "requestDigest": request_digest,
        "responseDigest": digest(response_body),
        "eventDigest": digest(event),
        "planDigest": digest(plan),
        "nonce": "d" * 32,
        "slotId": "setup/account/owner-a/signup",
    }
    issued = proof.mint_acknowledged_setup_proof(
        "owner-a",
        private_handoff=handoff,
        setup_receipt=receipt,
        gate_authority=gate,
        gate_acknowledgment=acknowledgment,
        expected_provider="password",
        expected_tenant=None,
        expected_claims={"o5role": "editor"},
        request_digest=request_digest,
        fixture_origin="http://127.0.0.1:12345",
        now=int(time.time()),
    )
    assert issued.trusted() and issued.uid == "fresh-uid"
    assert issued.request_digest == request_digest


def test_setup_ack_rejects_token_or_gate_binding_changes(tmp_path):
    token = _token(uid="fresh-uid")
    request_digest = digest({"setup": "signup"})
    item = {"id": "account/owner-a/signup", "service": "identity", "route": "accounts:signUp", "accountRef": "owner-a", "response": {"localId": "response-bound", "idToken": "response-bound", "expiresIn": "response-bound"}}
    response_body = {"localId": "fresh-uid", "idToken": token, "expiresIn": "3600"}
    setup_result = remote.adapt_setup_result(item, {"status": 200, "body": response_body}, endpoint="fixture", sequence=1, request_digest=request_digest)
    handoff, receipt = setup_result.private, setup_result.receipt
    plan = {"kind": "setup-test-plan"}
    event = {"id": "setup/account/owner-a/signup", "completed": True, "workerReaped": True, "responseDigest": digest(response_body)}
    gate_path = tmp_path / "gate"
    gate_path.mkdir(mode=0o700, exist_ok=True)
    (gate_path / "lock").write_text("")
    (gate_path / "state.json").write_text(json.dumps({"plan": plan, "planDigest": digest(plan), "managementEvents": [event]}))
    os.chmod(gate_path / "lock", 0o600)
    os.chmod(gate_path / "state.json", 0o600)
    gate = Gate(gate_path, {})
    acknowledgment = {"kind": "setup-ack", "principalRef": "owner-a", "uid": "fresh-uid", "tenant": None, "tokenHash": __import__("hashlib").sha256(token.encode()).hexdigest(), "requestDigest": request_digest, "responseDigest": digest(response_body), "eventDigest": digest(event), "planDigest": digest(plan), "nonce": "d" * 32, "slotId": "setup/account/owner-a/signup"}
    for mutation in ({"tokenHash": "e" * 64}, {"principalRef": "other"}, {"uid": "other"}):
        candidate = {**acknowledgment, **mutation}
        with pytest.raises(ValueError):
            proof.mint_acknowledged_setup_proof("owner-a", private_handoff=handoff, setup_receipt=receipt, gate_authority=gate, gate_acknowledgment=candidate, expected_provider="password", expected_tenant=None, expected_claims={}, request_digest=request_digest, now=int(time.time()))


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
