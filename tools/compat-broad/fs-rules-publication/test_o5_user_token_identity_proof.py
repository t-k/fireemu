from __future__ import annotations

import base64
import http.server
import json
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
from o5_user_token_case import compile_case
from o5_user_token_collector import _request

PORTCTL = Path("/Users/tk/.agents/skills/port-registry/scripts/portctl.py")


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
    claim = subprocess.run(
        [
            sys.executable,
            str(PORTCTL),
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
    server = socketserver.TCPServer(("127.0.0.1", int(reservation["port"])), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{reservation['port']}"
    finally:
        server.shutdown()
        server.server_close()
        subprocess.run(
            [sys.executable, str(PORTCTL), "release", "--token", reservation["token"]],
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
