from __future__ import annotations

import base64
import dataclasses
import hashlib
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
from urllib.parse import quote

import o5_user_token_identity_proof as identity_proof
import o5_user_token_remote_transport as remote
import pytest
from broad_contract import digest
from o5_user_token_case import compile_case, principal_actions
from o5_user_token_collector import RECOVERY_RECEIPT_KEYS, _accept, _request
from o8_admission import (
    _ACTIVE,
    _CAPABILITY_STATE,
    _CAPABILITY_TOKEN,
    ProductionWireCapability,
)

ROOT = Path(__file__).resolve().parents[3]
PORTCTL = os.environ.get("FIREEMU_PORTCTL")


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    requests: ClassVar[list[dict[str, object]]] = []
    issuance_body: ClassVar[dict[str, object] | None] = None
    response_status: ClassVar[int | None] = None
    response_body: ClassVar[dict[str, object] | None] = None

    def do_POST(self) -> None:
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        self.__class__.requests.append(
            {
                "method": "POST",
                "path": self.path,
                "body": body,
                "headers": dict(self.headers),
            }
        )
        if self.__class__.response_status is not None:
            payload = json.dumps(self.__class__.response_body or {}).encode()
            status = self.__class__.response_status
        elif self.path.startswith("/v1/accounts:"):
            payload = json.dumps(self.__class__.issuance_body or {}).encode()
            status = 200
        elif self.path.endswith("/documents:commit"):
            request_json = json.loads(body)
            writes = request_json.get("writes", [])
            payload = json.dumps(
                {
                    "writeResults": [
                        {"updateTime": "2026-09-22T00:00:00Z"} for _ in writes
                    ],
                    "commitTime": "2026-09-22T00:00:00Z",
                }
            ).encode()
            status = 200
        else:
            payload = json.dumps(
                {
                    "name": self.path.removeprefix("/v1/"),
                    "fields": {},
                }
            ).encode()
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST
    do_DELETE = do_POST

    def log_message(self, *_args: object) -> None:
        return


class _DelayedObservationHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        time.sleep(2.2)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args: object) -> None:
        return


class _FreshSetupHandler(http.server.BaseHTTPRequestHandler):
    def do_PATCH(self) -> None:
        payload = {"name": self.path.removeprefix("/v1/").split("?", 1)[0], "fields": {}, "updateTime": "2026-09-22T00:00:00Z"}
        self._reply(payload)

    def do_POST(self) -> None:
        if self.path.endswith("accounts:update"):
            payload = {"localId": "fresh-uid-7", "displayName": "owner"}
        else:
            payload = {"localId": "fresh-uid-7", "idToken": "fresh-token", "expiresIn": "3600"}
        self._reply(payload)

    def _reply(self, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args: object) -> None:
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
                "o5-user-token-test",
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
        port = int(reservation["port"])
        server = socketserver.TCPServer(("127.0.0.1", port), _FixtureHandler)
    else:
        server = socketserver.TCPServer(("127.0.0.1", 0), _FixtureHandler)
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
        _FixtureHandler.response_status = None
        _FixtureHandler.response_body = None
        if reservation is not None:
            subprocess.run(
                [
                    sys.executable,
                    PORTCTL,
                    "release",
                    "--token",
                    reservation["token"],
                ],
                check=True,
                capture_output=True,
                text=True,
            )


@pytest.fixture
def plan():
    return compile_case("fireemu-35fe6", "(default)", "a" * 32, "tenant1234")


def collector_request(plan, index):
    return _request(plan["observation"][index], plan["nonce"])


def account_bindings(plan):
    return {
        account["ref"]: {
            "uid": "uid-" + account["ref"],
            "provider": "anonymous" if account["kind"] == "anonymous" else "password",
            "tenant": account["tenant"],
            "claimsDigest": digest(account["claims"]),
        }
        for account in plan["ownedAccounts"]
    }


def minimal_wire_plan(method="get", operation="create"):
    resource = (
        "projects/fireemu-35fe6/databases/(default)/documents/"
        "o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/review-doc"
    )
    row = {
        "caseId": "review-wire-contract",
        "index": 0,
        "ruleset": "A",
        "method": method,
        "resources": [resource],
        "writes": (
            [{"document": "review-doc", "operation": operation, "fields": {"count": 1}}]
            if method == "commit"
            else None
        ),
        "createdDocuments": ["review-doc"] if method == "commit" and operation == "create" else [],
        "credential": {"ref": "unauthenticated", "class": "absent"},
        "principal": None,
    }
    return {
        "campaignId": remote.CAMPAIGN,
        "project": "fireemu-35fe6",
        "database": "(default)",
        "nonce": "a" * 32,
        "tenant": "tenant1234",
        "ownedAccounts": [],
        "ownedResources": [resource],
        "observation": [row],
        "rulesets": {"A": {"source": "rules-a"}, "B": {"source": "rules-b"}},
    }, row, resource


def _setup_fixture_plan():
    resource = (
        "projects/fireemu-35fe6/databases/(default)/documents/"
        "o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/setup-doc"
    )
    return {
        "fixtures": [{"document": "setup-doc", "resource": resource, "fields": {}}],
        "ownedAccounts": [
            {
                "ref": "owner-a",
                "email": "owner@example.test",
                "tenant": None,
                "claims": {"owner": "yes"},
            }
        ],
    }


def test_setup_fixture_uses_bound_patch_and_official_loopback_response(fixture_origin):
    plan = _setup_fixture_plan()
    item = {
        "id": "fixture/setup-doc",
        "service": "firestore",
        "route": "document-create",
        "method": "PATCH",
        "path": "/v1/" + plan["fixtures"][0]["resource"] + "?currentDocument.exists=false",
        "document": "setup-doc",
        "resource": plan["fixtures"][0]["resource"],
        "fields": {},
        "fieldsDigest": digest({}),
        "precondition": {"exists": False},
        "response": {
            "name": plan["fixtures"][0]["resource"],
            "fieldsDigest": digest({}),
            "updateTime": "response-bound",
        },
    }
    request = remote.prepare_setup_request(
        plan, item, credentials={"administrator": "fixture-admin"}
    )
    assert request["path"].startswith("/v1/projects/fireemu-35fe6/")
    result = {
        "status": 200,
        "body": {
            "name": plan["fixtures"][0]["resource"],
            "fields": {},
            "updateTime": "2026-09-22T00:00:00Z",
        },
    }
    got = remote.adapt_setup_result(item, result, endpoint="loopback", sequence=1)
    assert got.receipt.name == plan["fixtures"][0]["resource"]
    assert got.receipt.fields_digest == digest({})
    assert "fixture-admin" not in json.dumps(got.receipt.as_dict())


def test_setup_claim_update_requires_route_specific_owner_binding():
    plan = _setup_fixture_plan()
    item = {
        "id": "account/owner-a/claim-update",
        "service": "identity",
        "route": "accounts:update",
        "method": "POST",
        "accountRef": "owner-a",
        "tenant": None,
        "claimsDigest": digest(plan["ownedAccounts"][0]["claims"]),
        "response": {"localId": "response-bound"},
    }
    with pytest.raises(ValueError, match="owner UID binding required"):
        remote.prepare_setup_request(
            plan,
            item,
            credentials={"administrator": "fixture-admin"},
            setup_secrets={"owner-a": "secret"},
        )


def test_setup_signup_and_signin_use_client_api_key_routes():
    plan = _setup_fixture_plan()
    signup = {
        "id": "account/owner-a/signup",
        "service": "identity",
        "route": "accounts:signUp",
        "method": "POST",
        "accountRef": "owner-a",
        "tenant": None,
        "response": {"localId": "response-bound", "idToken": "response-bound", "expiresIn": "response-bound"},
    }
    signin = {**signup, "id": "account/owner-a/signin", "route": "accounts:signInWithPassword"}
    for item in (signup, signin):
        request = remote.prepare_setup_request(
            plan,
            item,
            credentials={"administrator": "fixture-admin", "api-key": "fixture-key"},
            account_bindings={"owner-a": {"uid": "uid-owner-a"}},
            setup_secrets={"owner-a": "secret"},
        )
        assert request["path"] == f"/v1/{item['route']}?key=fixture-key"
        assert "Authorization" not in request["headers"]
        assert request["body"]["returnSecureToken"] is True


def test_transport_accepts_bounded_deadline_and_timeout_parameters():
    plan, _operation, _resource = minimal_wire_plan()
    with pytest.raises(ValueError, match="bounded transport timeout"):
        remote.make_transport(plan, credentials={}, timeout_seconds=remote.MAX_SECONDS + 0.01)
    with pytest.raises(ValueError, match="absolute transport deadline"):
        remote.make_transport(plan, credentials={}, deadline=float("nan"))
    transport = remote.make_transport(plan, credentials={}, timeout_seconds=2.0, deadline=time.monotonic() + 3.0)
    assert callable(transport)


def test_two_second_transport_deadline_reaps_loopback_worker():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _DelayedObservationHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        source, source_digest = remote.worker_binding()
        envelope = {
            "service": "firestore",
            "route": "observation-get",
            "method": "GET",
            "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/owned-a",
            "headers": {"x-goog-user-project": "fireemu-35fe6"},
            "body": None,
            "seconds": 2.0,
        }
        with pytest.raises(remote.WorkerExchangeError, match="walltime") as error:
            remote.run_worker(
                envelope,
                binding=source,
                binding_digest=source_digest,
                fixture_origin=f"http://127.0.0.1:{server.server_port}",
            )
        assert error.value.worker_reaped is True
        assert not remote._OWNED_CHILDREN
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_per_call_deadline_cannot_extend_factory_timeout():
    plan, operation, _resource = minimal_wire_plan()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _DelayedObservationHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source, source_digest = remote.worker_binding()
    frozen = {"plan": plan, "planDigest": digest(plan)}
    frozen["inputsDigest"] = digest(frozen)
    capability = _fixture_capability(plan, source, source_digest, frozen)
    try:
        transmit = remote.make_transport(
            plan,
            credentials={"unauthenticated": ""},
            frozen_inputs=frozen,
            identity_proofs={},
            fixture_origin=f"http://127.0.0.1:{server.server_port}",
            timeout_seconds=0.1,
        )
        with pytest.raises(remote.WorkerExchangeError, match="walltime|reap reserve"):
            transmit(
                operation,
                binding=source,
                binding_digest=source_digest,
                capability=capability,
                timeout_seconds=2.0,
                deadline=time.monotonic() + 3.0,
            )
    finally:
        _ACTIVE.discard(capability)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_setup_transport_derives_fresh_uid_before_claims_and_signin():
    plan = _setup_fixture_plan()
    plan.update({"campaignId": remote.CAMPAIGN, "project": "fireemu-35fe6", "database": "(default)", "nonce": "a" * 32, "tenant": "tenant1234"})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FreshSetupHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    source, source_digest = remote.worker_binding()
    frozen = {"plan": plan, "planDigest": digest(plan)}
    frozen["inputsDigest"] = digest(frozen)
    capability = _fixture_capability(plan, source, source_digest, frozen)
    try:
        transport = remote.make_setup_transport(
            plan,
            credentials={"administrator": "fixture-admin", "api-key": "fixture-key"},
            setup_secrets={"owner-a": "secret"},
            frozen_inputs=frozen,
            capability=capability,
            fixture_origin=f"http://127.0.0.1:{server.server_port}",
        )
        signup = {"id": "account/owner-a/signup", "service": "identity", "route": "accounts:signUp", "method": "POST", "accountRef": "owner-a", "tenant": None, "response": {"localId": "response-bound", "idToken": "response-bound", "expiresIn": "response-bound"}}
        signin = {**signup, "id": "account/owner-a/signin", "route": "accounts:signInWithPassword"}
        claims = {"id": "account/owner-a/claim-update", "service": "identity", "route": "accounts:update", "method": "POST", "accountRef": "owner-a", "tenant": None, "claimsDigest": digest({"owner": "yes"}), "response": {"localId": "response-bound"}}
        result = transport(signup, binding=source, binding_digest=source_digest)
        assert result.receipt.local_id == "fresh-uid-7"
        transport(claims, binding=source, binding_digest=source_digest)
        signin_result = transport(signin, binding=source, binding_digest=source_digest)
        assert signin_result.receipt.local_id == "fresh-uid-7"
    finally:
        _ACTIVE.discard(capability)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_recovery_transport_requires_nonempty_sealed_partial_proofs():
    plan, _operation, _resource = minimal_wire_plan()
    with pytest.raises(ValueError, match="acknowledged identity proofs"):
        remote.make_recovery_transport(
            plan,
            credentials={"administrator": "fixture-admin"},
            frozen_inputs={"plan": plan, "planDigest": digest(plan), "inputsDigest": digest({"plan": plan, "planDigest": digest(plan)})},
            identity_proofs={},
            capability=object(),
        )


def test_principal_action_readback_is_a_separate_typed_request():
    plan = {"campaignId": remote.CAMPAIGN, "project": "fireemu-35fe6", "database": "(default)", "nonce": "a" * 32, "tenant": "tenant1234", "ownedAccounts": [{"ref": "owner-a", "tenant": None}]}
    operation = {"kind": "principal-action-readback", "phase": "principal", "principalRef": "owner-a", "credentialRef": "administrator", "credentialClass": "administrator"}
    request = remote.prepare_request(plan, operation, credentials={"administrator": "fixture-admin"}, account_bindings={"owner-a": {"uid": "fresh-uid", "tenant": None}})
    assert request["route"] == "principal-action-readback"
    assert request["path"] == "/v1/projects/fireemu-35fe6/accounts:lookup"
    assert request["body"] == {"localId": ["fresh-uid"]}


def test_setup_auth_token_is_private_and_public_receipt_is_redacted():
    item = {
        "id": "account/owner-a/signin",
        "service": "identity",
        "route": "accounts:signInWithPassword",
        "method": "POST",
        "accountRef": "owner-a",
        "tenant": None,
        "response": {
            "localId": "response-bound",
            "idToken": "response-bound",
            "expiresIn": "response-bound",
        },
    }
    result = remote.adapt_setup_result(
        item,
        {"status": 200, "body": {"localId": "uid-owner-a", "idToken": "secret-token", "expiresIn": "3600"}},
        endpoint="loopback",
        sequence=1,
        account_bindings={"owner-a": {"uid": "uid-owner-a"}},
    )
    assert result.receipt.local_id == "uid-owner-a"
    assert result.private.token_for_followup() == "secret-token"
    serialized = json.dumps(result.receipt.as_dict())
    assert "secret-token" not in serialized
    assert "password" not in serialized
    assert "secret-token" not in repr(result)
    assert "secret-token" not in repr(result.private)
    with pytest.raises(TypeError):
        dataclasses.asdict(result)


@pytest.mark.parametrize(
    "body",
    [
        {"localId": "uid-owner-a", "idToken": "", "expiresIn": "3600"},
        {"localId": "uid-owner-a", "idToken": "token", "expiresIn": "0"},
        {"localId": "uid-owner-a", "idToken": "token", "expiresIn": "not-a-duration"},
    ],
)
def test_setup_auth_token_response_requires_nonempty_token_and_positive_expiry(body):
    item = {
        "id": "account/owner-a/signin",
        "service": "identity",
        "route": "accounts:signInWithPassword",
        "method": "POST",
        "accountRef": "owner-a",
        "tenant": None,
        "response": {"localId": "response-bound", "idToken": "response-bound", "expiresIn": "response-bound"},
    }
    with pytest.raises(ValueError, match="setup token response refused"):
        remote.adapt_setup_result(item, {"status": 200, "body": body}, endpoint="loopback", sequence=1, account_bindings={"owner-a": {"uid": "uid-owner-a"}})


def _fixture_token(uid, provider, tenant, claims):
    now = int(time.time())
    firebase = {"sign_in_provider": provider}
    if tenant is not None:
        firebase["tenant"] = tenant
    payload = {
        "iss": "https://securetoken.google.com/fireemu-35fe6",
        "aud": "fireemu-35fe6",
        "sub": uid,
        "user_id": uid,
        "iat": now - 1,
        "auth_time": now - 1,
        "exp": now + 3600,
        "firebase": firebase,
        **claims,
    }
    segment = lambda value: (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    return segment({"alg": "RS256", "typ": "JWT"}) + "." + segment(payload) + ".fixture"


def _fixture_proofs(plan, fixture_origin):
    proofs = {}
    for account in plan["ownedAccounts"]:
        provider = "anonymous" if account["kind"] == "anonymous" else "password"
        claims = account["claims"]
        token = _fixture_token(
            "uid-" + account["ref"], provider, account["tenant"], claims
        )
        _FixtureHandler.issuance_body = {
            "localId": "uid-" + account["ref"],
            "idToken": token,
            "expiresIn": "3600",
        }
        request = identity_proof.build_request(
            "signup",
            api_key="fixture-key",
            email=None if provider == "anonymous" else account["email"],
            password=None if provider == "anonymous" else "fixture-password",
            tenant=account["tenant"],
        )
        proofs[account["ref"]] = identity_proof.issue_proof(
            account["ref"],
            request,
            expected_provider=provider,
            expected_tenant=account["tenant"],
            expected_claims=claims,
            fixture_origin=fixture_origin,
            now=int(time.time()),
        )
    return proofs


def _fixture_capability(
    plan, source, source_digest, frozen, *, window_seconds: float = 60
):
    if type(window_seconds) not in (int, float) or not 0 < window_seconds:
        raise ValueError("fixture capability window must be positive")
    window_seconds = float(window_seconds)
    capability = ProductionWireCapability(
        _CAPABILITY_TOKEN,
        binding=source,
        binding_digest=source_digest,
        campaign_id=remote.CAMPAIGN,
        window_seconds=window_seconds,
        inputs_digest=frozen["inputsDigest"],
        ledger_root="fixture-ledger",
        window_starts_at=time.time() - 1,
        window_expires_at=time.time() + window_seconds,
        approval_digest="f" * 64,
        transport_bound=True,
    )
    _ACTIVE.add(capability)
    return capability


def ruleset_request(plan, label):
    from o5_user_token_collector import digest as collector_digest

    return {
        "kind": "ruleset-release",
        "phase": "ruleset",
        "ruleset": label,
        "sourceDigest": collector_digest(plan["rulesets"][label]["source"]),
        "credentialRef": "administrator",
        "credentialClass": "administrator",
    }


@pytest.mark.parametrize(
    ("action", "extra", "route", "method"),
    [
        ("create", {"label": "A", "sourceDigest": digest("rules-a")}, "ruleset-create", "POST"),
        ("get", {"rulesetName": "projects/fireemu-35fe6/rulesets/ruleset-a"}, "ruleset-get", "GET"),
        ("delete", {"rulesetName": "projects/fireemu-35fe6/rulesets/ruleset-a"}, "ruleset-delete", "DELETE"),
        ("release-get", {"releaseName": "projects/fireemu-35fe6/releases/cloud.firestore"}, "release-get", "GET"),
        ("release-patch", {"releaseName": "projects/fireemu-35fe6/releases/cloud.firestore", "rulesetName": "projects/fireemu-35fe6/rulesets/ruleset-a"}, "release-patch", "PATCH"),
        ("release-get-executable", {"releaseName": "projects/fireemu-35fe6/releases/cloud.firestore"}, "release-get-executable", "GET"),
    ],
)
def test_rules_lifecycle_routes_are_closed(plan, action, extra, route, method):
    plan = dict(plan, rulesets={"A": {"source": "rules-a"}, "B": {"source": "rules-b"}})
    operation = {"kind": "rules-lifecycle", "phase": "ruleset", "action": action, **extra}
    request = remote.prepare_request(plan, operation, credentials={"administrator": "fixture-admin"})
    assert request["route"] == route
    assert request["method"] == method
    assert request["origin"] == remote.RULES_ORIGIN


def test_rules_lifecycle_rejects_arbitrary_project_and_release_path(plan):
    operation = {"kind": "rules-lifecycle", "phase": "ruleset", "action": "release-get", "releaseName": "projects/other/releases/x"}
    with pytest.raises(ValueError, match="release resource shape refused"):
        remote.prepare_request(plan, operation, credentials={"administrator": "fixture-admin"})


def test_prepare_accepts_every_actual_collector_observation(plan):
    credentials = {
        "owner-a": "fixture-a",
        "owner-b": "fixture-b",
        "owner-c": "fixture-c",
        "owner-d": "fixture-d",
        "owner-e": "fixture-e",
        "owner-f": "fixture-f",
        "owner-g": "fixture-g",
        "malformed-bearer": "malformed",
        "empty-bearer": "",
    }
    credentials.update(
        {
            operation["credential"]["ref"]: "fixture-token"
            for operation in plan["observation"]
            if operation["credential"]["class"] == "user-id-token"
        }
    )
    for index in range(33):
        prepared = remote.prepare_request(
            plan,
            collector_request(plan, index),
            credentials=credentials,
            account_bindings=account_bindings(plan),
        )
        assert prepared["service"] == "firestore"
        assert prepared["route"] in {"observation-get", "observation-commit"}


def test_prepare_observation_binds_project_nonce_and_principal(plan):
    operation = plan["observation"][0]
    prepared = remote.prepare_request(
        plan,
        operation,
        credentials={"owner-a": "fixture-user-token", "administrator": "fixture-admin"},
    )
    assert prepared["origin"] == remote.FIRESTORE_ORIGIN
    assert prepared["path"].startswith(
        "/v1/projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/na"
    )
    assert prepared["headers"]["Authorization"] == "Bearer fixture-user-token"
    assert "fixture-user-token" not in json.dumps(operation)


def test_prepare_rejects_foreign_project_and_nonce(plan):
    operation = dict(plan["observation"][0])
    operation["resources"] = [
        operation["resources"][0].replace("fireemu-35fe6", "other-project")
    ]
    with pytest.raises(ValueError, match="project binding"):
        remote.prepare_request(plan, operation, credentials={"owner-a": "fixture"})

    operation = dict(plan["observation"][0])
    operation["resources"] = [
        operation["resources"][0].replace("/n" + "a" * 32, "/n" + "b" * 32)
    ]
    with pytest.raises(ValueError, match="nonce binding"):
        remote.prepare_request(plan, operation, credentials={"owner-a": "fixture"})


def test_prepare_rejects_unbound_principal_and_unknown_shape(plan):
    operation = dict(plan["observation"][0])
    operation["credential"] = {"class": "user-id-token", "ref": "not-owned"}
    with pytest.raises(ValueError, match="principal binding"):
        remote.prepare_request(plan, operation, credentials={"not-owned": "fixture"})

    operation = dict(plan["observation"][0])
    operation["method"] = "delete-all"
    with pytest.raises(ValueError, match="operation shape"):
        remote.prepare_request(plan, operation, credentials={"owner-a": "fixture"})


def test_prepare_accepts_actual_multi_resource_commit_rows(plan):
    for index, count in ((16, 2), (17, 1), (18, 2)):
        prepared = remote.prepare_request(
            plan,
            collector_request(plan, index),
            credentials={"owner-a": "fixture"},
            account_bindings=account_bindings(plan),
        )
        assert prepared["method"] == "POST"
        assert prepared["path"].endswith("/documents:commit")
        assert len(prepared["body"]["writes"]) == count
        assert all(
            "$principal" not in json.dumps(write)
            for write in prepared["body"]["writes"]
        )
        for write in prepared["body"]["writes"]:
            assert write["update"]["name"].startswith("projects/fireemu-35fe6/")
            assert not write["update"]["name"].startswith("/v1/")
            assert "currentDocument" in write


def test_transport_adapts_official_document_response_through_real_worker(fixture_origin):
    plan, operation, resource = minimal_wire_plan()
    _FixtureHandler.response_status = 200
    _FixtureHandler.response_body = {
        "name": resource,
        "fields": {"count": {"integerValue": "1"}},
        "createTime": "2026-09-22T00:00:00Z",
        "updateTime": "2026-09-22T00:00:00Z",
    }
    source, source_digest = remote.worker_binding()
    frozen = {"plan": plan, "planDigest": digest(plan)}
    frozen["inputsDigest"] = digest(frozen)
    capability = _fixture_capability(plan, source, source_digest, frozen)
    try:
        transmit = remote.make_transport(
            plan,
            credentials={"unauthenticated": ""},
            frozen_inputs=frozen,
            identity_proofs={},
            fixture_origin=fixture_origin,
        )
        got = transmit(
            operation,
            binding=source,
            binding_digest=source_digest,
            capability=capability,
        )
    finally:
        _ACTIVE.discard(capability)
    assert got == {
        "status": "OK",
        "code": 0,
        "httpStatus": 200,
        "documentPresent": True,
        "fields": {"count": 1},
        "responseDigest": digest(_FixtureHandler.response_body),
        "complete": True,
        "workerReaped": True,
        "endpoint": fixture_origin.removeprefix("http://"),
        "wireSequence": 1,
    }


def test_transport_rejects_forged_normalized_firestore_document_response(fixture_origin):
    plan, operation, _resource = minimal_wire_plan()
    _FixtureHandler.response_status = 200
    _FixtureHandler.response_body = {"complete": True, "status": "OK"}
    source, source_digest = remote.worker_binding()
    frozen = {"plan": plan, "planDigest": digest(plan)}
    frozen["inputsDigest"] = digest(frozen)
    capability = _fixture_capability(plan, source, source_digest, frozen)
    try:
        transmit = remote.make_transport(
            plan,
            credentials={"unauthenticated": ""},
            frozen_inputs=frozen,
            identity_proofs={},
            fixture_origin=fixture_origin,
        )
        with pytest.raises(ValueError, match="REST Document response shape refused"):
            transmit(
                operation,
                binding=source,
                binding_digest=source_digest,
                capability=capability,
            )
    finally:
        _ACTIVE.discard(capability)


def test_transport_rejects_malformed_firestore_typed_value(fixture_origin):
    plan, operation, resource = minimal_wire_plan()
    _FixtureHandler.response_status = 200
    _FixtureHandler.response_body = {
        "name": resource,
        "fields": {"count": {"stringValue": {"not": "a string"}}},
    }
    source, source_digest = remote.worker_binding()
    frozen = {"plan": plan, "planDigest": digest(plan)}
    frozen["inputsDigest"] = digest(frozen)
    capability = _fixture_capability(plan, source, source_digest, frozen)
    try:
        transmit = remote.make_transport(
            plan,
            credentials={"unauthenticated": ""},
            frozen_inputs=frozen,
            identity_proofs={},
            fixture_origin=fixture_origin,
        )
        with pytest.raises(ValueError, match="Firestore string value refused"):
            transmit(
                operation,
                binding=source,
                binding_digest=source_digest,
                capability=capability,
            )
    finally:
        _ACTIVE.discard(capability)


def test_transport_adapts_official_commit_response_through_real_worker(fixture_origin):
    plan, operation, _resource = minimal_wire_plan("commit", "create")
    _FixtureHandler.response_status = 200
    _FixtureHandler.response_body = {
        "writeResults": [{"updateTime": "2026-09-22T00:00:00Z"}],
        "commitTime": "2026-09-22T00:00:00Z",
    }
    source, source_digest = remote.worker_binding()
    frozen = {"plan": plan, "planDigest": digest(plan)}
    frozen["inputsDigest"] = digest(frozen)
    capability = _fixture_capability(plan, source, source_digest, frozen)
    try:
        transmit = remote.make_transport(
            plan,
            credentials={"unauthenticated": ""},
            frozen_inputs=frozen,
            identity_proofs={},
            fixture_origin=fixture_origin,
        )
        got = transmit(
            operation,
            binding=source,
            binding_digest=source_digest,
            capability=capability,
        )
    finally:
        _ACTIVE.discard(capability)
    assert got["status"] == "OK"
    assert got["code"] == 0
    assert got["httpStatus"] == 200
    assert got["documentPresent"] is True
    assert got["complete"] is True
    assert got["endpoint"] == fixture_origin.removeprefix("http://")
    assert got["wireSequence"] == 1


def test_transport_adapts_official_permission_error_through_real_worker(fixture_origin):
    plan, operation, _resource = minimal_wire_plan()
    _FixtureHandler.response_status = 403
    _FixtureHandler.response_body = {
        "error": {
            "code": 403,
            "status": "PERMISSION_DENIED",
            "message": "Missing or insufficient permissions.",
        }
    }
    source, source_digest = remote.worker_binding()
    frozen = {"plan": plan, "planDigest": digest(plan)}
    frozen["inputsDigest"] = digest(frozen)
    capability = _fixture_capability(plan, source, source_digest, frozen)
    try:
        transmit = remote.make_transport(
            plan,
            credentials={"unauthenticated": ""},
            frozen_inputs=frozen,
            identity_proofs={},
            fixture_origin=fixture_origin,
        )
        got = transmit(
            operation,
            binding=source,
            binding_digest=source_digest,
            capability=capability,
        )
    finally:
        _ACTIVE.discard(capability)
    assert got == {
        "status": "PERMISSION_DENIED",
        "code": 403,
        "httpStatus": 403,
        "documentPresent": False,
        "fields": None,
        "responseDigest": digest(_FixtureHandler.response_body),
        "complete": True,
        "workerReaped": True,
        "endpoint": fixture_origin.removeprefix("http://"),
        "wireSequence": 1,
    }


def test_transport_rejects_incomplete_official_commit_response(fixture_origin):
    plan, operation, _resource = minimal_wire_plan("commit", "create")
    _FixtureHandler.response_status = 200
    _FixtureHandler.response_body = {"writeResults": [], "commitTime": "2026-09-22T00:00:00Z"}
    source, source_digest = remote.worker_binding()
    frozen = {"plan": plan, "planDigest": digest(plan)}
    frozen["inputsDigest"] = digest(frozen)
    capability = _fixture_capability(plan, source, source_digest, frozen)
    try:
        transmit = remote.make_transport(
            plan,
            credentials={"unauthenticated": ""},
            frozen_inputs=frozen,
            identity_proofs={},
            fixture_origin=fixture_origin,
        )
        with pytest.raises(ValueError, match="REST Commit response shape refused"):
            transmit(
                operation,
                binding=source,
                binding_digest=source_digest,
                capability=capability,
            )
    finally:
        _ACTIVE.discard(capability)


def test_prepare_rejects_unknown_pseudo_write_and_mismatched_cleanup_precondition(plan):
    operation = collector_request(plan, 16)
    operation["writes"][0]["operation"] = "merge"
    with pytest.raises(ValueError, match="operation differs"):
        remote.prepare_request(
            plan,
            operation,
            credentials={"owner-a": "fixture"},
            account_bindings=account_bindings(plan),
        )
    request = {
        "kind": "account-delete",
        "phase": "recovery",
        "resource": None,
        "accountRef": "owner-a",
        "credentialRef": "administrator",
        "credentialClass": "administrator",
        "precondition": {"uid": "wrong"},
    }
    with pytest.raises(ValueError, match="UID precondition"):
        remote.prepare_request(
            plan,
            request,
            credentials={"administrator": "fixture"},
            account_bindings=account_bindings(plan),
        )


def test_prepare_checks_credential_class_and_fingerprint(plan):
    operation = collector_request(plan, 0)
    operation["credentialClass"] = "anonymous"
    with pytest.raises(ValueError, match="credential class"):
        remote.prepare_request(plan, operation, credentials={"owner-a": "fixture"})
    operation = collector_request(plan, 0)
    operation["credentialFingerprint"] = "0" * 16
    with pytest.raises(ValueError, match="credential fingerprint"):
        remote.prepare_request(plan, operation, credentials={"owner-a": "fixture"})


def test_prepare_covers_absent_malformed_and_empty_credential_classes(plan):
    for index, ref, credential_class in (
        (4, "unauthenticated", "absent"),
        (21, "malformed-bearer", "malformed"),
        (22, "empty-bearer", "empty"),
    ):
        operation = collector_request(plan, index)
        assert operation["credentialRef"] == ref
        assert operation["credentialClass"] == credential_class
        prepared = remote.prepare_request(
            plan,
            operation,
            credentials={ref: "" if credential_class == "empty" else "malformed"},
            account_bindings=account_bindings(plan),
        )
        assert prepared["method"] == "GET"


def test_prepare_rejects_wrong_phase_and_prepares_recovery_preconditions(plan):
    release = ruleset_request(plan, "A")
    release["phase"] = "arbitrary"
    with pytest.raises(ValueError, match="alias"):
        remote.prepare_request(plan, release, credentials={"administrator": "fixture"})

    resource = plan["ownedResources"][0]
    readback = {
        "kind": "readback",
        "phase": "recovery",
        "resource": resource,
        "accountRef": None,
        "credentialRef": "administrator",
        "credentialClass": "administrator",
        "precondition": None,
    }
    prepared = remote.prepare_request(
        plan,
        readback,
        credentials={"administrator": "fixture"},
    )
    assert prepared["method"] == "GET"
    version = "2026-09-22T00:00:00.000000Z"
    delete = {**readback, "kind": "delete", "precondition": {"updateTime": version}}
    prepared = remote.prepare_request(
        plan, delete, credentials={"administrator": "fixture"}
    )
    assert prepared["method"] == "DELETE"
    assert "currentDocument.updateTime=" + quote(version, safe="") in prepared["path"]


def test_prepare_requires_bound_uid_for_account_recovery(plan):
    request = {
        "kind": "account-delete",
        "phase": "recovery",
        "resource": None,
        "accountRef": "owner-a",
        "credentialRef": "administrator",
        "credentialClass": "administrator",
        "precondition": {"uid": "uid-a"},
    }
    with pytest.raises(ValueError, match="account binding"):
        remote.prepare_request(plan, request, credentials={"administrator": "fixture"})
    prepared = remote.prepare_request(
        plan,
        request,
        credentials={"administrator": "fixture"},
        account_bindings={"owner-a": {"uid": "uid-a", "tenant": None}},
    )
    assert prepared["method"] == "POST"
    assert prepared["body"] == {"localId": "uid-a"}


def test_recovery_document_receipt_uses_version_without_observation_fields(plan):
    resource = plan["ownedResources"][0]
    operation = {
        "kind": "readback",
        "phase": "recovery",
        "resource": resource,
        "accountRef": None,
        "credentialRef": "administrator",
        "credentialClass": "administrator",
        "precondition": None,
    }
    prepared = remote.prepare_request(plan, operation, credentials={"administrator": "fixture"})
    got = remote._adapt_firestore_result(
        prepared,
        {
            "status": 200,
            "body": {
                "name": resource,
                "fields": {"count": {"integerValue": "1"}},
                "updateTime": "2026-09-22T00:00:00Z",
            },
        },
        sequence=1,
        endpoint="127.0.0.1:1234",
    )
    assert got["documentPresent"] is True
    assert got["version"] == "2026-09-22T00:00:00Z"
    assert got["fields"] == {"count": 1}
    assert got["responseDigest"] == digest({"name": resource, "fields": {"count": {"integerValue": "1"}}, "updateTime": "2026-09-22T00:00:00Z"})
    accepted, failure = _accept({key: got[key] for key in RECOVERY_RECEIPT_KEYS if key in got}, RECOVERY_RECEIPT_KEYS)
    assert failure is None
    assert accepted is not None


def test_recovery_not_found_receipt_uses_canonical_code_and_no_fields(plan):
    resource = plan["ownedResources"][0]
    operation = {
        "kind": "readback",
        "phase": "recovery",
        "resource": resource,
        "accountRef": None,
        "credentialRef": "administrator",
        "credentialClass": "administrator",
        "precondition": None,
    }
    prepared = remote.prepare_request(plan, operation, credentials={"administrator": "fixture"})
    got = remote._adapt_firestore_result(
        prepared,
        {"status": 404, "body": {"error": {"code": 404, "status": "NOT_FOUND"}}},
        sequence=1,
        endpoint="127.0.0.1:1234",
    )
    assert got["documentPresent"] is False
    assert got["status"] == "NOT_FOUND"
    assert got["code"] == 5
    assert got["version"] is None
    assert "fields" not in got
    accepted, failure = _accept(
        {key: got[key] for key in RECOVERY_RECEIPT_KEYS if key in got},
        RECOVERY_RECEIPT_KEYS,
    )
    assert failure is None
    assert accepted is not None


def test_commit_and_observation_error_receipts_use_null_fields(plan):
    commit_plan, operation, _ = minimal_wire_plan("commit", "create")
    prepared = remote.prepare_request(commit_plan, operation, credentials={"unauthenticated": ""})
    got = remote._adapt_firestore_result(
        prepared,
        {"status": 200, "body": {"writeResults": [{"updateTime": "2026-09-22T00:00:00Z"}], "commitTime": "2026-09-22T00:00:00Z"}},
        sequence=1,
        endpoint="127.0.0.1:1234",
    )
    assert got["fields"] is None
    assert len(got["effects"]) == 1
    assert got["responseDigest"] == digest({"writeResults": [{"updateTime": "2026-09-22T00:00:00Z"}], "commitTime": "2026-09-22T00:00:00Z"})
    get_plan, get_operation, _ = minimal_wire_plan()
    get_prepared = remote.prepare_request(get_plan, get_operation, credentials={"unauthenticated": ""})
    error = remote._adapt_firestore_result(
        get_prepared,
        {"status": 403, "body": {"error": {"code": 403, "status": "PERMISSION_DENIED"}}},
        sequence=1,
        endpoint="127.0.0.1:1234",
    )
    assert error["fields"] is None


def test_atomic_commit_permission_denial_projects_canonical_refusal():
    commit_plan, operation, _ = minimal_wire_plan("commit", "create")
    prepared = remote.prepare_request(commit_plan, operation, credentials={"unauthenticated": ""})
    result = remote._adapt_firestore_result(
        prepared,
        {"status": 403, "body": {"error": {"code": 403, "status": "PERMISSION_DENIED"}}},
        sequence=1,
        endpoint="127.0.0.1:1234",
    )
    assert result["code"] == 7
    assert result["restErrorCode"] == 403
    assert result["responseDigest"] == digest({"error": {"code": 403, "status": "PERMISSION_DENIED"}})
    assert result["refusal"]["canonicalRowDigest"] == prepared["canonicalRowDigest"]
    assert prepared["canonicalRowDigest"] == digest(commit_plan["observation"][operation["index"]])
    assert result["effects"] == []
    with pytest.raises(ValueError, match="REST error response shape refused"):
        remote._adapt_firestore_result(
            prepared,
            {"status": 403, "body": {"error": {"code": 403, "status": "PERMISSION_DENIED"}, "writeResults": []}},
            sequence=1,
            endpoint="127.0.0.1:1234",
        )
    with pytest.raises(ValueError, match="REST error response shape refused"):
        remote._adapt_firestore_result(
            prepared,
            {"status": 403, "body": {"error": {"code": 403, "status": "OTHER"}}},
            sequence=1,
            endpoint="127.0.0.1:1234",
        )


def test_plan_shape_keeps_o5_accounts_rows_and_rulesets(plan):
    assert len(plan["observation"]) == 33
    assert len(plan["ownedAccounts"]) == 7
    assert set(plan["rulesets"]) == {"A", "B"}
    assert plan["observation"][0]["ruleset"] == "A"
    assert plan["observation"][-1]["ruleset"] == "B"


def test_worker_uses_fixture_origin_and_never_redirects(fixture_origin):
    _FixtureHandler.requests.clear()
    source = (ROOT / remote.WORKER_ENTRY).read_bytes()
    envelope = {
        "service": "firestore",
        "route": "observation-commit",
        "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents:commit",
        "method": "POST",
        "headers": {
            "Content-Type": "application/json",
            "Authorization": "Bearer fixture",
        },
        "body": {"ok": True},
        "seconds": 5.0,
    }
    result = remote.run_worker(
        envelope,
        binding=source,
        binding_digest=hashlib.sha256(source).hexdigest(),
        fixture_origin=fixture_origin,
    )
    assert result["status"] == 200
    assert result["body"]["writeResults"] == []
    assert result["body"]["commitTime"] == "2026-09-22T00:00:00Z"
    assert (
        _FixtureHandler.requests[0]["path"]
        == "/v1/projects/fireemu-35fe6/databases/(default)/documents:commit"
    )


def test_worker_rejects_oversized_body_before_wire():
    source = (ROOT / remote.WORKER_ENTRY).read_bytes()
    with pytest.raises(ValueError, match="worker envelope exceeds bound"):
        remote.run_worker(
            {
                "service": "firestore",
                "route": "observation-commit",
                "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents:commit",
                "method": "POST",
                "headers": {"Authorization": "Bearer fixture"},
                "body": {"oversized": "x" * (2 * 1024 * 1024)},
                "seconds": 5.0,
            },
            binding=source,
            binding_digest=hashlib.sha256(source).hexdigest(),
        )


def test_worker_rejects_arbitrary_fixed_host_route_and_method():
    source = (ROOT / remote.WORKER_ENTRY).read_bytes()
    with pytest.raises(ValueError):
        remote.run_worker(
            {
                "service": "firestore",
                "route": "arbitrary",
                "method": "PATCH",
                "path": "/v1/test",
                "headers": {"Authorization": "Bearer fixture"},
                "body": {"ok": True},
                "seconds": 5.0,
            },
            binding=source,
            binding_digest=hashlib.sha256(source).hexdigest(),
        )


def test_worker_rejects_unbound_route_before_any_network():
    source = (ROOT / remote.WORKER_ENTRY).read_bytes()
    with pytest.raises(ValueError, match="worker exchange refused"):
        remote.run_worker(
            {
                "service": "firestore",
                "route": "observation-commit",
                "path": "/v1/test",
                "method": "POST",
                "headers": {},
                "body": {},
                "seconds": 5.0,
            },
            binding=source,
            binding_digest=hashlib.sha256(source).hexdigest(),
        )


def test_transport_requires_capability_before_any_wire_call(plan, fixture_origin):
    _FixtureHandler.requests.clear()
    operation = plan["observation"][0]
    transmit = remote.make_transport(
        plan,
        credentials={"owner-a": "fixture-user-token"},
        fixture_origin=fixture_origin,
    )
    source = (ROOT / remote.WORKER_ENTRY).read_bytes()
    with pytest.raises(ValueError, match="active O8 production capability"):
        transmit(
            operation,
            binding=source,
            binding_digest=hashlib.sha256(source).hexdigest(),
            capability=None,
        )
    assert _FixtureHandler.requests == []


def test_timeout_reports_reaped_owned_worker_without_success_receipt(fixture_origin):
    source = (ROOT / remote.WORKER_ENTRY).read_bytes()
    envelope = {
        "service": "firestore",
        "route": "observation-get",
        "method": "GET",
        "path": "/v1/projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/cases/owned-a",
        "headers": {},
        "body": None,
        "seconds": 0.03,
    }
    with pytest.raises(remote.WorkerExchangeError) as raised:
        remote.run_worker(
            envelope,
            binding=source,
            binding_digest=hashlib.sha256(source).hexdigest(),
            fixture_origin=fixture_origin,
        )
    assert raised.value.worker_reaped is False


def test_reap_owned_kills_only_its_new_process_group():
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); time.sleep(30)",
        ],
        start_new_session=True,
    )
    remote._OWNED_CHILDREN.add(child.pid)
    try:
        assert remote._reap_owned(child) is True
        assert child.poll() is not None
    finally:
        remote._OWNED_CHILDREN.discard(child.pid)
        if child.poll() is None:
            remote._reap_owned(child)


def test_reap_owned_refuses_foreign_process_group():
    foreign = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    try:
        assert remote._reap_owned(foreign) is False
        assert foreign.poll() is None
    finally:
        foreign.terminate()
        foreign.wait(timeout=2)


def test_binding_verifier_requires_exact_worker_bytes():
    source = (ROOT / remote.WORKER_ENTRY).read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    remote.verify_worker_binding(source, digest, None)
    with pytest.raises(ValueError, match="worker source digest"):
        remote.verify_worker_binding(source + b"x", digest, None)
    with pytest.raises(ValueError, match="worker source digest"):
        remote.verify_worker_binding(source, digest, {remote.WORKER_ENTRY: "0" * 64})


def test_make_transport_drives_all_33_rows_and_principal_transitions(
    plan, fixture_origin
):
    _FixtureHandler.requests.clear()
    proofs = _fixture_proofs(plan, fixture_origin)
    bindings = account_bindings(plan)
    for ref, issued in proofs.items():
        bindings[ref]["uid"] = issued.uid
        bindings[ref]["authTime"] = issued.auth_time
    credentials = {ref: issued.token for ref, issued in proofs.items()}
    credentials["administrator"] = "fixture-administrator-token"
    credentials.update(
        {"unauthenticated": "", "malformed-bearer": "not-a-jwt", "empty-bearer": ""}
    )
    from o5_user_token_local_run import _unsigned_jwt

    expired = _unsigned_jwt(
        {
            "aud": "fireemu-35fe6",
            "iss": "https://securetoken.google.com/fireemu-35fe6",
            "sub": "uid-owner-a",
            "user_id": "uid-owner-a",
            "iat": 1,
            "auth_time": 1,
            "exp": 2,
            "firebase": {"sign_in_provider": "password"},
        }
    )
    credentials["expired-token"] = expired
    credentials["revoked-expired-token"] = expired
    frozen = {"plan": plan, "planDigest": digest(plan)}
    frozen["inputsDigest"] = digest(frozen)
    source, source_digest = remote.worker_binding()
    capability = _fixture_capability(plan, source, source_digest, frozen)
    try:
        transmit = remote.make_transport(
            plan,
            credentials=credentials,
            account_bindings=bindings,
            identity_proofs=proofs,
            frozen_inputs=frozen,
            fixture_origin=fixture_origin,
        )
        actions = {item["beforeIndex"]: item for item in principal_actions(plan)}
        receipts = []
        for index in range(33):
            if index in actions:
                action = {
                    "kind": "principal-action",
                    "phase": "principal",
                    "principalRef": actions[index]["ref"],
                    "action": actions[index]["action"],
                    "credentialRef": "administrator",
                    "credentialClass": "administrator",
                }
                receipts.append(
                    transmit(
                        action,
                        binding=source,
                        binding_digest=source_digest,
                        capability=capability,
                    )
                )
            receipts.append(
                transmit(
                    collector_request(plan, index),
                    binding=source,
                    binding_digest=source_digest,
                    capability=capability,
                )
            )
        assert len(_FixtureHandler.requests) == 7 + 36
        assert [entry["wireSequence"] for entry in receipts] == list(range(1, 37))
        assert [entry["path"] for entry in _FixtureHandler.requests[:7]] == [
            "/v1/accounts:signUp?key=fixture-key"
        ] * 7
        commit_paths = [
            entry["path"]
            for entry in _FixtureHandler.requests
            if entry["path"].endswith("/documents:commit")
        ]
        assert len(commit_paths) == 3
    finally:
        _ACTIVE.discard(capability)
        _CAPABILITY_STATE.pop(capability, None)
