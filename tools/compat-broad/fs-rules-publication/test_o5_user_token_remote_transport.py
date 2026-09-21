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
from pathlib import Path
from typing import ClassVar
from urllib.parse import quote

import o5_user_token_identity_proof as identity_proof
import o5_user_token_remote_transport as remote
import pytest
from broad_contract import digest
from o5_user_token_case import compile_case, principal_actions
from o5_user_token_collector import _request
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
        if self.path.startswith("/v1/accounts:"):
            payload = json.dumps(self.__class__.issuance_body or {}).encode()
        else:
            payload = json.dumps(
                {
                    "complete": True,
                    "status": "OK",
                    "releaseName": "fixture-release",
                    "readbackKind": "release-get",
                    "readbackDigest": "d" * 64,
                }
            ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST
    do_DELETE = do_POST

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
        port = int(reservation["port"]) if reservation is not None else int(server.server_address[1])
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
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


def _fixture_capability(plan, source, source_digest, frozen):
    capability = ProductionWireCapability(
        _CAPABILITY_TOKEN,
        binding=source,
        binding_digest=source_digest,
        campaign_id=remote.CAMPAIGN,
        window_seconds=60,
        inputs_digest=frozen["inputsDigest"],
        ledger_root="fixture-ledger",
        window_starts_at=time.time() - 1,
        window_expires_at=time.time() + 60,
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
            assert write["update"]["name"].startswith("/v1/projects/fireemu-35fe6/")
            assert "currentDocument" in write


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
    with pytest.raises(ValueError, match="phase"):
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
    assert result["body"]["complete"] is True
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
