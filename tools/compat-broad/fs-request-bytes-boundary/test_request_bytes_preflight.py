"""Strict offline principal and baseline checks before production grants."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import request_bytes_preflight as preflight
from broad_contract import digest

TEST_PROJECT_NUMBER = "1" * 12


def token_receipt(**changes):
    body = {
        "issued_to": "client",
        "audience": "client",
        "user_id": "subject",
        "scope": preflight.SCOPE,
        "expires_in": 3600,
    }
    body.update(changes)
    return {"complete": True, "workerReaped": True, "status": 200, "body": body}


def principal():
    return {
        "clientId": "client",
        "subject": "subject",
        "requiredScopes": [preflight.SCOPE],
    }


def test_verified_expiry_and_failure_latch():
    session = preflight.verify_token(
        "private-token",
        token_receipt(),
        principal(),
        sent=100,
        now=101,
        required_seconds=1150,
    )
    assert session.usable(101, 1150)
    assert not session.usable(3700, 1)
    preflight.observe_status(session, 403)
    assert not session.usable(101, 1)
    assert session.token is None


@pytest.mark.parametrize(
    "changes",
    [
        {"user_id": "other"},
        {"user_id": None},
        {"issued_to": "other"},
        {"audience": "other"},
        {"scope": "openid"},
        {"expires_in": "3600"},
        {"expires_in": True},
        {"expires_in": 3601},
        {"expires_in": 1000},
    ],
)
def test_unattested_claims_refused(changes):
    with pytest.raises(ValueError):
        preflight.verify_token(
            "private-token",
            token_receipt(**changes),
            principal(),
            sent=100,
            now=101,
            required_seconds=1150,
        )


@pytest.mark.parametrize(
    "key,value",
    [("complete", False), ("workerReaped", False), ("status", True), ("status", 403)],
)
def test_incomplete_token_receipt_refused(key, value):
    receipt = token_receipt()
    receipt[key] = value
    with pytest.raises(ValueError):
        preflight.verify_token(
            "private-token",
            receipt,
            principal(),
            sent=100,
            now=101,
            required_seconds=1150,
        )


def test_closed_routes():
    assert (
        preflight.metadata_url("project")
        == "https://cloudresourcemanager.googleapis.com/v1/projects/fireemu-oracle-sbx"
    )
    with pytest.raises(ValueError):
        preflight.metadata_url("https://example.com")


def test_metadata_identity_and_digest():
    body = {"projectId": "fireemu-oracle-sbx", "projectNumber": TEST_PROJECT_NUMBER}
    permission = {"projectNumber": TEST_PROJECT_NUMBER}
    assert preflight.verify_metadata("project", body, permission)["bodyDigest"] == digest(body)
    body["projectNumber"] = "2" * 12
    with pytest.raises(ValueError):
        preflight.verify_metadata("project", body, permission)
    with pytest.raises(ValueError):
        preflight.verify_metadata("project", body, {})
    for invalid in (None, 12, "", "0", "<project-number>"):
        with pytest.raises(ValueError):
            preflight.validate_project_number(invalid)
    with pytest.raises(ValueError):
        preflight.verify_metadata(
            "auth", {}, {"authConfigDigest": digest({"setting": True})}
        )


@pytest.mark.parametrize("change", ["subject", "clientId", "requiredScopes"])
def test_missing_frozen_principal_is_not_discovered(change):
    expected = principal()
    del expected[change]
    with pytest.raises(ValueError):
        preflight.verify_token(
            "private-token",
            token_receipt(),
            expected,
            sent=100,
            now=101,
            required_seconds=1150,
        )


def test_database_unknown_setting_and_identity_bound():
    body = {
        "name": preflight.DATABASE,
        "uid": "uid",
        "databaseEdition": "STANDARD",
        "type": "FIRESTORE_NATIVE",
        "locationId": "us-central1",
        "futureSetting": True,
    }
    permission = {"databaseProjectionDigest": digest(body)}
    preflight.verify_metadata("database", body, permission)
    body["etag"] = "volatile"
    preflight.verify_metadata("database", body, permission)
    body["futureSetting"] = False
    with pytest.raises(ValueError):
        preflight.verify_metadata("database", body, permission)


@pytest.mark.parametrize("status", [401, 403])
def test_credential_denial_cannot_be_recovered_by_later_success(status):
    credential = preflight.verify_token(
        "private-token",
        token_receipt(),
        principal(),
        sent=100,
        now=101,
        required_seconds=1150,
    )
    preflight.observe_status(credential, status)
    preflight.observe_status(credential, 200)
    assert credential.failed and credential.token is None


def test_no_management_transport_without_capability():
    with pytest.raises(ValueError):
        preflight.management_transport(
            "project",
            "private-token",
            deadline=200,
            capability=None,
            binding={},
            binding_digest="missing",
        )


def test_credential_evidence_contains_only_attested_identity_hash():
    receipt = token_receipt()
    receipt["body"]["email"] = "private@example.test"
    receipt["body"]["untrustedExtra"] = "private-token"
    evidence = preflight.credential_evidence(
        receipt, principal(), sent=100, now=101, required_seconds=1150
    )
    import json

    encoded = json.dumps(evidence)
    assert "private-token" not in encoded
    assert "private@example.test" not in encoded
    assert "client" not in encoded
    assert evidence["principalDigest"] == digest(principal())
    assert evidence["remainingSecondsAtVerification"] == 3598


@pytest.mark.parametrize(
    "patch",
    [
        {"status": 403},
        {"status": True},
        {"complete": False},
        {"workerReaped": False},
        {"bodyKind": "non-json"},
    ],
)
def test_matching_metadata_body_requires_complete_success_receipt(patch):
    receipt = {
        "status": 200,
        "complete": True,
        "workerReaped": True,
        "bodyKind": "json",
        "body": {
            "projectId": preflight.PROJECT,
            "projectNumber": TEST_PROJECT_NUMBER,
        },
    }
    receipt.update(patch)
    with pytest.raises(ValueError):
        preflight.verify_metadata_receipt(
            "project", receipt, {"projectNumber": TEST_PROJECT_NUMBER}
        )


def test_matching_metadata_success_receipt():
    receipt = {
        "status": 200,
        "complete": True,
        "workerReaped": True,
        "bodyKind": "json",
        "body": {
            "projectId": preflight.PROJECT,
            "projectNumber": TEST_PROJECT_NUMBER,
        },
    }
    assert (
        preflight.verify_metadata_receipt(
            "project", receipt, {"projectNumber": TEST_PROJECT_NUMBER}
        )["slot"]
        == "project"
    )


def test_project_attestation_replays_against_the_permission_bound_number():
    permission = {"projectNumber": TEST_PROJECT_NUMBER}
    receipt = {
        "status": 200,
        "complete": True,
        "workerReaped": True,
        "bodyKind": "json",
        "body": {
            "projectId": preflight.PROJECT,
            "projectNumber": TEST_PROJECT_NUMBER,
        },
    }
    attestation = preflight.metadata_attestation("project", receipt, permission)
    assert attestation["complete"] is True
    assert attestation["body"]["projectNumberDigest"] == digest(
        {"projectNumber": TEST_PROJECT_NUMBER}
    )
    preflight.validate_metadata_attestation("project", attestation, permission)

    tampered = {**attestation, "body": dict(attestation["body"])}
    tampered["body"].pop("projectNumberDigest")
    with pytest.raises(ValueError, match="project metadata binding"):
        preflight.validate_metadata_attestation("project", tampered, permission)


def test_frozen_verified_email_identity():
    expected = {
        "clientId": "client",
        "verifiedEmail": "owner@example.test",
        "requiredScopes": [preflight.SCOPE],
    }
    receipt = token_receipt(email="owner@example.test", verified_email=True)
    assert preflight.verify_token(
        "private-token", receipt, expected, sent=100, now=101, required_seconds=1150
    ).usable(101)
    for changes in (
        {"verified_email": "true"},
        {"verified_email": False},
        {"email": "other@example.test"},
    ):
        with pytest.raises(ValueError):
            preflight.verify_token(
                "private-token",
                token_receipt(email="owner@example.test", verified_email=True)
                | {"body": receipt["body"] | changes},
                expected,
                sent=100,
                now=101,
                required_seconds=1150,
            )


def test_identity_modes_are_not_fallbacks():
    expected = principal() | {"verifiedEmail": "owner@example.test"}
    with pytest.raises(ValueError):
        preflight.verify_token(
            "private-token",
            token_receipt(),
            expected,
            sent=100,
            now=101,
            required_seconds=1150,
        )


def metadata_receipt(body):
    return {
        "status": 200,
        "complete": True,
        "workerReaped": True,
        "bodyKind": "json",
        "body": body,
    }


AUTH_BODY = {
    "name": "projects/<project-number>/config",
    "client": {"apiKey": "secret-looking-key"},
    "notification": {"sendEmail": {"smtp": {"host": "smtp.example.test"}}},
}


def test_metadata_attestation_publishes_digest_not_raw_auth_config():
    permission = {"authConfigDigest": digest(AUTH_BODY)}
    public = preflight.metadata_attestation("auth", metadata_receipt(AUTH_BODY), permission)
    assert set(public) == {"status", "complete", "workerReaped", "bodyKind", "body"}
    assert public["complete"] is True
    assert public["body"] == {
        "kind": "request-byte-metadata-attestation-v1",
        "slot": "auth",
        "bodyDigest": digest(AUTH_BODY),
        "baselineVerified": True,
    }
    assert "secret-looking-key" not in repr(public)
    preflight.validate_metadata_attestation("auth", public, permission)


def test_metadata_attestation_reports_drift_as_incomplete_not_raised():
    permission = {
        "authConfigDigest": digest({"name": "projects/<project-number>/config"})
    }
    public = preflight.metadata_attestation("auth", metadata_receipt(AUTH_BODY), permission)
    assert public["complete"] is False
    assert public["status"] == 200
    assert public["body"]["baselineVerified"] is False
    assert "secret-looking-key" not in repr(public)
    with pytest.raises(ValueError, match="attestation differs"):
        preflight.validate_metadata_attestation("auth", public, permission)


def test_database_attestation_keeps_only_the_shared_projection():
    from batch_contract import database_evidence

    body = {
        "name": preflight.DATABASE,
        "uid": "fixture-uid",
        "type": "FIRESTORE_NATIVE",
        "databaseEdition": "STANDARD",
        "locationId": "us-central1",
        "etag": "volatile",
        "earliestVersionTime": "2026-09-21T00:00:00Z",
    }
    projection = database_evidence(body)["projection"]
    permission = {"databaseProjectionDigest": digest(projection)}
    public = preflight.metadata_attestation("database", metadata_receipt(body), permission)
    assert public["body"]["projection"] == projection
    assert "etag" not in public["body"]["projection"]
    preflight.validate_metadata_attestation("database", public, permission)
    drifted = {**permission, "databaseProjectionDigest": digest({"name": "other"})}
    with pytest.raises(ValueError, match="database baseline differs"):
        preflight.validate_metadata_attestation("database", public, drifted)


@pytest.mark.parametrize(
    "patch",
    [
        {"completed": False},
        {"status": 500},
        {"status": "200"},
        {"bodyDigest": "0" * 64},
    ],
)
def test_saved_management_requires_completed_2xx_gate_events(patch):
    principal_value = principal()
    wall = 1150
    token_body = {
        "kind": "request-byte-token-attestation-v1",
        "principalDigest": digest(principal_value),
        "requiredScopeVerified": True,
        "identityMode": "subject",
        "identityVerified": True,
        "oauthClientVerified": True,
        "expiresInSeconds": 3600,
        "remainingSecondsAtVerification": 3599.0,
        "requiredSeconds": wall,
        "complete": True,
        "workerReaped": True,
    }
    project = {
        "projectId": preflight.PROJECT,
        "projectNumber": TEST_PROJECT_NUMBER,
    }
    database = {
        "name": preflight.DATABASE,
        "uid": "u",
        "type": "FIRESTORE_NATIVE",
        "databaseEdition": "STANDARD",
        "locationId": "us-central1",
    }
    permission = {
        "projectNumber": TEST_PROJECT_NUMBER,
        "credentialPrincipal": principal_value,
        "wallSeconds": wall,
        "authConfigDigest": digest(AUTH_BODY),
        "databaseProjectionDigest": digest(database),
    }
    responses = {
        "oauth-tokeninfo": metadata_receipt(token_body),
        "project": preflight.metadata_attestation(
            "project", metadata_receipt(project), permission
        ),
        "database": preflight.metadata_attestation(
            "database", metadata_receipt(database), permission
        ),
        "auth": preflight.metadata_attestation(
            "auth", metadata_receipt(AUTH_BODY), permission
        ),
    }
    ids = [
        "observation:oauth-tokeninfo",
        "observation:project",
        "observation:database",
        "observation:auth",
        "recovery:project",
        "recovery:database",
        "recovery:auth",
    ]
    rows, events = [], []
    for identity in ids:
        response = responses[identity.split(":", 1)[1]]
        rows.append({"id": identity, "response": response, "responseDigest": digest(response)})
        events.append(
            {
                "id": identity,
                "completed": True,
                "status": 200,
                "responseDigest": digest(response),
                "bodyDigest": digest(response["body"]),
            }
        )
    receipt = {
        "preflightComplete": True,
        "postflightComplete": True,
        "managementEvidence": rows,
        "credentialEvidence": [token_body],
    }
    preflight.validate_saved_management(receipt, {"managementEvents": events}, permission)
    events[5].update(patch)
    with pytest.raises(ValueError, match="binding differs"):
        preflight.validate_saved_management(
            receipt, {"managementEvents": events}, permission
        )


def test_management_transport_reports_bounded_wire_failures_as_receipts(monkeypatch):
    import batch_adapter
    import o8_admission
    import time as real_time

    monkeypatch.setattr(o8_admission, "authorize_transport", lambda *a, **k: None)

    def failing_wire(*_args, **_kwargs):
        raise ValueError("bounded transport failed")

    monkeypatch.setattr(batch_adapter, "wire", failing_wire)
    receipt = preflight.management_transport(
        "project",
        "private-token",
        deadline=real_time.monotonic() + 5,
        capability=object(),
        binding={},
        binding_digest="0" * 64,
    )
    assert receipt == {
        "complete": False,
        "workerReaped": True,
        "status": None,
        "body": None,
        "bodyKind": None,
    }


def test_frozen_baselines_required_before_any_slot_is_charged():
    good = {"databaseProjectionDigest": "a" * 64, "authConfigDigest": "b" * 64}
    preflight.validate_frozen_baselines(good)
    for damaged in (
        {},
        {**good, "authConfigDigest": None},
        {**good, "databaseProjectionDigest": "A" * 64},
        {**good, "authConfigDigest": "b" * 63},
    ):
        with pytest.raises(ValueError, match="frozen"):
            preflight.validate_frozen_baselines(damaged)
