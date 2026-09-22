"""Offline O8 integration: real capabilities, Gate journals and a temporary Ledger."""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import credential_admission as admission
import credential_descriptor as campaign
import credential_gate as gate_module
import credential_o8 as launcher
import credential_preflight as preflight
import credential_production as production
import credential_remote_transport as remote
import credential_shadow as shadow
import reservations
import shared_gate
from broad_contract import digest
from credential_collector import SecretLeak
from test_credential_admission import AUTH_BODY, PROJECT_BODY, Admission
from test_credential_shadow import _service

FIXTURE_TOKEN = "offline-fixture-token"
FIXTURE_KEY = "offline-fixture-key"


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(shadow, "_rest", lambda budget, seconds: None)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("network forbidden in O8 regression")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def wire_fixture(monkeypatch, *, tokeninfo_status=200, service=None):
    """Answer every bound wire call from the in-memory Identity service."""
    service = service or _service(project=PROJECT_BODY["projectId"])
    calls = {"management": [], "sign": [], "data": []}

    def management_fixture(slot, token, **_kwargs):
        assert token == FIXTURE_TOKEN
        calls["management"].append(slot)
        body = {"project": PROJECT_BODY, "auth": AUTH_BODY}.get(slot)
        status = 200
        if slot == "oauth-tokeninfo":
            status = tokeninfo_status
            body = {"issued_to": "offline-client", "user_id": "offline-subject", "scope": preflight.SCOPE, "expires_in": 3600}
            if status != 200:
                body = {"error": "invalid_token"}
        return {"status": status, "complete": True, "workerReaped": True, "bodyKind": "json", "body": body}

    def sign_fixture(payload, *, service_account, token, **_kwargs):
        assert token == FIXTURE_TOKEN and service_account == campaign.SERVICE_ACCOUNT
        calls["sign"].append(payload["claims"])
        return shadow.unsigned_jwt(payload), {
            "kind": "custom-token-signature-v1", "status": 200, "keyIdPresent": True,
            "algorithm": "RS256", "signatureBytes": 256, "payloadDigest": "a" * 64,
        }

    def transmit_fixture(declared, body, *, token, api_key, **_kwargs):
        assert token == FIXTURE_TOKEN and api_key == FIXTURE_KEY
        calls["data"].append(declared["kind"])
        host, _, rest = declared["path"].partition("/")
        rpc = rest.rsplit("/", 1)[-1]
        if rpc.startswith("accounts:"):
            path = "/" + rpc
        elif rpc.endswith(":createSessionCookie"):
            path = ":createSessionCookie"
        else:
            path = ""
        if not declared["owner"] and path:
            path += "?key=k"
        status, raw = service["sender"]("http://127.0.0.1:1/" + host, path, body, declared["owner"], 5)
        return status, json.loads(raw)

    monkeypatch.setattr(preflight.shared_preflight, "management_transport", management_fixture)
    monkeypatch.setattr(remote, "sign_custom_token", sign_fixture)
    monkeypatch.setattr(remote, "transmit", transmit_fixture)
    return calls, service


def issue(built):
    binding, binding_digest = remote.worker_binding()
    return admission.issue_production_capability(**built.bindings(), binding=binding, binding_digest=binding_digest)


def run(built, tmp_path, *, reader=None):
    cap = issue(built)
    return production.execute(
        capability=cap,
        inputs=built.inputs,
        permission=built.permission,
        credential_reader=reader or (lambda: admission.validate_handoff(built.handoff, built.permission, built.plan)),
        ledger_root=built.ledger,
        output=tmp_path / "output",
    )


# --- hosted execution ---------------------------------------------------------------------


def test_a_hosted_credential_run_releases_through_the_shared_ledger(tmp_path, monkeypatch) -> None:
    built = Admission(tmp_path)
    calls, service = wire_fixture(monkeypatch)
    result = run(built, tmp_path)
    assert result["failure"] is None
    assert result["reservationReleased"] is True
    assert result["stopPoint"] is None
    assert calls["management"] == ["oauth-tokeninfo", "project", "auth", "auth"]
    assert [claims for claims in calls["sign"]] == [{"role": "tester"}, {"sub": "elevated"}, {}]
    assert len(calls["data"]) == 42
    assert service["accounts"] == {}
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["accountEvidence"]["createdAccounts"] == 3
    assert receipt["accountEvidence"]["complete"] is True
    assert receipt["chargedCalls"] == 42 + 7
    assert receipt["collection"]["recordingComplete"] is True
    assert receipt["collection"]["cleanup"]["cleanupComplete"] is True
    # The comparison runs against the published shadow; whether that record's
    # collector binding is current is the shadow record test's question, not this
    # one's, so only the report's shape is pinned here.
    report = receipt["comparison"]["report"]
    assert receipt["comparison"]["formalCompatibilityClaim"] is False
    assert len(report["rows"]) == 19 and report["parityEstablished"] is False
    assert report["reason"] in ("classified", "collector-binding-mismatch")
    assert receipt["signing"] is True and len(receipt["signatureEvidence"]) == 3
    scanned = [path for path in output.rglob("*") if path.is_file()]
    assert any("responsibility" in path.parts for path in scanned)
    assert service["issuedSecrets"]
    for path in scanned:
        text = path.read_text()
        for secret in (FIXTURE_TOKEN, FIXTURE_KEY, *service["issuedSecrets"]):
            assert secret not in text, path
    production.verify_saved(output, expected_inputs_digest=built.inputs["inputsDigest"], ledger_root=built.ledger)
    final = reservations.Ledger(built.ledger).snapshot()["reservations"][result["ticket"]["reservation"]]
    assert final["state"] == "released"


def test_with_the_extension_a_run_without_signing_records_the_dependent_rows_as_not_run(tmp_path, monkeypatch) -> None:
    built = Admission(tmp_path, signing=False)
    calls, _ = wire_fixture(monkeypatch)
    result = run(built, tmp_path)
    assert result["failure"] is None and result["reservationReleased"] is True
    assert calls["sign"] == [] and len(calls["data"]) == 28
    rows = result["collection"]["rows"]
    not_run = [row for row in rows if row["errorCode"] == "NOT_RUN"]
    assert len(not_run) == 11
    assert {row["notRunReason"] for row in not_run} == {shadow.SIGNING_ABSENT_REASON}
    assert result["collection"]["recordingComplete"] is False
    assert result["accountEvidence"]["createdAccounts"] == 2


def test_a_refused_bearer_stops_the_run_before_any_data_call(tmp_path, monkeypatch) -> None:
    built = Admission(tmp_path)
    calls, _ = wire_fixture(monkeypatch, tokeninfo_status=401)
    result = run(built, tmp_path)
    assert result["failure"] == "ValueError"
    assert result["reservationReleased"] is False
    assert result["stopPoint"] == "preflight"
    assert calls["management"] == ["oauth-tokeninfo"] and calls["data"] == []
    snapshot = json.loads((tmp_path / "output" / "gate-snapshot.json").read_bytes())
    assert snapshot["events"] == [] and snapshot["credentialRejected"] is True
    assert reservations.Ledger(built.ledger).snapshot()["reservations"][result["ticket"]["reservation"]]["state"] == "held"


def test_a_privileged_call_refused_with_403_stops_every_later_bearer_use(tmp_path, monkeypatch) -> None:
    built = Admission(tmp_path)
    calls, service = wire_fixture(monkeypatch)
    real_transmit = remote.transmit

    def refusing(declared, body, **kwargs):
        if declared["owner"]:
            calls["data"].append("refused-" + declared["kind"])
            return 403, {"error": {"code": 403, "message": "PERMISSION_DENIED", "status": "PERMISSION_DENIED"}}
        return real_transmit(declared, body, **kwargs)

    monkeypatch.setattr(remote, "transmit", refusing)
    result = run(built, tmp_path)
    assert result["failure"] == "collection-incomplete"
    assert result["stopPoint"] == "credential-refused"
    assert result["reservationReleased"] is False
    # Exactly one privileged call went out; the latch stopped the next data call and
    # every cleanup delete, so the accounts the run created are recorded as remaining.
    assert calls["data"].count("refused-update") == 1
    assert not any(kind.startswith("refused-") and kind != "refused-update" for kind in calls["data"])
    assert result["collection"]["cleanup"]["remainingAccounts"] == 2
    assert result["collection"]["cleanup"]["cleanupComplete"] is False
    assert len(service["accounts"]) == 2
    assert reservations.Ledger(built.ledger).snapshot()["reservations"][result["ticket"]["reservation"]]["state"] == "held"


def test_a_refused_api_key_call_stops_observation_but_cleanup_still_runs(tmp_path, monkeypatch) -> None:
    """The mirror of the bearer latch: the key was refused, the bearer never was."""
    built = Admission(tmp_path)
    calls, service = wire_fixture(monkeypatch)
    real_transmit = remote.transmit

    def refusing(declared, body, **kwargs):
        # The client lookup after both sign-ups presents only the API key.
        if not declared["owner"] and declared["kind"] == "lookup":
            calls["data"].append("refused-" + declared["kind"])
            return 403, {"error": {"code": 403, "message": "PERMISSION_DENIED", "status": "PERMISSION_DENIED"}}
        return real_transmit(declared, body, **kwargs)

    monkeypatch.setattr(remote, "transmit", refusing)
    result = run(built, tmp_path)
    assert result["failure"] == "collection-incomplete"
    assert result["stopPoint"] == "api-key-refused"
    assert calls["data"].count("refused-lookup") == 1
    assert not any(kind.startswith("refused-") and kind != "refused-lookup" for kind in calls["data"])
    # Both accounts created before the refusal are deleted with the bearer.
    assert calls["data"][-6:] == ["delete", "uid-absence", "address-absence"] * 2
    assert result["collection"]["cleanup"]["remainingAccounts"] == 0
    assert result["collection"]["cleanup"]["cleanupComplete"] is True
    assert service["accounts"] == {}
    # The observation is incomplete, so the Gate cannot finish and the row stays held.
    assert result["reservationReleased"] is False
    assert reservations.Ledger(built.ledger).snapshot()["reservations"][result["ticket"]["reservation"]]["state"] == "held"


def test_a_worker_timeout_on_a_refresh_is_observation_incomplete_not_unsettled(tmp_path, monkeypatch) -> None:
    built = Admission(tmp_path)
    wire_fixture(monkeypatch)
    real_transmit = remote.transmit

    def timing_out(declared, body, **kwargs):
        if declared["kind"] == "refresh":
            raise ValueError("credential request deadline exceeded")
        return real_transmit(declared, body, **kwargs)

    monkeypatch.setattr(remote, "transmit", timing_out)
    result = run(built, tmp_path)
    assert result["failure"] == "collection-incomplete"
    assert result["stopPoint"] == "observation-incomplete"
    snapshot = json.loads((tmp_path / "output" / "gate-snapshot.json").read_bytes())
    assert shared_gate.unconfirmed_creates(snapshot, gate_module.JOB) == 0
    failed = [event for event in snapshot["events"] if event.get("failure")]
    assert len(failed) == 1 and failed[0]["authEvidence"]["settled"] == "failed-send-cannot-create"
    # The account from the first sign-up is still cleaned up.
    assert result["collection"]["cleanup"]["remainingAccounts"] == 0


def test_charged_calls_after_a_latch_count_only_admitted_slots(tmp_path, monkeypatch) -> None:
    built = Admission(tmp_path)
    wire_fixture(monkeypatch)
    real_transmit = remote.transmit

    def refusing(declared, body, **kwargs):
        if declared["owner"]:
            return 403, {"error": {"code": 403, "message": "PERMISSION_DENIED", "status": "PERMISSION_DENIED"}}
        return real_transmit(declared, body, **kwargs)

    monkeypatch.setattr(remote, "transmit", refusing)
    result = run(built, tmp_path)
    assert result["stopPoint"] == "credential-refused"
    snapshot = json.loads((tmp_path / "output" / "gate-snapshot.json").read_bytes())
    routes = json.loads((tmp_path / "output" / "routes.json").read_bytes())["rows"]
    sent = [row for row in routes if row["status"] is not None]
    # A latched bearer refuses the cleanup deletes before the Gate charges them, so
    # the Gate total is exactly the slots that reached the wire plus management.
    assert len(sent) == len(routes)
    assert result["chargedCalls"] == snapshot["total"] == len(sent) + len(snapshot["managementEvents"])


def test_a_refused_explicit_valid_since_update_stops_the_run_without_a_row(tmp_path, monkeypatch) -> None:
    built = Admission(tmp_path)
    wire_fixture(monkeypatch)
    real_transmit = remote.transmit
    updates = []

    def refusing(declared, body, **kwargs):
        if declared["kind"] == "update":
            updates.append(body)
            if "validSince" in body and len(updates) == 4:
                return 400, {"error": {"code": 400, "message": "INVALID_TIME", "status": "INVALID_ARGUMENT"}}
        return real_transmit(declared, body, **kwargs)

    monkeypatch.setattr(remote, "transmit", refusing)
    result = run(built, tmp_path)
    assert result["failure"] == "collection-incomplete"
    rows = {row["caseId"]: row for row in result["collection"]["rows"]}
    assert rows["refresh-after-explicit-valid-since-rejected"]["errorCode"] == "NOT_RUN"
    assert rows["refresh-after-password-reset-rejected"]["errorCode"] == "INVALID_REFRESH_TOKEN"
    assert result["collection"]["cleanup"]["cleanupComplete"] is True


def test_a_secret_shaped_value_in_the_receipt_is_refused_not_redacted(tmp_path, monkeypatch) -> None:
    built = Admission(tmp_path)
    wire_fixture(monkeypatch)
    original = admission.build_receipt

    def leaking(*args, **kwargs):
        receipt = original(*args, **kwargs)
        receipt["diagnostic"] = "bearer " + FIXTURE_TOKEN
        return receipt

    monkeypatch.setattr(admission, "build_receipt", leaking)
    with pytest.raises(SecretLeak):
        run(built, tmp_path)
    assert not (tmp_path / "output" / "receipt.json").exists()


def test_the_launcher_exits_zero_only_after_a_complete_release(tmp_path, monkeypatch) -> None:
    built = Admission(tmp_path)
    wire_fixture(monkeypatch)
    assert launcher.main(built.argv(tmp_path)) == 0
    receipt = json.loads((tmp_path / "output" / "receipt.json").read_bytes())
    assert receipt["releaseEligible"] is True
    assert digest(receipt) == json.loads((tmp_path / "output" / "release.json").read_bytes())["receiptDigest"]


def test_a_second_run_on_the_same_nonce_is_refused_as_reserved(tmp_path, monkeypatch) -> None:
    built = Admission(tmp_path)
    wire_fixture(monkeypatch)
    assert run(built, tmp_path)["reservationReleased"] is True
    with pytest.raises(ValueError, match="already reserved"):
        admission.validate_fresh_admission(built.ledger, built.plan, built.permission)


def test_the_gate_plan_names_only_placeholders_where_the_run_binds_values(tmp_path) -> None:
    built = Admission(tmp_path)
    plan = admission.gate_plan_for(built.inputs, built.permission)
    assert plan["jobs"][gate_module.JOB]["resources"] == plan["accountResources"]
    serialized = json.dumps(plan)
    assert FIXTURE_TOKEN not in serialized and FIXTURE_KEY not in serialized
