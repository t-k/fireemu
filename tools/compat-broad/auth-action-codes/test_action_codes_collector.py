"""Bounds, ownership, redaction and cleanup of the action-code collector."""

from __future__ import annotations

import json

import pytest
from action_codes_collector import (
    CollectorError,
    build_parser,
    character_class,
    collect,
    redact,
)
from action_codes_plan import SECRET_FIELDS, STAGE_IDS

NONCE = "abcdef0123456789" * 2
PROJECT = "demo-auth-action"
ORIGIN = "http://127.0.0.1:9099"

CODE_ALPHABET = "AbCdEfGhIjKlMnOpQrSt01_-"


class FakeService:
    """A minimal Identity Toolkit stand-in with real action-code semantics."""

    def __init__(self, **behaviour: object) -> None:
        self.accounts: dict[str, dict] = {}
        self.codes: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.counter = 0
        self.behaviour = behaviour

    def send(self, method: str, url: str, headers: dict, body: dict):
        self.calls.append((method, url))
        route = url.rsplit("accounts:", 1)[-1]
        privileged = "/projects/" in url
        if privileged and headers.get("authorization") != "Bearer owner":
            return 401, {"error": {"message": "MISSING_OWNER_CREDENTIAL"}}
        handler = getattr(self, "_" + route)
        return handler(body)

    def _issue(self, kind: str, account: dict) -> str:
        self.counter += 1
        code = CODE_ALPHABET + f"{self.counter:02d}"
        self.codes[code] = {"requestType": kind, "localId": account["localId"]}
        return code

    def _signUp(self, body: dict):
        self.counter += 1
        uid = f"uid-{self.counter}"
        self.accounts[uid] = {
            "localId": uid,
            "email": body["email"],
            "password": body["password"],
            "emailVerified": False,
        }
        return 200, {
            "kind": "identitytoolkit#SignupNewUserResponse",
            "email": body["email"],
            "localId": uid,
            "idToken": "id-token-" + uid,
            "refreshToken": "refresh-token-" + uid,
            "expiresIn": "3600",
        }

    def _find(self, email: str):
        for account in self.accounts.values():
            if account["email"] == email:
                return account
        return None

    def _sendOobCode(self, body: dict):
        account = self._find(body["email"])
        if account is None:
            return 200, {
                "kind": "identitytoolkit#GetOobConfirmationCodeResponse",
                "email": body["email"],
            }
        code = self._issue(body["requestType"], account)
        return 200, {
            "kind": "identitytoolkit#GetOobConfirmationCodeResponse",
            "email": body["email"],
            "oobCode": code,
            "oobLink": "http://127.0.0.1:9099/emulator/action?oobCode=" + code,
        }

    def _resetPassword(self, body: dict):
        record = self.codes.get(body.get("oobCode"))
        if record is None or record["requestType"] != "PASSWORD_RESET":
            return 400, {"error": {"message": "INVALID_OOB_CODE"}}
        account = self.accounts.get(record["localId"])
        if account is None:
            return 400, {"error": {"message": "USER_DISABLED"}}
        answer = {
            "kind": "identitytoolkit#ResetPasswordResponse",
            "email": account["email"],
            "requestType": "PASSWORD_RESET",
        }
        if "newPassword" not in body:
            return 200, answer
        if len(body["newPassword"]) < 6:
            return 400, {
                "error": {
                    "message": "WEAK_PASSWORD : Password should be at least 6 characters"
                }
            }
        account["password"] = body["newPassword"]
        del self.codes[body["oobCode"]]
        return 200, answer

    def _update(self, body: dict):
        if "oobCode" in body:
            record = self.codes.get(body["oobCode"])
            if record is None or record["requestType"] != "VERIFY_EMAIL":
                return 400, {"error": {"message": "INVALID_OOB_CODE"}}
            account = self.accounts[record["localId"]]
            account["emailVerified"] = True
            del self.codes[body["oobCode"]]
            return 200, {
                "kind": "identitytoolkit#SetAccountInfoResponse",
                "email": account["email"],
                "emailVerified": True,
                "localId": account["localId"],
            }
        account = self.accounts[body["localId"]]
        account["password"] = body["password"]
        return 200, {
            "kind": "identitytoolkit#SetAccountInfoResponse",
            "email": account["email"],
            "emailVerified": account["emailVerified"],
            "localId": account["localId"],
            "passwordHash": "hash-of-" + account["password"],
            "providerUserInfo": [{"providerId": "password"}],
            "idToken": "id-token-" + account["localId"],
            "refreshToken": "refresh-token-" + account["localId"],
            "expiresIn": "3600",
        }

    def _signInWithEmailLink(self, body: dict):
        record = self.codes.get(body.get("oobCode"))
        if record is None or record["requestType"] != "EMAIL_SIGNIN":
            return 400, {"error": {"message": "INVALID_OOB_CODE"}}
        account = self.accounts[record["localId"]]
        if account["email"] != body["email"]:
            return 400, {"error": {"message": "INVALID_OOB_CODE"}}
        del self.codes[body["oobCode"]]
        return 200, {
            "kind": "identitytoolkit#EmailLinkSigninResponse",
            "email": account["email"],
            "localId": account["localId"],
            "idToken": "id-token-" + account["localId"],
            "refreshToken": "refresh-token-" + account["localId"],
            "expiresIn": "3600",
            "isNewUser": False,
        }

    def _lookup(self, body: dict):
        account = self.accounts.get(body["localId"])
        if account is None:
            return 200, {"kind": "identitytoolkit#GetAccountInfoResponse"}
        return 200, {
            "kind": "identitytoolkit#GetAccountInfoResponse",
            "users": [
                {
                    "localId": account["localId"],
                    "email": account["email"],
                    "emailVerified": account["emailVerified"],
                }
            ],
        }

    def _delete(self, body: dict):
        if self.behaviour.get("deleteFails"):
            return 500, {"error": {"message": "INTERNAL"}}
        self.accounts.pop(body["localId"], None)
        return 200, {"kind": "identitytoolkit#DeleteAccountResponse"}


def run(service: FakeService | None = None, **options):
    service = service or FakeService()
    receipt = collect(
        origin=ORIGIN,
        project=PROJECT,
        nonce=NONCE,
        send=service.send,
        **options,
    )
    return service, receipt


def test_a_complete_run_records_every_stage_in_order() -> None:
    _, receipt = run()
    assert [row["id"] for row in receipt["stages"]] == list(STAGE_IDS)
    assert receipt["recordingComplete"] is True
    assert receipt["cleanupComplete"] is True
    assert receipt["remainingAccounts"] == 0
    assert receipt["side"] == "local"
    assert receipt["productionExecuted"] is False
    assert receipt["manifestDigest"] == receipt["manifestDigest"].lower()
    assert len(receipt["manifestDigest"]) == 64


def test_observed_stage_results_match_the_planned_local_expectations() -> None:
    _, receipt = run()
    rows = {row["id"]: row for row in receipt["stages"]}
    assert rows["reset-code-lookup"]["status"] == 200
    assert rows["reset-weak-password"]["errorCode"] == "WEAK_PASSWORD"
    assert rows["reset-weak-password"]["errorMessage"].startswith("WEAK_PASSWORD")
    assert rows["reset-weak-password-retry"]["status"] == 200
    assert rows["reset-reuse"]["errorCode"] == "INVALID_OOB_CODE"
    assert rows["reset-wrong-code"]["errorCode"] == "INVALID_OOB_CODE"
    assert rows["reset-after-delete"]["errorCode"] == "USER_DISABLED"
    assert rows["verify-apply"]["emailVerified"] is True
    assert rows["email-link-reuse"]["errorCode"] == "INVALID_OOB_CODE"
    assert rows["link-generate-unknown-email"]["oobCodeReturned"] is False


def test_code_shape_is_recorded_without_the_code_itself() -> None:
    _, receipt = run()
    row = {stage["id"]: stage for stage in receipt["stages"]}["reset-link-generate"]
    assert row["oobCodeReturned"] is True
    assert row["oobCodeLength"] == len(CODE_ALPHABET) + 2
    assert row["oobCodeCharacterClass"] == "base64url"
    assert row["oobLinkReturned"] is True
    assert "oobCode" not in row
    assert "oobCode" in row["keys"]


def test_no_secret_value_reaches_the_receipt() -> None:
    service, receipt = run()
    serialized = json.dumps(receipt)
    for code in service.codes:
        assert code not in serialized
    for field in SECRET_FIELDS:
        # Secret names may appear inside a recorded `keys` list, never as a key.
        assert '"' + field + '":' not in serialized
    assert "id-token-" not in serialized
    assert "refresh-token-" not in serialized
    for account in receipt["ownedAccounts"].values():
        assert "password" not in account


def test_redaction_covers_nested_values_and_keeps_shape() -> None:
    value = redact(
        {"oobCode": "secret", "nested": [{"idToken": "secret", "status": 200}]}
    )
    assert value == {
        "oobCode": "[REDACTED]",
        "nested": [{"idToken": "[REDACTED]", "status": 200}],
    }
    assert character_class("Ab0_-") == "base64url"
    assert character_class("Ab0!") == "other"
    assert character_class("") == "empty"


def test_only_a_loopback_origin_is_accepted() -> None:
    for origin in (
        "https://identitytoolkit.googleapis.com",
        "http://10.0.0.1:9099",
        "http://user@127.0.0.1:9099",
        "http://127.0.0.1:9099/path",
        "ftp://127.0.0.1:9099",
    ):
        with pytest.raises(CollectorError, match="loopback"):
            collect(
                origin=origin,
                project=PROJECT,
                nonce=NONCE,
                send=FakeService().send,
            )


def test_a_supplied_owner_approval_is_still_refused() -> None:
    with pytest.raises(CollectorError, match="production entry is closed"):
        collect(
            origin=ORIGIN,
            project=PROJECT,
            nonce=NONCE,
            send=FakeService().send,
            approval={"kind": "owner-execution-permission"},
        )


def test_the_request_budget_and_wall_clock_are_enforced() -> None:
    with pytest.raises(CollectorError, match="request budget"):
        run(request_budget=5)
    ticks = iter([0.0] + [float(index) * 40 for index in range(1, 200)])
    with pytest.raises(CollectorError, match="wall clock"):
        run(clock=lambda: next(ticks))


def test_cleanup_runs_and_is_reported_when_an_observation_fails() -> None:
    class Broken(FakeService):
        def _signInWithEmailLink(self, body: dict):
            raise RuntimeError("transport failure")

    service = Broken()
    _, receipt = run(service, tolerate_failure=True)
    assert receipt["recordingComplete"] is False
    assert receipt["stopReason"] == "stage-failed:email-link-signin"
    assert receipt["cleanupComplete"] is True
    assert receipt["remainingAccounts"] == 0
    assert service.accounts == {}


def test_a_failed_deletion_is_reported_instead_of_being_swallowed() -> None:
    service = FakeService(deleteFails=True)
    _, receipt = run(service)
    assert receipt["cleanupComplete"] is False
    assert receipt["remainingAccounts"] == 2
    assert receipt["deleteFailures"] == 2
    assert receipt["recovery"][0]["status"] == 500


def test_cleanup_only_touches_accounts_this_run_owns() -> None:
    service = FakeService()
    service.accounts["foreign"] = {
        "localId": "foreign",
        "email": "someone-else@example.invalid",
        "password": "unchanged",
        "emailVerified": False,
    }
    _, receipt = run(service)
    assert list(service.accounts) == ["foreign"]
    assert set(receipt["ownedAccounts"]) == {"accountA", "accountB"}
    assert all(
        row["account"] in receipt["ownedAccounts"] for row in receipt["recovery"]
    )


def test_privileged_stages_carry_the_owner_credential_and_clients_do_not() -> None:
    captured: list[dict] = []

    service = FakeService()

    def send(method, url, headers, body):
        captured.append({"url": url, "headers": headers})
        return service.send(method, url, headers, body)

    collect(origin=ORIGIN, project=PROJECT, nonce=NONCE, send=send)
    for record in captured:
        privileged = "/projects/" in record["url"]
        assert ("authorization" in record["headers"]) is privileged
        assert record["url"].startswith(ORIGIN + "/identitytoolkit.googleapis.com/v1/")


def test_the_command_line_never_accepts_a_code_or_a_credential() -> None:
    parser = build_parser()
    options = {action.dest for action in parser._actions}
    assert not options & {
        "oob_code",
        "code",
        "credential",
        "token",
        "password",
        "approval",
    }
    assert {"origin", "project", "nonce", "output"} <= options


def test_a_violated_bound_still_deletes_every_owned_account() -> None:
    service = FakeService()
    with pytest.raises(CollectorError, match="request budget") as raised:
        run(service, request_budget=5)
    receipt = raised.value.receipt
    assert receipt["stopReason"].startswith("bound-exceeded:")
    assert receipt["recordingComplete"] is False
    assert receipt["cleanupComplete"] is True
    assert receipt["remainingAccounts"] == 0
    assert service.accounts == {}
    assert receipt["recoveryRequests"] <= 4


def test_recovery_has_its_own_reserve_and_is_not_starved_by_observation() -> None:
    service = FakeService()
    with pytest.raises(CollectorError):
        run(service, request_budget=2)
    assert service.accounts == {}


def test_an_unbound_stage_input_is_recorded_rather_than_raised() -> None:
    class Silent(FakeService):
        def _sendOobCode(self, body: dict):
            return 200, {"kind": "identitytoolkit#GetOobConfirmationCodeResponse"}

    service = Silent()
    _, receipt = run(service, tolerate_failure=True)
    assert receipt["stopReason"] == "stage-failed:reset-code-lookup"
    assert receipt["cleanupComplete"] is True
    assert service.accounts == {}


def test_a_refused_delete_is_tolerated_when_absence_is_proven() -> None:
    class AlreadyGone(FakeService):
        def _delete(self, body: dict):
            if body["localId"] not in self.accounts:
                return 400, {"error": {"message": "USER_NOT_FOUND"}}
            return super()._delete(body)

    service = AlreadyGone()
    _, receipt = run(service)
    assert receipt["deleteFailures"] == 1
    assert receipt["remainingAccounts"] == 0
    assert receipt["cleanupComplete"] is True
