"""Offline drive of observe() against a scripted Identity Platform: the run completes for
both production shapes (tokens returned or not), never saves raw tokens even when a
follow-up request is lost, and keeps the token rows consistent with the update row."""

import json

import admin_update_recorder as recorder
import pytest
from admin_update_contract import CASES, DIAGNOSTIC, complete, error_code, validate_row


class World:
    """Password accounts by email; an administrative password update may return tokens."""

    def __init__(self, update_returns_tokens=True, lose_lookup_number=None):
        self.users = {}
        self.counter = 0
        self.lookups = 0
        self.update_returns_tokens = update_returns_tokens
        self.lose_lookup_number = lose_lookup_number

    def preflight(self):
        return "token", "key", {"sha256": "0" * 64}

    def tokens_for(self, user):
        return {
            "idToken": user["_token"],
            "refreshToken": user["_refresh"],
            "localId": user["localId"],
            "email": user["email"],
            "expiresIn": "3600",
        }

    def public(self, user):
        return {k: v for k, v in user.items() if not k.startswith("_")}

    def request(self, url, body=None, token=None, quota=False, form=False):
        if url.endswith("/config"):
            return 200, {"name": "projects/592603257417/config"}
        if "passwordPolicy" in url:
            return 200, recorder.PASSWORD_POLICY
        if "accounts:lookup" in url and token:
            found = [
                self.public(u)
                for u in self.users.values()
                if u["localId"] in body.get("localId", [])
                or u["email"] in body.get("email", [])
            ]
            return 200, {"users": found} if found else {}
        if "accounts:signUp" in url:
            self.counter += 1
            uid = f"uid-{self.counter}"
            user = {
                "localId": uid,
                "email": body["email"],
                "displayName": body["displayName"],
                "_password": body["password"],
                "_token": f"id-token-secret-{uid}",
                "_refresh": f"refresh-secret-{uid}",
            }
            self.users[uid] = user
            return 200, self.tokens_for(user)
        if "accounts:update" in url and token:
            user = self.users[body["localId"]]
            response = {"localId": user["localId"], "email": user["email"]}
            if "disableUser" in body:
                user["disabled"] = body["disableUser"]
            if "photoUrl" in body:
                user["photoUrl"] = body["photoUrl"]
            if "password" in body:
                user["_password"] = body["password"]
                user["_token"] = user["_token"] + "-new"
                if self.update_returns_tokens:
                    response.update(
                        {"idToken": user["_token"], "refreshToken": user["_refresh"]}
                    )
            return 200, response
        if "accounts:delete" in url:
            self.users.pop(body["localId"], None)
            return 200, {}
        if "signInWithPassword" in url:
            user = next(u for u in self.users.values() if u["email"] == body["email"])
            if user["_password"] != body["password"]:
                return 400, {"error": {"message": "INVALID_LOGIN_CREDENTIALS"}}
            if user.get("disabled"):
                return 400, {"error": {"message": "USER_DISABLED"}}
            return 200, self.tokens_for(user)
        if "accounts:lookup" in url:
            self.lookups += 1
            if self.lookups == self.lose_lookup_number:
                raise TimeoutError("lookup lost")
            user = next(
                u for u in self.users.values() if u["_token"] == body["idToken"]
            )
            return 200, {"users": [self.public(user)]}
        if "securetoken" in url:
            user = next(
                u for u in self.users.values() if u["_refresh"] == body["refresh_token"]
            )
            if user.get("disabled"):
                return 400, {"error": {"message": "USER_DISABLED"}}
            return 200, {
                "id_token": user["_token"],
                "refresh_token": user["_refresh"],
                "user_id": user["localId"],
                "expires_in": "3600",
                "token_type": "Bearer",
            }
        raise AssertionError(url)


def run(tmp_path, monkeypatch, world):
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", world.request)
    monkeypatch.setattr(recorder.core, "command", lambda argv: "deadbeef")
    monkeypatch.setattr(
        recorder.core, "config_projection", lambda status, config: {"sha256": "0" * 64}
    )
    report = recorder.observe(tmp_path / "run")
    return report, json.loads((tmp_path / "run" / "observation.json").read_bytes())


def test_a_run_where_the_update_returns_tokens_completes(tmp_path, monkeypatch):
    report, saved = run(tmp_path, monkeypatch, World(update_returns_tokens=True))
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = {r["id"]: r for r in saved["cases"]}
    assert rows["disabled-a-password-update"]["checks"]["tokensReturned"] is True
    assert rows["disabled-a-update-token-lookup"]["outcome"] == "accepted"
    assert rows["disabled-a-update-token-refresh"]["outcome"] == "refused"
    assert rows["disabled-a-signin"]["observedError"] == "USER_DISABLED"
    assert rows["reenabled-a-signin"]["outcome"] == "accepted"
    assert "secret" not in json.dumps(saved)


def test_a_run_where_the_update_returns_no_tokens_completes(tmp_path, monkeypatch):
    report, saved = run(tmp_path, monkeypatch, World(update_returns_tokens=False))
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = {r["id"]: r for r in saved["cases"]}
    assert rows["disabled-a-password-update"]["checks"]["tokensReturned"] is False
    assert rows["disabled-a-update-token-lookup"]["skipped"] is True


def test_an_interrupted_follow_up_never_saves_raw_tokens(tmp_path, monkeypatch):
    # Lookups: two baseline derived lookups, then the update-token lookup is the third.
    report, saved = run(tmp_path, monkeypatch, World(lose_lookup_number=3))
    assert report["status"] == "incomplete"
    assert "id-token-secret" not in json.dumps(saved)
    assert "refresh-secret" not in json.dumps(saved)
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}


def test_contract_shapes():
    assert len(CASES) == 10 and len(DIAGNOSTIC) == 6
    assert error_code({"error": {"message": "USER_DISABLED : x"}}) == "USER_DISABLED"
    with pytest.raises(ValueError):
        validate_row(
            {
                "id": "baseline-a-signin",
                "httpStatus": 400,
                "outcome": "refused",
                "observedError": "USER_DISABLED",
                "checks": {},
                "elapsedMs": 1,
                "skipped": False,
            },
            "baseline-a-signin",
        )
