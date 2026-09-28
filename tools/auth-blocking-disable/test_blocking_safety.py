"""The recorder must never bind a raw API response to the saved report, must not report
an unconfirmed account as absent, and must accept a pending credential on the MFA
account's second sign-in. Every network, deploy and wait step is faked."""

import json
import types

import blocking_recorder as recorder
from blocking_contract import DISABLING_CLAIM, TEST_CODE

CONFIG_INITIAL = {
    "name": "projects/592603257417/config",
    "signIn": {"email": {"enabled": True, "passwordRequired": True}},
    "emailPrivacyConfig": {"enableImprovedEmailPrivacy": True},
    "mfa": {"state": "DISABLED"},
    "smsRegionConfig": {"allowlistOnly": {}},
    "blockingFunctions": {"forwardInboundCredentials": {}},
}


class World:
    """A scripted Identity Platform: accounts by email, config by PATCH, one function."""

    def __init__(
        self, second_signin_a="refused", lookup_fails=False, signup_lost=False
    ):
        self.config = json.loads(json.dumps(CONFIG_INITIAL))
        self.users = {}
        self.functions = []
        self.second_signin_a = second_signin_a
        self.lookup_fails = lookup_fails
        self.signup_lost = signup_lost
        self.counter = 0

    def preflight(self):
        return "token", "key", {"sha256": "0" * 64}

    def patch(self, url, body, token):
        for key, value in body.items():
            if key == "signIn":
                self.config.setdefault("signIn", {}).update(value)
            else:
                self.config[key] = value
        return 200, {}

    def user_by_token(self, token):
        return next(u for u in self.users.values() if u["_token"] == token)

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
        if url == recorder.CONFIG_URL:
            return 200, json.loads(json.dumps(self.config))
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
                "_disabled_by_hook": False,
            }
            if self.signup_lost and self.counter == 3:
                raise TimeoutError("response lost")
            self.users[uid] = user
            return 200, self.tokens_for(user)
        if "accounts:update" in url and token:
            user = self.users[body["localId"]]
            if body.get("emailVerified"):
                user["emailVerified"] = True
            if "mfa" in body:
                user["mfaInfo"] = [
                    {
                        "mfaEnrollmentId": f"enr-{user['localId']}",
                        "phoneInfo": e["phoneInfo"],
                    }
                    for e in body["mfa"]["enrollments"]
                ]
            if "customAttributes" in body:
                user["customAttributes"] = body["customAttributes"]
            return 200, self.public(user)
        if "accounts:delete" in url:
            self.users.pop(body["localId"], None)
            return 200, {}
        if "signInWithPassword" in url:
            user = next(u for u in self.users.values() if u["email"] == body["email"])
            claimed = json.loads(user.get("customAttributes", "{}")).get(
                DISABLING_CLAIM
            )
            if user.get("disabled"):
                return 400, {"error": {"message": "USER_DISABLED"}}
            if "mfaInfo" in user:
                if claimed and self.second_signin_a == "refused" and user.get("_seen"):
                    return 400, {"error": {"message": "USER_DISABLED"}}
                return 200, {
                    "localId": user["localId"],
                    "mfaPendingCredential": f"pending-{user['localId']}",
                    "mfaInfo": user["mfaInfo"],
                }
            if claimed:
                # Production-like: the hook disables and the request is refused, except
                # when the world is told the first sign-in is accepted.
                if user.get("_seen"):
                    return 400, {"error": {"message": "USER_DISABLED"}}
                user["_seen"] = True
                return 200, self.tokens_for(user)
            return 200, self.tokens_for(user)
        if "accounts:lookup" in url:
            # The derived lookup inside the first row's checks succeeds; the token-lookup
            # row that follows is the one that loses its response.
            self.lookups = getattr(self, "lookups", 0) + 1
            if self.lookup_fails and self.lookups == 3:
                raise TimeoutError("lookup lost")
            return 200, {"users": [self.public(self.user_by_token(body["idToken"]))]}
        if "mfaSignIn:start" in url:
            return 200, {"phoneResponseInfo": {"sessionInfo": "session"}}
        if "mfaSignIn:finalize" in url:
            uid = body["mfaPendingCredential"].removeprefix("pending-")
            user = self.users[uid]
            require = body["phoneVerificationInfo"]["code"] == TEST_CODE
            assert require
            claimed = json.loads(user.get("customAttributes", "{}")).get(
                DISABLING_CLAIM
            )
            if claimed:
                if user.get("_seen"):
                    return 400, {"error": {"message": "USER_DISABLED"}}
                user["_seen"] = True
                return 200, {
                    "idToken": user["_token"],
                    "refreshToken": user["_refresh"],
                }
            return 200, {"idToken": user["_token"], "refreshToken": user["_refresh"]}
        if "securetoken" in url:
            user = next(
                u for u in self.users.values() if u["_refresh"] == body["refresh_token"]
            )
            return 200, {
                "id_token": user["_token"],
                "refresh_token": user["_refresh"],
                "user_id": user["localId"],
                "expires_in": "3600",
                "token_type": "Bearer",
            }
        raise AssertionError(url)

    def firebase(self, args, timeout):
        if args[0] == "deploy":
            self.functions = [recorder.FUNCTION]
            self.config["blockingFunctions"] = {
                "triggers": {
                    "beforeSignIn": {"functionUri": "https://x/" + recorder.FUNCTION}
                }
            }
        if args[0] == "functions:delete":
            self.functions = []
        return 0


def wire(monkeypatch, world):
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", world.request)
    monkeypatch.setattr(recorder.core, "command", lambda argv: "deadbeef")
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder, "deployed_functions", lambda: list(world.functions))
    monkeypatch.setattr(recorder, "firebase", world.firebase)
    monkeypatch.setattr(recorder.shutil, "copytree", lambda *a, **k: None)
    monkeypatch.setattr(
        recorder.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=0)
    )
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        recorder,
        "claims",
        lambda t: {
            "sub": t.removeprefix("id-token-secret-"),
            "email": None,
            "firebase": {"sign_in_second_factor": "phone"},
        },
    )
    # The identity checks compare sub and email through claims; patch them out of the fake.
    monkeypatch.setattr(
        recorder,
        "claims",
        lambda t: {
            "sub": t.removeprefix("id-token-secret-"),
            "email": EMAILS.get(t),
            "firebase": {"sign_in_second_factor": "phone"},
        },
    )


EMAILS = {}


def run(tmp_path, monkeypatch, world):
    wire(monkeypatch, world)
    original_request = world.request

    def request(url, body=None, token=None, quota=False, form=False):
        status, response = original_request(url, body, token, quota, form)
        if "accounts:signUp" in url and status == 200:
            EMAILS[response["idToken"]] = body["email"]
        return status, response

    monkeypatch.setattr(recorder.core, "request", request)
    return recorder.observe(tmp_path / "run"), json.loads(
        (tmp_path / "run" / "observation.json").read_bytes()
    )


def test_a_normal_run_completes_and_restores(tmp_path, monkeypatch):
    world = World()
    report, saved = run(tmp_path, monkeypatch, world)
    assert report["status"] == "observed", report.get("lastStep")
    assert world.functions == [] and world.config["mfa"] == {"state": "DISABLED"}
    assert "secret" not in json.dumps(saved)


def test_an_interrupted_token_lookup_never_saves_the_raw_response(
    tmp_path, monkeypatch
):
    world = World(lookup_fails=True)
    report, saved = run(tmp_path, monkeypatch, world)
    assert report["status"] == "incomplete"
    assert "id-token-secret" not in json.dumps(saved)
    assert "refresh-secret" not in json.dumps(saved)


def test_an_unconfirmed_account_is_not_reported_absent(tmp_path, monkeypatch):
    world = World(signup_lost=True)
    report, saved = run(tmp_path, monkeypatch, world)
    assert report["status"] == "incomplete"
    assert saved.get("cleanup") != {"uidAbsent": True, "emailAbsent": True}


def test_a_pending_credential_on_the_mfa_second_signin_is_recorded(
    tmp_path, monkeypatch
):
    world = World(second_signin_a="pending")
    report, saved = run(tmp_path, monkeypatch, world)
    assert report["status"] == "observed", report.get("lastStep")
    row = next(r for r in saved["cases"] if r["id"] == "hook-a-second-signin")
    assert (
        row["outcome"] == "accepted"
        and row["checks"].get("pendingCredentialPresent") is True
    )
