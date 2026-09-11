"""Offline drive of observe() against a scripted Identity Platform for the two production
shapes of a created-then-disabled sign-up (refused without a record, or accepted with a
disabled record), never saving raw tokens and reporting the target's cleanup truthfully."""

import json
import types

import create_recorder as recorder
from create_contract import CASES, CONTROL_PHOTO, DIAGNOSTIC, SELECTOR, complete


class World:
    def __init__(self, shape):
        self.shape = shape  # "refused-no-record" or "accepted-disabled"
        self.config = {
            "name": "projects/592603257417/config",
            "mfa": {"state": "DISABLED"},
            "blockingFunctions": {"forwardInboundCredentials": {}},
        }
        self.users = {}
        self.functions = []
        self.counter = 0

    def preflight(self):
        return "token", "key", {"sha256": "0" * 64}

    def patch(self, url, body, token):
        self.config.update(body)
        return 200, {}

    def tokens_for(self, u):
        return {
            "idToken": u["_token"],
            "refreshToken": u["_refresh"],
            "localId": u["localId"],
            "email": u["email"],
            "expiresIn": "3600",
        }

    def public(self, u):
        return {k: v for k, v in u.items() if not k.startswith("_")}

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
            if any(u["email"] == body["email"] for u in self.users.values()):
                return 400, {"error": {"message": "EMAIL_EXISTS"}}
            self.counter += 1
            uid = f"uid-{self.counter}"
            user = {
                "localId": uid,
                "email": body["email"],
                "displayName": body["displayName"],
                "photoUrl": body.get("photoUrl"),
                "_password": body["password"],
                "_token": f"id-token-secret-{uid}",
                "_refresh": f"refresh-secret-{uid}",
            }
            if body.get("photoUrl") == SELECTOR:
                if self.shape == "refused-no-record":
                    return 400, {"error": {"message": "USER_DISABLED"}}
                user["disabled"] = True
                self.users[uid] = user
                return 400, {"error": {"message": "USER_DISABLED"}}
            self.users[uid] = user
            return 200, self.tokens_for(user)
        if "accounts:delete" in url:
            self.users.pop(body["localId"], None)
            return 200, {}
        if "signInWithPassword" in url:
            user = next(
                (u for u in self.users.values() if u["email"] == body["email"]), None
            )
            if user is None:
                return 400, {"error": {"message": "INVALID_LOGIN_CREDENTIALS"}}
            if user.get("disabled"):
                return 400, {"error": {"message": "USER_DISABLED"}}
            return 200, self.tokens_for(user)
        if "accounts:lookup" in url:
            user = next(
                u for u in self.users.values() if u["_token"] == body["idToken"]
            )
            return 200, {"users": [self.public(user)]}
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


def run(tmp_path, monkeypatch, world):
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", world.request)
    monkeypatch.setattr(recorder.core, "command", lambda argv: "deadbeef")
    monkeypatch.setattr(
        recorder.core, "config_projection", lambda status, config: {"sha256": "0" * 64}
    )
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder, "deployed_functions", lambda: list(world.functions))
    monkeypatch.setattr(recorder, "firebase", world.firebase)
    monkeypatch.setattr(recorder.shutil, "copytree", lambda *a, **k: None)
    monkeypatch.setattr(
        recorder.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=0)
    )
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    report = recorder.observe(tmp_path / "run")
    return report, json.loads((tmp_path / "run" / "observation.json").read_bytes())


def test_refused_without_a_record_completes_with_truthful_cleanup(
    tmp_path, monkeypatch
):
    report, saved = run(tmp_path, monkeypatch, World("refused-no-record"))
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = {r["id"]: r for r in saved["cases"]}
    assert rows["target-t-signup"]["observedError"] == "USER_DISABLED"
    assert rows["target-t-record-readback"]["checks"] == {
        "recordExists": False,
        "disabledPersisted": False,
    }
    assert rows["control-c-signup-readback"]["checks"]["photoUrlPersisted"] is True
    assert saved["cleanup"]["t"] == {"recordNeverCreated": True, "emailAbsent": True}
    assert "secret" not in json.dumps(saved)


def test_refused_with_a_disabled_record_completes_and_deletes_it(tmp_path, monkeypatch):
    world = World("accepted-disabled")
    report, saved = run(tmp_path, monkeypatch, world)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = {r["id"]: r for r in saved["cases"]}
    assert rows["target-t-record-readback"]["checks"] == {
        "recordExists": True,
        "disabledPersisted": True,
    }
    assert rows["target-t-second-signup"]["observedError"] == "EMAIL_EXISTS"
    assert saved["cleanup"]["t"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {}


def test_contract_shape():
    assert len(CASES) == 10 and len(DIAGNOSTIC) == 5 and CONTROL_PHOTO != SELECTOR
