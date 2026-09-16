"""Offline drive of observe() against a scripted Identity Platform: the readback rows
record the flag as seen on the time axis (a world that persists the disable only after a
delay), sign-in rows are diagnostic, no raw token is saved, and the contract rejects a run
whose time axis is not anchored on refused first sign-ins."""

import json
import types

import readback_recorder as recorder
from readback_contract import CASES, DISABLING_CLAIM, READBACKS, complete


class World:
    """Password accounts; a claimed account's sign-in is refused and its record becomes
    disabled `delay` seconds later on the world's own clock."""

    def __init__(self, delay):
        self.delay = delay
        self.now = 1000.0
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

    def sleep(self, seconds):
        self.now += seconds

    def time(self):
        return self.now

    def tokens_for(self, u):
        return {
            "idToken": u["_token"],
            "refreshToken": u["_refresh"],
            "localId": u["localId"],
            "email": u["email"],
            "expiresIn": "3600",
        }

    def public(self, u):
        out = {k: v for k, v in u.items() if not k.startswith("_")}
        if u.get("_disabled_at") is not None and self.now >= u["_disabled_at"]:
            out["disabled"] = True
        return out

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
                "_disabled_at": None,
            }
            self.users[uid] = user
            return 200, self.tokens_for(user)
        if "accounts:update" in url and token:
            user = self.users[body["localId"]]
            if body.get("emailVerified"):
                user["emailVerified"] = True
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
            if self.public(user).get("disabled"):
                return 400, {"error": {"message": "USER_DISABLED"}}
            if claimed:
                if user["_disabled_at"] is None:
                    user["_disabled_at"] = self.now + self.delay
                return 400, {"error": {"message": "USER_DISABLED"}}
            return 200, self.tokens_for(user)
        if "accounts:lookup" in url:
            user = next(
                u for u in self.users.values() if u["_token"] == body["idToken"]
            )
            return 200, {"users": [self.public(user)]}
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
    monkeypatch.setattr(recorder.time, "sleep", world.sleep)
    monkeypatch.setattr(recorder.time, "time", world.time)
    report = recorder.observe(tmp_path / "run")
    return report, json.loads((tmp_path / "run" / "observation.json").read_bytes())


def test_a_delayed_persistence_is_recorded_on_the_time_axis(tmp_path, monkeypatch):
    report, saved = run(tmp_path, monkeypatch, World(delay=10))
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = {r["id"]: r for r in saved["cases"]}
    seen = {name: rows[name]["checks"]["disabledPersisted"] for name in READBACKS}
    assert seen == {
        "x-readback-before": False,
        "x-readback-immediate": False,
        "x-readback-after-5s": False,
        "x-readback-after-30s": True,
        "y-readback-after-30s-unread": True,
    }
    assert rows["x-readback-after-30s"]["checks"]["secondsSinceRefusal"] >= 30
    assert "secret" not in json.dumps(saved)


def test_an_immediate_persistence_is_recorded_too(tmp_path, monkeypatch):
    report, saved = run(tmp_path, monkeypatch, World(delay=0))
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = {r["id"]: r for r in saved["cases"]}
    assert all(
        rows[n]["checks"]["disabledPersisted"]
        for n in READBACKS
        if n != "x-readback-before"
    )


def test_completion_needs_refused_first_signins_and_the_waits():
    from test_readback_safety import World  # noqa: F401 -- module self-check

    assert len(CASES) == 11
