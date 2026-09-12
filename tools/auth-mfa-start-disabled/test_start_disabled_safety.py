"""Offline drive of observe() against a scripted Identity Platform with phone MFA: the run
completes whether mfaSignIn:start on the disabled account is refused or (surprisingly)
accepted, skips the finalize when its start was not accepted, writes no configuration
before its preconditions hold, restores what it read, survives a termination signal, and
refuses a dirty checkout. No credential reaches any file."""

import base64
import json
import os
import signal
import urllib.parse

import pytest
import start_disabled_contract as contract
import start_disabled_recorder as recorder
from start_disabled_contract import (
    CASES,
    FINALIZE_CHECKS,
    TEST_CODE,
    complete,
    validate_row,
)

ORIGINAL_CONFIG = {
    "mfa": {"state": "DISABLED"},
    "signIn": {"phoneNumber": None},
    "smsRegionConfig": {"allowlistOnly": {}},
    "client": {"apiKey": "config-secret-api-key"},
}
CONFIG_SHA = "0" * 64
SECRET_MARKERS = (
    "-secret-",
    "Aa9!",
    "config-secret",
    "access-secret",
    "key-secret",
    TEST_CODE,
    recorder.TEST_PHONE,
)


def jwt(payload, marker):
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{body}.signature-{marker}-" + "x" * 60


class World:
    """A password account with a phone factor. `start_when_disabled` decides whether
    mfaSignIn:start on a disabled account is refused (default) or accepted. `lose` and
    `terminate` interrupt a named request."""

    def __init__(self, output, **options):
        self.output = output
        self.start_when_disabled = options.pop("start_when_disabled", "refused")
        self.lose = options.pop("lose", None)
        self.terminate = options.pop("terminate", None)
        assert not options, options
        self.users = {}
        self.pendings = {}
        self.sessions = {}
        self.tokens = {}
        self.config = json.loads(json.dumps(ORIGINAL_CONFIG))
        self.patches = []
        self.counts = {}
        self.deleted = []

    def preflight(self):
        return "access-secret-token", "key-secret-value", {"sha256": CONFIG_SHA}

    def count(self, action):
        self.counts[action] = self.counts.get(action, 0) + 1
        if self.lose == (action, self.counts[action]):
            raise TimeoutError("request lost")
        if self.terminate == (action, self.counts[action]):
            os.kill(os.getpid(), signal.SIGTERM)

    @staticmethod
    def error(message):
        return 400, {"error": {"message": f"{message} : detail-secret-x"}}

    def public(self, user):
        return {k: v for k, v in user.items() if not k.startswith("_")}

    def issue(self, user):
        payload = {
            "sub": user["localId"],
            "email": user["email"],
            "auth_time": 1,
            "firebase": {"sign_in_second_factor": "phone"},
        }
        token = jwt(payload, "id-token-secret")
        self.tokens[token] = user["localId"]
        return {"idToken": token, "refreshToken": "refresh-secret-x"}

    def patch(self, url, body, token):
        assert token == "access-secret-token"
        base, _, query = url.partition("?")
        assert base == recorder.CONFIG_URL
        assert urllib.parse.parse_qs(query) == {"updateMask": [recorder.CONFIG_MASK]}
        self.patches.append(json.loads(json.dumps(body)))
        self.config["mfa"] = body["mfa"]
        self.config["signIn"] = {"phoneNumber": body["signIn"]["phoneNumber"]}
        self.config["smsRegionConfig"] = body["smsRegionConfig"]
        return 200, {}

    def request(self, url, body=None, token=None, quota=False, form=False):
        if url == recorder.CONFIG_URL:
            assert body is None and token == "access-secret-token"
            return 200, json.loads(json.dumps(self.config))
        assert url.startswith(
            (
                "https://identitytoolkit.googleapis.com/",
                "https://securetoken.googleapis.com/",
            )
        )
        if "securetoken" in url:
            self.count("token")
            uid = next(iter(self.users), None)
            return 200, {
                "id_token": self.issue(self.users[uid])["idToken"],
                "refresh_token": "refresh-secret-x",
                "user_id": uid,
                "expires_in": "3600",
                "token_type": "Bearer",
            }
        action = url.split("/")[-1].split("?")[0].removeprefix("accounts:")
        if "/projects/" in url:
            assert token == "access-secret-token" and quota
            self.count("admin:" + action)
            return self.admin(action, body)
        assert token is None
        self.count(action)
        return self.client(action, body)

    def admin(self, action, body):
        if action == "lookup":
            keys = {"localId": "localId", "email": "email", "phoneNumber": "_phone"}
            found = []
            for u in self.users.values():
                for field, key in keys.items():
                    if u.get(key) in body.get(field, []):
                        found.append(self.public(u))
                        break
            return 200, ({"users": found} if found else {})
        if action == "delete":
            self.deleted.append(body["localId"])
            self.users.pop(body["localId"], None)
            return 200, {}
        assert action == "update"
        user = self.users[body["localId"]]
        if "disableUser" in body:
            user["disabled"] = body["disableUser"]
        if "emailVerified" in body:
            user["emailVerified"] = body["emailVerified"]
        if "mfa" in body:
            user["mfaInfo"] = [
                {"mfaEnrollmentId": "enr-x", "phoneInfo": e["phoneInfo"]}
                for e in body["mfa"]["enrollments"]
            ]
            user["_phone"] = user["mfaInfo"][0]["phoneInfo"]
        return 200, {"localId": user["localId"], "email": user["email"]}

    def client(self, action, body):
        if action == "signUp":
            uid = "uid-x"
            self.users[uid] = {
                "localId": uid,
                "email": body["email"],
                "displayName": body["displayName"],
                "emailVerified": False,
                "_password": body["password"],
            }
            return 200, {**self.issue(self.users[uid]), "localId": uid, "email": uid}
        if action == "signInWithPassword":
            user = next(u for u in self.users.values() if u["email"] == body["email"])
            if user["_password"] != body["password"]:
                return self.error("INVALID_LOGIN_CREDENTIALS")
            if user.get("disabled"):
                return self.error("USER_DISABLED")
            assert user.get("emailVerified") is True
            credential = "pending-secret-" + str(len(self.pendings))
            self.pendings[credential] = user["localId"]
            return 200, {
                "mfaPendingCredential": credential,
                "mfaInfo": user["mfaInfo"],
                "localId": user["localId"],
            }
        if action == "lookup":
            uid = self.tokens.get(body["idToken"])
            if uid is None:
                return self.error("INVALID_ID_TOKEN")
            return 200, {"users": [self.public(self.users[uid])]}
        raise AssertionError(action)

    def mfa(self, action, body):
        pending = self.pendings.get(body["mfaPendingCredential"])
        if pending is None:
            return self.error("INVALID_MFA_PENDING_CREDENTIAL")
        disabled = self.users[pending].get("disabled", False)
        if action == "mfaSignIn:start":
            if disabled and self.start_when_disabled == "refused":
                return self.error("USER_DISABLED")
            session = "session-secret-" + str(len(self.sessions))
            self.sessions[session] = {"uid": pending, "consumed": False}
            return 200, {"phoneResponseInfo": {"sessionInfo": session}}
        info = body["phoneVerificationInfo"]
        session = self.sessions.get(info["sessionInfo"])
        if session is None or session["consumed"] or session["uid"] != pending:
            return self.error("INVALID_SESSION_INFO")
        if self.users[pending].get("disabled"):
            return self.error("USER_DISABLED")
        if info["code"] != TEST_CODE:
            return self.error("INVALID_CODE")
        session["consumed"] = True
        self.pendings.pop(body["mfaPendingCredential"])
        return 200, self.issue(self.users[pending])


def request_router(world):
    orig = world.request

    def router(url, body=None, token=None, quota=False, form=False):
        if "/v2/accounts/mfaSignIn" in url:
            action = url.split("/")[-1].split("?")[0]
            world.count(action)
            return world.mfa(action, body)
        return orig(url, body, token, quota, form)

    return router


def git(dirty):
    def command(argv):
        if argv[:3] == ["git", "status", "--porcelain"]:
            assert argv[3] == "--" and set(argv[4:]) == set(recorder.PROBE_TREES)
            return (
                " M tools/auth-mfa-start-disabled/start_disabled_recorder.py"
                if dirty
                else ""
            )
        assert argv == ["git", "rev-parse", "HEAD"]
        return "deadbeef"

    return command


def run(tmp_path, monkeypatch, dirty=False, projection_sha=CONFIG_SHA, **options):
    world = World(tmp_path / "run", **options)
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", request_router(world))
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder.core, "command", git(dirty))
    monkeypatch.setattr(
        recorder.core,
        "config_projection",
        lambda status, config: {"sha256": projection_sha},
    )
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    report = recorder.observe(world.output)
    saved = json.loads((world.output / "observation.json").read_bytes())
    for path in world.output.rglob("*"):
        if path.is_file():
            text = path.read_text()
            for marker in SECRET_MARKERS:
                assert marker not in text, (path.name, marker)
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    return world, report, saved


def rows_of(saved):
    return {r["id"]: r for r in saved["cases"]}


def test_start_refused_while_disabled_completes_and_the_pending_survives(
    tmp_path, monkeypatch
):
    world, report, saved = run(tmp_path, monkeypatch, start_when_disabled="refused")
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    assert rows["disabled-start"]["observedError"] == "USER_DISABLED"
    assert rows["disabled-finalize"]["skipped"] is True
    assert rows["reenabled-start"]["outcome"] == "accepted"
    assert rows["reenabled-finalize"]["outcome"] == "accepted"
    assert saved["transitions"] == [
        {"disabled": True, "readback": True},
        {"disabled": False, "readback": True},
    ]
    assert saved["heldPendingBeforeDisable"] is True
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.deleted == ["uid-x"] and world.users == {}
    assert len(world.patches) == 2 and world.patches[1]["mfa"] == {"state": "DISABLED"}
    assert saved["configRestored"] is True and saved["configDigestMatches"] is True


def test_start_accepted_while_disabled_is_recorded_not_pinned(tmp_path, monkeypatch):
    # A surprising acceptance is an observation: the disabled finalize then runs too.
    _world, report, saved = run(tmp_path, monkeypatch, start_when_disabled="accepted")
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    assert rows["disabled-start"]["outcome"] == "accepted"
    # The finalize still refuses the disabled account (USER_DISABLED), recorded as a
    # diagnostic refusal, and the run completes.
    assert rows["disabled-finalize"]["observedError"] == "USER_DISABLED"
    assert rows["reenabled-finalize"]["outcome"] == "accepted"


def test_a_termination_signal_still_cleans_up_and_restores(tmp_path, monkeypatch):
    world, report, saved = run(tmp_path, monkeypatch, terminate=("mfaSignIn:start", 1))
    assert report["status"] == "incomplete" and saved["failure"] == "Terminated"
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {} and world.patches[-1]["mfa"] == {"state": "DISABLED"}
    assert not complete(saved)


def test_a_dirty_checkout_is_refused(tmp_path, monkeypatch):
    world, report, saved = run(tmp_path, monkeypatch, dirty=True)
    assert report["status"] == "incomplete" and saved["failure"] == "ValueError"
    assert (
        "committedCheckout" not in saved and world.patches == [] and world.counts == {}
    )


def test_no_configuration_write_when_preconditions_fail(tmp_path, monkeypatch):
    world = World(tmp_path / "run")
    world.config["mfa"] = {"state": "ENABLED"}
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", request_router(world))
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder.core, "command", git(False))
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    report = recorder.observe(tmp_path / "run")
    assert report["status"] == "incomplete" and report["cases"] == []
    assert (
        world.patches == [] and not (tmp_path / "run" / "config-recovery.json").exists()
    )


def test_a_digest_mismatch_after_restore_is_not_complete(tmp_path, monkeypatch):
    _world, report, saved = run(tmp_path, monkeypatch, projection_sha="f" * 64)
    assert report["status"] == "observed"
    assert saved["configDigestMatches"] is False and complete(saved) is False


def accepted(name, checks):
    return {
        "id": name,
        "httpStatus": 200,
        "outcome": "accepted",
        "observedError": None,
        "checks": checks,
        "elapsedMs": 1,
        "skipped": False,
    }


def refused(name, error, status=400):
    return {
        "id": name,
        "httpStatus": status,
        "outcome": "refused",
        "observedError": error,
        "checks": {},
        "elapsedMs": 1,
        "skipped": False,
    }


def skipped(name):
    return {
        "id": name,
        "httpStatus": None,
        "outcome": "skipped",
        "observedError": None,
        "checks": {},
        "elapsedMs": 1,
        "skipped": True,
    }


def complete_report():
    finalize = dict.fromkeys(FINALIZE_CHECKS, True)
    rows = {
        "baseline-fresh-finalize": accepted("baseline-fresh-finalize", finalize),
        "disabled-start": refused("disabled-start", "USER_DISABLED"),
        "disabled-finalize": skipped("disabled-finalize"),
        "reenabled-start": accepted("reenabled-start", {"sessionInfoPresent": True}),
        "reenabled-finalize": accepted("reenabled-finalize", finalize),
        "final-fresh-finalize": accepted("final-fresh-finalize", finalize),
    }
    return {
        "status": "observed",
        "target": "production",
        "committedCheckout": True,
        "cases": [rows[n] for n in CASES],
        "setup": True,
        "heldPendingBeforeDisable": True,
        "transitions": [
            {"disabled": True, "readback": True},
            {"disabled": False, "readback": True},
        ],
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
        "configRestored": True,
        "configDigestMatches": True,
    }


def test_complete_report_is_complete():
    assert complete(complete_report())


def test_complete_rejects_inconsistencies():
    assert complete({**complete_report(), "configDigestMatches": False}) is False
    assert complete({**complete_report(), "heldPendingBeforeDisable": False}) is False
    assert complete({**complete_report(), "transitions": []}) is False
    assert complete({**complete_report(), "setup": False}) is False
    # A disabled-start that was accepted must not skip its finalize.
    report = complete_report()
    report["cases"][1] = accepted("disabled-start", {"sessionInfoPresent": True})
    assert complete(report) is False
    report["cases"][2] = accepted(
        "disabled-finalize", dict.fromkeys(FINALIZE_CHECKS, True)
    )
    assert complete(report)


def test_a_transient_diagnostic_refusal_is_never_complete():
    for status in (400, 403, 429):
        report = complete_report()
        row = refused("disabled-start", "TOO_MANY_ATTEMPTS_TRY_LATER", status)
        validate_row(row, "disabled-start")
        report["cases"][1] = row
        assert complete(report) is False, status


def test_control_rows_may_not_be_refused():
    with pytest.raises(ValueError):
        validate_row(
            refused("baseline-fresh-finalize", "USER_DISABLED"),
            "baseline-fresh-finalize",
        )


def test_contract_shapes():
    assert len(CASES) == 6 and len(contract.DIAGNOSTIC) == 4
    assert (
        contract.CORPUS["slice"] == "auth-mfa-start-disabled"
        and contract.CORPUS["revision"] == 1
    )
    assert (
        contract.error_code({"error": {"message": "USER_DISABLED : x"}})
        == "USER_DISABLED"
    )
