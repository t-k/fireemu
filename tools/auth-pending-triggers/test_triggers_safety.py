"""Offline drive of observe() against a scripted Identity Platform with phone MFA, once
per trigger: the run completes whether the trigger leaves the held credential usable or
revokes it, aborts a provider unlink whose administrative link precondition is refused,
never writes credentials to any file, writes no configuration before its preconditions
hold, restores what it read, survives a termination signal, and refuses a dirty checkout.
"""

import base64
import json
import os
import signal
import urllib.parse

import pytest
import triggers_contract as contract
import triggers_recorder as recorder
from triggers_contract import (
    CASES,
    FINALIZE_CHECKS,
    LINK_PROVIDER,
    TEST_CODE,
    TRIGGERS,
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
    contract.TEST_CODE,
    contract.TEST_PHONE,
)


def jwt(payload, marker):
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{body}.signature-{marker}-" + "x" * 60


class World:
    """A password account with an administratively enrolled phone factor.

    `revokes_held` makes the trigger invalidate the held pending credential (as a
    validSince advance would). `link_refused` makes the administrative federated link
    precondition fail. `lose`/`terminate` interrupt a named request."""

    def __init__(self, output, **options):
        self.output = output
        self.revokes_held = options.pop("revokes_held", False)
        self.link_refused = options.pop("link_refused", False)
        self.lose = options.pop("lose", None)
        self.terminate = options.pop("terminate", None)
        self.reject_post_trigger_sessions = options.pop(
            "reject_post_trigger_sessions", False
        )
        self.bump_volatile_on_unlink = options.pop("bump_volatile_on_unlink", False)
        assert not options, options
        self.trigger_fired = False
        self.users = {}
        self.pendings = {}
        self.sessions = {}
        self.tokens = {}
        self.oob = {}
        self.config = json.loads(json.dumps(ORIGINAL_CONFIG))
        self.patches = []
        self.counts = {}
        self.deleted = []
        self.revoked_pendings = set()
        self.revoked_sessions = set()

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

    def issue(self, user, second_factor):
        payload = {"sub": user["localId"], "email": user["email"], "auth_time": 1}
        if second_factor:
            payload["firebase"] = {"sign_in_second_factor": "phone"}
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
            token_row = body["refresh_token"]
            uid = (
                next(iter(self.users), None)
                if token_row == "refresh-secret-x"
                else None
            )
            if uid is None:
                return self.error("INVALID_REFRESH_TOKEN")
            user = self.users[uid]
            return 200, {
                "id_token": self.issue(user, True)["idToken"],
                "refresh_token": token_row,
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

    def revoke_held(self):
        """A validSince-style revocation: the credentials issued before the trigger stop
        working, while a fresh sign-in after the trigger still succeeds."""
        if self.revokes_held:
            self.revoked_pendings.update(self.pendings)
            self.revoked_sessions.update(self.sessions)

    def admin(self, action, body):
        if action == "lookup":
            keys = {"localId": "localId", "email": "email", "phoneNumber": "_phone"}
            found = [
                self.public(u)
                for u in self.users.values()
                for field, key in keys.items()
                if u.get(key) in body.get(field, [])
            ]
            # De-duplicate while keeping order.
            seen = []
            for u in found:
                if u not in seen:
                    seen.append(u)
            return 200, ({"users": seen} if seen else {})
        if action == "delete":
            self.deleted.append(body["localId"])
            self.users.pop(body["localId"], None)
            return 200, {}
        if action == "sendOobCode":
            assert (
                body["requestType"] == "PASSWORD_RESET"
                and body["returnOobLink"] is True
            )
            user = next(u for u in self.users.values() if u["email"] == body["email"])
            code = "oob-secret-code"
            self.oob[code] = user["localId"]
            return 200, {"email": body["email"], "oobCode": code}
        assert action == "update"
        user = self.users[body["localId"]]
        if "password" in body:
            user["_password"] = body["password"]
            self.trigger_fired = True
            self.revoke_held()
            return 200, {**self.issue(user, False), "localId": user["localId"]}
        if "emailVerified" in body:
            user["emailVerified"] = body["emailVerified"]
        if "mfa" in body:
            user["mfaInfo"] = [
                {"mfaEnrollmentId": "enr-x", "phoneInfo": e["phoneInfo"]}
                for e in body["mfa"]["enrollments"]
            ]
            user["_phone"] = user["mfaInfo"][0]["phoneInfo"]
        if "linkProviderUserInfo" in body:
            if self.link_refused:
                return self.error("OPERATION_NOT_ALLOWED")
            user.setdefault("providerUserInfo", []).append(
                {"providerId": body["linkProviderUserInfo"]["providerId"]}
            )
        return 200, {"localId": user["localId"], "email": user["email"]}

    def client(self, action, body):
        if action == "signUp":
            uid = "uid-x"
            user = {
                "localId": uid,
                "email": body["email"],
                "displayName": body["displayName"],
                "emailVerified": False,
                "_password": body["password"],
            }
            self.users[uid] = user
            return 200, {**self.issue(user, False), "localId": uid, "email": uid}
        if action == "signInWithPassword":
            user = next(u for u in self.users.values() if u["email"] == body["email"])
            if user["_password"] != body["password"]:
                return self.error("INVALID_LOGIN_CREDENTIALS")
            assert user.get("emailVerified") is True, (
                "MFA sign-in of an unverified email"
            )
            credential = "pending-secret-" + str(len(self.pendings))
            self.pendings[credential] = {
                "uid": user["localId"],
                "after_trigger": self.trigger_fired,
            }
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
        if action == "resetPassword":
            uid = self.oob.get(body["oobCode"])
            if uid is None:
                return self.error("INVALID_OOB_CODE")
            self.users[uid]["_password"] = body["newPassword"]
            self.trigger_fired = True
            self.revoke_held()
            return 200, {
                "email": self.users[uid]["email"],
                "requestType": "PASSWORD_RESET",
            }
        if action == "update":
            uid = self.tokens.get(body["idToken"])
            if uid is None:
                return self.error("INVALID_ID_TOKEN")
            user = self.users[uid]
            if "password" in body:
                user["_password"] = body["password"]
                self.trigger_fired = True
                self.revoke_held()
                return 200, {**self.issue(user, False), "localId": uid}
            if "deleteProvider" in body:
                user["providerUserInfo"] = [
                    p
                    for p in user.get("providerUserInfo", [])
                    if p["providerId"] not in body["deleteProvider"]
                ]
                self.trigger_fired = True
                if self.bump_volatile_on_unlink:
                    user["validSince"] = "999"
                    user["lastLoginAt"] = "111"
                self.revoke_held()
                return 200, {"localId": uid}
            return 200, {"localId": uid}
        if action == "mfaSignIn:start":
            pending = self.pendings.get(body["mfaPendingCredential"])
            if pending is None or body["mfaPendingCredential"] in self.revoked_pendings:
                return self.error("INVALID_MFA_PENDING_CREDENTIAL")
            session = "session-secret-" + str(len(self.sessions))
            self.sessions[session] = {
                "uid": pending["uid"],
                "consumed": False,
                "after_trigger": self.trigger_fired,
            }
            return 200, {"phoneResponseInfo": {"sessionInfo": session}}
        assert action == "mfaSignIn:finalize"
        pending = self.pendings.get(body["mfaPendingCredential"])
        if pending is None or body["mfaPendingCredential"] in self.revoked_pendings:
            return self.error("INVALID_MFA_PENDING_CREDENTIAL")
        info = body["phoneVerificationInfo"]
        session = self.sessions.get(info["sessionInfo"])
        if (
            session is None
            or session["consumed"]
            or session["uid"] != pending["uid"]
            or info["sessionInfo"] in self.revoked_sessions
            or (
                self.reject_post_trigger_sessions
                and session["after_trigger"]
                and not pending["after_trigger"]
            )
        ):
            return self.error("INVALID_SESSION_INFO")
        if info["code"] != TEST_CODE:
            return self.error("INVALID_CODE")
        session["consumed"] = True
        self.pendings.pop(body["mfaPendingCredential"])
        return 200, self.issue(self.users[pending["uid"]], True)


def git(dirty):
    def command(argv):
        if argv[:3] == ["git", "status", "--porcelain"]:
            assert argv[3] == "--" and set(argv[4:]) == set(recorder.PROBE_TREES)
            return (
                " M tools/auth-pending-triggers/triggers_recorder.py" if dirty else ""
            )
        assert argv == ["git", "rev-parse", "HEAD"]
        return "deadbeef"

    return command


def run(
    trigger, tmp_path, monkeypatch, dirty=False, projection_sha=CONFIG_SHA, **options
):
    world = World(tmp_path / "run", **options)
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", world.request)
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder.core, "command", git(dirty))
    monkeypatch.setattr(
        recorder.core,
        "config_projection",
        lambda status, config: {"sha256": projection_sha},
    )
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    report = recorder.observe(trigger, world.output)
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


@pytest.mark.parametrize("trigger", TRIGGERS)
def test_each_trigger_completes_when_the_held_credential_survives(
    trigger, tmp_path, monkeypatch
):
    world, report, saved = run(trigger, tmp_path, monkeypatch)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    assert rows["trigger"]["outcome"] == "accepted"
    assert rows["held-finalize"]["outcome"] == "accepted"
    assert rows["held-lookup"]["outcome"] == "accepted"
    assert rows["final-fresh-finalize"]["outcome"] == "accepted"
    assert saved["providerLinked"] is (trigger == "provider-unlink")
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.deleted == ["uid-x"] and world.users == {}
    assert len(world.patches) == 2 and world.patches[1]["mfa"] == {"state": "DISABLED"}
    assert saved["configRestored"] is True and saved["configDigestMatches"] is True
    if trigger == "provider-unlink":
        assert rows["trigger"]["checks"]["providerAbsentAfter"] is True
        assert rows["trigger"]["checks"]["otherStateUnchanged"] is True


@pytest.mark.parametrize("trigger", TRIGGERS)
def test_each_trigger_completes_when_the_held_credential_is_revoked(
    trigger, tmp_path, monkeypatch
):
    _world, report, saved = run(trigger, tmp_path, monkeypatch, revokes_held=True)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    # Revoked: the held credential can no longer start or finalize, and the dependent
    # rows are skipped, but the run is complete and the fresh control still succeeds.
    assert rows["held-start"]["outcome"] == "refused"
    assert rows["held-finalize"]["outcome"] == "refused"
    assert rows["held-lookup"]["skipped"] is True
    assert rows["held-refresh"]["skipped"] is True
    assert rows["final-fresh-finalize"]["outcome"] == "accepted"


def test_provider_unlink_aborts_when_the_admin_link_is_refused(tmp_path, monkeypatch):
    world, report, saved = run(
        "provider-unlink", tmp_path, monkeypatch, link_refused=True
    )
    assert report["status"] == "incomplete" and saved["failure"] == "ValueError"
    assert saved["providerLinked"] is False and saved["setup"] is False
    assert saved["cases"] == []
    # The refused link is not recorded as an unlink result, and the account is cleaned up.
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {} and world.patches[-1]["mfa"] == {"state": "DISABLED"}
    assert not complete(saved)


def test_a_termination_signal_still_cleans_up_and_restores(tmp_path, monkeypatch):
    world, report, saved = run(
        "admin-password-update", tmp_path, monkeypatch, terminate=("mfaSignIn:start", 2)
    )
    assert report["status"] == "incomplete" and saved["failure"] == "Terminated"
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {} and world.patches[-1]["mfa"] == {"state": "DISABLED"}
    assert not complete(saved)


def test_a_lost_request_keeps_no_credentials_and_restores(tmp_path, monkeypatch):
    world, report, saved = run(
        "client-password-change", tmp_path, monkeypatch, lose=("update", 1)
    )
    assert report["status"] == "incomplete" and saved["failure"] == "TimeoutError"
    assert saved["lastStep"] == "update" and saved["lastStatus"] is None
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.patches[-1]["mfa"] == {"state": "DISABLED"}


def test_held_finalize_uses_the_session_opened_before_the_trigger(
    tmp_path, monkeypatch
):
    # The scripted world refuses any SMS session opened after the trigger fires. The
    # recorder must finalize on the session it opened before the trigger, so the held
    # finalize is still accepted; a recorder that reused the post-trigger start session
    # would be refused here (invariant 6).
    for trigger in TRIGGERS:
        _world, report, saved = run(
            trigger, tmp_path / trigger, monkeypatch, reject_post_trigger_sessions=True
        )
        assert report["status"] == "observed", (trigger, report.get("lastStep"))
        assert complete(saved), trigger
        rows = rows_of(saved)
        assert rows["held-start"]["outcome"] == "accepted", trigger
        assert rows["held-finalize"]["outcome"] == "accepted", trigger
        assert rows["held-lookup"]["outcome"] == "accepted", trigger


def test_provider_unlink_ignores_volatile_timestamp_changes(tmp_path, monkeypatch):
    # The unlink bumps validSince and lastLoginAt; otherStateUnchanged must stay True
    # because those fields are excluded from the projection (invariant 7).
    _world, report, saved = run(
        "provider-unlink", tmp_path, monkeypatch, bump_volatile_on_unlink=True
    )
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    checks = rows_of(saved)["trigger"]["checks"]
    assert checks["providerAbsentAfter"] is True
    assert checks["otherStateUnchanged"] is True


def test_a_failed_restore_is_visible_and_not_complete(tmp_path, monkeypatch):
    world = World(tmp_path / "run")

    def raise_restore(access, original):
        raise TimeoutError("restore lost")

    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", world.request)
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder.core, "command", git(False))
    monkeypatch.setattr(
        recorder.core, "config_projection", lambda s, c: {"sha256": CONFIG_SHA}
    )
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    monkeypatch.setattr(recorder, "restore_configuration", raise_restore)
    recorder.observe("admin-password-update", world.output)
    saved = json.loads((world.output / "observation.json").read_bytes())
    assert saved["configRestoreFailure"] == "TimeoutError"
    assert "configRestored" not in saved
    assert complete(saved) is False
    # The account is still cleaned up even though the configuration restore raised.
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    # The private record still allows the manual restore.
    recovery = json.loads((world.output / "config-recovery.json").read_bytes())
    assert recovery["configSha256"] == CONFIG_SHA


def test_no_configuration_write_when_preconditions_fail(tmp_path, monkeypatch):
    world = World(tmp_path / "run")
    world.config["mfa"] = {"state": "ENABLED"}
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", world.request)
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder.core, "command", git(False))
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    report = recorder.observe("client-password-change", tmp_path / "run")
    assert report["status"] == "incomplete" and report["cases"] == []
    assert world.patches == [], "no PATCH before the preconditions hold"
    assert not (tmp_path / "run" / "config-recovery.json").exists()


def test_a_production_run_refuses_a_dirty_checkout(tmp_path, monkeypatch):
    world, report, saved = run("password-reset", tmp_path, monkeypatch, dirty=True)
    assert report["status"] == "incomplete" and saved["failure"] == "ValueError"
    assert "committedCheckout" not in saved and world.patches == []
    assert world.counts == {}


def test_recovery_record_precedes_the_change(tmp_path, monkeypatch):
    world, _report, _saved = run(
        "provider-unlink", tmp_path, monkeypatch, lose=("admin:update", 1)
    )
    # The first admin request (the emailVerified/mfa enrollment update) is lost right
    # after the enabling PATCH; the recovery record was already written.
    recovery = json.loads((tmp_path / "run" / "config-recovery.json").read_bytes())
    assert (
        recovery["configSha256"] == CONFIG_SHA and recovery["changeAttempted"] is True
    )
    assert world.patches[0]["mfa"] == recorder.MFA_ON
    assert world.patches[-1]["mfa"] == {"state": "DISABLED"}


def test_a_configuration_digest_mismatch_after_restore_is_not_complete(
    tmp_path, monkeypatch
):
    _world, report, saved = run(
        "admin-password-update", tmp_path, monkeypatch, projection_sha="f" * 64
    )
    assert report["status"] == "observed"
    assert saved["configRestored"] is True and saved["configDigestMatches"] is False
    assert complete(saved) is False


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


def complete_report(trigger="admin-password-update"):
    finalize = dict.fromkeys(FINALIZE_CHECKS, True)
    trig = (
        {
            "noError": True,
            "providerAbsentAfter": True,
            "otherStateUnchanged": True,
            "tokensReturned": False,
        }
        if trigger == "provider-unlink"
        else {"noError": True, "accountPresent": True, "tokensReturned": True}
    )
    rows = {
        "baseline-fresh-finalize": accepted("baseline-fresh-finalize", finalize),
        "trigger": accepted("trigger", trig),
        "held-start": accepted("held-start", {"sessionInfoPresent": True}),
        "held-finalize": accepted("held-finalize", finalize),
        "held-lookup": accepted("held-lookup", {"ownerMatches": True}),
        "held-refresh": accepted(
            "held-refresh",
            {
                **dict.fromkeys(
                    (
                        "noError",
                        "idTokenPresent",
                        "refreshTokenPresent",
                        "uidMatches",
                        "expiryIsPositiveInteger",
                        "expiryMatchesOneHour",
                        "bearerType",
                    ),
                    True,
                ),
                "derivedLookup": True,
            },
        ),
        "final-fresh-finalize": accepted("final-fresh-finalize", finalize),
    }
    return {
        "status": "observed",
        "target": "production",
        "committedCheckout": True,
        "trigger": trigger,
        "cases": [rows[name] for name in CASES],
        "setup": True,
        "providerLinked": trigger == "provider-unlink",
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
        "configRestored": True,
        "configDigestMatches": True,
    }


def test_complete_report_is_complete():
    for trigger in TRIGGERS:
        assert complete(complete_report(trigger)), trigger


def test_complete_rejects_inconsistencies():
    assert complete({**complete_report(), "configDigestMatches": False}) is False
    assert complete({**complete_report(), "setup": False}) is False
    assert complete({**complete_report(), "committedCheckout": False}) is False
    # providerLinked must match the trigger.
    assert (
        complete({**complete_report("admin-password-update"), "providerLinked": True})
        is False
    )
    assert (
        complete({**complete_report("provider-unlink"), "providerLinked": False})
        is False
    )
    # A refused held-finalize must skip lookup and refresh.
    report = complete_report()
    report["cases"] = [
        refused("held-finalize", "INVALID_MFA_PENDING_CREDENTIAL")
        if r["id"] == "held-finalize"
        else r
        for r in report["cases"]
    ]
    assert complete(report) is False
    report["cases"] = [
        skipped(r["id"]) if r["id"] in {"held-lookup", "held-refresh"} else r
        for r in report["cases"]
    ]
    # held-start was accepted but finalize refused: that is allowed.
    assert complete(report)
    # An unclassified refusal on a diagnostic row is recorded but not complete.
    report = complete_report()
    report["cases"] = [
        refused("held-start", "UNCLASSIFIED_ERROR") if r["id"] == "held-start" else r
        for r in report["cases"]
    ]
    validate_row(
        report["cases"][CASES.index("held-start")],
        "held-start",
        "admin-password-update",
    )
    assert complete(report) is False


def test_a_throttled_or_server_errored_diagnostic_is_recorded_but_not_complete():
    for status, error in (
        (429, "TOO_MANY_ATTEMPTS_TRY_LATER"),
        (500, "UNCLASSIFIED_ERROR"),
    ):
        report = complete_report()
        row = refused("held-start", error, status)
        validate_row(
            row, "held-start", "admin-password-update"
        )  # recorded without raising
        report["cases"] = [
            row if r["id"] == "held-start" else r for r in report["cases"]
        ]
        # held-start refused is allowed (held-finalize is a separate row); the run is
        # recorded but a non-400/403 status is not classified, so it is not complete.
        assert complete(report) is False, (status, error)
    # A 403 with an allowlisted class is classified and, with the rest consistent, complete.
    report = complete_report()
    report["cases"] = [
        refused("held-start", "PERMISSION_DENIED", 403)
        if r["id"] == "held-start"
        else r
        for r in report["cases"]
    ]
    assert complete(report)


def test_control_rows_may_not_be_refused():
    with pytest.raises(ValueError):
        validate_row(
            refused("baseline-fresh-finalize", "USER_DISABLED"),
            "baseline-fresh-finalize",
            "password-reset",
        )
    with pytest.raises(ValueError):
        validate_row(
            {
                **refused("final-fresh-finalize", "USER_DISABLED"),
                "outcome": "skipped",
                "httpStatus": None,
                "observedError": None,
            },
            "final-fresh-finalize",
            "password-reset",
        )


def test_contract_shapes():
    assert len(CASES) == 7 and len(contract.DIAGNOSTIC) == 5
    assert set(TRIGGERS) == {
        "client-password-change",
        "admin-password-update",
        "password-reset",
        "provider-unlink",
    }
    assert (
        contract.corpus("provider-unlink")["slice"]
        == "auth-pending-trigger-provider-unlink"
    )
    assert (
        contract.error_code({"error": {"message": "INVALID_OOB_CODE : x"}})
        == "INVALID_OOB_CODE"
    )
    assert (
        contract.error_code({"error": {"message": "SOMETHING"}}) == "UNCLASSIFIED_ERROR"
    )
    assert LINK_PROVIDER == "google.com"
