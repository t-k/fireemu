"""Offline drive of observe() against a scripted Identity Platform with phone MFA: the run
completes whichever refusal wins and whether or not a refusal consumes the held session,
records an accepted tampered-token update and unforeseen refusals as observations, never
writes credentials to any file even when a request is lost or the process is signalled,
writes no configuration before its preconditions hold, and restores what it read."""

import base64
import json
import os
import secrets
import signal
import urllib.parse

import precedence_contract as contract
import precedence_recorder as recorder
import pytest
from precedence_contract import (
    CASES,
    DIAGNOSTIC,
    FINALIZE_CHECKS,
    TEST_CODE,
    WRONG_CODE,
    complete,
    error_code,
    validate_row,
)

ORIGINAL_CONFIG = {
    "mfa": {"state": "DISABLED"},
    "signIn": {"phoneNumber": None},
    "smsRegionConfig": {"allowlistOnly": {}},
    # A field production returns that no output may carry.
    "client": {"apiKey": "config-secret-api-key"},
}
CONFIG_SHA = "0" * 64
SECRET_MARKERS = (
    "-secret-",
    "Aa9!",
    contract.PHOTO_SENTINEL_PREFIX,
    'fireemuPrecedence":',
    "config-secret",
    "access-secret",
    "key-secret",
)


def jwt(payload, marker):
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{body}.signature-{marker}-" + "x" * 80


class World:
    """Password accounts with an administratively enrolled phone factor.

    `order` is the refusal precedence on finalize: "code-first" checks the code before
    the account state, "disabled-first" the reverse, "ignores-disabled" issues tokens
    to a disabled account and refuses only their lookup. `consumes` makes a refusal
    consume the held session. `tampered_accepted` applies a client update whose token
    does not verify. `wrong_code_answer` overrides the answer to a wrong code. `lose`
    names a request (action, ordinal) that times out, `terminate` one that receives
    SIGTERM. `fail_restore` and `fail_delete` break the restore PATCH and the account
    delete. `ignore_disable` makes the privileged disable a no-op."""

    def __init__(self, output, **options):
        self.output = output
        self.order = options.pop("order", "code-first")
        self.consumes = options.pop("consumes", False)
        self.tampered_accepted = options.pop("tampered_accepted", False)
        self.wrong_code_answer = options.pop("wrong_code_answer", None)
        self.lose = options.pop("lose", None)
        self.terminate = options.pop("terminate", None)
        self.fail_restore = options.pop("fail_restore", False)
        self.fail_delete = options.pop("fail_delete", False)
        self.ignore_disable = options.pop("ignore_disable", False)
        self.dirty = options.pop("dirty", False)
        assert not options, options
        self.users = {}
        self.pendings = {}
        self.sessions = {}
        self.tokens = {}
        self.config = json.loads(json.dumps(ORIGINAL_CONFIG))
        self.patches = []
        self.counts = {}
        self.deleted = []
        self.signups = 0

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
        return 400, {
            "error": {"message": f"{message} : detail-secret-{secrets.token_hex(2)}"}
        }

    def public(self, user):
        return {k: v for k, v in user.items() if not k.startswith("_")}

    def issue(self, user, second_factor):
        payload = {"sub": user["localId"], "email": user["email"], "auth_time": 1}
        if second_factor:
            payload["firebase"] = {"sign_in_second_factor": "phone"}
        token = jwt(payload, "id-token-secret-" + secrets.token_hex(4))
        refresh = "refresh-secret-" + secrets.token_hex(4)
        self.tokens[token] = user["localId"]
        return {"idToken": token, "refreshToken": refresh}

    def find(self, selector):
        keys = {"localId": "localId", "email": "email", "phoneNumber": "_phone"}
        found = []
        for user in self.users.values():
            for field, key in keys.items():
                if user.get(key) in selector.get(field, []):
                    found.append(self.public(user))
                    break
        return {"users": found} if found else {}

    def patch(self, url, body, token):
        assert token == "access-secret-token"
        base, _, query = url.partition("?")
        assert base == recorder.CONFIG_URL
        assert urllib.parse.parse_qs(query) == {"updateMask": [recorder.CONFIG_MASK]}
        assert set(body) == {"mfa", "signIn", "smsRegionConfig"}
        assert set(body["signIn"]) == {"phoneNumber"}
        self.patches.append(json.loads(json.dumps(body)))
        if self.fail_restore and len(self.patches) == 2:
            raise TimeoutError("restore lost")
        self.config["mfa"] = body["mfa"]
        self.config["signIn"] = {"phoneNumber": body["signIn"]["phoneNumber"]}
        self.config["smsRegionConfig"] = body["smsRegionConfig"]
        return 200, {}

    def request(self, url, body=None, token=None, quota=False, form=False):
        if url == recorder.CONFIG_URL:
            assert body is None and token == "access-secret-token"
            return 200, json.loads(json.dumps(self.config))
        assert url.startswith("https://identitytoolkit.googleapis.com/")
        action = url.split("/")[-1].split("?")[0].removeprefix("accounts:")
        if "/projects/" in url:
            assert token == "access-secret-token" and quota
            self.count("admin:" + action)
            return self.admin(action, body)
        assert token is None
        assert urllib.parse.parse_qs(url.partition("?")[2]) == {
            "key": ["key-secret-value"]
        }
        self.count(action)
        return self.client(action, body)

    def admin(self, action, body):
        if action == "lookup":
            return 200, self.find(body)
        if action == "delete":
            self.deleted.append(body["localId"])
            if self.fail_delete:
                return self.error("PERMISSION_DENIED")
            self.users.pop(body["localId"], None)
            return 200, {}
        assert action == "update"
        user = self.users[body["localId"]]
        if "disableUser" in body and not self.ignore_disable:
            user["disabled"] = body["disableUser"]
        if "emailVerified" in body:
            user["emailVerified"] = body["emailVerified"]
        if "customAttributes" in body:
            user["customAttributes"] = body["customAttributes"]
        if "photoUrl" in body:
            user["photoUrl"] = body["photoUrl"]
        if "mfa" in body:
            user["mfaInfo"] = [
                {
                    "mfaEnrollmentId": "enrollment-" + secrets.token_hex(4),
                    "phoneInfo": e["phoneInfo"],
                }
                for e in body["mfa"]["enrollments"]
            ]
            user["_phone"] = user["mfaInfo"][0]["phoneInfo"]
        return 200, {"localId": user["localId"], "email": user["email"]}

    def client(self, action, body):
        if action == "signUp":
            # The private journal of the account precedes its creation.
            label = "ab"[self.signups]
            self.signups += 1
            journal = self.output / label / "recovery.json"
            assert journal.exists() and journal.stat().st_mode & 0o077 == 0
            assert json.loads(journal.read_bytes())["email"] == body["email"]
            uid = "uid-" + secrets.token_hex(4)
            user = {
                "localId": uid,
                "email": body["email"],
                "displayName": body["displayName"],
                "_password": body["password"],
            }
            self.users[uid] = user
            return 200, {**self.issue(user, False), "localId": uid, "email": uid}
        if action == "signInWithPassword":
            user = next(u for u in self.users.values() if u["email"] == body["email"])
            if user["_password"] != body["password"]:
                return self.error("INVALID_LOGIN_CREDENTIALS")
            if user.get("disabled"):
                return self.error("USER_DISABLED")
            # Production requires a verified email for multi-factor users; the recorder
            # must never leave A unverified before an MFA sign-in.
            assert user.get("emailVerified") is True, (
                "MFA sign-in of an unverified email"
            )
            credential = "pending-secret-" + secrets.token_hex(4)
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
            if self.users[uid].get("disabled"):
                return self.error("USER_DISABLED")
            return 200, {"users": [self.public(self.users[uid])]}
        if action == "update":
            return self.update(body)
        if action == "mfaSignIn:start":
            uid = self.pendings.get(body["mfaPendingCredential"])
            if uid is None:
                return self.error("INVALID_MFA_PENDING_CREDENTIAL")
            session = "session-secret-" + secrets.token_hex(4)
            self.sessions[session] = {"uid": uid, "consumed": False}
            return 200, {"phoneResponseInfo": {"sessionInfo": session}}
        assert action == "mfaSignIn:finalize"
        return self.finalize(body)

    def update(self, body):
        # The tampered token is a token this world issued with its signature changed,
        # and it arrives before any account is disabled.
        head, payload, signature = body["idToken"].split(".")
        issued = [t for t in self.tokens if t.startswith(f"{head}.{payload}.")]
        assert len(issued) == 1 and issued[0].split(".")[2] != signature
        assert not any(u.get("disabled") for u in self.users.values())
        assert set(body) == {
            "idToken",
            "customAttributes",
            "photoUrl",
            "returnSecureToken",
        }
        uid = self.tokens.get(body["idToken"])
        assert uid is None
        if not self.tampered_accepted:
            return self.error("INVALID_ID_TOKEN")
        user = self.users[self.tokens[issued[0]]]
        user["customAttributes"] = body["customAttributes"]
        user["photoUrl"] = body["photoUrl"]
        return 200, {"localId": user["localId"], "email": user["email"]}

    def finalize(self, body):
        uid = self.pendings.get(body["mfaPendingCredential"])
        if uid is None:
            return self.error("INVALID_MFA_PENDING_CREDENTIAL")
        info = body["phoneVerificationInfo"]
        session = self.sessions.get(info["sessionInfo"])
        if session is None or session["consumed"] or session["uid"] != uid:
            return self.error("INVALID_SESSION_INFO")
        user = self.users[uid]
        checks = [
            ("disabled", user.get("disabled", False)),
            ("code", info["code"] != TEST_CODE),
        ]
        if self.order == "code-first":
            checks.reverse()
        if self.order == "ignores-disabled":
            checks = checks[1:]
        for kind, failed in checks:
            if failed:
                if self.consumes:
                    session["consumed"] = True
                if kind == "code" and self.wrong_code_answer is not None:
                    return self.wrong_code_answer
                return self.error(
                    "USER_DISABLED" if kind == "disabled" else "INVALID_CODE"
                )
        session["consumed"] = True
        self.pendings.pop(body["mfaPendingCredential"])
        return 200, self.issue(user, True)


def git(dirty):
    def command(argv):
        if argv[:3] == ["git", "status", "--porcelain"]:
            assert argv[3] == "--" and set(argv[4:]) == set(recorder.PROBE_TREES)
            return (
                " M tools/auth-refusal-precedence/precedence_recorder.py"
                if dirty
                else ""
            )
        assert argv == ["git", "rev-parse", "HEAD"]
        return "deadbeef"

    return command


def run(tmp_path, monkeypatch, world, projection_sha=CONFIG_SHA):
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", world.request)
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder.core, "command", git(world.dirty))
    monkeypatch.setattr(
        recorder.core,
        "config_projection",
        lambda status, config: {"sha256": projection_sha},
    )
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    report = recorder.observe(world.output)
    saved = json.loads((world.output / "observation.json").read_bytes())
    # Every credential the scripted world hands out carries a marker; no file the run
    # wrote may contain one, and the handlers are restored.
    for path in world.output.rglob("*"):
        if path.is_file():
            text = path.read_text()
            for marker in SECRET_MARKERS:
                assert marker not in text, (path.name, marker)
    assert signal.getsignal(signal.SIGTERM) is signal.SIG_DFL
    return report, saved


def world(tmp_path, **options):
    return World(tmp_path / "run", **options)


def rows_of(saved):
    return {r["id"]: r for r in saved["cases"]}


def test_code_first_order_completes_and_records_both_refusals(tmp_path, monkeypatch):
    w = world(tmp_path, order="code-first")
    report, saved = run(tmp_path, monkeypatch, w)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    assert (
        rows["invalid-token-admin-field-update"]["observedError"] == "INVALID_ID_TOKEN"
    )
    assert saved["invalidTokenStateUnchanged"] is True
    assert rows["disabled-a-wrong-code-finalize"]["observedError"] == "INVALID_CODE"
    assert rows["disabled-b-correct-code-finalize"]["observedError"] == "USER_DISABLED"
    assert rows["reenabled-a-held-finalize"]["outcome"] == "accepted"
    assert rows["reenabled-b-held-finalize"]["outcome"] == "accepted"
    assert set(rows["reenabled-a-held-finalize"]["checks"]) == FINALIZE_CHECKS
    assert saved["transitions"] == [
        {"disabled": True, "targetReadback": True},
        {"disabled": False, "targetReadback": True},
    ]
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert saved["cleanupAccounts"] == {"a": "absent", "b": "absent"}
    assert len(w.deleted) == 2 and w.users == {}
    # Enabling PATCH, then the restore from the values read before the change.
    assert len(w.patches) == 2
    assert w.patches[0] == {
        "mfa": recorder.MFA_ON,
        "signIn": {
            "phoneNumber": {
                "enabled": True,
                "testPhoneNumbers": {
                    "+15555550100": TEST_CODE,
                    "+15555550101": TEST_CODE,
                },
            }
        },
        "smsRegionConfig": recorder.SMS_REGIONS_ON,
    }
    assert w.patches[1] == {
        "mfa": {"state": "DISABLED"},
        "signIn": {"phoneNumber": {"enabled": False, "testPhoneNumbers": {}}},
        "smsRegionConfig": {"allowlistOnly": {}},
    }
    assert saved["configRestored"] is True and saved["configDigestMatches"] is True
    assert saved["configRestoredReadback"] == {
        "mfa": {"state": "DISABLED"},
        "phoneNumber": {"enabled": False, "testPhoneNumbers": {}},
        "smsRegionConfig": {"allowlistOnly": {}},
    }


def test_disabled_first_order_completes(tmp_path, monkeypatch):
    report, saved = run(tmp_path, monkeypatch, world(tmp_path, order="disabled-first"))
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    assert rows["disabled-a-wrong-code-finalize"]["observedError"] == "USER_DISABLED"
    assert rows["disabled-b-correct-code-finalize"]["observedError"] == "USER_DISABLED"
    assert rows["reenabled-a-held-finalize"]["outcome"] == "accepted"


def test_a_consuming_refusal_is_recorded_not_fatal(tmp_path, monkeypatch):
    report, saved = run(tmp_path, monkeypatch, world(tmp_path, consumes=True))
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    assert rows["reenabled-a-held-finalize"]["observedError"] == "INVALID_SESSION_INFO"
    assert rows["reenabled-b-held-finalize"]["observedError"] == "INVALID_SESSION_INFO"
    assert rows["final-a-fresh-finalize"]["outcome"] == "accepted"


def test_an_accepted_tampered_update_is_an_observation(tmp_path, monkeypatch):
    report, saved = run(tmp_path, monkeypatch, world(tmp_path, tampered_accepted=True))
    # The unexpected acceptance changed only the sentinels: the later MFA rows still ran.
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    row = rows_of(saved)["invalid-token-admin-field-update"]
    assert row["outcome"] == "accepted"
    assert row["checks"] == {
        "noError": True,
        "customAttributesApplied": True,
        "photoUrlApplied": True,
    }
    assert saved["invalidTokenStateUnchanged"] is False
    assert rows_of(saved)["final-a-fresh-finalize"]["outcome"] == "accepted"


def test_tokens_issued_to_a_disabled_account_are_recorded_as_booleans(
    tmp_path, monkeypatch
):
    report, saved = run(
        tmp_path, monkeypatch, world(tmp_path, order="ignores-disabled")
    )
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    accepted_disabled = rows["disabled-b-correct-code-finalize"]
    assert accepted_disabled["outcome"] == "accepted"
    assert accepted_disabled["checks"] == {
        "noError": True,
        "idTokenPresent": True,
        "refreshTokenPresent": True,
        "claimSubMatches": True,
        "claimEmailMatches": True,
        "secondFactorClaim": True,
        "derivedLookup": False,
    }
    assert rows["disabled-a-wrong-code-finalize"]["observedError"] == "INVALID_CODE"
    # The consumed pending credential is then refused after re-enablement, recorded too.
    assert (
        rows["reenabled-b-held-finalize"]["observedError"]
        == "INVALID_MFA_PENDING_CREDENTIAL"
    )
    assert rows["final-b-fresh-finalize"]["outcome"] == "accepted"


@pytest.mark.parametrize(
    ("answer", "status", "error"),
    [
        (
            (400, {"error": {"message": "SOMETHING_NEW : detail-secret-x"}}),
            400,
            "UNCLASSIFIED_ERROR",
        ),
        (
            (429, {"error": {"message": "TOO_MANY_ATTEMPTS_TRY_LATER"}}),
            429,
            "TOO_MANY_ATTEMPTS_TRY_LATER",
        ),
        (
            (500, {"error": {"message": "Internal error : detail-secret-y"}}),
            500,
            "UNCLASSIFIED_ERROR",
        ),
    ],
)
def test_an_unforeseen_refusal_on_a_diagnostic_row_is_recorded_and_the_run_goes_on(
    tmp_path, monkeypatch, answer, status, error
):
    report, saved = run(
        tmp_path, monkeypatch, world(tmp_path, wrong_code_answer=answer)
    )
    assert report["status"] == "observed", report.get("lastStep")
    rows = rows_of(saved)
    assert rows["disabled-a-wrong-code-finalize"]["httpStatus"] == status
    assert rows["disabled-a-wrong-code-finalize"]["observedError"] == error
    assert [r["id"] for r in saved["cases"]] == list(CASES)
    # Recorded, but not a receipt anyone can rely on: the run must be repeated with the
    # class named in the contract or after the throttle clears.
    assert complete(saved) is False
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}


def test_a_lost_finalize_keeps_no_credentials_and_restores(tmp_path, monkeypatch):
    # The third finalize is the wrong-code attempt of disabled A.
    w = world(tmp_path, lose=("mfaSignIn:finalize", 3))
    report, saved = run(tmp_path, monkeypatch, w)
    assert report["status"] == "incomplete" and saved["failure"] == "TimeoutError"
    # The request that never answered is named, with no status or error class.
    assert saved["lastStep"] == "mfaSignIn:finalize" and saved["lastStatus"] is None
    assert saved["lastError"] is None
    assert [r["id"] for r in saved["cases"]] == list(CASES[:3])
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert w.users == {}
    assert w.patches[-1]["mfa"] == {"state": "DISABLED"}
    assert saved["configRestored"] is True
    assert not complete(saved)


def test_a_lost_update_keeps_the_failing_step_through_cleanup(tmp_path, monkeypatch):
    w = world(tmp_path, lose=("update", 1))
    report, saved = run(tmp_path, monkeypatch, w)
    assert report["status"] == "incomplete" and saved["failure"] == "TimeoutError"
    # The lost client update is named; the cleanup lookups and deletes after the
    # failure do not overwrite it.
    assert saved["lastStep"] == "update" and saved["lastStatus"] is None
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert w.patches[-1]["mfa"] == {"state": "DISABLED"}


def test_a_termination_signal_still_deletes_and_restores(tmp_path, monkeypatch):
    w = world(tmp_path, terminate=("mfaSignIn:start", 3))
    report, saved = run(tmp_path, monkeypatch, w)
    assert report["status"] == "incomplete" and saved["failure"] == "Terminated"
    assert saved["lastStep"] == "mfaSignIn:start"
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert w.users == {} and w.patches[-1]["mfa"] == {"state": "DISABLED"}
    assert not complete(saved)


def test_a_failed_restore_is_visible_and_the_accounts_are_still_deleted(
    tmp_path, monkeypatch
):
    w = world(tmp_path, fail_restore=True)
    report, saved = run(tmp_path, monkeypatch, w)
    assert report["status"] == "observed"
    assert saved["configRestoreFailure"] == "TimeoutError"
    assert "configRestored" not in saved
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert complete(saved) is False
    # The private record still allows the manual restore.
    recovery = tmp_path / "run" / "config-recovery.json"
    assert recorder.recovery_record(recovery)["configSha256"] == CONFIG_SHA


def test_a_failed_delete_is_a_cleanup_failure(tmp_path, monkeypatch):
    w = world(tmp_path, fail_delete=True)
    report, saved = run(tmp_path, monkeypatch, w)
    assert report["status"] == "observed"
    assert saved["cleanupFailure"] == "ValueError"
    assert saved["cleanupAccounts"] == {"a": "unresolved", "b": "unresolved"}
    assert saved["cleanup"] == {}
    assert complete(saved) is False
    # The journals keep the identities for --recover.
    for label in "ab":
        identity = json.loads(
            (tmp_path / "run" / label / "verified-account.json").read_bytes()
        )
        assert identity["uid"] in w.users


def test_a_configuration_digest_mismatch_after_the_restore_is_not_complete(
    tmp_path, monkeypatch
):
    report, saved = run(tmp_path, monkeypatch, world(tmp_path), projection_sha="f" * 64)
    assert report["status"] == "observed"
    assert saved["configRestored"] is True and saved["configDigestMatches"] is False
    assert complete(saved) is False


def test_a_disable_that_does_not_read_back_aborts_before_the_overlap_rows(
    tmp_path, monkeypatch
):
    report, saved = run(tmp_path, monkeypatch, world(tmp_path, ignore_disable=True))
    assert report["status"] == "incomplete" and saved["failure"] == "ValueError"
    assert saved["lastStep"] == "admin:lookup"
    assert saved["transitions"] == [] and saved["held"] == {"a": True, "b": True}
    assert [r["id"] for r in saved["cases"]] == list(CASES[:3])
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}


def test_a_production_run_refuses_to_start_from_a_dirty_checkout(tmp_path, monkeypatch):
    w = world(tmp_path, dirty=True)
    report, saved = run(tmp_path, monkeypatch, w)
    assert report["status"] == "incomplete" and saved["failure"] == "ValueError"
    assert "committedCheckout" not in saved and "configReadback" not in saved
    assert w.patches == [] and w.counts == {}, "nothing may be read or written"
    assert not (tmp_path / "run" / "config-recovery.json").exists()


def test_no_configuration_write_when_preconditions_fail(tmp_path, monkeypatch):
    w = world(tmp_path)
    w.config["mfa"] = {"state": "ENABLED"}
    report, saved = run(tmp_path, monkeypatch, w)
    assert report["status"] == "incomplete" and saved["cases"] == []
    assert w.patches == [], "no PATCH may be sent before the preconditions hold"
    assert "configRestored" not in saved
    assert not (tmp_path / "run" / "config-recovery.json").exists()


def test_recovery_record_precedes_the_change_and_restores_with_a_digest_check(
    tmp_path, monkeypatch
):
    w = world(tmp_path, lose=("admin:lookup", 1))
    _report, saved = run(tmp_path, monkeypatch, w)
    # The first admin request is lost right after the enabling PATCH: the record was
    # already written, and the restore was still sent from it.
    assert saved["failure"] == "TimeoutError" and len(w.patches) == 2
    recovery = tmp_path / "run" / "config-recovery.json"
    assert recovery.stat().st_mode & 0o077 == 0
    assert json.loads(recovery.read_bytes()) == {
        "project": recorder.PROJECT,
        "original": {
            "mfa": {"state": "DISABLED"},
            "phoneNumber": None,
            "smsRegionConfig": {"allowlistOnly": {}},
        },
        "changeAttempted": True,
        "configSha256": CONFIG_SHA,
    }
    # The manual path restores from the record and reports the digest comparison.
    w.config["mfa"] = recorder.MFA_ON
    assert recorder.restore_from_record(recovery) == {
        "configRestored": True,
        "configDigestMatches": True,
    }
    assert w.patches[-1]["mfa"] == {"state": "DISABLED"}
    monkeypatch.setattr(
        recorder.core, "config_projection", lambda status, config: {"sha256": "e" * 64}
    )
    assert recorder.restore_from_record(recovery)["configDigestMatches"] is False


def test_the_recovery_record_is_validated_before_any_restore(tmp_path):
    good = {
        "project": recorder.PROJECT,
        "original": {
            "mfa": {"state": "DISABLED"},
            "phoneNumber": None,
            "smsRegionConfig": {"allowlistOnly": {}},
        },
        "changeAttempted": True,
        "configSha256": CONFIG_SHA,
    }
    path = tmp_path / "config-recovery.json"
    recorder.save(path, good)
    assert recorder.recovery_record(path) == good
    for broken in [
        {**good, "project": "other"},
        {**good, "changeAttempted": False},
        {**good, "original": {**good["original"], "mfa": recorder.MFA_ON}},
        {**good, "original": {**good["original"], "extra": 1}},
        {**good, "configSha256": "short"},
        {k: v for k, v in good.items() if k != "configSha256"},
    ]:
        path.unlink()
        recorder.save(path, broken)
        with pytest.raises(ValueError):
            recorder.recovery_record(path)
    path.unlink()
    recorder.save(path, good)
    path.chmod(0o644)
    with pytest.raises(ValueError):
        recorder.recovery_record(path)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        recorder.recovery_record(link)


def test_note_keeps_only_classified_diagnostics():
    report = {}
    recorder.note(
        report,
        "mfaSignIn:finalize",
        400,
        {"error": {"message": "INVALID_CODE : secret-token-value-123"}},
    )
    assert report["lastError"] == "INVALID_CODE"
    assert "secret-token-value-123" not in json.dumps(report)
    assert report["lastErrorDetail"] is None
    assert error_code({"error": {"message": "SOMETHING_ELSE"}}) == "UNCLASSIFIED_ERROR"
    recorder.begin(report, "admin:lookup")
    assert report["lastStep"] == "admin:lookup" and report["lastStatus"] is None
    report["failure"] = "ValueError"
    recorder.begin(report, "admin:delete")
    recorder.note(report, "admin:delete", 200, {})
    assert report["lastStep"] == "admin:lookup"


def test_tampering_changes_a_signature_character_inside_the_signature():
    token = jwt({"sub": "x"}, "m")
    changed = recorder.tampered(token)
    head, payload, signature = token.split(".")
    changed_head, changed_payload, changed_signature = changed.split(".")
    assert (head, payload) == (changed_head, changed_payload)
    assert len(signature) == len(changed_signature)
    differing = [
        i for i, (a, b) in enumerate(zip(signature, changed_signature)) if a != b
    ]
    assert differing == [recorder.TAMPER_INDEX]
    unsigned = recorder.tampered(f"{head}.{payload}.")
    assert unsigned == f"{head}.{payload}.{recorder.UNSIGNED_SIGNATURE}"
    with pytest.raises(ValueError):
        recorder.tampered("not.a-jwt")
    with pytest.raises(ValueError):
        recorder.tampered(f"{head}.{payload}.short")


def test_contract_shapes():
    assert len(CASES) == 9 and len(DIAGNOSTIC) == 5
    assert set(DIAGNOSTIC) == {
        "invalid-token-admin-field-update",
        "disabled-a-wrong-code-finalize",
        "disabled-b-correct-code-finalize",
        "reenabled-a-held-finalize",
        "reenabled-b-held-finalize",
    }
    assert len(WRONG_CODE) == 6 and WRONG_CODE.isdigit()
    assert all(a != b for a, b in zip(WRONG_CODE, TEST_CODE, strict=True))
    # A control row may not be refused, a diagnostic row may not be skipped, and a
    # refused row needs an error status.
    with pytest.raises(ValueError):
        validate_row(
            refused("baseline-a-fresh-finalize", "USER_DISABLED"),
            "baseline-a-fresh-finalize",
        )
    with pytest.raises(ValueError):
        validate_row(
            {
                "id": "reenabled-a-held-finalize",
                "httpStatus": None,
                "outcome": "skipped",
                "observedError": None,
                "checks": {},
                "elapsedMs": 1,
                "skipped": True,
            },
            "reenabled-a-held-finalize",
        )
    with pytest.raises(ValueError):
        validate_row(
            {**refused("reenabled-a-held-finalize", "INVALID_CODE"), "httpStatus": 200},
            "reenabled-a-held-finalize",
        )


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


def complete_report():
    finalize = dict.fromkeys(FINALIZE_CHECKS, True)
    rows = {
        "invalid-token-admin-field-update": refused(
            "invalid-token-admin-field-update", "INVALID_ID_TOKEN"
        ),
        "disabled-a-wrong-code-finalize": refused(
            "disabled-a-wrong-code-finalize", "INVALID_CODE"
        ),
        "disabled-b-correct-code-finalize": refused(
            "disabled-b-correct-code-finalize", "USER_DISABLED"
        ),
    }
    return {
        "status": "observed",
        "target": "production",
        "committedCheckout": True,
        "cases": [rows.get(name) or accepted(name, finalize) for name in CASES],
        "setup": {"a": True, "b": True},
        "held": {"a": True, "b": True},
        "invalidTokenStateUnchanged": True,
        "transitions": [
            {"disabled": True, "targetReadback": True},
            {"disabled": False, "targetReadback": True},
        ],
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
        "configRestored": True,
        "configDigestMatches": True,
    }


def test_complete_report_is_complete():
    assert complete(complete_report())


def test_complete_rejects_missing_or_inconsistent_projections():
    assert complete({**complete_report(), "configDigestMatches": False}) is False
    assert complete({**complete_report(), "configRestored": False}) is False
    assert complete({**complete_report(), "committedCheckout": False}) is False
    report = complete_report()
    del report["committedCheckout"]
    assert complete(report) is False
    assert complete({**report, "target": "local"})
    assert complete({**complete_report(), "cleanup": {}}) is False
    assert complete({**complete_report(), "setup": {"a": True}}) is False
    assert complete({**complete_report(), "held": {"a": True}}) is False
    assert complete({**complete_report(), "transitions": []}) is False
    assert complete({**complete_report(), "invalidTokenStateUnchanged": "yes"}) is False
    # A refused tampered-token row must come with an unchanged readback.
    assert complete({**complete_report(), "invalidTokenStateUnchanged": False}) is False
    # An accepted one must agree with its applied flags.
    report = complete_report()
    report["cases"][2] = accepted(
        "invalid-token-admin-field-update",
        {"noError": True, "customAttributesApplied": True, "photoUrlApplied": False},
    )
    assert complete(report) is False
    report["invalidTokenStateUnchanged"] = False
    assert complete(report)
    report["cases"][2]["checks"]["customAttributesApplied"] = False
    report["cases"][2]["checks"]["photoUrlApplied"] = False
    assert complete(report) is False
    report["invalidTokenStateUnchanged"] = True
    assert complete(report)
    # The rows must come in corpus order.
    report = complete_report()
    report["cases"][0], report["cases"][1] = report["cases"][1], report["cases"][0]
    assert complete(report) is False


def test_diagnostic_finalizes_may_carry_false_checks_but_controls_may_not():
    report = complete_report()
    partial = {**dict.fromkeys(FINALIZE_CHECKS, True), "derivedLookup": False}
    report["cases"][4] = accepted("disabled-b-correct-code-finalize", partial)
    assert complete(report)
    report["cases"][0] = accepted("baseline-a-fresh-finalize", partial)
    assert complete(report) is False
    # A diagnostic finalize still needs the full check set with boolean values.
    report = complete_report()
    report["cases"][4] = accepted("disabled-b-correct-code-finalize", {"noError": True})
    assert complete(report) is False
    report["cases"][4] = accepted(
        "disabled-b-correct-code-finalize",
        {**dict.fromkeys(FINALIZE_CHECKS, True), "derivedLookup": "no"},
    )
    assert complete(report) is False


def test_complete_requires_classified_refusals():
    report = complete_report()
    report["cases"][3] = refused("disabled-a-wrong-code-finalize", "UNCLASSIFIED_ERROR")
    validate_row(report["cases"][3], "disabled-a-wrong-code-finalize")
    assert complete(report) is False
    report["cases"][3] = refused(
        "disabled-a-wrong-code-finalize", "TOO_MANY_ATTEMPTS_TRY_LATER", 429
    )
    validate_row(report["cases"][3], "disabled-a-wrong-code-finalize")
    assert complete(report) is False
    report["cases"][3] = refused(
        "disabled-a-wrong-code-finalize", "INSUFFICIENT_PERMISSION", 403
    )
    assert complete(report)


def test_complete_rejects_a_failed_or_unrestored_run():
    assert complete({**complete_report(), "failure": "ValueError"}) is False
    assert complete({**complete_report(), "cleanupFailure": "ValueError"}) is False
    assert (
        complete({**complete_report(), "configRestoreFailure": "ValueError"}) is False
    )
    assert complete({**complete_report(), "status": "incomplete"}) is False
    assert complete({}) is False
    assert contract.semantic_rows([{"id": "x", "elapsedMs": 3}]) == [{"id": "x"}]
