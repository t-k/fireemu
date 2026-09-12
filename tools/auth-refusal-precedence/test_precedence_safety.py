"""Offline drive of observe() against a scripted Identity Platform with phone MFA: the run
completes whichever refusal wins and whether or not a refusal consumes the held session,
records an accepted tampered-token update as an observation, never writes pending
credentials, sessions, codes or tokens even when a request is lost, writes no
configuration before its preconditions hold, and restores what it read."""

import base64
import json
import secrets

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
}


def jwt(payload, marker):
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{body}.signature-{marker}-" + "x" * 80


class World:
    """Password accounts with an administratively enrolled phone factor.

    `order` is the refusal precedence on finalize: "code-first" checks the code before
    the account state, "disabled-first" the reverse, "ignores-disabled" issues tokens
    to a disabled account and refuses only their lookup. `consumes` makes a refusal
    consume the held session. `tampered_accepted` applies a client update whose token
    does not verify. `lose` names a request (action, ordinal) that times out."""

    def __init__(
        self, order="code-first", consumes=False, tampered_accepted=False, lose=None
    ):
        self.order = order
        self.consumes = consumes
        self.tampered_accepted = tampered_accepted
        self.lose = lose
        self.users = {}
        self.pendings = {}
        self.sessions = {}
        self.tokens = {}
        self.config = json.loads(json.dumps(ORIGINAL_CONFIG))
        self.patches = []
        self.counts = {}
        self.deleted = []

    def preflight(self):
        return "access-token-secret", "key", {"sha256": "0" * 64}

    def count(self, action):
        self.counts[action] = self.counts.get(action, 0) + 1
        if self.lose == (action, self.counts[action]):
            raise TimeoutError("request lost")

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
        assert url.startswith(recorder.CONFIG_URL) and token == "access-token-secret"
        self.patches.append(json.loads(json.dumps(body)))
        self.config["mfa"] = body["mfa"]
        self.config["signIn"] = {"phoneNumber": body["signIn"]["phoneNumber"]}
        self.config["smsRegionConfig"] = body["smsRegionConfig"]
        return 200, {}

    def request(self, url, body=None, token=None, quota=False, form=False):
        if url == recorder.CONFIG_URL:
            assert body is None and token == "access-token-secret"
            return 200, json.loads(json.dumps(self.config))
        action = url.split("/")[-1].split("?")[0].removeprefix("accounts:")
        if "/projects/" in url:
            assert token == "access-token-secret" and quota
            self.count("admin:" + action)
            return self.admin(action, body)
        assert token is None
        self.count(action)
        return self.client(action, body)

    def admin(self, action, body):
        if action == "lookup":
            return 200, self.find(body)
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
                return 400, {"error": {"message": "INVALID_LOGIN_CREDENTIALS"}}
            if user.get("disabled"):
                return 400, {"error": {"message": "USER_DISABLED"}}
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
                return 400, {"error": {"message": "INVALID_ID_TOKEN"}}
            if self.users[uid].get("disabled"):
                return 400, {"error": {"message": "USER_DISABLED"}}
            return 200, {"users": [self.public(self.users[uid])]}
        if action == "update":
            uid = self.tokens.get(body["idToken"])
            if uid is None and not self.tampered_accepted:
                return 400, {"error": {"message": "INVALID_ID_TOKEN : tampered"}}
            if uid is None:
                uid = next(iter(self.users))
            user = self.users[uid]
            user["customAttributes"] = body["customAttributes"]
            user["photoUrl"] = body["photoUrl"]
            return 200, {"localId": uid, "email": user["email"]}
        if action == "mfaSignIn:start":
            uid = self.pendings.get(body["mfaPendingCredential"])
            if uid is None:
                return 400, {"error": {"message": "INVALID_MFA_PENDING_CREDENTIAL"}}
            session = "session-secret-" + secrets.token_hex(4)
            self.sessions[session] = {"uid": uid, "consumed": False}
            return 200, {"phoneResponseInfo": {"sessionInfo": session}}
        assert action == "mfaSignIn:finalize"
        return self.finalize(body)

    def finalize(self, body):
        uid = self.pendings.get(body["mfaPendingCredential"])
        if uid is None:
            return 400, {"error": {"message": "INVALID_MFA_PENDING_CREDENTIAL"}}
        info = body["phoneVerificationInfo"]
        session = self.sessions.get(info["sessionInfo"])
        if session is None or session["consumed"] or session["uid"] != uid:
            return 400, {"error": {"message": "INVALID_SESSION_INFO"}}
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
                message = "USER_DISABLED" if kind == "disabled" else "INVALID_CODE"
                return 400, {"error": {"message": message}}
        session["consumed"] = True
        self.pendings.pop(body["mfaPendingCredential"])
        return 200, self.issue(user, True)


def run(tmp_path, monkeypatch, world):
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", world.request)
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder.core, "command", lambda argv: "deadbeef")
    monkeypatch.setattr(
        recorder.core, "config_projection", lambda status, config: {"sha256": "0" * 64}
    )
    monkeypatch.setattr(recorder.time, "sleep", lambda s: None)
    report = recorder.observe(tmp_path / "run")
    saved = json.loads((tmp_path / "run" / "observation.json").read_bytes())
    text = json.dumps(saved)
    # Every credential the scripted world hands out carries "-secret-"; the password
    # prefix and the sentinel display name must not appear either.
    for marker in (
        "-secret-",
        "Aa9!",
        contract.PHOTO_SENTINEL_PREFIX,
        'fireemuPrecedence":',
    ):
        assert marker not in text, marker
    return report, saved


def rows_of(saved):
    return {r["id"]: r for r in saved["cases"]}


def test_code_first_order_completes_and_records_both_refusals(tmp_path, monkeypatch):
    world = World(order="code-first")
    report, saved = run(tmp_path, monkeypatch, world)
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
    assert len(world.deleted) == 2 and world.users == {}
    # Enabling PATCH, then the restore from the values read before the change.
    assert len(world.patches) == 2
    assert world.patches[1] == {
        "mfa": {"state": "DISABLED"},
        "signIn": {"phoneNumber": {"enabled": False, "testPhoneNumbers": {}}},
        "smsRegionConfig": {"allowlistOnly": {}},
    }
    assert saved["configRestored"] is True and saved["configDigestMatches"] is True


def test_disabled_first_order_completes(tmp_path, monkeypatch):
    report, saved = run(tmp_path, monkeypatch, World(order="disabled-first"))
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    assert rows["disabled-a-wrong-code-finalize"]["observedError"] == "USER_DISABLED"
    assert rows["disabled-b-correct-code-finalize"]["observedError"] == "USER_DISABLED"
    assert rows["reenabled-a-held-finalize"]["outcome"] == "accepted"


def test_a_consuming_refusal_is_recorded_not_fatal(tmp_path, monkeypatch):
    report, saved = run(tmp_path, monkeypatch, World(consumes=True))
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    assert rows["reenabled-a-held-finalize"]["observedError"] == "INVALID_SESSION_INFO"
    assert rows["reenabled-b-held-finalize"]["observedError"] == "INVALID_SESSION_INFO"
    assert rows["final-a-fresh-finalize"]["outcome"] == "accepted"


def test_an_accepted_tampered_update_is_an_observation(tmp_path, monkeypatch):
    world = World(tampered_accepted=True)
    report, saved = run(tmp_path, monkeypatch, world)
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
    report, saved = run(tmp_path, monkeypatch, World(order="ignores-disabled"))
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


def test_a_lost_finalize_keeps_no_credentials_and_restores(tmp_path, monkeypatch):
    # The third finalize is the wrong-code attempt of disabled A.
    world = World(lose=("mfaSignIn:finalize", 3))
    report, saved = run(tmp_path, monkeypatch, world)
    assert report["status"] == "incomplete" and saved["failure"] == "TimeoutError"
    # The request that never answered is named, with no status or error class.
    assert saved["lastStep"] == "mfaSignIn:finalize" and saved["lastStatus"] is None
    assert saved["lastError"] is None
    assert [r["id"] for r in saved["cases"]] == list(CASES[:3])
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {}
    assert world.patches[-1]["mfa"] == {"state": "DISABLED"}
    assert saved["configRestored"] is True
    assert not complete(saved)


def test_a_lost_update_keeps_the_failing_step_through_cleanup(tmp_path, monkeypatch):
    world = World(lose=("update", 1))
    report, saved = run(tmp_path, monkeypatch, world)
    assert report["status"] == "incomplete" and saved["failure"] == "TimeoutError"
    # The lost client update is named; the cleanup lookups and deletes after the
    # failure do not overwrite it.
    assert saved["lastStep"] == "update" and saved["lastStatus"] is None
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.patches[-1]["mfa"] == {"state": "DISABLED"}


def test_no_configuration_write_when_preconditions_fail(tmp_path, monkeypatch):
    world = World()
    world.config["mfa"] = {"state": "ENABLED"}
    report, saved = run(tmp_path, monkeypatch, world)
    assert report["status"] == "incomplete" and saved["cases"] == []
    assert world.patches == [], "no PATCH may be sent before the preconditions hold"
    assert "configRestored" not in saved
    assert not (tmp_path / "run" / "config-recovery.json").exists()


def test_recovery_record_precedes_the_change(tmp_path, monkeypatch):
    world = World()
    run(tmp_path, monkeypatch, world)
    recovery = json.loads((tmp_path / "run" / "config-recovery.json").read_bytes())
    assert recovery == {
        "project": recorder.PROJECT,
        "original": {
            "mfa": {"state": "DISABLED"},
            "phoneNumber": None,
            "smsRegionConfig": {"allowlistOnly": {}},
        },
        "changeAttempted": True,
    }
    assert world.patches[0]["mfa"] == recorder.MFA_ON
    assert world.patches[0]["signIn"]["phoneNumber"]["testPhoneNumbers"] == {
        "+15555550100": TEST_CODE,
        "+15555550101": TEST_CODE,
    }


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
    # A control row may not be refused, a diagnostic row may not be skipped.
    with pytest.raises(ValueError):
        validate_row(
            {
                "id": "baseline-a-fresh-finalize",
                "httpStatus": 400,
                "outcome": "refused",
                "observedError": "USER_DISABLED",
                "checks": {},
                "elapsedMs": 1,
                "skipped": False,
            },
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


def refused(name, error):
    return {
        "id": name,
        "httpStatus": 400,
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


def test_complete_rejects_a_failed_or_unrestored_run():
    assert complete({**complete_report(), "failure": "ValueError"}) is False
    assert complete({**complete_report(), "cleanupFailure": "ValueError"}) is False
    assert (
        complete({**complete_report(), "configRestoreFailure": "ValueError"}) is False
    )
    assert complete({**complete_report(), "status": "incomplete"}) is False
    assert complete(contract.semantic_rows and {}) is False
