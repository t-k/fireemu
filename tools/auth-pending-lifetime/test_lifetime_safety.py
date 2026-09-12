"""Offline drive of observe() against a scripted Identity Platform with phone MFA, aging
pendings against a shared fake clock. Verifies: the run completes when every sampled age
is still usable (a lower bound, not an infinite lifetime) and equally when an age is
refused (an upper bound); the SMS session is fresh at each diagnostic while only the
pending age grows; a finalize is skipped when its start was refused; the production run
refuses a dirty checkout, restores what it read, and cleans up on a termination signal or
a lost request; the owned local run ages by the virtual clock. No credential reaches any
file, and the run never overclaims a TTL."""

import base64
import json
import os
import signal
import urllib.parse

import lifetime_recorder as recorder
import pytest
from lifetime_contract import (
    AGE_SECONDS,
    TEST_CODE,
    complete,
    lifetime_summary,
    semantic_rows,
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
    "pending-secret",
    "session-secret",
    TEST_CODE,
    recorder.TEST_PHONE,
)
LOCAL_ORIGIN = "http://127.0.0.1:12345"


def jwt(payload, marker):
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{body}.signature-{marker}-" + "x" * 60


class Clock:
    """One fake clock shared by the recorder and the scripted backend. In production the
    recorder reads it as time.monotonic and moves it with time.sleep; in the owned local
    run it reads it as the control clock and moves it with clock:advance. The backend reads
    it to decide whether a pending has aged past the configured lifetime."""

    def __init__(self):
        self.t = 1_000.0

    def now(self):
        return self.t

    def advance(self, seconds):
        self.t += max(0.0, seconds)


class World:
    def __init__(self, output, clock, **options):
        self.output = output
        self.clock = clock
        self.production = options.pop("production", True)
        self.ttl = options.pop("ttl", 10_000)
        self.lose = options.pop("lose", None)
        self.terminate = options.pop("terminate", None)
        assert not options, options
        self.users = {}
        self.pendings = {}
        self.sessions = {}
        self.tokens = {}
        self.uid_counter = 0
        self.pending_counter = 0
        self.session_counter = 0
        self.config = json.loads(json.dumps(ORIGINAL_CONFIG))
        self.patches = []
        self.counts = {}
        self.deleted = []
        self.start_ages = []

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

    def config_get(self):
        return 200, json.loads(json.dumps(self.config))

    def verification_codes(self):
        return 200, {
            "verificationCodes": [
                {"sessionInfo": s, "code": TEST_CODE} for s in self.sessions
            ]
        }

    def admin(self, action, body):
        if action == "lookup":
            keys = {"localId": "localId", "email": "email"}
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
            uid = f"uid-{self.uid_counter}"
            self.uid_counter += 1
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
            assert user.get("emailVerified") is True
            credential = "pending-secret-" + str(self.pending_counter)
            self.pending_counter += 1
            self.pendings[credential] = {
                "uid": user["localId"],
                "born": self.clock.now(),
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
        raise AssertionError(action)

    def mfa(self, action, body):
        entry = self.pendings.get(body["mfaPendingCredential"])
        if entry is None:
            return self.error("INVALID_MFA_PENDING_CREDENTIAL")
        if action == "mfaSignIn:start":
            age = self.clock.now() - entry["born"]
            self.start_ages.append(age)
            # The pending expires once older than the lifetime; the session is minted fresh.
            if age > self.ttl:
                return self.error("INVALID_MFA_PENDING_CREDENTIAL")
            session = "session-secret-" + str(self.session_counter)
            self.session_counter += 1
            self.sessions[session] = {
                "credential": body["mfaPendingCredential"],
                "born": self.clock.now(),
                "consumed": False,
            }
            return 200, {"phoneResponseInfo": {"sessionInfo": session}}
        info = body["phoneVerificationInfo"]
        session = self.sessions.get(info["sessionInfo"])
        if session is None or session["consumed"]:
            return self.error("INVALID_SESSION_INFO")
        if session["credential"] != body["mfaPendingCredential"]:
            return self.error("INVALID_SESSION_INFO")
        if info["code"] != TEST_CODE:
            return self.error("INVALID_CODE")
        session["consumed"] = True
        self.pendings.pop(body["mfaPendingCredential"])
        return 200, self.issue(self.users[entry["uid"]])


def router(world):
    def request(url, body=None, token=None, quota=False, form=False):
        if url == recorder.CONFIG_URL and body is None:
            assert token == "access-secret-token" and quota
            return world.config_get()
        if "/emulator/v1/" in url and url.endswith("verificationCodes"):
            assert token is None
            return world.verification_codes()
        if "/v2/accounts/mfaSignIn" in url:
            action = url.split("/")[-1].split("?")[0]
            assert token is None
            world.count(action)
            return world.mfa(action, body)
        assert "/accounts:" in url
        action = url.split("/accounts:")[-1].split("?")[0]
        if "/projects/" in url:
            if world.production:
                assert token == "access-secret-token" and quota
            else:
                assert token == "owner" and not quota
            world.count("admin:" + action)
            return world.admin(action, body)
        assert token is None
        world.count(action)
        return world.client(action, body)

    return request


def git(dirty):
    def command(argv):
        if argv[:3] == ["git", "status", "--porcelain"]:
            assert argv[3] == "--" and set(argv[4:]) == set(recorder.PROBE_TREES)
            return (
                " M tools/auth-pending-lifetime/lifetime_recorder.py" if dirty else ""
            )
        assert argv == ["git", "rev-parse", "HEAD"]
        return "deadbeef"

    return command


def wire(world, monkeypatch, dirty=False):
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", router(world))
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder.core, "command", git(dirty))
    monkeypatch.setattr(
        recorder.core,
        "config_projection",
        lambda status, config: {"sha256": CONFIG_SHA},
    )
    # Production reads and moves the clock as monotonic time / real sleep.
    monkeypatch.setattr(recorder.time, "monotonic", world.clock.now)
    monkeypatch.setattr(recorder.time, "sleep", world.clock.advance)
    # The owned local run reads and moves it as the control clock.
    monkeypatch.setattr(recorder, "clock_now", lambda cc: world.clock.now())
    monkeypatch.setattr(
        recorder, "advance_clock", lambda cc, seconds: world.clock.advance(seconds)
    )


def run(tmp_path, monkeypatch, dirty=False, **options):
    clock = Clock()
    world = World(tmp_path / "run", clock, **options)
    wire(world, monkeypatch, dirty=dirty)
    origin = None if world.production else LOCAL_ORIGIN
    control = None if world.production else (LOCAL_ORIGIN, "control-token")
    report = recorder.observe(world.output, origin=origin, clock_control=control)
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


def test_all_ages_usable_is_a_lower_bound_not_an_infinite_lifetime(
    tmp_path, monkeypatch
):
    world, report, saved = run(tmp_path, monkeypatch, ttl=10_000)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    for a in AGE_SECONDS:
        assert rows[f"age-{a}s-start"]["outcome"] == "accepted"
        assert rows[f"age-{a}s-finalize"]["outcome"] == "accepted"
        assert rows[f"age-{a}s-start"]["checks"]["pendingAgeSeconds"] >= a
        assert rows[f"age-{a}s-start"]["checks"]["sessionAgeSeconds"] <= 30
    summary = lifetime_summary(saved)
    assert summary["usableAges"] == list(AGE_SECONDS)
    assert summary["refusedAges"] == []
    assert summary["lowerBoundSeconds"] == max(AGE_SECONDS)
    assert summary["upperBoundEstablished"] is False
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert saved["configRestored"] and saved["configDigestMatches"]
    assert world.users == {}


def test_an_expired_age_is_recorded_as_an_upper_bound_and_finalize_skipped(
    tmp_path, monkeypatch
):
    # A pending older than the lifetime is refused at start; its finalize is skipped. This
    # is the expiry-observed path: the run still completes and reports an upper bound.
    _world, report, saved = run(tmp_path, monkeypatch, ttl=60)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    assert rows["age-2s-start"]["outcome"] == "accepted"
    assert rows["age-2s-finalize"]["outcome"] == "accepted"
    for a in (120, 300):
        assert rows[f"age-{a}s-start"]["outcome"] == "refused"
        assert (
            rows[f"age-{a}s-start"]["observedError"] == "INVALID_MFA_PENDING_CREDENTIAL"
        )
        assert rows[f"age-{a}s-finalize"]["skipped"] is True
    summary = lifetime_summary(saved)
    assert summary["usableAges"] == [2]
    assert summary["refusedAges"] == [120, 300]
    assert summary["lowerBoundSeconds"] == 2
    assert summary["upperBoundEstablished"] is True
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}


def test_each_diagnostic_uses_an_independent_account_and_a_fresh_session(
    tmp_path, monkeypatch
):
    world, report, _saved = run(tmp_path, monkeypatch, ttl=10_000)
    assert report["status"] == "observed"
    # One account per age plus the two controls; each is a distinct uid, deleted in cleanup.
    assert world.uid_counter == len(AGE_SECONDS) + 2
    assert sorted(world.deleted) == sorted(f"uid-{i}" for i in range(world.uid_counter))
    # Sessions are minted fresh at each start; none is reused across diagnostics.
    # One start per age plus the two controls, each opening exactly one session.
    assert world.session_counter == len(AGE_SECONDS) + 2
    # The measured start ages cover the fresh controls (~0) and the sampled ages.
    aged = sorted(round(a) for a in world.start_ages)
    assert aged[:2] == [0, 0]  # baseline and final controls
    for a in AGE_SECONDS:
        assert any(round(x) >= a for x in world.start_ages)


def test_a_dirty_checkout_is_refused_before_any_write(tmp_path, monkeypatch):
    world, report, saved = run(tmp_path, monkeypatch, dirty=True)
    assert report["status"] == "incomplete" and saved["failure"] == "ValueError"
    assert "committedCheckout" not in saved
    assert world.patches == [] and world.counts == {}
    assert not complete(saved)


def test_a_termination_signal_restores_config_and_deletes_accounts(
    tmp_path, monkeypatch
):
    world, report, saved = run(
        tmp_path, monkeypatch, ttl=10_000, terminate=("mfaSignIn:start", 2)
    )
    assert report["status"] == "incomplete" and saved["failure"] == "Terminated"
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {}
    assert world.patches[-1]["mfa"] == {"state": "DISABLED"}
    assert saved["configRestored"] and not complete(saved)


def test_a_lost_admin_request_still_cleans_up_and_is_incomplete(tmp_path, monkeypatch):
    world, report, saved = run(
        tmp_path, monkeypatch, ttl=10_000, lose=("admin:update", 1)
    )
    assert report["status"] == "incomplete" and saved["failure"] == "TimeoutError"
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {} and not complete(saved)


def test_a_failed_restore_is_visible_and_not_complete(tmp_path, monkeypatch):
    clock = Clock()
    world = World(tmp_path / "run", clock, ttl=10_000)
    wire(world, monkeypatch)

    def raise_restore(access, original):
        raise TimeoutError("restore lost")

    monkeypatch.setattr(recorder, "restore_configuration", raise_restore)
    recorder.observe(world.output)
    saved = json.loads((world.output / "observation.json").read_bytes())
    assert saved["configRestoreFailure"] == "TimeoutError"
    assert "configRestored" not in saved and complete(saved) is False
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}


def test_owned_local_run_ages_by_the_virtual_clock(tmp_path, monkeypatch):
    world, report, saved = run(tmp_path, monkeypatch, production=False, ttl=10_000)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    assert saved["target"] == "local" and saved["agingMode"] == "virtual-clock"
    assert saved["configEnabled"] is False
    # No production configuration was touched and no quota project was recorded.
    assert world.patches == [] and saved["projectNumber"] is None
    rows = rows_of(saved)
    for a in AGE_SECONDS:
        assert rows[f"age-{a}s-start"]["checks"]["pendingAgeSeconds"] >= a


def test_owned_local_run_observes_expiry_when_advanced_past_the_lifetime(
    tmp_path, monkeypatch
):
    _world, report, saved = run(tmp_path, monkeypatch, production=False, ttl=60)
    assert report["status"] == "observed"
    assert complete(saved)
    summary = lifetime_summary(saved)
    assert summary["upperBoundEstablished"] is True
    assert summary["usableAges"] == [2]


def test_semantic_rows_drop_timing_and_measured_ages(tmp_path, monkeypatch):
    _world, report, saved = run(tmp_path, monkeypatch, ttl=10_000)
    assert report["status"] == "observed"
    stripped = semantic_rows(saved["cases"])
    for row in stripped:
        assert "elapsedMs" not in row
        assert "pendingAgeSeconds" not in row["checks"]
        assert "sessionAgeSeconds" not in row["checks"]
    # The start rows keep their session-presence check after stripping the ages.
    start = next(r for r in stripped if r["id"] == "age-2s-start")
    assert set(start["checks"]) == {"sessionInfoPresent"}


def test_no_expected_secret_marker_would_be_a_false_negative():
    # Guards the leak scan: every marker the World actually emits must be searched for.
    emitted = ("pending-secret-0", "session-secret-0", "Aa9!x", TEST_CODE)
    for value in emitted:
        assert any(marker in value for marker in SECRET_MARKERS), value


def test_budget_is_declared_and_accounts_respect_it(tmp_path, monkeypatch):
    _world, report, saved = run(tmp_path, monkeypatch, ttl=10_000)
    assert report["status"] == "observed"
    assert saved["accountsUsed"] == len(AGE_SECONDS) + 2
    assert saved["accountsUsed"] <= saved["budget"]["maxAccounts"]
    assert set(saved["budget"]) == {
        "maxAccounts",
        "maxRequests",
        "totalBudgetSeconds",
        "configHoldMaxSeconds",
        "cleanupReserveSeconds",
    }
    assert all(type(v) is int and v > 0 for v in saved["budget"].values())


def test_contract_rejects_a_transient_error_row():
    # A throttle answer at a start must not complete a run: it is not a semantic result.
    template = {
        "status": "observed",
        "target": "local",
        "agingMode": "virtual-clock",
        "setup": True,
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
        "configRestored": True,
        "configDigestMatches": True,
        "accountsUsed": 1,
        "budget": dict(recorder.BUDGET),
        "cases": [],
    }
    assert complete(template) is False  # empty cases never satisfy the id sequence


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
