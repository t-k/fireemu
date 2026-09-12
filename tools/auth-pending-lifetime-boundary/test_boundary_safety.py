"""Offline drive of the revision-2 (boundary) observe() against a scripted Identity Platform.

Reuses revision 1's two-clock harness (a WALL clock enforcing the budget, a VIRTUAL clock
aging pendings) and adds the revision-2 concerns: aging past the local pending lifetime so a
refusal is observed and the usability-window upper bound is recorded; an expiry-class refusal
above a verified success establishes that bound while a non-expiry refusal does not; and the
admin access token is refreshed across a long run so no admin request uses one older than the
budget. No credential reaches any file."""

import base64
import copy
import json
import os
import signal
import urllib.parse

import boundary_recorder as recorder
import pytest
from boundary_contract import (
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
ACCESS_TOKEN = "access-secret-token"
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
# The local fireemu pending lifetime the scripted backend mimics; revision 2's ages straddle
# it (600/1800/3300 below, 3900 above).
LOCAL_TTL = 3600


def jwt(payload, marker):
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"eyJhbGciOiJSUzI1NiJ9.{body}.signature-{marker}-" + "x" * 60


class Clock:
    def __init__(self, t0=1_000.0):
        self.t = t0

    def now(self):
        return self.t

    def advance(self, seconds):
        self.t += max(0.0, seconds)


class World:
    def __init__(self, output, wall, virtual, **options):
        self.output = output
        self.wall = wall
        self.virtual = virtual
        self.production = options.pop("production", True)
        self.aging = wall if self.production else virtual
        self.ttl = options.pop("ttl", 100_000)
        self.lose = options.pop("lose", None)
        self.terminate = options.pop("terminate", None)
        self.delay = options.pop("delay", {})
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
        self.token_refreshes = 0

    def preflight(self):
        return ACCESS_TOKEN, "key-secret-value", {"sha256": CONFIG_SHA}

    def command(self, argv):
        # git status / rev-parse, plus the admin-token refresh (gcloud print-access-token).
        if argv[:3] == ["git", "status", "--porcelain"]:
            assert argv[3] == "--" and set(argv[4:]) == set(recorder.PROBE_TREES)
            return ""
        if argv == ["git", "rev-parse", "HEAD"]:
            return "deadbeef"
        if argv == ["gcloud", "auth", "application-default", "print-access-token"]:
            self.token_refreshes += 1
            return (
                ACCESS_TOKEN  # a fresh token, same value so the router still accepts it
            )
        raise AssertionError(argv)

    def count(self, action):
        self.counts[action] = self.counts.get(action, 0) + 1
        if self.lose == (action, self.counts[action]):
            raise TimeoutError("request lost")
        if self.terminate == (action, self.counts[action]):
            os.kill(os.getpid(), signal.SIGTERM)
        if action != "signInWithPassword":
            self.aging.advance(self.delay.get(action, 0))

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
        assert token == ACCESS_TOKEN
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
            born = self.aging.now()
            self.aging.advance(self.delay.get("signInWithPassword", 0))
            self.pendings[credential] = {"uid": user["localId"], "born": born}
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
            age = self.aging.now() - entry["born"]
            if age > self.ttl:
                # A pending older than the lifetime: gone/invalid, an expiry-class refusal.
                return self.error("INVALID_MFA_PENDING_CREDENTIAL")
            session = "session-secret-" + str(self.session_counter)
            self.session_counter += 1
            self.sessions[session] = {
                "credential": body["mfaPendingCredential"],
                "born": self.aging.now(),
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
            assert token == ACCESS_TOKEN and quota
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
                assert token == ACCESS_TOKEN and quota
            else:
                assert token == "owner" and not quota
            world.count("admin:" + action)
            return world.admin(action, body)
        assert token is None
        world.count(action)
        return world.client(action, body)

    return request


def wire(world, monkeypatch, budget=None):
    if budget is not None:
        monkeypatch.setattr(recorder, "BUDGET", budget)
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", router(world))
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder.core, "command", world.command)
    monkeypatch.setattr(
        recorder.core,
        "config_projection",
        lambda status, config: {"sha256": CONFIG_SHA},
    )
    monkeypatch.setattr(recorder.time, "monotonic", world.wall.now)
    monkeypatch.setattr(recorder.time, "sleep", world.wall.advance)
    monkeypatch.setattr(recorder, "clock_now", lambda cc: world.virtual.now())
    monkeypatch.setattr(
        recorder, "advance_clock", lambda cc, seconds: world.virtual.advance(seconds)
    )


def run(tmp_path, monkeypatch, budget=None, **options):
    world = World(tmp_path / "run", Clock(), Clock(), **options)
    wire(world, monkeypatch, budget=budget)
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


def test_all_ages_usable_is_a_lower_bound_only(tmp_path, monkeypatch):
    _world, report, saved = run(tmp_path, monkeypatch, ttl=100_000)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    summary = lifetime_summary(saved)
    assert summary["usableAges"] == list(AGE_SECONDS)
    assert summary["lowerBoundSeconds"] == max(AGE_SECONDS)
    assert summary["upperBoundEstablished"] is False
    assert summary["upperBoundSeconds"] is None


def test_expiry_past_the_local_lifetime_establishes_the_window_upper_bound(
    tmp_path, monkeypatch
):
    # 600/1800/3300 s below the 3600 s lifetime are usable; 3900 s is refused with an
    # expiry-class error, so the usability window's upper bound is (3300, 3900].
    _world, report, saved = run(tmp_path, monkeypatch, ttl=LOCAL_TTL)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    for a in (600, 1800, 3300):
        assert rows[f"age-{a}s-start"]["outcome"] == "accepted"
        assert rows[f"age-{a}s-finalize"]["outcome"] == "accepted"
    assert rows["age-3900s-start"]["outcome"] == "refused"
    assert rows["age-3900s-start"]["observedError"] == "INVALID_MFA_PENDING_CREDENTIAL"
    assert rows["age-3900s-finalize"]["skipped"] is True
    # The refused start still keeps its measured pending age.
    assert rows["age-3900s-start"]["timing"]["pendingAgeAtStart"]["lower"] >= 3900
    summary = lifetime_summary(saved)
    assert summary["usableAges"] == [600, 1800, 3300]
    assert summary["refusedAges"] == [3900]
    assert summary["lowerBoundSeconds"] == 3300
    assert summary["upperBoundEstablished"] is True
    assert summary["upperBoundSeconds"] == 3900


def test_a_non_expiry_refusal_does_not_establish_an_upper_bound(tmp_path, monkeypatch):
    # Take a complete all-usable report and turn the largest age into a non-expiry refusal
    # (USER_DISABLED). It is recorded, but the window upper bound stays undetermined.
    _world, _report, saved = run(tmp_path, monkeypatch, ttl=100_000)
    rows = {r["id"]: r for r in saved["cases"]}
    rows["age-3900s-start"].update(
        outcome="refused", httpStatus=400, observedError="USER_DISABLED", checks={}
    )
    rows["age-3900s-finalize"].update(
        outcome="skipped",
        httpStatus=None,
        observedError=None,
        checks={},
        skipped=True,
        timing={},
    )
    assert complete(saved) is True
    summary = lifetime_summary(saved)
    assert 3900 in summary["refusedAges"]
    assert summary["refusalReasons"]["3900"] == "USER_DISABLED"
    assert summary["upperBoundEstablished"] is False
    assert summary["upperBoundSeconds"] is None


def test_a_refusal_below_a_later_success_does_not_establish_an_upper_bound(
    tmp_path, monkeypatch
):
    # An expiry-class refusal at a SMALL age with a success ABOVE it is anomalous, not a
    # boundary: the upper bound requires the refusal to be above every verified success.
    _world, _report, saved = run(tmp_path, monkeypatch, ttl=100_000)
    rows = {r["id"]: r for r in saved["cases"]}
    rows["age-600s-start"].update(
        outcome="refused",
        httpStatus=400,
        observedError="INVALID_MFA_PENDING_CREDENTIAL",
        checks={},
    )
    rows["age-600s-finalize"].update(
        outcome="skipped",
        httpStatus=None,
        observedError=None,
        checks={},
        skipped=True,
        timing={},
    )
    assert complete(saved) is True
    summary = lifetime_summary(saved)
    assert summary["usableAges"] == [1800, 3300, 3900]
    assert summary["refusedAges"] == [600]
    assert summary["lowerBoundSeconds"] == 3900
    assert summary["upperBoundEstablished"] is False


def test_admin_token_is_refreshed_and_ages_stay_within_budget(tmp_path, monkeypatch):
    # A production run ages ~3900 s of wall time, well past the ~40-minute refresh threshold,
    # so the admin token must be refreshed; every recorded admin-token age stays within the
    # budget and the run completes.
    world, report, saved = run(tmp_path, monkeypatch, ttl=100_000)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    # The token was refreshed at least once (the recovery phase after ~65 minutes).
    assert world.token_refreshes >= 1
    assert saved["adminTokenAges"]  # recorded on every production admin use
    assert all(
        a <= saved["budget"]["adminTokenMaxAgeSeconds"] for a in saved["adminTokenAges"]
    )
    # The wall clock really did advance past the refresh threshold during the run.
    assert saved["wallElapsedSeconds"] > recorder.ADMIN_TOKEN_REFRESH_SECONDS


def test_owned_local_run_observes_the_boundary(tmp_path, monkeypatch):
    _world, report, saved = run(tmp_path, monkeypatch, production=False, ttl=LOCAL_TTL)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    assert saved["target"] == "local" and saved["agingMode"] == "virtual-clock"
    # Local admin uses the fixed owner token; no token ages are recorded.
    assert saved["adminTokenAges"] == []
    summary = lifetime_summary(saved)
    assert summary["usableAges"] == [600, 1800, 3300]
    assert summary["upperBoundSeconds"] == 3900


def test_dirty_checkout_is_refused_before_any_write(tmp_path, monkeypatch):
    world = World(tmp_path / "run", Clock(), Clock())
    wire(world, monkeypatch)
    monkeypatch.setattr(
        recorder,
        "committed_checkout",
        lambda: False,
    )
    recorder.observe(world.output)
    saved = json.loads((world.output / "observation.json").read_bytes())
    assert saved["failure"] == "ValueError" and "committedCheckout" not in saved
    assert world.patches == [] and not complete(saved)


def test_semantic_rows_drop_timing_and_elapsed(tmp_path, monkeypatch):
    _world, report, saved = run(tmp_path, monkeypatch, ttl=100_000)
    assert report["status"] == "observed"
    for row in semantic_rows(saved["cases"]):
        assert "elapsedMs" not in row and "timing" not in row


def test_timing_intervals_must_agree_with_their_raw_timestamps(tmp_path, monkeypatch):
    _world, _report, saved = run(tmp_path, monkeypatch, ttl=100_000)
    stale = copy.deepcopy(saved)
    row = next(r for r in stale["cases"] if r["id"] == "age-3300s-start")
    row["timing"]["pendingAgeAtStart"] = {"lower": 0.0, "upper": 0.0}
    assert complete(stale) is False


def test_no_expected_secret_marker_would_be_a_false_negative():
    for value in ("pending-secret-0", "session-secret-0", "Aa9!x", TEST_CODE):
        assert any(marker in value for marker in SECRET_MARKERS), value


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
