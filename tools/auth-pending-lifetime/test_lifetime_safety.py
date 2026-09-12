"""Offline drive of observe() against a scripted Identity Platform with phone MFA.

Two clocks are kept apart, as in production: a WALL clock (drives time.monotonic and
time.sleep, enforces the budget) and a VIRTUAL clock (drives the control clock, ages
pendings locally). The scripted backend expires a pending by whichever clock the run ages
against. The suite verifies: a fully-verified success at every age is a lower bound and an
expiry is recorded without asserting an upper bound; the declared time, config-hold and
request budgets actually stop the run and still restore configuration and delete accounts;
the pending and session ages are saved as intervals on every row, refusals included; an
HTTP 200 without a usable token is not counted as usable; a non-expiry refusal never
establishes an upper bound; a transient row never completes a run; and no credential reaches
any file."""

import base64
import copy
import json
import os
import signal
import urllib.parse

import lifetime_recorder as recorder
import pytest
from lifetime_contract import (
    AGE_SECONDS,
    CASES,
    FINALIZE_CHECKS,
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
        # The clock the run ages against: real wall time in production, the virtual clock
        # locally. The backend expires a pending by this clock, as fireemu would.
        self.aging = wall if self.production else virtual
        self.ttl = options.pop("ttl", 10_000)
        self.lose = options.pop("lose", None)
        self.terminate = options.pop("terminate", None)
        # delay: {request-action: seconds} advances the aging clock after handling the
        # request, so a start or finalize can take measurable time.
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
        self.start_ages = []

    def preflight(self):
        return "access-secret-token", "key-secret-value", {"sha256": CONFIG_SHA}

    def count(self, action):
        self.counts[action] = self.counts.get(action, 0) + 1
        if self.lose == (action, self.counts[action]):
            raise TimeoutError("request lost")
        if self.terminate == (action, self.counts[action]):
            os.kill(os.getpid(), signal.SIGTERM)
        # A request occupies time on the aging clock (which is the wall clock in production),
        # so a delayed setup, diagnostic or recovery request advances real time and can cross
        # a budget deadline. signInWithPassword is handled in client() so its pending's birth
        # is stamped at send time, before the acquisition latency.
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
            # Birth is stamped at send time; the acquisition latency (if any) is added after,
            # so the recorder's [pendingSent, pendingReceived] bracket brackets this birth.
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
            # count() already advanced the aging clock by any start delay.
            age = self.aging.now() - entry["born"]
            self.start_ages.append(age)
            if age > self.ttl:
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


def wire(world, monkeypatch, dirty=False, budget=None):
    if budget is not None:
        monkeypatch.setattr(recorder, "BUDGET", budget)
    monkeypatch.setattr(recorder.core, "production_preflight", world.preflight)
    monkeypatch.setattr(recorder.core, "request", router(world))
    monkeypatch.setattr(recorder.revocation, "patch", world.patch)
    monkeypatch.setattr(recorder.core, "command", git(dirty))
    monkeypatch.setattr(
        recorder.core,
        "config_projection",
        lambda status, config: {"sha256": CONFIG_SHA},
    )
    # Production reads/moves the wall clock as monotonic time / real sleep.
    monkeypatch.setattr(recorder.time, "monotonic", world.wall.now)
    monkeypatch.setattr(recorder.time, "sleep", world.wall.advance)
    # The owned local run reads/moves the virtual clock as the control clock.
    monkeypatch.setattr(recorder, "clock_now", lambda cc: world.virtual.now())
    monkeypatch.setattr(
        recorder, "advance_clock", lambda cc, seconds: world.virtual.advance(seconds)
    )


def run(tmp_path, monkeypatch, dirty=False, budget=None, **options):
    world = World(tmp_path / "run", Clock(), Clock(), **options)
    wire(world, monkeypatch, dirty=dirty, budget=budget)
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


def complete_report(tmp_path, monkeypatch):
    """A real, complete production report to mutate in the pure-summary tests."""
    _world, report, saved = run(tmp_path, monkeypatch, ttl=10_000)
    assert report["status"] == "observed" and complete(saved)
    return saved


# --- Recorder integration: lower bound, expiry, budgets, cleanup --------------------


def test_all_ages_usable_is_a_lower_bound_not_an_infinite_lifetime(
    tmp_path, monkeypatch
):
    world, report, saved = run(tmp_path, monkeypatch, ttl=10_000)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved) and saved["stopReason"] == "completed"
    rows = rows_of(saved)
    for a in AGE_SECONDS:
        assert rows[f"age-{a}s-start"]["outcome"] == "accepted"
        assert rows[f"age-{a}s-finalize"]["outcome"] == "accepted"
        assert rows[f"age-{a}s-start"]["timing"]["pendingAgeAtStart"]["lower"] >= a
    summary = lifetime_summary(saved)
    assert summary["usableAges"] == list(AGE_SECONDS)
    assert summary["refusedAges"] == []
    assert summary["lowerBoundSeconds"] == max(AGE_SECONDS)
    assert summary["upperBoundEstablished"] is False
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert saved["configRestored"] and saved["configDigestMatches"]
    assert world.users == {}


def test_an_expired_age_is_recorded_but_does_not_assert_an_upper_bound(
    tmp_path, monkeypatch
):
    # A pending older than the lifetime is refused at start; its finalize is skipped. The
    # refusal is recorded with its reason, but revision 1 asserts no upper bound.
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
        # The refused start keeps its measured pending age.
        assert rows[f"age-{a}s-start"]["timing"]["pendingAgeAtStart"]["lower"] >= a
    summary = lifetime_summary(saved)
    assert summary["usableAges"] == [2]
    assert summary["refusedAges"] == [120, 300]
    assert summary["refusalReasons"] == {
        "120": "INVALID_MFA_PENDING_CREDENTIAL",
        "300": "INVALID_MFA_PENDING_CREDENTIAL",
    }
    assert summary["lowerBoundSeconds"] == 2
    assert summary["upperBoundEstablished"] is False


def test_time_budget_stops_observation_and_still_cleans_up(tmp_path, monkeypatch):
    tight = {
        "maxAccounts": 5,
        "maxRequests": 200,
        "recoveryRequestReserve": 40,
        "totalBudgetSeconds": 100,
        "configHoldMaxSeconds": 100_000,
        "cleanupReserveSeconds": 20,
    }
    world, report, saved = run(tmp_path, monkeypatch, ttl=10_000, budget=tight)
    assert report["status"] == "incomplete" and saved["stopReason"] == "time-budget"
    assert "failure" not in saved
    # Setup finished, then aging past the wall budget stopped a later diagnostic, so the
    # corpus is incomplete (a proper prefix of the cases, missing the largest age).
    assert saved["setup"] is True
    recorded = [r["id"] for r in saved["cases"]]
    assert recorded != list(CASES) and "age-300s-start" not in recorded
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {} and not complete(saved)


def test_request_budget_leaves_room_for_cleanup(tmp_path, monkeypatch):
    tight = {
        "maxAccounts": 5,
        "maxRequests": 30,
        "recoveryRequestReserve": 20,
        "totalBudgetSeconds": 100_000,
        "configHoldMaxSeconds": 100_000,
        "cleanupReserveSeconds": 120,
    }
    world, report, saved = run(tmp_path, monkeypatch, ttl=10_000, budget=tight)
    assert report["status"] == "incomplete" and saved["stopReason"] == "request-budget"
    counts = saved["requestCount"]
    # Observation stayed within its reserve; recovery ran; the total stayed within budget.
    assert (
        counts["observation"] <= tight["maxRequests"] - tight["recoveryRequestReserve"]
    )
    assert counts["recovery"] > 0
    assert counts["observation"] + counts["recovery"] <= tight["maxRequests"]
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {} and not complete(saved)


def test_config_hold_budget_stops_observation_and_restores(tmp_path, monkeypatch):
    tight = {
        "maxAccounts": 5,
        "maxRequests": 200,
        "recoveryRequestReserve": 40,
        "totalBudgetSeconds": 100_000,
        "configHoldMaxSeconds": 100,
        "cleanupReserveSeconds": 20,
    }
    world, report, saved = run(tmp_path, monkeypatch, ttl=10_000, budget=tight)
    assert report["status"] == "incomplete"
    assert saved["stopReason"] == "config-hold-budget"
    assert saved["configRestored"] and saved["cleanup"] == {
        "uidAbsent": True,
        "emailAbsent": True,
    }
    assert world.users == {} and not complete(saved)


def test_a_termination_signal_restores_config_and_deletes_accounts(
    tmp_path, monkeypatch
):
    world, report, saved = run(
        tmp_path, monkeypatch, ttl=10_000, terminate=("mfaSignIn:start", 2)
    )
    assert report["status"] == "incomplete" and saved["stopReason"] == "terminated"
    assert saved["failure"] == "Terminated"
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {}
    assert world.patches[-1]["mfa"] == {"state": "DISABLED"}
    assert saved["configRestored"] and not complete(saved)


def test_a_lost_admin_request_still_cleans_up_and_is_incomplete(tmp_path, monkeypatch):
    world, report, saved = run(
        tmp_path, monkeypatch, ttl=10_000, lose=("admin:update", 1)
    )
    assert report["status"] == "incomplete" and saved["failure"] == "TimeoutError"
    assert saved["stopReason"] == "error"
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}
    assert world.users == {} and not complete(saved)


def test_a_failed_restore_is_visible_and_not_complete(tmp_path, monkeypatch):
    world = World(tmp_path / "run", Clock(), Clock(), ttl=10_000)
    wire(world, monkeypatch)

    def raise_restore(original):
        raise TimeoutError("restore lost")

    # The inline recovery restore builds the restore body via revocation.restore_body.
    monkeypatch.setattr(recorder.revocation, "restore_body", raise_restore)
    recorder.observe(world.output)
    saved = json.loads((world.output / "observation.json").read_bytes())
    assert saved["configRestoreFailure"] == "TimeoutError"
    assert "configRestored" not in saved and complete(saved) is False
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}


def test_a_dirty_checkout_is_refused_before_any_write(tmp_path, monkeypatch):
    world, report, saved = run(tmp_path, monkeypatch, dirty=True)
    assert report["status"] == "incomplete" and saved["failure"] == "ValueError"
    assert "committedCheckout" not in saved
    assert world.patches == [] and world.counts == {}
    assert not complete(saved)


# --- Timing intervals ---------------------------------------------------------------


def test_pending_and_session_ages_are_saved_as_intervals_measured_at_the_right_moment(
    tmp_path, monkeypatch
):
    # A 4-second start latency: the pending age at start widens by it, and the session age
    # at finalize is measured at finalize (not at the start round-trip) and stays small.
    _world, report, saved = run(
        tmp_path, monkeypatch, ttl=10_000, delay={"mfaSignIn:start": 4}
    )
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    for a in AGE_SECONDS:
        start_timing = rows[f"age-{a}s-start"]["timing"]
        interval = start_timing["pendingAgeAtStart"]
        assert interval["lower"] >= a
        # The 4-second start latency shows up as interval width.
        assert interval["upper"] - interval["lower"] == pytest.approx(4, abs=0.01)
        fin_timing = rows[f"age-{a}s-finalize"]["timing"]
        session_age = fin_timing["sessionAgeAtFinalize"]
        # The session is minted during the start request, so at finalize it is at most the
        # start latency plus the finalize round-trip, always small and never the pending age.
        assert session_age["upper"] <= 30
        # For the large ages the session age is far below the pending age: they are separate.
        if a >= 120:
            assert session_age["upper"] < a
        # Interval bounds are consistent with the recorded send/receive timestamps.
        assert (
            session_age["lower"]
            == fin_timing["finalizeSent"] - fin_timing["startReceived"]
        )
        assert (
            session_age["upper"]
            == fin_timing["finalizeReceived"] - fin_timing["startSent"]
        )


def test_a_refused_start_keeps_its_measured_pending_age(tmp_path, monkeypatch):
    _world, report, saved = run(tmp_path, monkeypatch, ttl=60)
    assert report["status"] == "observed"
    rows = rows_of(saved)
    refused = rows["age-120s-start"]
    assert refused["outcome"] == "refused" and refused["checks"] == {}
    # checks are empty, but the timing region still carries the measured age.
    assert refused["timing"]["pendingAgeAtStart"]["lower"] >= 120
    # Its skipped finalize carries no timing.
    assert rows["age-120s-finalize"]["skipped"] is True
    assert rows["age-120s-finalize"]["timing"] == {}


def test_a_stale_session_at_an_accepted_finalize_fails_the_freshness_check(
    tmp_path, monkeypatch
):
    # If the SMS session were not fresh at finalize (here forced by a 40 s finalize latency
    # on the aging clock), the session-age-at-finalize interval exceeds the 30 s freshness
    # bound, validate_timing refuses the accepted finalize row, and the run is not complete.
    # Guards the <= 30 s check from silent deletion.
    _world, report, saved = run(
        tmp_path, monkeypatch, ttl=10_000, delay={"mfaSignIn:finalize": 40}
    )
    assert report["status"] == "incomplete" and saved["failure"] == "ValueError"
    assert not complete(saved)


# --- Time budget reaches setup, individual requests and recovery --------------------

# Every request occupies up to the transport timeout (REQUEST_BUDGET_SECONDS = 20 s); the
# tests below use per-request delays below that, so the reservation is meant to hold.
NEAR_TIMEOUT = 19


def test_a_slow_setup_stops_before_the_deadline_and_recovers(tmp_path, monkeypatch):
    # A slow setup (each sign-up ~19 s) crosses the observation deadline before the corpus
    # even begins. The run must not start a request past the deadline: setup does not finish,
    # no diagnostics run, and the accounts created so far are still deleted.
    tight = {
        "maxAccounts": 5,
        "maxRequests": 200,
        "recoveryRequestReserve": 40,
        "totalBudgetSeconds": 120,
        "configHoldMaxSeconds": 100_000,
        "cleanupReserveSeconds": 20,
    }
    world, report, saved = run(
        tmp_path, monkeypatch, ttl=10_000, budget=tight, delay={"signUp": NEAR_TIMEOUT}
    )
    assert report["status"] == "incomplete" and saved["stopReason"] == "time-budget"
    # Setup did not finish and no diagnostic ran; no sign-up was issued past the deadline.
    assert saved["setup"] is False and saved["cases"] == []
    assert world.counts.get("signUp", 0) < len(AGE_SECONDS) + 2
    # Every fully created account was deleted; a partial account whose creation was blocked
    # cannot be confirmed clean and is left for --recover, so cleanup is not full.
    assert world.users == {} and not complete(saved)


def test_a_slow_observation_request_is_stopped_before_the_deadline(
    tmp_path, monkeypatch
):
    # Not only the aging wait: a slow observation request (here the held-pending sign-ins)
    # is itself time-guarded, so once the deadline is near no further request is sent.
    tight = {
        "maxAccounts": 5,
        "maxRequests": 200,
        "recoveryRequestReserve": 40,
        "totalBudgetSeconds": 80,
        "configHoldMaxSeconds": 100_000,
        "cleanupReserveSeconds": 20,
    }
    world, report, saved = run(
        tmp_path,
        monkeypatch,
        ttl=10_000,
        budget=tight,
        delay={"signInWithPassword": NEAR_TIMEOUT},
    )
    assert report["status"] == "incomplete" and saved["stopReason"] == "time-budget"
    assert "failure" not in saved
    assert world.users == {} and saved["cleanup"] == {
        "uidAbsent": True,
        "emailAbsent": True,
    }
    assert not complete(saved)


def test_slow_recovery_stops_within_budget_and_leaves_accounts_for_re_recovery(
    tmp_path, monkeypatch
):
    # Observation completes, then deletion is slow (~19 s per delete, a recovery-only
    # request that spends the wall budget). Recovery must stop at the total budget rather
    # than run past it, marking the accounts it could not confirm as un-recovered (their
    # journals persist for a later --recover).
    tight = {
        "maxAccounts": 5,
        "maxRequests": 200,
        "recoveryRequestReserve": 40,
        "totalBudgetSeconds": 400,
        "configHoldMaxSeconds": 100_000,
        "cleanupReserveSeconds": 40,
    }
    world, report, saved = run(
        tmp_path,
        monkeypatch,
        ttl=10_000,
        budget=tight,
        delay={"admin:delete": NEAR_TIMEOUT},
    )
    assert report["status"] == "observed" and saved["stopReason"] == "completed"
    # The run never exceeded its declared total wall budget.
    assert saved["wallElapsedSeconds"] <= saved["budget"]["totalBudgetSeconds"]
    # Recovery could not confirm every account, so it is incomplete and not a complete run.
    assert saved["recoveryIncomplete"] is True and saved["unrecoveredCount"] >= 1
    # Some accounts were deleted; the rest are left with their journals for re-recovery.
    assert 0 < len(world.deleted) < len(AGE_SECONDS) + 2
    assert saved["cleanup"] == {} and not complete(saved)
    journals = list((tmp_path / "run").rglob("recovery.json"))
    assert len(journals) >= saved["unrecoveredCount"]


def test_a_slow_pending_acquisition_is_covered_by_the_age_interval(
    tmp_path, monkeypatch
):
    # A 3 s latency between the pending being issued and its response: the reported age
    # interval must COVER the pending's true age, i.e. its upper bound includes the latency.
    _world, report, saved = run(
        tmp_path, monkeypatch, ttl=10_000, delay={"signInWithPassword": 3}
    )
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    rows = rows_of(saved)
    for a in AGE_SECONDS:
        interval = rows[f"age-{a}s-start"]["timing"]["pendingAgeAtStart"]
        # Lower bound is still at least the sampled age; upper bound covers the 3 s latency,
        # so the pending's true age (born at send, aged past a) lies inside the interval.
        assert interval["lower"] >= a
        assert interval["upper"] >= a + 3


def test_timing_intervals_must_agree_with_their_raw_timestamps(tmp_path, monkeypatch):
    # The derived age intervals are checked against the raw send/receive times, so a report
    # whose interval or whose timestamps were tampered independently is rejected.
    base = complete_report(tmp_path, monkeypatch)
    # (a) keep the raw times, corrupt only the derived interval.
    stale = copy.deepcopy(base)
    row = next(r for r in stale["cases"] if r["id"] == "age-300s-start")
    row["timing"]["pendingAgeAtStart"] = {"lower": 300.0, "upper": 300.0}
    row["timing"]["pendingReceived"] = row["timing"]["startSent"] - 1
    assert complete(stale) is False
    # (b) keep the derived interval, corrupt only a raw timestamp out of order.
    reordered = copy.deepcopy(base)
    row = next(r for r in reordered["cases"] if r["id"] == "age-300s-start")
    row["timing"]["startSent"] = row["timing"]["startReceived"] + 5
    assert complete(reordered) is False


# --- Owned local run (virtual-clock aging) ------------------------------------------


def test_owned_local_run_ages_by_the_virtual_clock(tmp_path, monkeypatch):
    world, report, saved = run(tmp_path, monkeypatch, production=False, ttl=10_000)
    assert report["status"] == "observed", report.get("lastStep")
    assert complete(saved)
    assert saved["target"] == "local" and saved["agingMode"] == "virtual-clock"
    assert saved["configEnabled"] is False
    assert world.patches == [] and saved["projectNumber"] is None
    # Virtual aging never spent the wall budget.
    assert saved["wallElapsedSeconds"] <= saved["budget"]["totalBudgetSeconds"]
    assert saved["configHoldSeconds"] == 0
    rows = rows_of(saved)
    for a in AGE_SECONDS:
        assert rows[f"age-{a}s-start"]["timing"]["pendingAgeAtStart"]["lower"] >= a


def test_owned_local_run_records_expiry_without_asserting_an_upper_bound(
    tmp_path, monkeypatch
):
    _world, report, saved = run(tmp_path, monkeypatch, production=False, ttl=60)
    assert report["status"] == "observed"
    assert complete(saved)
    summary = lifetime_summary(saved)
    assert summary["usableAges"] == [2]
    assert summary["refusedAges"] == [120, 300]
    assert summary["upperBoundEstablished"] is False


# --- Budget accounting on a complete run --------------------------------------------


def test_budget_usage_is_recorded_and_within_the_declared_budget(tmp_path, monkeypatch):
    _world, report, saved = run(tmp_path, monkeypatch, ttl=10_000)
    assert report["status"] == "observed"
    budget = saved["budget"]
    counts = saved["requestCount"]
    assert set(counts) == {"observation", "recovery", "config"}
    assert (
        counts["observation"]
        <= budget["maxRequests"] - budget["recoveryRequestReserve"]
    )
    assert counts["observation"] + counts["recovery"] <= budget["maxRequests"]
    assert saved["accountsUsed"] == len(AGE_SECONDS) + 2 <= budget["maxAccounts"]
    assert saved["wallElapsedSeconds"] <= budget["totalBudgetSeconds"]
    assert saved["configHoldSeconds"] <= budget["configHoldMaxSeconds"]


# --- Pure summary / contract mutations ----------------------------------------------


def test_an_http_200_without_a_usable_token_is_not_counted_as_usable(
    tmp_path, monkeypatch
):
    saved = complete_report(tmp_path, monkeypatch)
    empty_checks = {k: (k == "noError") for k in FINALIZE_CHECKS}
    for row in saved["cases"]:
        if row["id"].endswith("-finalize") and row["id"].startswith("age-"):
            row["checks"] = dict(empty_checks)
    # The run is still a complete observation, but no age is a verified success.
    assert complete(saved) is True
    summary = lifetime_summary(saved)
    assert summary["usableAges"] == []
    assert summary["indeterminateAges"] == list(AGE_SECONDS)
    assert summary["lowerBoundSeconds"] is None
    assert summary["upperBoundEstablished"] is False


def test_a_non_expiry_refusal_records_the_reason_but_asserts_no_upper_bound(
    tmp_path, monkeypatch
):
    saved = complete_report(tmp_path, monkeypatch)
    rows = {r["id"]: r for r in saved["cases"]}
    start = rows["age-120s-start"]
    start.update(
        outcome="refused", httpStatus=400, observedError="USER_DISABLED", checks={}
    )
    fin = rows["age-120s-finalize"]
    fin.update(
        outcome="skipped",
        httpStatus=None,
        observedError=None,
        checks={},
        skipped=True,
        timing={},
    )
    assert complete(saved) is True
    summary = lifetime_summary(saved)
    assert 120 in summary["refusedAges"]
    assert summary["refusalReasons"]["120"] == "USER_DISABLED"
    assert summary["upperBoundEstablished"] is False


def test_a_refusal_below_a_later_success_does_not_produce_a_contradiction(
    tmp_path, monkeypatch
):
    saved = complete_report(tmp_path, monkeypatch)
    rows = {r["id"]: r for r in saved["cases"]}
    rows["age-120s-start"].update(
        outcome="refused",
        httpStatus=400,
        observedError="INVALID_MFA_PENDING_CREDENTIAL",
        checks={},
    )
    rows["age-120s-finalize"].update(
        outcome="skipped",
        httpStatus=None,
        observedError=None,
        checks={},
        skipped=True,
        timing={},
    )
    assert complete(saved) is True
    summary = lifetime_summary(saved)
    # 300 usable, 120 refused: reported side by side, no upper bound asserted.
    assert summary["usableAges"] == [2, 300]
    assert summary["refusedAges"] == [120]
    assert summary["lowerBoundSeconds"] == 300
    assert summary["upperBoundEstablished"] is False


def test_a_transient_error_row_never_completes_a_run(tmp_path, monkeypatch):
    saved = complete_report(tmp_path, monkeypatch)
    rows = {r["id"]: r for r in saved["cases"]}
    rows["age-300s-start"].update(
        outcome="refused",
        httpStatus=400,
        observedError="TOO_MANY_ATTEMPTS_TRY_LATER",
        checks={},
    )
    rows["age-300s-finalize"].update(
        outcome="skipped",
        httpStatus=None,
        observedError=None,
        checks={},
        skipped=True,
        timing={},
    )
    # A throttle answer is an observation but not a semantic result: the run is not complete.
    assert complete(saved) is False


def test_semantic_rows_drop_timing_and_elapsed(tmp_path, monkeypatch):
    saved = complete_report(tmp_path, monkeypatch)
    stripped = semantic_rows(saved["cases"])
    for row in stripped:
        assert "elapsedMs" not in row and "timing" not in row
    start = next(r for r in stripped if r["id"] == "age-2s-start")
    assert set(start["checks"]) == {"sessionInfoPresent"}


def test_no_expected_secret_marker_would_be_a_false_negative():
    emitted = ("pending-secret-0", "session-secret-0", "Aa9!x", TEST_CODE)
    for value in emitted:
        assert any(marker in value for marker in SECRET_MARKERS), value


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
