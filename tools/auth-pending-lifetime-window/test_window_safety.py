"""Offline executable two-clock backend for revision-3 safety regressions.

The fixture models pending issuance latency, actual admin expiry, refresh failure and
phase deadlines. Contract mutations check missing/tampered request evidence. No production
operation is performed and no credential reaches an artifact.
"""

import base64
import copy
import json
import os
import signal
import urllib.parse

import pytest
import window_recorder as recorder
from window_contract import (
    AGE_SECONDS,
    TEST_CODE,
    complete,
    lifetime_summary,
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
        self.access_expires = wall.now() + 3600

    def command(self, argv):
        # git status / rev-parse, plus the admin-token refresh (gcloud print-access-token).
        if argv[:3] == ["git", "status", "--porcelain"]:
            assert argv[3] == "--" and set(argv[4:]) == set(recorder.PROBE_TREES)
            return ""
        if argv == ["git", "rev-parse", "HEAD"]:
            return "deadbeef"
        if argv == ["gcloud", "auth", "application-default", "print-access-token"]:
            self.token_refreshes += 1
            self.access_expires = self.wall.now() + 3600
            return (
                ACCESS_TOKEN  # a fresh token, same value so the router still accepts it
            )
        if argv[:3] == ["gcloud", "functions", "list"]:
            self.wall.advance(self.delay.get("preflight", 0))
            return "[]"
        if argv[:4] == ["gcloud", "services", "api-keys", "list"]:
            return f"projects/{recorder.NUMBER}/locations/global/keys/test"
        if argv[:4] == ["gcloud", "services", "api-keys", "get-key-string"]:
            return "key-secret-value"
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
        assert self.wall.now() + 20 <= self.access_expires
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
                # This fixture knows expiry caused the refusal; the observer does not.
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
        if (
            url
            == f"https://cloudresourcemanager.googleapis.com/v1/projects/{recorder.PROJECT}"
        ):
            assert token == ACCESS_TOKEN and quota
            return 200, {
                "projectId": recorder.PROJECT,
                "projectNumber": recorder.NUMBER,
            }
        if url == recorder.TOKEN_INFO_URL:
            assert form and body == {"access_token": ACCESS_TOKEN} and token is None
            return 200, {
                "expires_in": max(0, int(world.access_expires - world.wall.now()))
            }
        if token == ACCESS_TOKEN:
            assert world.wall.now() + 20 <= world.access_expires
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


def run(tmp_path, monkeypatch, budget=None, world_type=World, **options):
    world = world_type(tmp_path / "run", Clock(), Clock(), **options)
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


def test_short_schedule_and_healthy_same_account_controls(tmp_path, monkeypatch):
    assert AGE_SECONDS == (300, 450, 600)
    world, report, saved = run(tmp_path, monkeypatch, ttl=449)
    assert complete(saved), report
    rows = rows_of(saved)
    assert saved["accountsUsed"] == 5
    assert lifetime_summary(saved)["usableAges"] == [300]
    for age in (450, 600):
        prefix = f"age-{age}s-"
        state = rows[prefix + "post-refusal-state"]
        fresh = rows[prefix + "post-refusal-fresh-finalize"]
        assert all(state["checks"].values())
        assert all(fresh["checks"].values())
        assert (
            rows[prefix + "start"]["timing"]["startReceived"]
            <= state["timing"]["readbackSent"]
        )
        assert state["timing"]["readbackReceived"] <= fresh["timing"]["pendingSent"]
    assert rows["age-300s-post-refusal-state"]["skipped"]
    assert not world.users


def test_all_success_skips_same_account_controls(tmp_path, monkeypatch):
    _, _, saved = run(tmp_path, monkeypatch)
    assert complete(saved)
    for age in AGE_SECONDS:
        for suffix in ("state", "fresh-start", "fresh-finalize"):
            assert rows_of(saved)[f"age-{age}s-post-refusal-{suffix}"]["skipped"]
    assert lifetime_summary(saved)["upperBoundEstablished"] is False


def test_post_refusal_evidence_is_required_and_ordered(tmp_path, monkeypatch):
    _, _, saved = run(tmp_path, monkeypatch, ttl=449)
    assert complete(saved)
    changed = copy.deepcopy(saved)
    changed["cases"] = [
        r for r in changed["cases"] if r["id"] != "age-450s-post-refusal-state"
    ]
    assert not complete(changed)
    changed = copy.deepcopy(saved)
    rows_of(changed)["age-450s-post-refusal-state"]["timing"] = {
        "readbackSent": 0,
        "readbackReceived": 0,
    }
    assert not complete(changed)


class ControlledWorld(World):
    """Independent state machine: reject held credentials and trace per-UID events."""

    drift = None
    fresh_error = None
    old_stage = "start"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events = []
        self.refused_uids = set()

    def admin(self, action, body):
        result = super().admin(action, body)
        if action == "lookup" and body.get("localId"):
            self.events.append(("readback", body["localId"][0]))
        return result

    def client(self, action, body):
        result = super().client(action, body)
        if action == "signInWithPassword":
            self.events.append(("pending", result[1]["localId"]))
        return result

    def mfa(self, action, body):
        entry = self.pendings[body["mfaPendingCredential"]]
        uid = entry["uid"]
        age = self.aging.now() - entry["born"]
        if age >= 450 and action.endswith(":" + self.old_stage):
            self.events.append(("old-refused", uid))
            self.refused_uids.add(uid)
            user = self.users[uid]
            if self.drift == "missing":
                self.users.pop(uid)
            elif self.drift == "uid":
                user["localId"] = "different-uid"
            elif self.drift == "email":
                user["email"] = "changed@example.invalid"
            elif self.drift == "marker":
                user["displayName"] = "different-marker"
            elif self.drift == "disabled":
                user["disabled"] = True
            elif self.drift == "verified":
                user["emailVerified"] = False
            elif self.drift == "enrollment":
                user["mfaInfo"] = []
            elif self.drift == "phone":
                user["mfaInfo"][0]["phoneInfo"] = "+15555550199"
            return self.error("INVALID_MFA_PENDING_CREDENTIAL")
        if uid in self.refused_uids and self.fresh_error and action.endswith(":start"):
            self.events.append(("fresh-refused", uid))
            return self.error(self.fresh_error)
        self.events.append((action, uid))
        return super().mfa(action, body)


def test_same_uid_control_sequence_runs_after_old_response(tmp_path, monkeypatch):
    world, _, saved = run(tmp_path, monkeypatch, world_type=ControlledWorld)
    assert complete(saved)
    for uid in world.refused_uids:
        events = [event for event, subject in world.events if subject == uid]
        old = events.index("old-refused")
        assert events[old : old + 5] == [
            "old-refused",
            "readback",
            "pending",
            "mfaSignIn:start",
            "mfaSignIn:finalize",
        ]
        assert events[:old].count("pending") == 1
    controls = lifetime_summary(saved)["sameAccountControls"]
    assert len(controls) == 2
    assert all(
        c["accountStateMatches"] and c["freshCompletionVerified"] for c in controls
    )
    assert not any(c["ageCausalityEstablished"] for c in controls)


@pytest.mark.parametrize(
    "drift",
    [
        "missing",
        "uid",
        "email",
        "marker",
        "disabled",
        "verified",
        "enrollment",
        "phone",
    ],
)
def test_state_drift_suppresses_fresh_pending(tmp_path, monkeypatch, drift):
    class DriftWorld(ControlledWorld):
        pass

    DriftWorld.drift = drift
    world, _, saved = run(tmp_path, monkeypatch, world_type=DriftWorld)
    for uid in world.refused_uids:
        events = [event for event, subject in world.events if subject == uid]
        assert events[events.index("old-refused") + 1] == "readback"
        assert "pending" not in events[events.index("old-refused") + 1 :]
    for age in (450, 600):
        rows = rows_of(saved)
        assert not all(rows[f"age-{age}s-post-refusal-state"]["checks"].values())
        assert rows[f"age-{age}s-post-refusal-fresh-start"]["skipped"]
    assert not any(
        c["freshCompletionVerified"]
        for c in lifetime_summary(saved)["sameAccountControls"]
    )


@pytest.mark.parametrize(
    "error",
    [
        "INVALID_MFA_PENDING_CREDENTIAL",
        "MISSING_MFA_PENDING_CREDENTIAL",
        "MFA_ENROLLMENT_NOT_FOUND",
    ],
)
def test_fresh_refusal_is_preserved_without_causal_promotion(
    tmp_path, monkeypatch, error
):
    class FreshFailureWorld(ControlledWorld):
        fresh_error = error

    _, _, saved = run(tmp_path, monkeypatch, world_type=FreshFailureWorld)
    assert complete(saved)
    for age in (450, 600):
        row = rows_of(saved)[f"age-{age}s-post-refusal-fresh-start"]
        assert row["observedError"] == error
    assert not any(
        c["freshCompletionVerified"]
        for c in lifetime_summary(saved)["sameAccountControls"]
    )
    assert not lifetime_summary(saved)["ageCausedExpiryEstablished"]


def test_old_finalize_refusal_is_followed_by_same_account_control(
    tmp_path, monkeypatch
):
    class FinalizeRefusalWorld(ControlledWorld):
        old_stage = "finalize"

    _, _, saved = run(tmp_path, monkeypatch, world_type=FinalizeRefusalWorld)
    assert complete(saved)
    summary = lifetime_summary(saved)
    assert summary["startAcceptedAges"] == list(AGE_SECONDS)
    assert all(r["stage"] == "finalize" for r in summary["refusalObservations"])
    assert all(c["freshCompletionVerified"] for c in summary["sameAccountControls"])


def test_measured_candidate_includes_known_model_lifetime(tmp_path, monkeypatch):
    _, _, saved = run(tmp_path, monkeypatch, ttl=451, delay={"signInWithPassword": 3})
    assert complete(saved)
    summary = lifetime_summary(saved)
    first = summary["boundaryCandidates"][0]
    assert first["pendingAge"] == {"lower": 450, "upper": 453}
    assert first["lowerSeconds"] <= 451 <= first["upperSeconds"]
    assert not summary["upperBoundEstablished"]


def test_nonmonotonic_old_refusals_never_establish_a_boundary(tmp_path, monkeypatch):
    class NonmonotonicWorld(ControlledWorld):
        def mfa(self, action, body):
            entry = self.pendings[body["mfaPendingCredential"]]
            age = self.aging.now() - entry["born"]
            if 300 <= age < 450 or age >= 600:
                return self.error("INVALID_MFA_PENDING_CREDENTIAL")
            return World.mfa(self, action, body)

    _, _, saved = run(tmp_path, monkeypatch, world_type=NonmonotonicWorld)
    assert complete(saved)
    summary = lifetime_summary(saved)
    assert summary["nonMonotonic"] and not summary["boundaryCandidates"]


@pytest.mark.parametrize("remaining", [0, 20, "unknown", True])
def test_unverified_initial_expiry_prevents_configuration_changes(
    tmp_path, monkeypatch, remaining
):
    world = World(tmp_path / "run", Clock(), Clock())
    wire(world, monkeypatch)
    transport = router(world)

    def request(url, *args, **kwargs):
        if url == recorder.TOKEN_INFO_URL:
            return 200, {"expires_in": remaining}
        return transport(url, *args, **kwargs)

    monkeypatch.setattr(recorder.core, "request", request)
    report = recorder.observe(world.output)
    assert not world.patches and not world.users
    assert not complete(report)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-config",
        "missing-account",
        "remaining",
        "expiry",
        "phase",
        "refresh-count",
    ],
)
def test_auth_evidence_mutations_are_rejected(tmp_path, monkeypatch, mutation):
    _, _, saved = run(tmp_path, monkeypatch)
    assert complete(saved)
    evidence = saved["privilegedRequests"]
    if mutation.startswith("missing-"):
        prefix = "config:" if mutation == "missing-config" else "admin:"
        evidence.remove(next(e for e in evidence if e["action"].startswith(prefix)))
    elif mutation == "remaining":
        evidence[0]["remainingSeconds"] = 19
        evidence[0]["verifiedExpiry"] = evidence[0]["started"] + 19
    elif mutation == "expiry":
        evidence[0]["verifiedExpiry"] = evidence[0]["started"]
    elif mutation == "phase":
        evidence[0]["phase"] = "recovery"
    else:
        saved["authRefreshAttempts"]["observation"] = 0
    assert not complete(saved)


def test_admin_evidence_cannot_be_erased_with_its_duplicate_counts(
    tmp_path, monkeypatch
):
    _, _, saved = run(tmp_path, monkeypatch)
    saved["privilegedRequests"] = [
        e for e in saved["privilegedRequests"] if not e["action"].startswith("admin:")
    ]
    saved["adminTokenAges"] = [
        e["tokenAgeSeconds"] for e in saved["privilegedRequests"]
    ]
    for i, e in enumerate(saved["privilegedRequests"]):
        e["sequence"] = i + 1
    saved["privilegedRequestCount"] = {
        p: sum(e["phase"] == p for e in saved["privilegedRequests"])
        for p in ("observation", "recovery")
    }
    assert not complete(saved)


def test_fresh_pending_must_differ_from_refused_credential(tmp_path, monkeypatch):
    class ReusedPendingWorld(ControlledWorld):
        def client(self, action, body):
            result = super().client(action, body)
            if action == "signInWithPassword":
                uid = result[1]["localId"]
                if uid in self.refused_uids:
                    old = next(
                        key
                        for key, value in self.pendings.items()
                        if value["uid"] == uid
                    )
                    result[1]["mfaPendingCredential"] = old
            return result

    _, _, saved = run(tmp_path, monkeypatch, world_type=ReusedPendingWorld)
    assert not complete(saved)
    assert saved["cleanup"] == {"uidAbsent": True, "emailAbsent": True}


def test_refresh_failure_remains_latched_in_short_run(tmp_path, monkeypatch):
    class FailedRefreshWorld(World):
        def command(self, argv):
            if (
                argv == ["gcloud", "auth", "application-default", "print-access-token"]
                and self.token_refreshes
            ):
                self.token_refreshes += 1
                self.wall.advance(60)
                raise TimeoutError("refresh failure")
            result = super().command(argv)
            if argv == ["gcloud", "auth", "application-default", "print-access-token"]:
                self.access_expires = self.wall.now() + 500
            return result

    world, _, saved = run(tmp_path, monkeypatch, world_type=FailedRefreshWorld)
    assert not complete(saved)
    assert world.token_refreshes == 2
    assert saved["unrecoveredCount"] == 5
    assert len(world.patches) == 1
    assert saved["wallElapsedSeconds"] <= recorder.BUDGET["totalBudgetSeconds"]


def test_deadline_prevents_new_refresh_and_retains_all_journals(tmp_path, monkeypatch):
    class LateWorld(World):
        def mfa(self, action, body):
            result = super().mfa(action, body)
            if self.aging.now() - 1000 >= 600:
                self.wall.t = 1000 + recorder.BUDGET["totalBudgetSeconds"] - 59
                self.access_expires = self.wall.now()
            return result

    world, _, saved = run(tmp_path, monkeypatch, world_type=LateWorld)
    assert not complete(saved)
    assert world.token_refreshes == 1
    assert saved["unrecoveredCount"] == 5
    assert len(list(world.output.rglob("recovery.json"))) == 5


def test_bounded_outcome_model_never_promotes_controls_to_expiry(tmp_path, monkeypatch):
    import itertools

    checked = 0
    for outcomes in itertools.product(("success", "start", "finalize"), repeat=3):
        for control in (
            "healthy",
            "state-drift",
            "fresh-refusal",
            "bad-identity",
            "missing-session",
            "fresh-finalize-refusal",
        ):

            class ModelWorld(World):
                model_outcomes = outcomes
                model_control = control

                def mfa(self, action, body):
                    entry = self.pendings[body["mfaPendingCredential"]]
                    age = self.aging.now() - entry["born"]
                    uid = entry["uid"]
                    if age >= 300:
                        target = max(a for a in AGE_SECONDS if a <= age)
                        outcome = self.model_outcomes[AGE_SECONDS.index(target)]
                        if action.endswith(":" + outcome):
                            if self.model_control == "state-drift":
                                self.users[uid]["disabled"] = True
                            return self.error("INVALID_MFA_PENDING_CREDENTIAL")
                    elif uid not in {"uid-0", "uid-4"}:
                        if self.model_control == "missing-session" and action.endswith(
                            ":start"
                        ):
                            return 200, {}
                        if (
                            self.model_control == "fresh-finalize-refusal"
                            and action.endswith(":finalize")
                        ):
                            return self.error("INVALID_CODE")
                        if self.model_control == "fresh-refusal":
                            return self.error("MFA_ENROLLMENT_NOT_FOUND")
                        if self.model_control == "bad-identity" and action.endswith(
                            ":finalize"
                        ):
                            status, result = super().mfa(action, body)
                            result.pop("idToken")
                            return status, result
                    return super().mfa(action, body)

            with monkeypatch.context() as patch:
                _, _, saved = run(tmp_path / str(checked), patch, world_type=ModelWorld)
                assert complete(saved), (outcomes, control, saved.get("lastStep"))
                summary = lifetime_summary(saved)
                assert not summary["upperBoundEstablished"]
                assert not summary["ageCausedExpiryEstablished"]
                expected_successes = [
                    a
                    for a, outcome in zip(AGE_SECONDS, outcomes, strict=True)
                    if outcome == "success"
                ]
                assert summary["usableAges"] == expected_successes
                expected_refusals = [
                    a
                    for a, outcome in zip(AGE_SECONDS, outcomes, strict=True)
                    if outcome != "success"
                ]
                assert summary["refusedAges"] == expected_refusals
                for same in summary["sameAccountControls"]:
                    assert same["freshCompletionVerified"] == (control == "healthy")
                    assert same["accountStateMatches"] == (control != "state-drift")
                if any(a < b for a in expected_refusals for b in expected_successes):
                    assert summary["nonMonotonic"] and not summary["boundaryCandidates"]
            checked += 1
    assert checked == 162


def test_fresh_success_response_without_session_is_retained(tmp_path, monkeypatch):
    class MissingSessionWorld(ControlledWorld):
        def mfa(self, action, body):
            uid = self.pendings[body["mfaPendingCredential"]]["uid"]
            if uid in self.refused_uids and action.endswith(":start"):
                return 200, {}
            return super().mfa(action, body)

    _, _, saved = run(tmp_path, monkeypatch, world_type=MissingSessionWorld)
    assert complete(saved)
    row = rows_of(saved)["age-450s-post-refusal-fresh-start"]
    assert row["httpStatus"] == 200 and row["checks"] == {"sessionInfoPresent": False}
    assert row["timing"]["pendingAgeAtStart"]["lower"] == 0
    assert rows_of(saved)["age-450s-post-refusal-fresh-finalize"]["skipped"]
    assert not any(
        c["freshCompletionVerified"]
        for c in lifetime_summary(saved)["sameAccountControls"]
    )


def test_fresh_acquisition_cannot_precede_readback(tmp_path, monkeypatch):
    class FreshFailureWorld(ControlledWorld):
        fresh_error = "INVALID_MFA_PENDING_CREDENTIAL"

    _, _, saved = run(tmp_path, monkeypatch, world_type=FreshFailureWorld)
    assert complete(saved)
    row = rows_of(saved)["age-450s-post-refusal-fresh-start"]
    row["timing"] = {
        "pendingSent": 0,
        "pendingReceived": 0,
        "startSent": 0,
        "startReceived": 0,
        "pendingAgeAtStart": {"lower": 0, "upper": 0},
    }
    assert not complete(saved)


def test_state_drift_cannot_be_combined_with_recorded_fresh_success(
    tmp_path, monkeypatch
):
    _, _, saved = run(tmp_path, monkeypatch, ttl=449)
    assert complete(saved)
    rows_of(saved)["age-450s-post-refusal-state"]["checks"]["enabled"] = False
    assert not complete(saved)
