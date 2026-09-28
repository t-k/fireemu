"""Conditions from the independent reviews of this lane, with post-fix expectations.

The first review ran seventeen conditions against these modules as they stood at
`07c9dac08` and recorded what each one did. Eleven recorded a defect and six were
controls. A second review at `9b01f635c` ran twenty-two, of which eight were new: six
recorded a further defect and two were controls. All twenty-five are reproduced here: the
ones that recorded a defect state what the fixed code must do instead, and the controls
state what must not have changed.

The harness injects the raw HTTP sender and substitutes a deterministic clock, so
the real parser, claim decoder, assertions, cleanup and receipt assembly run while no
daemon, service or network is involved. Every token here is a synthetic unsigned fixture
built by the shadow's own `unsigned_jwt`; none is a credential.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import io
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import credential_shadow as shadow
from credential_cases import (
    CASE_COUNT,
    SAME_SECOND_CASE_ID,
    control_members,
    observation_cases,
)

#: A complete undisturbed run: 34 observation requests over the 19 cases and 8
#: cleanup requests for the three accounts it creates (delete, UID readback, and an
#: address readback for the two accounts that have one).
FULL_RUN_REQUESTS = 42
from credential_collector import (
    BudgetExceeded,
    build_receipt,
    claim_set,
    claim_shape,
    cleanup_report,
    enter_recovery,
    mark_deleted,
    new_tracker,
    owned_email,
    request_allowance,
    track_account,
)
from credential_comparator import compare

BELOW_CONTROL = "revocation-older-session-rejected"
ABOVE_CONTROL = "revocation-newer-session-accepted"
COMPOSITION_CASE = "session-cookie-claim-composition"
SOURCE_BINDING = {"commit": "a" * 40, "artifactSha256": "b" * 64}
FIXTURE_LATENCY_SECONDS = 0.01


# --- a deterministic clock and an in-memory Identity service --------------------


def _clock(stall_seconds: float = 0.0) -> SimpleNamespace:
    """Stand in for the `time` module so a run takes no real time.

    `stall_seconds` is the reviewer's stall: the first wait of a second or more also
    advances the clock by that much, which is the machine pausing under the run rather
    than a request taking longer. Nothing charges it to a request duration.
    """
    state = {"now": 1_800_000_000.0, "stalled": False}

    def sleep(seconds: float) -> None:
        if stall_seconds and seconds >= 1 and not state["stalled"]:
            state["stalled"] = True
            state["now"] += stall_seconds
        state["now"] += seconds

    return SimpleNamespace(
        time=lambda: state["now"],
        monotonic=lambda: state["now"] - 1_799_000_000.0,
        sleep=sleep,
        state=state,
    )


def _payload(token: str) -> dict:
    segment = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def _refused(code: str) -> tuple[int, dict]:
    return 400, {"error": {"message": code}}


def _service(clock, *, cookie_subject="same") -> SimpleNamespace:
    """Answer the requests the declared case list makes, and nothing else.

    `cookie_subject` replaces the subject a session cookie carries: the reviewer's four
    cookie conditions are the same run with this set to the source subject, another
    account's, a number, and nothing at all.
    """
    accounts: dict[str, dict] = {}
    sessions: dict[str, tuple] = {}
    sent: list[str] = []
    cookie_pairs: list[dict] = []
    oob_codes: dict[str, str] = {}
    issued_count = [0]

    def drop_sessions(uid: str) -> None:
        """The local strict runtime removes the refresh sessions of a revoked account."""
        for refresh_token, known in list(sessions.items()):
            if known[0] == uid:
                del sessions[refresh_token]

    def session(uid: str, claims: dict | None = None, auth_time: int | None = None):
        now = int(clock.time())
        claims = dict(claims or {})
        token = shadow.unsigned_jwt(
            {
                "iss": f"https://securetoken.google.com/{shadow.PROJECT}",
                "aud": shadow.PROJECT,
                "sub": uid,
                "firebase": {"sign_in_provider": "custom"},
                "iat": now,
                "exp": now + 3600,
                "auth_time": now if auth_time is None else auth_time,
                **accounts[uid]["attributes"],
                **claims,
            }
        )
        # A counter, not the live session count: a retired session must never free
        # its name for a later account.
        issued_count[0] += 1
        refresh_token = f"fixture-refresh-{issued_count[0]}"
        sessions[refresh_token] = (uid, now if auth_time is None else auth_time, claims)
        return {"localId": uid, "idToken": token, "refreshToken": refresh_token}

    def create_session_cookie(body: dict):
        source = _payload(body["idToken"])
        account = accounts[source["sub"]]
        if source["auth_time"] < int(account["validSince"]):
            return _refused("TOKEN_EXPIRED")
        duration = int(body.get("validDuration", 1209600))
        if not 300 <= duration <= 1209600:
            return _refused("INVALID_DURATION")
        cookie = {
            **source,
            "iss": f"https://session.firebase.google.com/{shadow.PROJECT}",
            "iat": int(clock.time()),
            "exp": int(clock.time()) + duration,
        }
        if cookie_subject == "missing":
            cookie.pop("sub")
        elif cookie_subject != "same":
            cookie["sub"] = cookie_subject
        cookie_pairs.append(
            {"sourceSubject": source["sub"], "cookieSubject": cookie.get("sub")}
        )
        return 200, {"sessionCookie": shadow.unsigned_jwt(cookie)}

    def dispatch(url: str, body: dict):
        if "/securetoken.googleapis.com/" in url:
            known = sessions.get(body.get("refresh_token"))
            if known is None:
                return _refused("INVALID_REFRESH_TOKEN")
            uid, auth_time, claims = known
            issued = session(uid, claims, auth_time)
            return 200, {
                "id_token": issued["idToken"],
                "refresh_token": issued["refreshToken"],
            }
        if "accounts:signUp" in url:
            uid = f"fixture-u{len(accounts)}"
            accounts[uid] = {
                "email": body["email"],
                "password": body["password"],
                "attributes": {},
                "validSince": "0",
            }
            return 200, session(uid)
        if "accounts:signInWithPassword" in url:
            uid = next(k for k, v in accounts.items() if v["email"] == body["email"])
            if accounts[uid]["password"] != body["password"]:
                return _refused("INVALID_PASSWORD")
            return 200, session(uid)
        if "accounts:sendOobCode" in url:
            uid = next(k for k, v in accounts.items() if v["email"] == body["email"])
            code = f"fixture-oob-{len(oob_codes)}"
            oob_codes[code] = uid
            return 200, {"email": body["email"], "oobCode": code}
        if "accounts:resetPassword" in url:
            uid = oob_codes.pop(body["oobCode"], None)
            if uid is None:
                return _refused("INVALID_OOB_CODE")
            accounts[uid]["password"] = body["newPassword"]
            accounts[uid]["validSince"] = str(int(clock.time()))
            drop_sessions(uid)
            return 200, {"email": accounts[uid]["email"], "requestType": "PASSWORD_RESET"}
        if "accounts:signInWithCustomToken" in url:
            custom = _payload(body["token"])
            if "sub" in custom.get("claims", {}):
                return _refused("INVALID_CUSTOM_TOKEN")
            if custom["exp"] <= clock.time():
                return _refused("TOKEN_EXPIRED")
            uid = custom["uid"]
            is_new = uid not in accounts
            accounts.setdefault(
                uid, {"email": None, "attributes": {}, "validSince": "0"}
            )
            return 200, {**session(uid, custom.get("claims")), "isNewUser": is_new}
        if "accounts:update" in url:
            account = accounts[body["localId"]]
            if "validSince" in body:
                account["validSince"] = body["validSince"]
                drop_sessions(body["localId"])
            if "customAttributes" in body:
                account["attributes"] = json.loads(body["customAttributes"])
            return 200, {"localId": body["localId"]}
        if "accounts:lookup" in url:
            if "idToken" in body:
                claims = _payload(body["idToken"])
                if claims["auth_time"] < int(accounts[claims["sub"]]["validSince"]):
                    return _refused("TOKEN_EXPIRED")
                return 200, {"users": [{"localId": claims["sub"]}]}
            found = [
                {"localId": uid, "validSince": account["validSince"]}
                for uid, account in accounts.items()
                if uid in body.get("localId", [])
                or account["email"] in body.get("email", [])
            ]
            return 200, {"users": found}
        if ":createSessionCookie" in url:
            return create_session_cookie(body)
        if "accounts:delete" in url:
            accounts.pop(body["localId"], None)
            return 200, {}
        raise AssertionError(f"the fixture was asked for an unknown route: {url}")

    def urlopen(request, timeout=None):
        body = json.loads(request.data)
        url = request.full_url
        sent.append(url.split("?")[0].rsplit("/", 1)[-1])
        clock.sleep(FIXTURE_LATENCY_SECONDS)
        status, answer = dispatch(url, body)
        raw = json.dumps(answer).encode()
        if status != 200:
            raise urllib.error.HTTPError(
                url, status, "fixture refusal", {}, io.BytesIO(raw)
            )
        return contextlib.nullcontext(SimpleNamespace(status=status, read=lambda: raw))

    return SimpleNamespace(
        urlopen=urlopen, accounts=accounts, sent=sent, cookie_pairs=cookie_pairs
    )


@contextlib.contextmanager
def _driven(service, clock):
    """Run the shadow against the fixture, with no real clock and no real socket."""
    def sender(base, path, body, owner, timeout):
        request = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST")
        try:
            with service.urlopen(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.read()

    with (
        patch.object(shadow, "time", clock),
        patch.object(shadow, "_send_over_http", sender),
    ):
        yield


def _full_run(cookie_subject="same", clock=None):
    """The reviewer's condition: collect, clean up and assemble the record.

    This mirrors `main`, including the handoff into the reserve and a cleanup that is
    recorded rather than raised, so a run stopped by a deadline is driven the way a real
    one would be.
    """
    clock = clock or _clock()
    started = clock.monotonic()
    service = _service(clock, cookie_subject=cookie_subject)
    tracker = new_tracker("a" * 32)
    budget = shadow.shadow_budget(now=clock.monotonic())
    with _driven(service, clock):
        rows, failure = shadow.collect("http://127.0.0.1:8123", budget, tracker)
        enter_recovery(budget, clock.monotonic())
        try:
            problems = shadow.cleanup("http://127.0.0.1:8123", budget, tracker)
        except shadow.STOP_CONDITIONS as error:
            problems = [f"cleanup: {type(error).__name__}"]
    if problems:
        failure = failure or "cleanup: " + "; ".join(problems)
    record, exit_code = shadow.finish_record(
        rows=rows,
        tracker=tracker,
        budget=budget,
        failure=failure,
        shutdown={"exitCode": 0, "processStopped": True, "remainingChildren": 0,
                  "outputDrainerStopped": True, "failures": []},
        source_binding=dict(SOURCE_BINDING),
    )
    return SimpleNamespace(
        service=service,
        rows=rows,
        record=record,
        exitCode=exit_code,
        problems=problems,
        tracker=tracker,
        clock=clock,
        elapsedSeconds=clock.monotonic() - started,
    )


# --- the four cookie conditions -------------------------------------------------


def test_review_cookie_sub_same_still_agrees_on_every_declared_case() -> None:
    """Control `cookie-sub-same`: the honest run must stay clean."""
    run = _full_run("same")
    assert run.rows[COMPOSITION_CASE]["assertions"]["cookieSubjectMatchesIdToken"]
    assert run.record["expectedLocalAgreement"]["unexpected"] == []
    assert run.exitCode == 0
    assert run.problems == []
    assert run.service.accounts == {}


@pytest.mark.parametrize(
    ("condition", "cookie_subject"),
    [
        ("cookie-sub-wrong-user", "wrong-user"),
        ("cookie-sub-17", 17),
        ("cookie-sub-missing", "missing"),
    ],
)
def test_review_cookie_subject_defects_now_fail_the_run(
    condition: str, cookie_subject
) -> None:
    """A cookie for another account, a numeric subject and a missing one all fail.

    The first two passed the whole seventeen-case agreement before the fix.
    """
    run = _full_run(cookie_subject)
    pair = run.service.cookie_pairs[-1]
    assert pair["cookieSubject"] != pair["sourceSubject"]
    row = run.rows[COMPOSITION_CASE]
    assert row["status"] == 200
    assert row["assertions"]["cookieSubjectMatchesIdToken"] is False
    assert [
        item["caseId"] for item in run.record["expectedLocalAgreement"]["unexpected"]
    ] == [COMPOSITION_CASE]
    assert run.exitCode == 1
    # The run still owns nothing afterwards: a failed assertion is not a failed cleanup.
    assert run.service.accounts == {}


def test_review_cookie_conditions_publish_no_subject() -> None:
    """The record carries the answer, never the subject either side used."""
    run = _full_run("wrong-user")
    published = json.dumps(run.record)
    assert "wrong-user" not in published
    assert run.service.cookie_pairs[-1]["sourceSubject"] not in published


# --- the six boundary conditions ------------------------------------------------


def _synthetic_claim_projection() -> dict:
    token = shadow.unsigned_jwt({
        "aud": "fixture-claims",
        "sub": "fixture-user",
        "auth_time": 100,
        "iat": 102,
        "exp": 3702,
        "firebase": {"identities": {}, "sign_in_provider": "password"},
    })
    return claim_set(claim_shape(token))


def _review_row(case: dict) -> dict:
    assertions = {name: True for name in case["expectedLocal"]["assertions"]}
    row = {
        "caseId": case["id"],
        "status": case["expectedLocal"]["status"],
        "errorCode": case["expectedLocal"]["errorCode"],
        "assertions": assertions,
        "trustRoot": "unsigned-emulator",
        **control_members(case),
    }
    if (
        assertions.get("idTokenReturned") is True
        or assertions.get("sessionCookieReturned") is True
        or case["group"] == "claim-precedence"
    ):
        row["claims"] = _synthetic_claim_projection()
    if case["id"] == SAME_SECOND_CASE_ID:
        row.update(
            boundaryPinned=True,
            boundarySeconds={"authTime": 100, "validSince": 100},
        )
    return row


def _review_rows() -> list[dict]:
    return [_review_row(case) for case in observation_cases()]


def _cleaned_tracker() -> dict:
    tracker = new_tracker("a" * 32)
    track_account(tracker, "owned-u", owned_email(tracker, 0))
    mark_deleted(tracker, "owned-u", uid_absent=True, email_absent=True)
    return tracker


def _receipt(side: str, rows: list[dict]) -> dict:
    rows = copy.deepcopy(rows)
    if side == "production":
        for row in rows:
            row["trustRoot"] = "signed"
    return build_receipt(
        side=side,
        rows=rows,
        tracker=_cleaned_tracker(),
        budget=shadow.shadow_budget(now=0.0),
        source_binding=dict(SOURCE_BINDING),
        production_executed=side == "production",
    )


def _boundary_class(local_rows: list[dict], production_rows: list[dict]) -> str:
    report = compare(
        _receipt("local", local_rows), _receipt("production", production_rows)
    )
    return next(
        row["classification"]
        for row in report["rows"]
        if row["caseId"] == SAME_SECOND_CASE_ID
    )


def _accept(row: dict) -> None:
    row.update(status=200, errorCode=None, assertions={})


def _refuse(row: dict) -> None:
    row.update(
        status=400,
        errorCode="TOKEN_EXPIRED",
        assertions={"acceptedResponse": False, "idTokenReturned": True},
    )


def _find(rows: list[dict], case_id: str) -> dict:
    return next(row for row in rows if row["caseId"] == case_id)


def test_review_boundary_normal_still_compares() -> None:
    """Control `boundary-normal`: holding controls and a consistent pin still match."""
    assert _boundary_class(_review_rows(), _review_rows()) == "MATCH"


def test_review_both_sides_accepting_the_older_session_no_longer_matches() -> None:
    """`boundary-both-below-accepted`: agreement on the wrong answer placed a boundary."""
    local, production = _review_rows(), _review_rows()
    for rows in (local, production):
        _accept(_find(rows, BELOW_CONTROL))
    assert _boundary_class(local, production) == "INDETERMINATE"


def test_review_both_sides_refusing_the_newer_session_no_longer_matches() -> None:
    """`boundary-both-above-refused`: the same defect from the other side."""
    local, production = _review_rows(), _review_rows()
    for rows in (local, production):
        _refuse(_find(rows, ABOVE_CONTROL))
    assert _boundary_class(local, production) == "INDETERMINATE"


def test_review_one_side_accepting_the_older_session_stays_indeterminate() -> None:
    """Control `boundary-one-below-accepted`: a disagreeing control already stopped this."""
    local, production = _review_rows(), _review_rows()
    _accept(_find(production, BELOW_CONTROL))
    assert _boundary_class(local, production) == "INDETERMINATE"


def test_review_inconsistent_pinned_seconds_are_no_longer_a_match() -> None:
    """`boundary-inconsistent-pin`: auth_time 100 against validSince 102 pinned nothing."""
    local, production = _review_rows(), _review_rows()
    for rows in (local, production):
        _find(rows, SAME_SECOND_CASE_ID)["boundarySeconds"] = {
            "authTime": 100,
            "validSince": 102,
        }
    assert _boundary_class(local, production) == "EXPECTED_NONDETERMINISM"


def test_review_an_unpinned_boundary_row_stays_expected_nondeterminism() -> None:
    """Control `boundary-unpinned-auth-failure`: a refused boundary call is not a difference."""
    local, production = _review_rows(), _review_rows()
    for rows in (local, production):
        _find(rows, SAME_SECOND_CASE_ID).update(
            boundaryPinned=False, status=401, errorCode="UNAUTHENTICATED", assertions={}
        )
    assert _boundary_class(local, production) == "EXPECTED_NONDETERMINISM"


# --- the five refusal-control conditions ----------------------------------------


def _classification(local_rows: list[dict], production_rows: list[dict], case_id: str):
    report = compare(
        _receipt("local", local_rows), _receipt("production", production_rows)
    )
    row = next(row for row in report["rows"] if row["caseId"] == case_id)
    return row["classification"], report["summary"]


@pytest.mark.parametrize(
    ("condition", "status", "code"),
    [
        ("wrong-refusal-control-400", 400, "INVALID_ID_TOKEN"),
        ("wrong-refusal-control-401", 401, "UNAUTHENTICATED"),
        ("wrong-refusal-control-403", 403, "PERMISSION_DENIED"),
        ("wrong-refusal-control-429", 429, "TOO_MANY_ATTEMPTS_TRY_LATER"),
        ("wrong-refusal-control-503", 503, "UNAVAILABLE"),
    ],
)
def test_review_a_refusal_that_is_not_an_expiry_no_longer_places_the_boundary(
    condition: str, status: int, code: str
) -> None:
    """Four of these reached MATCH on all seventeen rows before the fix.

    The older session was refused, but for being an invalid token, an unauthenticated
    caller, a denied permission or one call too many. None of those says the session was
    too old, so the same-second row above them rests on nothing. The 503 was already
    rejected and is the control that the status test was never the whole test.
    """
    local, production = _review_rows(), _review_rows()
    for rows in (local, production):
        _find(rows, BELOW_CONTROL).update(status=status, errorCode=code, assertions={})
    classification, summary = _classification(local, production, SAME_SECOND_CASE_ID)
    assert classification == "INDETERMINATE"
    # The refusal is still compared as data: both sides said the same thing, so the
    # control row itself agrees. It simply places no boundary.
    assert _classification(local, production, BELOW_CONTROL)[0] == "MATCH"
    assert summary["indeterminate"] == 1
    assert summary["different"] == 0


@pytest.mark.parametrize("code", ["TOKEN_EXPIRED", "USER_DISABLED"])
def test_review_the_documented_expiry_refusals_still_place_the_boundary(
    code: str,
) -> None:
    """Control: what the lookup endpoint answers a revoked session is what counts."""
    local, production = _review_rows(), _review_rows()
    for rows in (local, production):
        _find(rows, BELOW_CONTROL).update(status=400, errorCode=code, assertions={})
    assert _classification(local, production, SAME_SECOND_CASE_ID)[0] == "MATCH"


# --- the three recording conditions ---------------------------------------------


def _partial_record() -> dict:
    first = _review_rows()[0]
    record, exit_code = shadow.finish_record(
        rows={first["caseId"]: first},
        tracker=_cleaned_tracker(),
        budget=shadow.shadow_budget(now=0.0),
        failure="BudgetExceeded: fixture stop",
        shutdown={"exitCode": 0, "processStopped": True, "remainingChildren": 0,
                  "outputDrainerStopped": True, "failures": []},
        source_binding=dict(SOURCE_BINDING),
    )
    assert exit_code == 1
    return record


def test_review_partial_against_complete_is_no_longer_a_row_of_differences() -> None:
    """`partial-vs-complete`: sixteen NOT_RUN rows were classified DIFFERENT."""
    partial = _partial_record()["receipt"]
    assert partial["recordingComplete"] is False
    assert sum(row["errorCode"] == "NOT_RUN" for row in partial["rows"]) == CASE_COUNT - 1
    report = compare(partial, _receipt("production", _review_rows()))
    assert report["reason"] == "incomplete-recording"
    assert report["summary"]["indeterminate"] == len(observation_cases())
    assert report["summary"]["different"] == 0


def test_review_partial_against_partial_is_no_longer_sixteen_matches() -> None:
    """`partial-vs-partial`: two stopped runs agreed about cases neither ever ran."""
    partial = _partial_record()["receipt"]
    report = compare(partial, _receipt("production", partial["rows"]))
    assert report["summary"]["match"] == 0
    assert report["summary"]["indeterminate"] == len(observation_cases())


def test_review_an_incomplete_recording_flag_still_refuses_the_pair() -> None:
    """Control `incomplete-flag-control`: the declared flag still fails closed."""
    production = _receipt("production", _review_rows())
    production["recordingComplete"] = False
    report = compare(_receipt("local", _review_rows()), production)
    assert report["reason"] == "incomplete-recording"
    assert report["summary"]["indeterminate"] == len(observation_cases())


# --- the four budget conditions -------------------------------------------------


# --- the three deadline conditions ----------------------------------------------


def test_review_an_unstalled_run_still_records_every_case() -> None:
    """Control `wall-budget-normal`: an ordinary run is untouched by the deadlines."""
    run = _full_run()
    assert run.exitCode == 0
    assert run.problems == []
    assert run.record["receipt"]["recordingComplete"] is True
    assert run.record["receipt"]["deadlines"]["exceeded"] == {}
    assert run.record["receipt"]["budget"]["requests"] == FULL_RUN_REQUESTS
    assert run.service.accounts == {}


def test_review_a_stall_between_requests_now_stops_the_run() -> None:
    """`wall-budget-600-second-pause`: 609 s of clock, 0.33 s charged, 42 requests.

    The stall is time nobody spent inside a request, so no sum of request durations can
    see it. The absolute deadline does: the wait ends past it, the run opens no further
    observation, and the record says which phase stopped and when.
    """
    run = _full_run(clock=_clock(stall_seconds=600))
    assert run.elapsedSeconds > 600
    exceeded = run.record["receipt"]["deadlines"]["exceeded"]
    assert set(exceeded) == {"run"}
    assert exceeded["run"]["limitSeconds"] == 540
    assert exceeded["run"]["elapsedSeconds"] > 540
    assert run.record["failure"] is not None
    assert run.record["receipt"]["recordingComplete"] is False
    assert run.record["receipt"]["budget"]["requests"] < FULL_RUN_REQUESTS
    assert run.exitCode == 1
    # The account created before the stall is never dropped, and the cleanup window the
    # campaign declares is granted whatever the observation phase did with its own.
    assert len(run.tracker["accounts"]) == 1
    assert run.problems == []
    assert run.record["receipt"]["cleanup"]["remainingAccounts"] == 0
    assert run.record["receipt"]["cleanup"]["cleanupComplete"] is True
    assert run.service.accounts == {}


def test_review_a_run_stopped_past_the_nominal_total_still_cleans_up() -> None:
    """A stall to just past 600 s: the tail is a window of its own, not what is left.

    This is the condition the earlier cap got wrong. The run stops at its observation
    deadline, and cleanup then gets the whole sixty seconds the manifest declares,
    measured from the moment it starts.
    """
    run = _full_run(clock=_clock(stall_seconds=599))
    deadlines = run.record["receipt"]["deadlines"]
    assert 600 < run.elapsedSeconds < 660
    assert set(deadlines["exceeded"]) == {"run"}
    assert deadlines["recoverySeconds"] == 60
    entered = deadlines["recoveryEnteredSeconds"]
    assert entered > 600
    assert deadlines["recoveryDeadlineSeconds"] == entered + 60
    # Cleanup ran inside its own window and deleted everything the run created.
    assert run.problems == []
    assert run.record["receipt"]["cleanup"]["cleanupComplete"] is True
    assert run.service.accounts == {}


def test_review_a_stall_that_still_fits_the_observation_window_completes() -> None:
    """Control: the deadline stops a run that overran, not one that merely waited."""
    run = _full_run(clock=_clock(stall_seconds=300))
    assert 300 < run.elapsedSeconds < 540
    assert run.exitCode == 0
    assert run.record["receipt"]["deadlines"]["exceeded"] == {}
    assert run.record["receipt"]["recordingComplete"] is True
    assert run.service.accounts == {}


def test_review_a_request_at_the_deadline_is_capped_to_the_time_that_remains() -> None:
    """`recovery-over-total-wall`: a fixed five-second timeout with 0.01 s left.

    The request returned 200 and the counter reached 603.99 against a 600 s bound. The
    transport now waits only what the phase has left, and the next request is refused
    rather than sent, while the answer already received is still returned. The phase here
    is the cleanup window, which is bounded in its turn.
    """
    clock = _clock()
    budget = shadow.shadow_budget(now=clock.monotonic())
    clock.state["now"] += budget["maxWallSeconds"] - budget["recoveryWallSeconds"]
    enter_recovery(budget, clock.monotonic())
    clock.state["now"] += budget["recoveryWallSeconds"] - 0.01
    timeouts: list[float] = []

    def sender(base, path, body, owner, timeout):
        timeouts.append(timeout)
        clock.sleep(4.0)
        return 200, b"{}"

    with patch.object(shadow, "time", clock):
        status, _ = shadow.post(
            budget,
            "http://127.0.0.1:8123",
            "/accounts:lookup",
            {},
            owner=True,
            sender=sender,
        )
    assert status == 200
    assert timeouts == [pytest.approx(0.01)]
    assert timeouts[0] < shadow.REQUEST_TIMEOUT_SECONDS

    with (
        patch.object(shadow, "time", clock),
        pytest.raises(BudgetExceeded, match="deadline"),
    ):
        shadow.post(
            budget,
            "http://127.0.0.1:8123",
            "/accounts:lookup",
            {},
            owner=True,
            sender=sender,
        )
    assert len(timeouts) == 1
    assert budget["deadlineExceeded"]["recovery"]["limitSeconds"] == 600


def _owned_accounts(service, tracker, count: int) -> None:
    for index in range(count):
        uid = f"u{index}"
        email = owned_email(tracker, index)
        service.accounts[uid] = {
            "email": email,
            "attributes": {},
            "validSince": "0",
        }
        track_account(tracker, uid, email)


def test_review_a_budget_with_room_still_creates_tracks_and_cleans_up() -> None:
    """Control `budget-remaining`: the ordinary path is unchanged."""
    clock = _clock()
    service = _service(clock)
    tracker = new_tracker("b" * 32)
    budget = shadow.shadow_budget(now=clock.monotonic())
    with _driven(service, clock):
        _, body = shadow.post(
            budget,
            "http://127.0.0.1:8123",
            "/accounts:signUp",
            {"email": owned_email(tracker, 0), "password": "fixture"},
        )
        track_account(tracker, body["localId"], owned_email(tracker, 0))
        problems = shadow.cleanup("http://127.0.0.1:8123", budget, tracker)
    assert len(service.sent) == 4
    assert len(tracker["accounts"]) == 1
    assert problems == []
    assert service.accounts == {}


@pytest.mark.parametrize(
    ("condition", "spend"),
    [
        ("request-budget-used", "requests"),
        ("time-budget-used", "wallSeconds"),
    ],
)
def test_review_an_exhausted_budget_now_sends_nothing(
    condition: str, spend: str
) -> None:
    """An exhausted bound created an untracked account before the fix.

    The extra request was sent, its account was created, and `BudgetExceeded` was raised
    before the UID reached the tracker. Nothing may be sent now.
    """
    clock = _clock()
    service = _service(clock)
    tracker = new_tracker("b" * 32)
    budget = shadow.shadow_budget(now=clock.monotonic())
    budget[spend] = (
        budget["maxRequests"]
        if spend == "requests"
        else (budget["maxWallSeconds"] - FIXTURE_LATENCY_SECONDS / 2)
    )
    with _driven(service, clock):
        rows, failure = shadow.collect("http://127.0.0.1:8123", budget, tracker)
        shadow.cleanup("http://127.0.0.1:8123", budget, tracker)
    assert service.sent == []
    assert service.accounts == {}
    assert tracker["accounts"] == {}
    assert rows == {}
    assert failure is not None and "BudgetExceeded" in failure


def test_review_cleanup_on_a_spent_total_deletes_nothing_rather_than_some() -> None:
    """`cleanup-with-exhausted-budget`: one DELETE went out and the rest did not.

    Two of the three accounts were left behind with the first already deleted. With the
    total spent, nothing is sent at all, every account stays in the tracker for recovery
    and the cleanup report says so.
    """
    clock = _clock()
    service = _service(clock)
    tracker = new_tracker("c" * 32)
    budget = shadow.shadow_budget(now=clock.monotonic())
    _owned_accounts(service, tracker, 3)
    budget["requests"] = budget["maxRequests"]
    with _driven(service, clock):
        problems = shadow.cleanup("http://127.0.0.1:8123", budget, tracker)
    assert len(problems) == 3 and all("BudgetExceeded" in problem for problem in problems)
    assert service.sent == []
    assert len(service.accounts) == 3
    report = cleanup_report(tracker)
    assert report["cleanupComplete"] is False
    assert report["remainingAccounts"] == 3


def test_review_cleanup_completes_on_the_reserve_after_the_run_allowance_is_spent() -> (
    None
):
    """The condition the reserve exists for, which no earlier run could reach.

    A run may only spend the observation allowance. Once that is gone, releasing the
    reserve still leaves enough to delete all three accounts and read both keys back.
    """
    clock = _clock()
    service = _service(clock)
    tracker = new_tracker("c" * 32)
    budget = shadow.shadow_budget(now=clock.monotonic())
    _owned_accounts(service, tracker, 3)
    budget["requests"] = request_allowance(budget)
    with _driven(service, clock), pytest.raises(BudgetExceeded):
        shadow.post(
            budget, "http://127.0.0.1:8123", "/accounts:delete", {"localId": "u0"}
        )
    assert service.sent == []

    enter_recovery(budget, clock.monotonic())
    with _driven(service, clock):
        problems = shadow.cleanup("http://127.0.0.1:8123", budget, tracker)
    assert problems == []
    assert len(service.sent) == 9
    assert service.accounts == {}
    assert cleanup_report(tracker)["cleanupComplete"] is True
    assert budget["requests"] <= budget["maxRequests"]
