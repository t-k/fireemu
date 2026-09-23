"""Contract tests for the local shadow's pure parts.

The live shadow is exercised separately against a `fireemu` binary built from this
checkout; these tests cover the decisions that must hold before a process is started.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import credential_shadow as shadow
from credential_cases import control_members, observation_cases
from credential_collector import (
    BudgetExceeded,
    build_receipt,
    claim_set,
    claim_shape,
    cleanup_report,
    enter_recovery,
    mark_deleted,
    new_budget,
    new_tracker,
    owned_email,
    reserve_request,
    subjects_match,
    track_account,
)
from credential_comparator import compare
from credential_plan import BUDGET


def _budget(
    max_requests: int, max_wall_seconds: float, max_cost_usd: float, **fields
) -> dict:
    """A budget anchored where a run anchors its own: the monotonic reading now."""
    fields.setdefault("started_monotonic", time.monotonic())
    return new_budget(max_requests, max_wall_seconds, max_cost_usd, **fields)


def _classes(report: dict) -> dict:
    return {row["caseId"]: row["classification"] for row in report["rows"]}


def test_transport_refuses_a_target_outside_the_loopback_interface() -> None:
    budget = _budget(10, 10, 0.0)
    for base in (
        "http://identitytoolkit.googleapis.com",
        "http://10.0.0.1:9099",
        "http://example.com:80",
    ):
        with pytest.raises(shadow.ShadowError, match="non-loopback"):
            shadow.post(budget, base, "/accounts:signUp", {})
    assert budget["requests"] == 0


def test_loopback_hosts_are_the_only_permitted_targets() -> None:
    assert set(shadow.LOOPBACK_HOSTS) == {"127.0.0.1", "::1"}


def test_custom_token_is_unsigned_and_decodes_to_the_given_payload() -> None:
    payload = {
        "aud": shadow.CUSTOM_TOKEN_AUDIENCE,
        "uid": "u1",
        "claims": {"role": "tester"},
        "iat": 1,
        "exp": 2,
    }
    token = shadow.unsigned_jwt(payload)
    assert token.endswith(".")
    header, body, signature = token.split(".")
    assert signature == ""
    assert json.loads(base64.urlsafe_b64decode(header + "==")) == {
        "alg": "none",
        "typ": "JWT",
    }
    assert (
        json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))) == payload
    )
    assert claim_shape(token)["trustRoot"] == "unsigned-emulator"


def test_error_code_drops_the_trailing_detail_and_tolerates_a_success_body() -> None:
    assert (
        shadow.error_code({"error": {"message": "TOKEN_EXPIRED : credentials revoked"}})
        == "TOKEN_EXPIRED"
    )
    assert (
        shadow.error_code({"error": {"message": "INVALID_DURATION"}})
        == "INVALID_DURATION"
    )
    assert shadow.error_code({"idToken": "x"}) is None
    assert shadow.error_code({"error": "not-an-object"}) is None


def test_a_missing_case_is_recorded_as_not_run_rather_than_passing() -> None:
    rows = [
        {"caseId": case["id"], "status": 0, "errorCode": "NOT_RUN", "assertions": {}}
        for case in observation_cases()
    ]
    agreement = shadow._agreement(rows)
    assert agreement["cases"] == len(observation_cases())
    assert len(agreement["unexpected"]) == len(observation_cases())


def test_agreement_requires_every_declared_assertion_to_hold() -> None:
    rows = []
    for case in observation_cases():
        expected = case["expectedLocal"]
        rows.append(
            {
                "caseId": case["id"],
                "status": expected["status"],
                "errorCode": expected["errorCode"],
                "assertions": {name: True for name in expected["assertions"]},
                **control_members(case),
            }
        )
    assert shadow._agreement(rows)["unexpected"] == []

    for case in observation_cases():
        if not case["expectedLocal"]["assertions"]:
            continue
        weakened = [dict(row) for row in rows]
        for row in weakened:
            if row["caseId"] == case["id"]:
                row["assertions"] = {
                    **row["assertions"],
                    case["expectedLocal"]["assertions"][0]: False,
                }
        problems = shadow._agreement(weakened)["unexpected"]
        assert [item["caseId"] for item in problems] == [case["id"]]
        break


def test_an_unset_assertion_is_not_treated_as_held() -> None:
    rows = [
        {
            "caseId": case["id"],
            "status": case["expectedLocal"]["status"],
            "errorCode": case["expectedLocal"]["errorCode"],
            "assertions": {},
            **control_members(case),
        }
        for case in observation_cases()
    ]
    failing = {item["caseId"] for item in shadow._agreement(rows)["unexpected"]}
    assert failing == {
        case["id"]
        for case in observation_cases()
        if case["expectedLocal"]["assertions"]
    }


def test_the_shadow_never_claims_production() -> None:
    source = (HERE / "credential_shadow.py").read_text()
    assert (
        "googleapis.com/v1" in source
    )  # the local adapter routes on the full host prefix
    assert (
        "https://identitytoolkit.googleapis.com" in source
    )  # the custom-token audience only
    assert '"productionExecuted": False' in source


def test_startup_failure_publishes_only_safe_diagnostic_and_stop_status(tmp_path, monkeypatch):
    binary = tmp_path / "artifact"
    binary.write_bytes(b"fixture")
    binary.chmod(0o700)
    output = tmp_path / "result.json"
    secret = "PRIVATE-STARTUP-DETAIL"

    def fail_start(_binary, _workdir):
        error = RuntimeError(secret)
        error.diagnostics = {"phase": "readiness", "type": "StartupError",
                             "bytes": len(secret), "sha256": hashlib.sha256(secret.encode()).hexdigest()}
        error.shutdown = {"exitCode": -15, "processStopped": True, "remainingChildren": 0,
                          "outputDrainerStopped": True, "failures": []}
        raise error

    monkeypatch.setattr(shadow, "start_daemon", fail_start)
    assert shadow.main(["--binary", str(binary), "--output", str(output)]) == 1
    published = output.read_text()
    record = json.loads(published)
    assert record["startupDiagnostics"] == {"phase": "readiness", "type": "StartupError",
        "bytes": len(secret), "sha256": hashlib.sha256(secret.encode()).hexdigest()}
    assert record["shutdown"]["processStopped"] is True
    assert record["shutdown"]["remainingChildren"] == 0
    assert secret not in published


def test_launch_failure_records_no_process_as_confirmed_noop_shutdown():
    shutdown = {"processStarted": False, "processStopped": True, "exitCode": None,
                "remainingChildren": 0, "outputDrainerStopped": True, "failures": []}
    complete_rows = {}
    for case in observation_cases():
        expected = case["expectedLocal"]
        complete_rows[case["id"]] = {
            "caseId": case["id"], "status": expected["status"],
            "errorCode": expected["errorCode"],
            "assertions": {name: True for name in expected["assertions"]},
            "trustRoot": "unsigned-emulator", **control_members(case),
        }
    record, code = shadow.finish_record(
        rows=complete_rows, tracker=new_tracker("b" * 32), budget=shadow.shadow_budget(),
        failure="OSError: local execution failed", shutdown=shutdown,
        source_binding={"commit": None, "artifactSha256": "a" * 64},
    )
    assert code == 1
    assert "process-cleanup-unconfirmed" not in record["completionIssues"]


# --- cleanup must prove absence, not infer it --------------------------------


def _tracker_with(uid: str, email: str | None) -> dict:
    tracker = new_tracker("a" * 32)
    track_account(tracker, uid, email)
    return tracker


def _stub(responses: list[tuple[int, dict]]):
    calls: list[tuple[str, dict]] = []

    def poster(budget, base, path, body, *, owner=False):
        calls.append((path, body))
        return responses[min(len(calls) - 1, len(responses) - 1)]

    poster.calls = calls
    return poster


def test_an_absent_account_needs_a_200_lookup_with_an_empty_result() -> None:
    tracker = _tracker_with("uid-1", owned_email(_tracker_with("uid-1", None), 0))
    poster = _stub([(200, {}), (200, {"users": []}), (200, {"users": []})])
    shadow.cleanup("http://127.0.0.1:1", _budget(30, 60, 0.0), tracker, poster=poster)
    report = cleanup_report(tracker)
    assert report["cleanupComplete"] is True
    assert report["remainingAccounts"] == 0


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_a_refused_lookup_is_never_read_as_a_completed_cleanup(status: int) -> None:
    email = owned_email(new_tracker("a" * 32), 0)
    tracker = _tracker_with("uid-1", email)
    # A refusal body carries no `users` member; inferring absence from that would
    # report a live account as deleted.
    poster = _stub([(200, {}), (status, {"error": {"message": "PERMISSION_DENIED"}})])
    shadow.cleanup("http://127.0.0.1:1", _budget(30, 60, 0.0), tracker, poster=poster)
    report = cleanup_report(tracker)
    assert report["cleanupComplete"] is False
    assert report["remainingAccounts"] == 1


def test_a_refused_delete_is_never_read_as_a_completed_cleanup() -> None:
    email = owned_email(new_tracker("a" * 32), 0)
    tracker = _tracker_with("uid-1", email)
    poster = _stub([(403, {"error": {"message": "PERMISSION_DENIED"}}), (200, {})])
    shadow.cleanup("http://127.0.0.1:1", _budget(30, 60, 0.0), tracker, poster=poster)
    assert cleanup_report(tracker)["cleanupComplete"] is False


def test_a_lookup_that_still_returns_the_account_is_not_absence() -> None:
    email = owned_email(new_tracker("a" * 32), 0)
    tracker = _tracker_with("uid-1", email)
    poster = _stub([(200, {}), (200, {"users": [{"localId": "uid-1"}]})])
    shadow.cleanup("http://127.0.0.1:1", _budget(30, 60, 0.0), tracker, poster=poster)
    assert cleanup_report(tracker)["cleanupComplete"] is False


def test_an_addressless_account_skips_the_address_lookup_entirely() -> None:
    tracker = _tracker_with("uid-custom", None)
    poster = _stub([(200, {}), (200, {"users": []})])
    shadow.cleanup("http://127.0.0.1:1", _budget(30, 60, 0.0), tracker, poster=poster)
    paths = [path for path, _ in poster.calls]
    assert paths == ["/accounts:delete", "/accounts:lookup"]
    assert cleanup_report(tracker)["cleanupComplete"] is True
    assert cleanup_report(tracker)["addressReadbacks"] == 0


def test_a_cleanup_failure_keeps_the_receipt_uncomparable() -> None:
    email = owned_email(new_tracker("a" * 32), 0)
    tracker = _tracker_with("uid-1", email)
    poster = _stub([(200, {}), (429, {"error": {"message": "RESOURCE_EXHAUSTED"}})])
    shadow.cleanup("http://127.0.0.1:1", _budget(30, 60, 0.0), tracker, poster=poster)
    rows = [
        {"caseId": case["id"], "status": 200, "errorCode": None, "assertions": {}}
        for case in observation_cases()
    ]
    receipt = build_receipt(
        side="local", rows=rows, tracker=tracker, budget=_budget(60, 600, 0.05)
    )
    # The rows were observed, so the recording is complete; the cleanup is not, and that
    # alone is enough to keep the receipt out of a comparison.
    assert receipt["recordingComplete"] is True
    assert receipt["cleanup"]["cleanupComplete"] is False
    assert receipt["cleanup"]["remainingAccounts"] == 1


# --- a stopped run still records what it observed -----------------------------


def test_budget_exhaustion_keeps_the_rows_already_observed() -> None:
    first = observation_cases()[0]["id"]

    def runner(base, budget, tracker, rows):
        rows[first] = {
            "caseId": first,
            "status": 200,
            "errorCode": None,
            "assertions": {},
        }
        raise BudgetExceeded("request budget exhausted")

    rows, failure = shadow.collect(
        "http://127.0.0.1:1",
        _budget(1, 1, 0.0),
        new_tracker("a" * 32),
        runner=runner,
    )
    assert first in rows
    assert failure is not None and "BudgetExceeded" in failure


@pytest.mark.parametrize(
    "error",
    [
        BudgetExceeded("wall-clock budget exhausted"),
        shadow.ShadowError("sign-up failed"),
        ValueError("token is not a three-segment JWT"),
        KeyError("id_token"),
    ],
)
def test_every_stop_condition_is_recorded_rather_than_raised(error: Exception) -> None:
    def runner(base, budget, tracker, rows):
        rows["x"] = {"caseId": "x"}
        raise error

    rows, failure = shadow.collect(
        "http://127.0.0.1:1",
        _budget(5, 5, 0.0),
        new_tracker("a" * 32),
        runner=runner,
    )
    assert rows == {"x": {"caseId": "x"}}
    assert failure is not None and type(error).__name__ in failure


def test_a_stopped_run_writes_a_record_with_the_missing_cases_marked_not_run(
    tmp_path,
) -> None:
    first = observation_cases()[0]["id"]
    partial = {
        first: {"caseId": first, "status": 200, "errorCode": None, "assertions": {}}
    }
    tracker = new_tracker("a" * 32)
    record, exit_code = shadow.finish_record(
        rows=partial,
        tracker=tracker,
        budget=_budget(60, 600, 0.0),
        failure="BudgetExceeded: request budget exhausted",
        shutdown={"exitCode": 0, "processStopped": True, "remainingChildren": 0,
                  "outputDrainerStopped": True, "failures": []},
        source_binding={"commit": None, "artifactSha256": "c" * 64},
    )
    assert exit_code == 1
    assert record["failure"].startswith("BudgetExceeded")
    by_id = {row["caseId"]: row for row in record["receipt"]["rows"]}
    assert by_id[first]["status"] == 200
    assert by_id[observation_cases()[-1]["id"]]["errorCode"] == "NOT_RUN"
    assert len(record["receipt"]["rows"]) == len(observation_cases())
    assert record["receipt"]["recordingComplete"] is False
    assert record["productionExecuted"] is False


def test_the_shadow_budget_cannot_drift_from_the_declared_campaign_budget() -> None:
    budget = shadow.shadow_budget()
    assert budget["maxRequests"] == BUDGET["maxRequests"] == 60
    assert budget["maxWallSeconds"] == BUDGET["maxWallSeconds"]
    # A local run spends nothing, so its cost ceiling is zero rather than the campaign's.
    assert budget["maxCostUsd"] == 0.0
    assert budget["enforced"] is True


# --- an in-memory Identity service the real case run can be driven against -------

SESSION_ISSUER = "https://session.firebase.google.com/demo-app"
TOKEN_ISSUER = "https://securetoken.google.com/demo-app"
COOKIE_MIN_SECONDS = 300
COOKIE_MAX_SECONDS = 1209600
RESERVED_COOKIE_CLAIMS = ("iss", "sub", "aud", "iat", "exp", "auth_time")


def _payload(token: str) -> dict:
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def _refused(code: str) -> tuple[int, dict]:
    return 400, {"error": {"message": code}}


def _service(*, cookie_subject: str | None = None, project: str = "demo-app") -> dict:
    """A minimal in-memory Identity service, enough to drive `run_cases` end to end.

    Every request the declared case list makes is answered here, so the shadow's own
    reasoning is what the resulting rows measure. `cookie_subject` replaces the subject
    a session cookie carries, which is the mutant the subject check must catch.
    """
    state: dict = {
        "now": int(time.time()),
        "accounts": {},
        "sessions": {},
        "sent": [],
        "timeouts": [],
        # Every credential the service ever issued, so a leak scan can look for all
        # of them and not only the sessions that survived the run.
        "issuedSecrets": [],
    }
    token_issuer = f"https://securetoken.google.com/{project}"
    session_issuer = f"https://session.firebase.google.com/{project}"

    def issue(session: dict) -> str:
        account = state["accounts"][session["uid"]]
        claims = {**account["customAttributes"], **session["claims"]}
        state["issuedSecrets"].append(token := shadow.unsigned_jwt(
            {
                "iss": token_issuer,
                "sub": session["uid"],
                "aud": project,
                "firebase": {"sign_in_provider": "custom"},
                "auth_time": session["authTime"],
                "iat": state["now"],
                "exp": state["now"] + 3600,
                **claims,
            }
        ))
        return token

    def start_session(uid: str, claims: dict | None = None) -> dict:
        state["sessionCount"] = state.get("sessionCount", 0) + 1
        refresh_token = f"refresh-{state['sessionCount']}"
        state["issuedSecrets"].append(refresh_token)
        session = {
            "uid": uid,
            "authTime": state["now"],
            "claims": dict(claims or {}),
            "refreshToken": refresh_token,
        }
        state["sessions"][refresh_token] = session
        return session

    def signed_in(session: dict) -> tuple[int, dict]:
        return 200, {
            "localId": session["uid"],
            "idToken": issue(session),
            "refreshToken": session["refreshToken"],
        }

    def revoked(id_token: str) -> bool:
        claims = _payload(id_token)
        account = state["accounts"].get(claims.get("sub"))
        return account is None or claims.get("auth_time", 0) < account["validSince"]

    def create_session_cookie(body: dict) -> tuple[int, dict]:
        if revoked(body["idToken"]):
            return _refused("TOKEN_EXPIRED")
        duration = int(body.get("validDuration", COOKIE_MAX_SECONDS))
        if not COOKIE_MIN_SECONDS <= duration <= COOKIE_MAX_SECONDS:
            return _refused("INVALID_DURATION")
        source = _payload(body["idToken"])
        carried = {
            name: value
            for name, value in source.items()
            if name not in RESERVED_COOKIE_CLAIMS
        }
        return 200, {
            "sessionCookie": shadow.unsigned_jwt(
                {
                    "iss": session_issuer,
                    "sub": cookie_subject or source["sub"],
                    "auth_time": source["auth_time"],
                    "iat": state["now"],
                    "exp": state["now"] + duration,
                    **carried,
                }
            )
        }

    def custom_token_sign_in(body: dict) -> tuple[int, dict]:
        token = _payload(body["token"])
        if token["exp"] < state["now"]:
            return _refused("TOKEN_EXPIRED")
        claims = token.get("claims") or {}
        if any(name in RESERVED_COOKIE_CLAIMS for name in claims):
            return _refused("INVALID_CUSTOM_TOKEN")
        uid = token["uid"]
        is_new = uid not in state["accounts"]
        state["accounts"].setdefault(
            uid, {"email": None, "validSince": 0, "customAttributes": {}}
        )
        status, result = signed_in(start_session(uid, claims))
        return status, {**result, "isNewUser": is_new}

    def sign_up(body: dict) -> tuple[int, dict]:
        uid = f"uid-{len(state['accounts']) + 1}"
        state["accounts"][uid] = {
            "email": body["email"],
            "password": body["password"],
            "validSince": 0,
            "customAttributes": {},
        }
        return signed_in(start_session(uid))

    def sign_in(body: dict) -> tuple[int, dict]:
        for uid, account in state["accounts"].items():
            if account["email"] == body["email"]:
                if account["password"] != body["password"]:
                    return _refused("INVALID_PASSWORD")
                return signed_in(start_session(uid))
        return _refused("EMAIL_NOT_FOUND")

    def drop_sessions(uid: str) -> None:
        """The local strict runtime removes the refresh sessions of a revoked account."""
        for refresh_token, session in list(state["sessions"].items()):
            if session["uid"] == uid:
                del state["sessions"][refresh_token]

    def send_oob_code(body: dict) -> tuple[int, dict]:
        if body.get("requestType") != "PASSWORD_RESET" or body.get("returnOobLink") is not True:
            return _refused("MISSING_REQ_TYPE")
        for uid, account in state["accounts"].items():
            if account["email"] == body["email"]:
                code = f"oob-{len(state.setdefault('oob', {}))}"
                state["oob"][code] = uid
                state["issuedSecrets"].append(code)
                return 200, {"kind": "identitytoolkit#GetOobConfirmationCodeResponse",
                             "email": body["email"], "oobCode": code}
        return _refused("EMAIL_NOT_FOUND")

    def reset_password(body: dict) -> tuple[int, dict]:
        uid = state.get("oob", {}).pop(body.get("oobCode"), None)
        if uid is None:
            return _refused("INVALID_OOB_CODE")
        account = state["accounts"][uid]
        account["password"] = body["newPassword"]
        account["validSince"] = state["now"]
        drop_sessions(uid)
        return 200, {"kind": "identitytoolkit#ResetPasswordResponse",
                     "email": account["email"], "requestType": "PASSWORD_RESET"}

    def refresh(body: dict) -> tuple[int, dict]:
        session = state["sessions"].get(body.get("refresh_token"))
        if session is None:
            return _refused("INVALID_REFRESH_TOKEN")
        return 200, {
            "id_token": issue(session),
            "refresh_token": session["refreshToken"],
        }

    def admin_update(body: dict) -> tuple[int, dict]:
        account = state["accounts"][body["localId"]]
        if "validSince" in body:
            account["validSince"] = int(body["validSince"])
            # An explicit validSince retires the account's refresh sessions locally.
            drop_sessions(body["localId"])
        if "customAttributes" in body:
            account["customAttributes"] = json.loads(body["customAttributes"])
        return 200, {"localId": body["localId"]}

    def admin_lookup(body: dict) -> tuple[int, dict]:
        found = [
            {"localId": uid, "validSince": str(account["validSince"])}
            for uid, account in state["accounts"].items()
            if uid in body.get("localId", [])
            or account["email"] in body.get("email", [])
        ]
        return 200, {"users": found}

    def user_lookup(body: dict) -> tuple[int, dict]:
        if revoked(body["idToken"]):
            return _refused("TOKEN_EXPIRED")
        return 200, {"users": [{"localId": _payload(body["idToken"])["sub"]}]}

    def respond(base: str, path: str, body: dict) -> tuple[int, dict]:
        state["now"] += 1
        if "securetoken" in base:
            return refresh(body)
        name = path.split("?")[0]
        if name == "/accounts:signUp":
            return sign_up(body)
        if name == "/accounts:signInWithPassword":
            return sign_in(body)
        if name == "/accounts:signInWithCustomToken":
            return custom_token_sign_in(body)
        if name == "/accounts:lookup":
            return user_lookup(body) if "key=" in path else admin_lookup(body)
        if name == "/accounts:update":
            return admin_update(body)
        if name == "/accounts:sendOobCode":
            return send_oob_code(body)
        if name == "/accounts:resetPassword":
            return reset_password(body)
        if name == "/accounts:delete":
            state["accounts"].pop(body["localId"], None)
            return 200, {}
        if name == ":createSessionCookie":
            return create_session_cookie(body)
        raise AssertionError(f"the service was asked for an unknown path: {path!r}")

    def sender(
        base: str, path: str, body: dict, owner: bool, timeout: float
    ) -> tuple[int, bytes]:
        state["sent"].append(path or "token")
        state["timeouts"].append(timeout)
        status, parsed = respond(base, path, body)
        return status, json.dumps(parsed).encode()

    state["sender"] = sender
    return state


def _poster(service: dict):
    """Drive the real `shadow.post`, so budget reservation is never mocked away."""

    def poster(budget, base, path, body, *, owner=False):
        return shadow.post(
            budget, base, path, body, owner=owner, sender=service["sender"]
        )

    return poster


@pytest.fixture
def _instant_rest(monkeypatch) -> None:
    monkeypatch.setattr(shadow, "_rest", lambda budget, seconds: None)


# --- the budget is reserved before a request is sent, never charged after ------


def test_no_request_is_sent_once_the_request_budget_is_exhausted() -> None:
    service = _service()
    budget = _budget(2, 60, 0.0)
    for _ in range(2):
        shadow.post(
            budget,
            "http://127.0.0.1:1",
            "/accounts:delete",
            {"localId": "uid-1"},
            sender=service["sender"],
        )
    with pytest.raises(BudgetExceeded, match="request"):
        shadow.post(
            budget,
            "http://127.0.0.1:1",
            "/accounts:delete",
            {"localId": "uid-1"},
            sender=service["sender"],
        )
    assert len(service["sent"]) == 2
    assert budget["requests"] == 2


def test_a_response_already_received_is_never_discarded_by_the_wall_clock_bound(
    monkeypatch,
) -> None:
    service = _service()
    budget = _budget(10, 2, 0.0, started_monotonic=0.0)
    ticks = iter([0.0, 5.0, 5.0])
    monkeypatch.setattr(shadow.time, "monotonic", lambda: next(ticks))
    # The request was sent and paid for, so its result must reach the caller.
    status, _ = shadow.post(
        budget,
        "http://127.0.0.1:1",
        "/accounts:signUp?key=k",
        {"email": "a@b.invalid", "password": "p"},
        sender=service["sender"],
    )
    assert status == 200
    assert budget["wallSeconds"] == 5.0
    with pytest.raises(BudgetExceeded, match="wall"):
        shadow.post(
            budget,
            "http://127.0.0.1:1",
            "/accounts:delete",
            {"localId": "uid-1"},
            sender=service["sender"],
        )
    assert len(service["sent"]) == 1


def test_an_account_created_at_the_budget_edge_is_still_tracked_and_cleaned_up(
    _instant_rest,
) -> None:
    service = _service()
    tracker = new_tracker("b" * 32)
    # One request for the whole run, three held back so cleanup can still complete.
    budget = _budget(4, 600, 0.0, recovery_requests=3, recovery_wall_seconds=60)
    rows, failure = shadow.collect(
        "http://127.0.0.1:1",
        budget,
        tracker,
        runner=lambda base, b, t, r: shadow.run_cases(
            base, b, t, r, poster=_poster(service)
        ),
    )
    assert failure is not None and "BudgetExceeded" in failure
    # The sign-up that spent the last run request created an account; losing it here
    # would leave a live account behind with nothing recording that it exists.
    assert len(tracker["accounts"]) == 1
    assert rows == {}
    assert len(service["sent"]) == 1

    enter_recovery(budget, time.monotonic())
    assert (
        shadow.cleanup("http://127.0.0.1:1", budget, tracker, poster=_poster(service))
        == []
    )
    assert cleanup_report(tracker)["cleanupComplete"] is True
    assert budget["requests"] == 4


def test_the_run_phase_cannot_spend_the_reserve_cleanup_depends_on() -> None:
    budget = _budget(10, 60, 0.0, recovery_requests=4, recovery_wall_seconds=10)
    for _ in range(6):
        reserve_request(budget, time.monotonic())
    with pytest.raises(BudgetExceeded, match="request"):
        reserve_request(budget, time.monotonic())
    enter_recovery(budget, time.monotonic())
    for _ in range(4):
        reserve_request(budget, time.monotonic())
    with pytest.raises(BudgetExceeded, match="request"):
        reserve_request(budget, time.monotonic())


def test_the_shadow_holds_back_the_recovery_reserve_the_manifest_declares() -> None:
    budget = shadow.shadow_budget()
    assert budget["recoveryRequests"] == BUDGET["recoveryRequests"]
    assert budget["recoveryWallSeconds"] == BUDGET["recoveryWallSeconds"]
    assert budget["recoveryRequests"] < budget["maxRequests"]


# --- the session cookie must carry the ID token's own subject -------------------


def _token(claims: dict) -> str:
    return shadow.unsigned_jwt({"iat": 1, "exp": 2, **claims})


def test_two_tokens_naming_the_same_subject_match() -> None:
    assert subjects_match(_token({"sub": "uid-1"}), _token({"sub": "uid-1"})) is True


def test_a_cookie_minted_for_another_account_is_not_a_subject_match() -> None:
    assert subjects_match(_token({"sub": "uid-1"}), _token({"sub": "uid-2"})) is False


def test_a_missing_subject_on_either_side_is_not_a_subject_match() -> None:
    assert subjects_match(_token({"sub": "uid-1"}), _token({})) is False
    assert subjects_match(_token({}), _token({"sub": "uid-1"})) is False
    assert subjects_match(_token({}), _token({})) is False


@pytest.mark.parametrize(
    "subject", [7, 7.5, True, None, "", ["uid-1"], {"id": "uid-1"}]
)
def test_a_subject_that_is_not_a_non_empty_string_is_never_a_match(subject) -> None:
    assert subjects_match(_token({"sub": subject}), _token({"sub": subject})) is False


def test_a_malformed_token_is_not_a_subject_match_rather_than_an_error() -> None:
    assert subjects_match("not-a-jwt", _token({"sub": "uid-1"})) is False
    assert subjects_match(_token({"sub": "uid-1"}), "a.b.c") is False


def test_the_subject_check_publishes_only_the_boolean() -> None:
    source = (HERE / "credential_collector.py").read_text()
    assert "def subjects_match" in source
    assert "sub" not in claim_shape(_token({"sub": "uid-1"}))["claimValues"]


# --- the declared cases run end to end against a service ------------------------


def _run(service: dict, tracker: dict) -> dict:
    budget = _budget(
        BUDGET["maxRequests"],
        BUDGET["maxWallSeconds"],
        0.0,
        recovery_requests=BUDGET["recoveryRequests"],
        recovery_wall_seconds=BUDGET["recoveryWallSeconds"],
    )
    rows: dict = {}
    shadow.run_cases(
        "http://127.0.0.1:1", budget, tracker, rows, poster=_poster(service)
    )
    return rows


def test_every_declared_case_holds_against_a_service_that_behaves(
    _instant_rest,
) -> None:
    rows = _run(_service(), new_tracker("c" * 32))
    assert set(rows) == {case["id"] for case in observation_cases()}
    assert shadow._agreement(list(rows.values()))["unexpected"] == []


def test_a_cookie_minted_for_a_different_subject_fails_the_real_case_run(
    _instant_rest,
) -> None:
    rows = _run(_service(cookie_subject="uid-impostor"), new_tracker("c" * 32))
    composition = rows["session-cookie-claim-composition"]
    assert composition["status"] == 200
    assert composition["assertions"]["cookieSubjectMatchesIdToken"] is False
    unexpected = shadow._agreement(list(rows.values()))["unexpected"]
    assert [item["caseId"] for item in unexpected] == [
        "session-cookie-claim-composition"
    ]


# --- a stopped run is never comparable, whatever the receipt claims -------------


def _expected_row(case: dict, *, trust_root: str = "unsigned-emulator") -> dict:
    expected = case["expectedLocal"]
    assertions = {name: True for name in expected["assertions"]}
    row = {
        "caseId": case["id"],
        "status": expected["status"],
        "errorCode": expected["errorCode"],
        "assertions": assertions,
        "trustRoot": trust_root,
        **control_members(case),
    }
    if (
        assertions.get("idTokenReturned") is True
        or assertions.get("sessionCookieReturned") is True
        or case["group"] == "claim-precedence"
    ):
        row["claims"] = claim_set(
            claim_shape(
                shadow.unsigned_jwt(
                    {
                        "aud": "fixture-claims",
                        "sub": "fixture-user",
                        "auth_time": 100,
                        "iat": 102,
                        "exp": 3702,
                        "firebase": {
                            "identities": {},
                            "sign_in_provider": "password",
                        },
                    }
                )
            )
        )
    if case["nondeterminism"] == "SAME_SECOND_BOUNDARY":
        row["boundaryPinned"] = False
    return row


def _cleaned_tracker() -> dict:
    tracker = new_tracker("a" * 32)
    track_account(tracker, "uid-1", owned_email(tracker, 0))
    mark_deleted(tracker, "uid-1", uid_absent=True, email_absent=True)
    return tracker


def _stopped_local_receipt() -> dict:
    """The receipt a run that stopped after one case actually produces."""
    first = observation_cases()[0]
    record, exit_code = shadow.finish_record(
        rows={first["id"]: _expected_row(first)},
        tracker=_cleaned_tracker(),
        budget=_budget(60, 600, 0.0),
        failure="BudgetExceeded: request budget exhausted",
        shutdown={"exitCode": 0, "processStopped": True, "remainingChildren": 0,
                  "outputDrainerStopped": True, "failures": []},
        source_binding={"commit": "a" * 40, "artifactSha256": "c" * 64},
    )
    assert exit_code == 1
    return record["receipt"]


def _full_production_receipt() -> dict:
    return build_receipt(
        side="production",
        rows=[_expected_row(case, trust_root="signed") for case in observation_cases()],
        tracker=_cleaned_tracker(),
        budget=_budget(60, 600, 0.05),
        source_binding={"commit": "a" * 40, "artifactSha256": "d" * 64},
        production_executed=True,
    )


def test_a_row_the_run_never_reached_is_not_a_recorded_observation() -> None:
    receipt = _stopped_local_receipt()
    # Cleanup succeeded; the recording did not. The two are separate facts.
    assert receipt["cleanup"]["cleanupComplete"] is True
    assert receipt["recordingComplete"] is False


def test_a_stopped_run_is_refused_by_the_comparator_end_to_end() -> None:
    report = compare(_stopped_local_receipt(), _full_production_receipt())
    assert report["productionCompared"] is False
    assert report["reason"] == "incomplete-recording"
    assert set(_classes(report).values()) == {"INDETERMINATE"}


def test_a_receipt_claiming_a_complete_recording_cannot_pass_off_unrun_rows() -> None:
    local = _stopped_local_receipt()
    # The comparator re-derives observation from each row; a caller boolean is not
    # evidence, so forcing this member cannot turn a case nobody ran into a MATCH.
    local["recordingComplete"] = True
    classes = _classes(compare(local, _full_production_receipt()))
    first = observation_cases()[0]["id"]
    assert classes[first] == "MATCH"
    assert {value for case_id, value in classes.items() if case_id != first} == {
        "INDETERMINATE"
    }


def test_a_complete_recording_with_a_failed_cleanup_is_refused_for_the_cleanup() -> (
    None
):
    tracker = new_tracker("a" * 32)
    track_account(tracker, "uid-1", owned_email(tracker, 0))
    mark_deleted(tracker, "uid-1", uid_absent=True, email_absent=False)
    local = build_receipt(
        side="local",
        rows=[_expected_row(case) for case in observation_cases()],
        tracker=tracker,
        budget=_budget(60, 600, 0.0),
        source_binding={"commit": "a" * 40, "artifactSha256": "c" * 64},
    )
    assert local["recordingComplete"] is True
    assert local["cleanup"]["cleanupComplete"] is False
    assert compare(local, _full_production_receipt())["reason"] == "incomplete-cleanup"
