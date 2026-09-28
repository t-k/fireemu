"""Local shadow of the AUTH-CREDENTIAL campaign against a running `fireemu`.

This runs every declared case against a locally owned `fireemu` process and records
what the local runtime actually does. It is local evidence only: it contacts no
production service, and a shadow row is never a production comparison.

The transport refuses any host but the loopback interface, so a mistyped target cannot
leave the machine. Credential material never reaches argv or the record: tokens live in
local variables, and only decoded non-secret claim shapes are written out.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
from pathlib import Path
from typing import Any

from credential_cases import CAMPAIGN_ID, observation_cases
from credential_process import start_daemon, stop_daemon
import credential_wire
import credential_responsibility as responsibility
from credential_collector import (
    collector_binding,
    BudgetExceeded,
    build_receipt,
    charge_elapsed,
    cleanup_report,
    check_deadline,
    claim_set,
    claim_shape,
    custom_signin_response_uid,
    id_token_matches_account,
    lookup_matches_account,
    enter_recovery,
    mark_deleted,
    new_budget,
    new_tracker,
    owned_email,
    remaining_seconds,
    reserve_request,
    subjects_match,
    track_account,
)
from credential_plan import BUDGET

LOOPBACK_HOSTS = credential_wire.LOOPBACK_HOSTS
API_KEY = "local-shadow-key"
OWNER = "Bearer owner"
PROJECT = "demo-app"
PASSWORD = "shadow-Passw0rd!"
RESET_PASSWORD = "shadow-Reset-Passw0rd!"
CUSTOM_TOKEN_ISSUER = "shadow@example.com"
CUSTOM_TOKEN_AUDIENCE = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit"
REQUEST_TIMEOUT_SECONDS = 5


class ShadowError(Exception):
    """The shadow could not carry out a step it needs to record a row."""


# --- transport ---------------------------------------------------------------------


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unsigned_jwt(payload: dict[str, Any]) -> str:
    """Build the unsigned custom token the local runtime accepts."""
    header = _b64url(
        json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header}.{body}."


CUSTOM_TOKEN_KINDS = ("developer", "reserved", "expired")


def custom_token_payload(kind: str, issuer: str, uid: str, now: int) -> dict[str, Any]:
    """The custom-token payload each signing-dependent case uses.

    The same builder serves the local unsigned signer and a production signer, so
    the two sides sign the same claims: developer claims for the ordinary sign-in, a
    reserved claim name for the refused one, and an expired lifetime.
    """
    if kind == "developer":
        claims, iat = {"role": "tester"}, now
    elif kind == "reserved":
        claims, iat = {"sub": "elevated"}, now
    elif kind == "expired":
        claims, iat = {}, now - 7200
    else:
        raise ValueError("unknown custom token kind")
    return {
        "aud": CUSTOM_TOKEN_AUDIENCE,
        "iss": issuer,
        "sub": issuer,
        "uid": uid,
        "claims": claims,
        "iat": iat,
        "exp": iat + 3600,
    }


def unsigned_signer(kind: str, payload: dict[str, Any]) -> str:
    """The local signer: the payload as an unsigned token, whatever its kind."""
    if kind not in CUSTOM_TOKEN_KINDS:
        raise ValueError("unknown custom token kind")
    return unsigned_jwt(payload)


def _send_over_http(
    base: str, path: str, body: dict[str, Any], owner: bool, timeout: float
) -> tuple[int, bytes]:
    """One fixed local worker; the parent owns the whole-response deadline."""
    try:
        return credential_wire.request(credential_wire.target(base, path), body, owner, timeout)
    except ValueError:
        raise ShadowError("local credential HTTP request failed") from None


def post(
    budget: dict[str, Any],
    base: str,
    path: str,
    body: dict[str, Any],
    *,
    owner: bool = False,
    sender: Any = None,
) -> tuple[int, dict[str, Any]]:
    """POST JSON to the owned local daemon and return the status and parsed body.

    The budget is reserved before anything is sent, so an exhausted bound costs nothing.
    The transport waits no longer than the phase has left, because a request started just
    inside the deadline must not be what carries the run past it. The wall time is
    charged afterwards and never raises: by then the response exists, and discarding it
    could lose an account this run just created.
    """
    try:
        credential_wire.target(base, path)
        if type(owner) is not bool or not isinstance(body, dict):
            raise ValueError("typed local request required")
    except ValueError:
        raise ShadowError("refusing a non-loopback or malformed target/request") from None
    started = time.monotonic()
    allowance = reserve_request(budget, started)
    timeout = min(REQUEST_TIMEOUT_SECONDS, allowance)
    try:
        status, raw = (sender or _send_over_http)(base, path, body, owner, timeout)
    finally:
        # Do not discard a received ACK because later elapsed accounting failed.
        charge_elapsed(budget, time.monotonic() - started)
    try:
        if type(status) is not int or not 200 <= status <= 599 or 300 <= status < 400:
            raise ValueError("invalid HTTP status")
        parsed = credential_wire.response_body(raw)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ShadowError("response was not a usable local JSON object") from None
    return status, parsed


def error_code(body: dict[str, Any]) -> str | None:
    """Extract the Identity Toolkit error code, dropping any trailing detail."""
    message = (
        body.get("error", {}).get("message")
        if isinstance(body.get("error"), dict)
        else None
    )
    return message.split(":")[0].strip() if isinstance(message, str) else None


# --- environment ---------------------------------------------------------------------


def local_environment() -> dict[str, Any]:
    """What the case runner needs to know about the service it runs against.

    The runner is the same on both sides; only these values differ. The local values
    are constants of the owned daemon. A production environment supplies the oracle
    project, its Web API key, per-run passwords and an RS256 signer, and it names its
    endpoints explicitly because the three services live on separate origins there.
    The signer is a callable from a custom-token payload to a compact token; the local
    runtime accepts an unsigned one, production requires a service-account signature.
    """
    return {
        "project": PROJECT,
        "apiKey": API_KEY,
        "password": PASSWORD,
        "resetPassword": RESET_PASSWORD,
        "customTokenIssuer": CUSTOM_TOKEN_ISSUER,
        "signer": unsigned_signer,
        "trustRoot": "unsigned-emulator",
        "endpoints": None,
        # Whether custom tokens can be minted. Without it the signing-dependent
        # groups are skipped and their rows are recorded as not run.
        "signing": True,
    }


#: The reason a signing-dependent row carries when the run had no signer.
SIGNING_ABSENT_REASON = "signing capability absent"


def _endpoints(base: str, environment: dict[str, Any]) -> dict[str, str]:
    """The identity, secure-token and admin bases; derived from `base` when not named."""
    declared = environment.get("endpoints")
    if declared is not None:
        if set(declared) != {"identity", "secure", "admin"}:
            raise ShadowError("typed endpoints required")
        return dict(declared)
    identity = f"{base}/identitytoolkit.googleapis.com/v1"
    return {
        "identity": identity,
        "secure": f"{base}/securetoken.googleapis.com/v1/token?key={environment['apiKey']}",
        "admin": f"{identity}/projects/{environment['project']}",
    }


# --- case execution ----------------------------------------------------------------


def _row(
    case_id: str,
    status: int,
    body: dict[str, Any],
    assertions: dict[str, bool],
    **extra: Any,
) -> dict[str, Any]:
    return {
        "caseId": case_id,
        "status": status,
        "errorCode": error_code(body),
        "assertions": assertions,
        "trustRoot": "unsigned-emulator",
        **extra,
    }


def _claims(shape: dict[str, Any] | None) -> dict[str, Any] | None:
    """The claim set a row records for an issued token, or None when none was issued."""
    return None if shape is None else claim_set(shape)


def _rest(budget: dict[str, Any], seconds: float) -> None:
    """Wait for real time to pass, named so a test can drive a run without waiting.

    Waiting spends the campaign's time exactly as a request does, so the wait stops at
    the phase's deadline and a wait that reaches it opens no further observation.
    """
    time.sleep(max(0.0, min(seconds, remaining_seconds(budget, time.monotonic()))))
    check_deadline(budget, time.monotonic())


def _sleep_to_next_second(budget: dict[str, Any]) -> None:
    _rest(budget, 1.05 - (time.time() % 1))


def _track_custom_signin(
    tracker: dict[str, Any],
    intent: str,
    status: int,
    body: dict[str, Any],
    *,
    project: str,
    requested_uid: str,
) -> str:
    """Track the admitted response, deriving identity from its ID-token subject."""
    if status != 200:
        raise ShadowError(f"custom-token sign-in failed: {error_code(body)}")
    uid = custom_signin_response_uid(
        status, body, project=project, requested_uid=requested_uid
    )
    if uid is None:
        raise ShadowError("custom sign-in creation status unconfirmed")
    if body["isNewUser"] is False:
        responsibility.resolve(tracker, intent, uid, created=False)
        raise ShadowError("custom sign-in reused an account not owned by this run")
    track_account(tracker, uid, None)
    responsibility.resolve(tracker, intent, uid, created=True)
    return uid


def _boundary_readback_second(status: Any, body: Any, uid: str) -> int | str:
    """Read this default-namespace account's second, not another result's number.

    Keep the received int64 representation in diagnostics. A valid but different
    second is still an unpinned observation; an invalid readback is not evidence
    of timing nondeterminism. This grants no account ownership or cleanup right.
    """
    failure = "same-second readback did not confirm the requested account"
    if (
        type(status) is not int or status != 200
        or type(body) is not dict or "error" in body
        or type(uid) is not str or not uid
    ):
        raise ShadowError(failure)
    users = body.get("users")
    if (
        type(users) is not list or len(users) != 1
        or type(users[0]) is not dict or "error" in users[0]
        or type(users[0].get("localId")) is not str
        or users[0]["localId"] != uid
        or users[0].get("tenantId") not in (None, "")
    ):
        raise ShadowError(failure)
    stored = users[0].get("validSince")
    if not (
        type(stored) is int
        or (type(stored) is str and len(stored) <= 32
            and re.fullmatch(r"-?[0-9]+", stored) is not None)
    ):
        raise ShadowError("same-second readback has no valid int64 second")
    if not -(1 << 63) <= int(stored) < (1 << 63):
        raise ShadowError("same-second readback has no valid int64 second")
    return stored


def _require_account_update_ack(status: Any, body: Any, uid: str) -> None:
    """A failed setup cannot establish the next credential observation's premise.

    This is an ACK check, not state readback or ownership evidence. Do not
    require optional response fields or echoed settings, but reject an explicit
    conflicting identity. Raw responses, UIDs and credentials stay out of errors.
    """
    if (
        type(status) is not int or status != 200
        or type(body) is not dict or "error" in body
        or ("localId" in body and (
            type(body["localId"]) is not str or body["localId"] != uid
        ))
    ):
        raise ShadowError("account-update setup acknowledgement unconfirmed")


def _revocation_session_shape(
    session: dict[str, Any], *, uid: str, project: str
) -> dict[str, Any]:
    """Bind a revocation specimen before deriving or testing this account's cutoff.

    The existing response-identity check is not signature verification or ownership
    authority. A token for another account/project cannot place this boundary;
    do not mutate the cutoff or send the specimen's lookup in that case.
    """
    if (
        type(session) is not dict or "error" in session
        or ("localId" in session and session["localId"] != uid)
        or not id_token_matches_account(session.get("idToken"), uid=uid, project=project)
    ):
        raise ShadowError("revocation setup token did not identify the requested account")
    shape = claim_shape(session["idToken"])
    if "auth_time" not in shape["times"]:
        raise ShadowError("revocation setup token has no integer auth_time")
    return shape


def run_cases(
    base: str,
    budget: dict[str, Any],
    tracker: dict[str, Any],
    rows: dict[str, dict[str, Any]],
    poster: Any = None,
    environment: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Run every declared case, filling `rows` as it goes.

    The caller owns `rows` so that a stop condition part-way through still leaves every
    row observed so far in the caller's hands, which is what the failure rehearsal
    promises for an exhausted budget. `environment` names the service the run targets;
    the local daemon's values are the default, and a production run supplies its own.
    """
    send = poster or post
    env = local_environment() if environment is None else dict(environment)
    endpoints = _endpoints(base, env)
    identity, secure, admin = endpoints["identity"], endpoints["secure"], endpoints["admin"]
    key = env["apiKey"]
    password, trust_root = env["password"], env["trustRoot"]
    signer, issuer = env["signer"], env["customTokenIssuer"]

    def row(case_id: str, status: int, body: dict[str, Any], assertions: dict[str, bool], **extra: Any) -> dict[str, Any]:
        return _row(case_id, status, body, assertions, trustRoot=trust_root, **extra)

    def signup(index: int) -> dict[str, Any]:
        email = owned_email(tracker, index)
        intent = responsibility.begin(tracker, "signup", email=email)
        status, body = send(
            budget,
            identity,
            f"/accounts:signUp?key={key}",
            {"email": email, "password": password, "returnSecureToken": True},
        )
        if status != 200:
            raise ShadowError(f"sign-up failed: {error_code(body)}")
        uid = body.get("localId")
        if ("error" in body or type(uid) is not str or not uid or len(uid) > 128
                or body.get("email", email) != email):
            raise ShadowError("sign-up acknowledgement did not identify the intended account")
        track_account(tracker, uid, email)
        responsibility.resolve(tracker, intent, uid, created=True)
        return body

    def signin(email: str, secret: str = password) -> dict[str, Any]:
        status, body = send(
            budget,
            identity,
            f"/accounts:signInWithPassword?key={key}",
            {"email": email, "password": secret, "returnSecureToken": True},
        )
        if status != 200:
            raise ShadowError(f"sign-in failed: {error_code(body)}")
        return body

    def lookup(id_token: str) -> tuple[int, dict[str, Any]]:
        return send(
            budget, identity, f"/accounts:lookup?key={key}", {"idToken": id_token}
        )

    def refresh(refresh_token: str) -> tuple[int, dict[str, Any]]:
        return send(
            budget,
            secure,
            "",
            {"grant_type": "refresh_token", "refresh_token": refresh_token},
        )

    def custom_token(kind: str, uid: str) -> str:
        return signer(kind, custom_token_payload(kind, issuer, uid, int(time.time())))

    def control_id_token(
        body: Any, id_field: str, refresh_field: str, reference_token: str
    ) -> str:
        """Check an admitted response's control identity, not its JWT signature.

        HTTP 200 alone does not prove a fresh exchange on this account. Keep
        the tokens private and grant no ownership, cleanup or authentication
        authority here. An unusable control must not place a refusal boundary.
        """
        failure = "fresh-session control did not confirm the intended account"
        if type(body) is not dict or "error" in body:
            raise ShadowError(failure)
        token, refresh_value = body.get(id_field), body.get(refresh_field)
        if any(
            type(value) is not str or not 0 < len(value) <= 8192
            for value in (token, refresh_value)
        ):
            raise ShadowError(failure)
        try:
            shape = claim_shape(token, reveal=("aud",))
        except (ValueError, TypeError):
            raise ShadowError(failure) from None
        if (
            not subjects_match(reference_token, token)
            or shape["issuer"] != f"https://securetoken.google.com/{env['project']}"
            or shape["claimValues"].get("aud") != env["project"]
            or shape["firebase"] is None
            or "tenant" in shape["firebase"]["claimNames"]
        ):
            raise ShadowError(failure)
        return token

    def fresh_control(
        email: str, reference_token: str, secret: str = password
    ) -> dict[str, Any]:
        """Exchange a fresh session of the same default-namespace account."""
        fresh = signin(email, secret)
        fresh_token = control_id_token(fresh, "idToken", "refreshToken", reference_token)
        status, body = refresh(fresh["refreshToken"])
        if status == 200:
            control_id_token(body, "id_token", "refresh_token", fresh_token)
        # A real refusal is still data; do not turn it into a synthetic success.
        return {"status": status, "errorCode": error_code(body)}

    # The refresh-refusal group runs last on both paths, so it is a closure over
    # the sessions the earlier groups established.
    state: dict[str, Any] = {}

    def _refresh_refusal_cases() -> None:
        first_email, first_refresh_token = state["firstEmail"], state["firstRefresh"]
        revoked, revoked_email, later, later_shape = (
            state["revoked"], state["revokedEmail"], state["later"], state["laterShape"]
        )
        # --- refresh refusal class (TP-AUTH-C-02) --------------------------------
        # An out-of-band reset on the first account: the code is returned to the
        # privileged caller rather than mailed, the password is replaced, and the
        # pre-reset refresh token is exchanged. A fresh sign-in with the new password
        # is exchanged once more as the row's control.
        status, body = send(
            budget,
            admin,
            "/accounts:sendOobCode",
            {"requestType": "PASSWORD_RESET", "email": first_email, "returnOobLink": True},
            owner=True,
        )
        oob_code = body.get("oobCode")
        if status != 200 or type(oob_code) is not str or not oob_code:
            raise ShadowError(f"privileged reset code request failed: {error_code(body)}")
        status, body = send(
            budget,
            identity,
            f"/accounts:resetPassword?key={key}",
            {"oobCode": oob_code, "newPassword": env["resetPassword"]},
        )
        if status != 200:
            raise ShadowError(f"password reset failed: {error_code(body)}")
        _rest(budget, 1)
        status, body = refresh(first_refresh_token)
        rows["refresh-after-password-reset-rejected"] = row(
            "refresh-after-password-reset-rejected",
            status,
            body,
            {},
        )
        # Preserve the received subject response before the follow-up control.
        # A failed control stays absent and cannot establish this comparison.
        rows["refresh-after-password-reset-rejected"]["freshSessionRefresh"] = fresh_control(
            first_email, state["firstIdToken"], env["resetPassword"]
        )

        # An explicit administrative validSince on the second account, set two whole
        # seconds after the newest session's own auth_time, then that session's refresh
        # token is exchanged; a fresh sign-in is exchanged once more as the control.
        _rest(budget, 2)
        explicit_second = later_shape["times"]["auth_time"] + 2
        status, body = send(
            budget,
            admin,
            "/accounts:update",
            {"localId": revoked["localId"], "validSince": str(explicit_second)},
            owner=True,
        )
        # A refused or malformed setup ACK is not a revocation observation.
        # The requested second is recorded; an ACK alone is not state readback.
        _require_account_update_ack(status, body, revoked["localId"])
        status, body = refresh(later["refreshToken"])
        rows["refresh-after-explicit-valid-since-rejected"] = row(
            "refresh-after-explicit-valid-since-rejected",
            status,
            body,
            {},
            diagnostics={
                "authTime": later_shape["times"]["auth_time"],
                "validSince": explicit_second,
            },
        )
        rows["refresh-after-explicit-valid-since-rejected"]["freshSessionRefresh"] = fresh_control(
            revoked_email, revoked["idToken"]
        )

    # --- refresh -------------------------------------------------------------
    first = signup(0)
    first_email = owned_email(tracker, 0)
    base_shape = claim_shape(first["idToken"])
    _rest(budget, 2)
    status, body = refresh(first["refreshToken"])
    refreshed = claim_shape(body["id_token"]) if status == 200 else None
    rows["refresh-preserves-auth-time"] = row(
        "refresh-preserves-auth-time",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "idTokenReturned": bool(body.get("id_token")),
            "refreshTokenReturned": bool(body.get("refresh_token")),
            "idTokenMatchesAccount": bool(
                status == 200 and id_token_matches_account(
                    body.get("id_token"), uid=first["localId"], project=env["project"]
                )
            ),
            "authTimePreserved": bool(
                refreshed
                and refreshed["times"]["auth_time"] == base_shape["times"]["auth_time"]
            ),
            "iatAdvanced": bool(
                refreshed and refreshed["times"]["iat"] > base_shape["times"]["iat"]
            ),
            "expIsIatPlusHour": bool(
                refreshed
                and refreshed["times"]["exp"] - refreshed["times"]["iat"] == 3600
            ),
        },
        claims=_claims(refreshed),
        diagnostics={
            "signIn": base_shape["times"],
            "refreshed": refreshed["times"] if refreshed else None,
        },
    )
    first_refresh_token = body.get("refresh_token", first["refreshToken"])
    _rest(budget, 1)
    status, body = refresh(first_refresh_token)
    second = claim_shape(body["id_token"]) if status == 200 else None
    rows["refresh-repeat-preserves-auth-time"] = row(
        "refresh-repeat-preserves-auth-time",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "idTokenReturned": bool(body.get("id_token")),
            "refreshTokenReturned": bool(body.get("refresh_token")),
            "idTokenMatchesAccount": bool(
                status == 200 and id_token_matches_account(
                    body.get("id_token"), uid=first["localId"], project=env["project"]
                )
            ),
            "authTimePreserved": bool(
                second
                and second["times"]["auth_time"] == base_shape["times"]["auth_time"]
            ),
            "iatAdvanced": bool(
                second
                and refreshed
                and second["times"]["iat"] > refreshed["times"]["iat"]
            ),
        },
        claims=_claims(second),
        diagnostics={
            "signIn": base_shape["times"],
            "refreshed": second["times"] if second else None,
        },
    )
    first_refresh_token = body.get("refresh_token", first_refresh_token)
    state.update(
        firstEmail=first_email, firstRefresh=first_refresh_token,
        firstIdToken=first["idToken"],
    )
    status, body = refresh("rt1.0.0.demo-app.unissued0000000000000")
    rows["refresh-unknown-token-rejected"] = row(
        "refresh-unknown-token-rejected", status, body, {}
    )

    # --- revocation ----------------------------------------------------------
    revoked = signup(1)
    revoked_email = owned_email(tracker, 1)
    revoked_shape = _revocation_session_shape(
        revoked, uid=revoked["localId"], project=env["project"]
    )
    valid_since = revoked_shape["times"]["auth_time"] + 2
    setup_status, setup_body = send(
        budget,
        admin,
        "/accounts:update",
        {"localId": revoked["localId"], "validSince": str(valid_since)},
        owner=True,
    )
    _require_account_update_ack(setup_status, setup_body, revoked["localId"])
    status, body = lookup(revoked["idToken"])
    rows["revocation-older-session-rejected"] = row(
        "revocation-older-session-rejected", status, body, {}
    )

    # Pin the boundary from server-reported values: sign in, read the token's own
    # auth_time back, set validSince to exactly that whole second and confirm the
    # readback. Without all three the row is not a boundary observation.
    _rest(budget, 2)
    _sleep_to_next_second(budget)
    boundary = signin(revoked_email)
    boundary_shape = _revocation_session_shape(
        boundary, uid=revoked["localId"], project=env["project"]
    )
    boundary_second = boundary_shape["times"]["auth_time"]
    setup_status, setup_body = send(
        budget,
        admin,
        "/accounts:update",
        {"localId": revoked["localId"], "validSince": str(boundary_second)},
        owner=True,
    )
    _require_account_update_ack(setup_status, setup_body, revoked["localId"])
    read_status, read_back = send(
        budget, admin, "/accounts:lookup", {"localId": [revoked["localId"]]}, owner=True
    )
    stored = _boundary_readback_second(read_status, read_back, revoked["localId"])
    pinned = int(stored) == boundary_second
    status, body = lookup(boundary["idToken"])
    rows["revocation-same-second-session"] = row(
        "revocation-same-second-session",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "boundaryPinnedFromServerValues": pinned,
            "lookupMatchesAccount": lookup_matches_account(
                status, body, uid=revoked["localId"]
            ),
        },
        boundaryPinned=pinned,
        boundarySeconds={"authTime": boundary_second, "validSince": stored},
    )

    _rest(budget, 2)
    later = signin(revoked_email)
    later_shape = _revocation_session_shape(
        later, uid=revoked["localId"], project=env["project"]
    )
    status, body = lookup(later["idToken"])
    rows["revocation-newer-session-accepted"] = row(
        "revocation-newer-session-accepted",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "idTokenReturned": bool(later.get("idToken")),
            "lookupMatchesAccount": lookup_matches_account(
                status, body, uid=revoked["localId"]
            ),
        },
        claims=_claims(later_shape),
    )
    state.update(revoked=revoked, revokedEmail=revoked_email, later=later, laterShape=later_shape)

    if env.get("signing", True) is not True:
        # No signer: the custom-token, session-cookie and claim-precedence groups
        # cannot run, so the runner continues with the groups that need none.
        _refresh_refusal_cases()
        return rows

    # --- custom token --------------------------------------------------------
    custom_uid = f"custom-{tracker['nonce']}"
    custom = custom_token("developer", custom_uid)
    intent = responsibility.begin(tracker, "custom-signin", requested_uid=custom_uid)
    status, body = send(
        budget,
        identity,
        f"/accounts:signInWithCustomToken?key={key}",
        {"token": custom, "returnSecureToken": True},
    )
    custom_uid = _track_custom_signin(
        tracker,
        intent,
        status,
        body,
        project=env["project"],
        requested_uid=custom_uid,
    )
    custom_session = body
    custom_shape = claim_shape(body["idToken"], reveal=("role",))
    rows["custom-token-developer-claims-present"] = row(
        "custom-token-developer-claims-present",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "idTokenReturned": bool(body.get("idToken")),
            "refreshTokenReturned": bool(body.get("refreshToken")),
            "developerClaimPresent": custom_shape["claimValues"].get("role")
            == "tester",
        },
        claims=_claims(custom_shape),
    )
    reserved = custom_token("reserved", custom_uid)
    status, body = send(
        budget,
        identity,
        f"/accounts:signInWithCustomToken?key={key}",
        {"token": reserved, "returnSecureToken": True},
    )
    rows["custom-token-reserved-claim-rejected"] = row(
        "custom-token-reserved-claim-rejected", status, body, {}
    )
    expired = custom_token("expired", custom_uid)
    status, body = send(
        budget,
        identity,
        f"/accounts:signInWithCustomToken?key={key}",
        {"token": expired, "returnSecureToken": True},
    )
    rows["custom-token-expired-rejected"] = row(
        "custom-token-expired-rejected", status, body, {}
    )

    # --- session cookies -----------------------------------------------------
    cookie_token = custom_session["idToken"]
    cookie_source = claim_shape(cookie_token, reveal=("role",))
    for case_id, duration in (
        ("session-cookie-default-duration", None),
        ("session-cookie-min-duration-accepted", 300),
        ("session-cookie-below-min-rejected", 299),
        ("session-cookie-max-duration-accepted", 1209600),
        ("session-cookie-above-max-rejected", 1209601),
        ("session-cookie-claim-composition", 3600),
    ):
        payload: dict[str, Any] = {"idToken": cookie_token}
        if duration is not None:
            payload["validDuration"] = str(duration)
        status, body = send(budget, admin, ":createSessionCookie", payload, owner=True)
        cookie = (
            claim_shape(body["sessionCookie"], reveal=("role", "iss"))
            if status == 200 and body.get("sessionCookie")
            else None
        )
        lifetime = cookie["times"]["exp"] - cookie["times"]["iat"] if cookie else None
        rows[case_id] = row(
            case_id,
            status,
            body,
            {
                "sessionCookieReturned": cookie is not None,
                "cookieLifetimeIsTwoWeeks": lifetime == 1209600,
                "cookieLifetimeMatchesRequest": lifetime == duration,
                "cookieIssuerIsSessionIssuer": bool(
                    cookie
                    and cookie["issuer"]
                    == f"https://session.firebase.google.com/{env['project']}"
                ),
                # The subject itself is an account identifier and stays out of the
                # record; a cookie minted for another account must fail here.
                "cookieSubjectMatchesIdToken": cookie is not None
                and subjects_match(cookie_token, body["sessionCookie"]),
                "cookieAuthTimePreserved": bool(
                    cookie
                    and cookie["times"].get("auth_time")
                    == cookie_source["times"]["auth_time"]
                ),
                "developerClaimPresent": bool(
                    cookie and cookie["claimValues"].get("role") == "tester"
                ),
            },
            claims=_claims(cookie),
        )
        # Only the assertions the case declares are reported.
        declared = set(
            next(c for c in observation_cases() if c["id"] == case_id)["expectedLocal"][
                "assertions"
            ]
        )
        rows[case_id]["assertions"] = {
            k: v for k, v in rows[case_id]["assertions"].items() if k in declared
        }

    status, body = send(
        budget,
        admin,
        ":createSessionCookie",
        {"idToken": revoked["idToken"], "validDuration": "3600"},
        owner=True,
    )
    rows["session-cookie-revoked-id-token-rejected"] = row(
        "session-cookie-revoked-id-token-rejected", status, body, {}
    )

    # --- claim precedence ----------------------------------------------------
    setup_status, setup_body = send(
        budget,
        admin,
        "/accounts:update",
        {
            "localId": custom_uid,
            "customAttributes": json.dumps({"role": "admin", "tier": "gold"}),
        },
        owner=True,
    )
    _require_account_update_ack(setup_status, setup_body, custom_uid)
    _rest(budget, 1)
    status, body = refresh(custom_session["refreshToken"])
    refreshed_custom = (
        claim_shape(body["id_token"], reveal=("role", "tier"))
        if status == 200
        else None
    )
    rows["claim-precedence-session-over-account"] = row(
        "claim-precedence-session-over-account",
        status,
        body,
        {
            "acceptedResponse": status == 200,
            "idTokenMatchesAccount": bool(
                status == 200 and id_token_matches_account(
                    body.get("id_token"), uid=custom_uid, project=env["project"]
                )
            ),
            "sessionClaimWinsOverAccountClaim": bool(
                refreshed_custom
                and refreshed_custom["claimValues"].get("role") == "tester"
            ),
            "accountOnlyClaimPresent": bool(
                refreshed_custom
                and refreshed_custom["claimValues"].get("tier") == "gold"
            ),
            "authTimePreserved": bool(
                refreshed_custom
                and refreshed_custom["times"]["auth_time"]
                == custom_shape["times"]["auth_time"]
            ),
        },
        claims=_claims(refreshed_custom),
        diagnostics={
            "signIn": custom_shape["times"],
            "refreshed": refreshed_custom["times"] if refreshed_custom else None,
        },
    )

    _refresh_refusal_cases()
    return rows


def _deleted_response(status: Any, body: Any) -> bool:
    return type(status) is int and status == 200 and isinstance(body, dict) and (
        body == {} or body == {"kind": "identitytoolkit#DeleteAccountResponse"}
    )


def _absent_response(status: Any, body: Any) -> bool:
    if (type(status) is not int or status != 200 or not isinstance(body, dict)
            or not body or set(body) - {"kind", "users"}):
        return False
    if "kind" in body and body["kind"] != "identitytoolkit#GetAccountInfoResponse":
        return False
    if "users" in body:
        return isinstance(body["users"], list) and body["users"] == []
    return body == {"kind": "identitytoolkit#GetAccountInfoResponse"}


def cleanup(
    base: str,
    budget: dict[str, Any],
    tracker: dict[str, Any],
    poster: Any = None,
    environment: dict[str, Any] | None = None,
) -> list[str]:
    """Use typed delete and absence evidence, and retain each failed owned UID.

    No new authority or retry is introduced. An exception for one account does
    not prevent the next owned account from attempting the existing reserve.
    """
    send = poster or post
    env = local_environment() if environment is None else dict(environment)
    admin = _endpoints(base, env)["admin"]
    problems: list[str] = []
    for uid, account in list(tracker["accounts"].items()):
        uid_absent = email_absent = False
        try:
            status, body = send(budget, admin, "/accounts:delete", {"localId": uid}, owner=True)
            if not _deleted_response(status, body):
                problems.append("delete-unconfirmed")
                continue
            status, body = send(budget, admin, "/accounts:lookup", {"localId": [uid]}, owner=True)
            uid_absent = _absent_response(status, body)
            if not uid_absent:
                problems.append("uid-absence-unconfirmed")
            if account["email"] is None:
                email_absent = True  # No address readback is claimed for addressless users.
            else:
                status, body = send(budget, admin, "/accounts:lookup", {"email": [account["email"]]}, owner=True)
                email_absent = _absent_response(status, body)
                if not email_absent:
                    problems.append("address-absence-unconfirmed")
        except Exception as error:
            # Server bodies and exception strings may contain token material.
            problems.append("account-cleanup-" + type(error).__name__)
        finally:
            mark_deleted(tracker, uid, uid_absent=uid_absent, email_absent=email_absent)
    return problems


#: Every way a run can stop part-way. Each is recorded with the rows already observed
#: rather than raised, so an exhausted budget never discards work already paid for.
STOP_CONDITIONS = (
    BudgetExceeded,
    ShadowError,
    ValueError,
    KeyError,
    urllib.error.URLError,
    OSError,
)


def shadow_budget(now: float | None = None) -> dict[str, Any]:
    """The local run's budget, bound to the campaign's declared request and time bounds.

    The cost ceiling is zero because a loopback run spends nothing. The request and
    wall-clock bounds come from the manifest so the executed instance cannot exercise a
    looser bound than the campaign declares. `now` is the monotonic reading the campaign
    starts at; a caller driving a run on its own clock passes that clock's reading.
    """
    return new_budget(
        max_requests=BUDGET["maxRequests"],
        max_wall_seconds=BUDGET["maxWallSeconds"],
        max_cost_usd=0.0,
        started_monotonic=time.monotonic() if now is None else now,
        recovery_requests=BUDGET["recoveryRequests"],
        recovery_wall_seconds=BUDGET["recoveryWallSeconds"],
    )


def collect(
    base: str,
    budget: dict[str, Any],
    tracker: dict[str, Any],
    runner: Any = None,
) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Run the cases, returning whatever was observed plus any stop condition."""
    rows: dict[str, dict[str, Any]] = {}
    try:
        (runner or run_cases)(base, budget, tracker, rows)
    except Exception as error:
        return rows, f"{type(error).__name__}: local collection failed"
    return rows, None


def not_run_row(case: dict[str, Any], reason: str | None = None) -> dict[str, Any]:
    """The row a case nobody ran carries; a reason names why when one is known."""
    row = {"caseId": case["id"], "status": 0, "errorCode": "NOT_RUN", "assertions": {}}
    if reason is not None:
        row["notRunReason"] = reason
    return row


def finish_record(
    *,
    rows: dict[str, dict[str, Any]],
    tracker: dict[str, Any],
    budget: dict[str, Any],
    failure: str | None,
    shutdown: dict[str, Any],
    source_binding: dict[str, Any],
    startup_diagnostics: dict[str, Any] | None = None,
    signing: bool = True,
) -> tuple[dict[str, Any], int]:
    """Assemble the record from whatever was observed, marking the rest not run."""
    ordered = [
        rows.get(
            case["id"],
            not_run_row(
                case,
                SIGNING_ABSENT_REASON
                if not signing and case["requiresSigning"]
                else None,
            ),
        )
        for case in observation_cases()
    ]
    receipt = build_receipt(
        side="local",
        rows=ordered,
        tracker=tracker,
        budget=budget,
        source_binding=source_binding,
    )
    agreement = _agreement(ordered)
    record = {
        "campaignId": CAMPAIGN_ID,
        "kind": "local-shadow",
        "productionExecuted": False,
        "failure": failure,
        "shutdown": shutdown,
        "startupDiagnostics": startup_diagnostics,
        "receipt": receipt,
        "expectedLocalAgreement": agreement,
    }
    issues = []
    if receipt.get("recordingComplete") is not True:
        issues.append("incomplete-recording")
    if cleanup_report(tracker)["cleanupComplete"] is not True:
        issues.append("incomplete-resource-cleanup")
    if budget.get("integrityFailure") is not None:
        issues.append("budget-integrity-failure")
    stopped_process = (
        isinstance(shutdown, dict)
        and shutdown.get("processStopped") is True
        and type(shutdown.get("remainingChildren")) is int
        and shutdown["remainingChildren"] == 0
        and type(shutdown.get("exitCode")) is int
        and shutdown["exitCode"] in (0, -15, -9)
        and shutdown.get("outputDrainerStopped") is True
        and shutdown.get("failures") == []
    )
    no_process_started = (
        isinstance(shutdown, dict)
        and shutdown.get("processStarted") is False
        and shutdown.get("processStopped") is True
        and type(shutdown.get("remainingChildren")) is int
        and shutdown["remainingChildren"] == 0
        and shutdown.get("exitCode") is None
        and shutdown.get("outputDrainerStopped") is True
        and shutdown.get("failures") == []
    )
    if not (stopped_process or no_process_started):
        issues.append("process-cleanup-unconfirmed")
    record["completionIssues"] = issues
    return record, 0 if failure is None and not issues and agreement["unexpected"] == [] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the local AUTH-CREDENTIAL shadow."
    )
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--nonce", default=os.urandom(16).hex())
    parser.add_argument(
        "--commit",
        help="the checkout the binary was built from; recorded, never verified here",
    )
    args = parser.parse_args(argv)

    tracker = new_tracker(args.nonce)
    budget = shadow_budget()
    # Output freshness and input failures are checked before a daemon is started.
    try:
        binary = args.binary.resolve(strict=True)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError("executable artifact required")
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("fresh output required")
        artifact_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        workdir = args.output.with_name(args.output.name + ".work")
        workdir.mkdir(mode=0o700, exist_ok=False)
        responsibility.attach(tracker, workdir / "responsibility", {
            "artifactSha256": artifact_sha256,
            "collectorBinding": collector_binding(),
            "commit": args.commit,
            "commitStatus": "operator-asserted; not verified by this run",
        })
    except (OSError, ValueError):
        print("credential shadow: input or output unavailable", file=sys.stderr)
        return 2
    rows, failure = {}, None
    process = None
    startup_diagnostics = None
    shutdown = {"processStopped": False, "remainingChildren": None,
                "exitCode": None, "outputDrainerStopped": False, "failures": []}
    problems: list[str] = []
    try:
        process, base = start_daemon(binary, workdir)
        rows, failure = collect(base, budget, tracker)
    except Exception as error:
        failure = type(error).__name__ + ": local execution failed"
        diagnostic = getattr(error, "diagnostics", None)
        if isinstance(diagnostic, dict):
            phase, error_type = diagnostic.get("phase"), diagnostic.get("type")
            byte_count, digest = diagnostic.get("bytes"), diagnostic.get("sha256")
            if (phase in {"readiness", "launch"} and isinstance(error_type, str)
                    and error_type.isascii() and error_type.isidentifier()
                    and type(byte_count) is int and 0 <= byte_count <= 262144
                    and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)):
                startup_diagnostics = {"phase": phase, "type": error_type,
                                       "bytes": byte_count, "sha256": digest}
        failed_shutdown = getattr(error, "shutdown", None)
        if process is None and isinstance(failed_shutdown, dict):
            shutdown = failed_shutdown
    finally:
        try:
            if process is not None:
                try:
                    enter_recovery(budget, time.monotonic())
                    problems = cleanup(base, budget, tracker)
                except Exception as error:
                    problems = ["cleanup: " + type(error).__name__]
                finally:
                    # Even unexpected cleanup errors/interrupts must reach daemon stop.
                    shutdown = stop_daemon(process)
        finally:
            responsibility.close(tracker)
    if problems:
        failure = failure or "cleanup: " + "; ".join(problems)
    record, exit_code = finish_record(
        rows=rows, tracker=tracker, budget=budget, failure=failure, shutdown=shutdown,
        startup_diagnostics=startup_diagnostics,
        source_binding={"commit": args.commit,
                        "commitStatus": "operator-asserted; not verified by this run",
                        "artifactSha256": artifact_sha256},
    )
    try:
        # No old successful output is overwritten, including concurrent publication.
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(args.output.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except (OSError, ValueError):
        print("credential shadow: result publication failed", file=sys.stderr)
        return 2
    return exit_code


def _agreement(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare each observed row with the case's declared expected local result."""
    unexpected = []
    for case in observation_cases():
        row = next(r for r in rows if r["caseId"] == case["id"])
        expected = case["expectedLocal"]
        problems = []
        if row.get("status") != expected["status"]:
            problems.append(f"status {row.get('status')} != {expected['status']}")
        if expected["errorCode"] and row.get("errorCode") != expected["errorCode"]:
            problems.append(
                f"errorCode {row.get('errorCode')} != {expected['errorCode']}"
            )
        for name in expected["assertions"]:
            if row.get("assertions", {}).get(name) is not True:
                problems.append(f"assertion {name} not held")
        fresh = case.get("freshControl")
        if fresh is not None:
            control = row.get("freshSessionRefresh")
            held = (
                isinstance(control, dict)
                and control.get("status") == 200
                and control.get("errorCode") is None
            )
            if held is not (fresh["requires"] == "accepted"):
                problems.append("fresh control not held")
        if problems:
            unexpected.append({"caseId": case["id"], "problems": problems})
    return {"cases": len(observation_cases()), "unexpected": unexpected}


if __name__ == "__main__":
    sys.exit(main())
