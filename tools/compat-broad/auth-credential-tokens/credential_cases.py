"""Observation cases for the AUTH-CREDENTIAL token and session-cookie oracle.

Every row states what the local `fireemu` runtime is expected to do. The production
column stays `UNOBSERVED`: this package performs no production request and holds no
production receipt. Logical inputs only; no host, URL, key or account identifier
appears here, so the list can be published unchanged.
"""

from __future__ import annotations

from typing import Any

CAMPAIGN_ID = "AUTH-CREDENTIAL-TOKENS-01"

CASE_GROUPS = (
    "refresh",
    "revocation",
    "session-cookie",
    "custom-token",
    "claim-precedence",
    "refresh-refusal",
)
CASE_KINDS = ("observation", "control", "negative")

SAME_SECOND_CASE_ID = "revocation-same-second-session"

#: What a boundary control must have done on the side that recorded it. A boundary row
#: means nothing unless the older session was refused and the newer one accepted on that
#: same side; two sides agreeing on the wrong answer place no boundary at all.
CONTROL_OUTCOMES = ("accepted", "refused")

#: The HTTP status Identity Toolkit and the secure-token service give a credential they
#: reject on its own terms. A 401 or 403 is the caller not being allowed to ask, a 429 is
#: the service declining to answer and a 5xx is the service failing; none of them says
#: anything about the session presented.
REVOCATION_REFUSAL_STATUS = 400

#: Per operation, the error codes that prove the presented session is no longer honoured.
#: Identity Toolkit answers `accounts:lookup` and `projects.createSessionCookie` with
#: TOKEN_EXPIRED when the token's `auth_time` precedes the account's `validSince`, and
#: with USER_DISABLED when the account itself was disabled; the secure-token endpoint
#: answers a refresh the same way. Both mean the credential was refused, which is what
#: places a boundary.
#:
#: Everything else is refused for a different reason and places nothing: INVALID_ID_TOKEN
#: and INVALID_REFRESH_TOKEN say the token was never valid, USER_NOT_FOUND says the run
#: lost the account it owned, and any other refusal is about the caller or the service.
#: Such a response is still recorded and compared as data; it simply cannot be read as an
#: expiry. An operation absent from this map places no boundary at all.
REVOCATION_REFUSAL_CODES = {
    "secure-token.refresh": ("TOKEN_EXPIRED", "USER_DISABLED"),
    "identity.accounts-lookup": ("TOKEN_EXPIRED", "USER_DISABLED"),
    "identity.create-session-cookie": ("TOKEN_EXPIRED", "USER_DISABLED"),
}

#: The vocabulary a receipt may use to describe an accepted response. Each name is a
#: decidable check over non-secret response measurements, never a recorded secret.
ASSERTION_NAMES = (
    "acceptedResponse",
    "idTokenReturned",
    "refreshTokenReturned",
    "idTokenMatchesAccount",
    "authTimePreserved",
    "iatAdvanced",
    "expIsIatPlusHour",
    "sessionCookieReturned",
    "cookieIssuerIsSessionIssuer",
    "cookieSubjectMatchesIdToken",
    "cookieAuthTimePreserved",
    "cookieLifetimeMatchesRequest",
    "cookieLifetimeIsTwoWeeks",
    "developerClaimPresent",
    "sessionClaimWinsOverAccountClaim",
    "accountOnlyClaimPresent",
    "boundaryPinnedFromServerValues",
    "lookupMatchesAccount",
)

#: Groups whose ID token comes from a custom-token sign-in. In production a custom token
#: must be RS256-signed by a service account, so every case in these groups is blocked
#: until an owner supplies signing access. The session-cookie group is included because
#: it derives its cookie from the custom-token session.
SIGNING_DEPENDENT_GROUPS = ("session-cookie", "custom-token", "claim-precedence")

#: Stated here so the doc and the owner preconditions cannot drift from the list.
SIGNING_DEPENDENT_CASE_COUNT = 11

#: The total the campaign declares: seventeen original cases plus the two refresh
#: refusal-class rows folded in from TP-AUTH-C-02.
CASE_COUNT = 19

#: A fresh control is a second observation inside a refusal row: after the stale
#: refresh token is refused, a fresh sign-in on the same account is exchanged and must
#: be accepted, so the refusal is shown to be about the stale credential rather than
#: about the account. It is recorded on the row as `freshSessionRefresh` and compared
#: as data; it is not an assertion, because a refused row asserts nothing.
FRESH_CONTROL_OPERATION = "secure-token.refresh"

#: Claim names the local runtime adds to an ID token and production never issues.
#: Every claim-set comparison strips them first; see `credential_comparator`.
LOCAL_ONLY_CLAIMS = (("firebase", "fireemu_session_epoch"),)

_SESSION_V2 = "docs/compatibility/auth-session-v2.md"
_SESSION_TOKEN = "docs/compatibility/auth-session-token.md"


def _accepted(*assertions: str, **fields: Any) -> dict[str, Any]:
    return {"status": 200, "errorCode": None, "assertions": list(assertions), **fields}


def _refused(error_code: str) -> dict[str, Any]:
    return {"status": 400, "errorCode": error_code, "assertions": []}


def _fresh_control() -> dict[str, str]:
    return {"operation": FRESH_CONTROL_OPERATION, "requires": "accepted"}


def _case(
    case_id: str,
    group: str,
    kind: str,
    operation: str,
    intent: str,
    expected_local: dict[str, Any],
    *,
    inputs: dict[str, Any] | None = None,
    nondeterminism: str = "NONE",
    covered_elsewhere: tuple[str, ...] = (),
    boundary_controls: dict[str, dict[str, str]] | None = None,
    fresh_control: dict[str, str] | None = None,
) -> dict[str, Any]:
    case: dict[str, Any] = {
        "id": case_id,
        "group": group,
        "kind": kind,
        "operation": operation,
        "intent": intent,
        "input": dict(inputs or {}),
        "expectedLocal": expected_local,
        "production": "UNOBSERVED",
        "nondeterminism": nondeterminism,
        "coveredElsewhere": list(covered_elsewhere),
        "requiresSigning": group in SIGNING_DEPENDENT_GROUPS,
    }
    if boundary_controls is not None:
        for control in boundary_controls.values():
            if control["requires"] not in CONTROL_OUTCOMES:
                raise ValueError(f"a control must require one of {CONTROL_OUTCOMES}")
        case["boundaryControls"] = {
            position: dict(control) for position, control in boundary_controls.items()
        }
    if fresh_control is not None:
        if fresh_control["requires"] not in CONTROL_OUTCOMES:
            raise ValueError(f"a control must require one of {CONTROL_OUTCOMES}")
        case["freshControl"] = dict(fresh_control)
    return case


def observation_cases() -> list[dict[str, Any]]:
    """Return the ordered case list; groups stay contiguous so a partial run shows."""
    return [
        # --- refresh token exchange -------------------------------------------------
        _case(
            "refresh-preserves-auth-time",
            "refresh",
            "observation",
            "secure-token.refresh",
            "A refresh exchange keeps the originating session's auth_time while iat and exp advance.",
            _accepted(
                "acceptedResponse",
                "idTokenMatchesAccount",
                "idTokenReturned",
                "refreshTokenReturned",
                "authTimePreserved",
                "iatAdvanced",
                "expIsIatPlusHour",
            ),
            inputs={"waitSecondsBeforeExchange": 2},
        ),
        _case(
            "refresh-repeat-preserves-auth-time",
            "refresh",
            "control",
            "secure-token.refresh",
            "A second exchange still reports the original sign-in auth_time, not the first exchange's iat.",
            _accepted(
                "acceptedResponse",
                "idTokenMatchesAccount",
                "idTokenReturned",
                "refreshTokenReturned",
                "authTimePreserved",
                "iatAdvanced",
            ),
            inputs={"waitSecondsBeforeExchange": 2, "exchangeOrdinal": 2},
        ),
        _case(
            "refresh-unknown-token-rejected",
            "refresh",
            "negative",
            "secure-token.refresh",
            "A well-formed but unissued refresh token is refused, proving the run reached a real service.",
            _refused("INVALID_REFRESH_TOKEN"),
            covered_elsewhere=(_SESSION_V2, _SESSION_TOKEN),
        ),
        # --- revocation and the same-second boundary --------------------------------
        _case(
            "revocation-older-session-rejected",
            "revocation",
            "control",
            "identity.accounts-lookup",
            "An ID token whose auth_time precedes validSince by whole seconds is refused.",
            _refused("TOKEN_EXPIRED"),
            inputs={"authTimeMinusValidSinceSeconds": -2},
            covered_elsewhere=(_SESSION_V2,),
        ),
        _case(
            SAME_SECOND_CASE_ID,
            "revocation",
            "observation",
            "identity.accounts-lookup",
            "An ID token whose auth_time equals the recorded validSince whole second.",
            _accepted("acceptedResponse", "boundaryPinnedFromServerValues", "lookupMatchesAccount"),
            inputs={"authTimeMinusValidSinceSeconds": 0},
            nondeterminism="SAME_SECOND_BOUNDARY",
            boundary_controls={
                "below": {
                    "case": "revocation-older-session-rejected",
                    "requires": "refused",
                },
                "above": {
                    "case": "revocation-newer-session-accepted",
                    "requires": "accepted",
                },
            },
        ),
        _case(
            "revocation-newer-session-accepted",
            "revocation",
            "control",
            "identity.accounts-lookup",
            "A session started after validSince is accepted, so the refusal above is not blanket.",
            _accepted("acceptedResponse", "idTokenReturned", "lookupMatchesAccount"),
            inputs={"authTimeMinusValidSinceSeconds": 2},
        ),
        # --- session cookies ---------------------------------------------------------
        _case(
            "session-cookie-default-duration",
            "session-cookie",
            "observation",
            "identity.create-session-cookie",
            "An omitted validDuration yields the maximum lifetime.",
            _accepted(
                "sessionCookieReturned",
                "cookieLifetimeIsTwoWeeks",
                "cookieIssuerIsSessionIssuer",
            ),
            inputs={"validDurationSeconds": None},
        ),
        _case(
            "session-cookie-min-duration-accepted",
            "session-cookie",
            "control",
            "identity.create-session-cookie",
            "The documented five-minute minimum is accepted exactly.",
            _accepted("sessionCookieReturned", "cookieLifetimeMatchesRequest"),
            inputs={"validDurationSeconds": 300},
        ),
        _case(
            "session-cookie-below-min-rejected",
            "session-cookie",
            "negative",
            "identity.create-session-cookie",
            "One second below the minimum is refused.",
            _refused("INVALID_DURATION"),
            inputs={"validDurationSeconds": 299},
        ),
        _case(
            "session-cookie-max-duration-accepted",
            "session-cookie",
            "control",
            "identity.create-session-cookie",
            "The documented two-week maximum is accepted exactly.",
            _accepted("sessionCookieReturned", "cookieLifetimeMatchesRequest"),
            inputs={"validDurationSeconds": 1209600},
        ),
        _case(
            "session-cookie-above-max-rejected",
            "session-cookie",
            "negative",
            "identity.create-session-cookie",
            "One second above the maximum is refused.",
            _refused("INVALID_DURATION"),
            inputs={"validDurationSeconds": 1209601},
        ),
        _case(
            "session-cookie-claim-composition",
            "session-cookie",
            "observation",
            "identity.create-session-cookie",
            "The cookie carries the ID token's subject, auth_time and developer claims under the session issuer.",
            _accepted(
                "sessionCookieReturned",
                "cookieSubjectMatchesIdToken",
                "cookieAuthTimePreserved",
                "cookieIssuerIsSessionIssuer",
                "developerClaimPresent",
            ),
            inputs={"validDurationSeconds": 3600, "developerClaimName": "role"},
        ),
        _case(
            "session-cookie-revoked-id-token-rejected",
            "session-cookie",
            "negative",
            "identity.create-session-cookie",
            "A revoked ID token cannot be exchanged for a session cookie.",
            _refused("TOKEN_EXPIRED"),
            inputs={"validDurationSeconds": 3600, "authTimeMinusValidSinceSeconds": -2},
        ),
        # --- custom tokens -----------------------------------------------------------
        _case(
            "custom-token-developer-claims-present",
            "custom-token",
            "observation",
            "identity.sign-in-with-custom-token",
            "Developer claims carried by a custom token appear in the issued ID token.",
            _accepted(
                "acceptedResponse",
                "idTokenReturned",
                "refreshTokenReturned",
                "developerClaimPresent",
            ),
            inputs={"developerClaimName": "role"},
        ),
        _case(
            "custom-token-reserved-claim-rejected",
            "custom-token",
            "negative",
            "identity.sign-in-with-custom-token",
            "A reserved claim name inside the developer claims is refused.",
            _refused("INVALID_CUSTOM_TOKEN"),
            inputs={"developerClaimName": "sub"},
        ),
        _case(
            "custom-token-expired-rejected",
            "custom-token",
            "negative",
            "identity.sign-in-with-custom-token",
            "A custom token past its own exp is refused.",
            _refused("TOKEN_EXPIRED"),
            inputs={"customTokenAgeSeconds": 7200},
        ),
        # --- claim precedence ---------------------------------------------------------
        _case(
            "claim-precedence-session-over-account",
            "claim-precedence",
            "observation",
            "secure-token.refresh",
            "After an account claim is added under the same name, a refresh still reports the session's developer claim, while a new account-only claim appears.",
            _accepted(
                "acceptedResponse",
                "idTokenMatchesAccount",
                "sessionClaimWinsOverAccountClaim",
                "accountOnlyClaimPresent",
                "authTimePreserved",
            ),
            inputs={"developerClaimName": "role", "accountOnlyClaimName": "tier"},
        ),
        # --- refresh refusal class (TP-AUTH-C-02) --------------------------------------
        # Which refusal a stale refresh token receives after the account's credentials
        # change is unobserved in production. The local strict runtime removes the
        # session on a password reset and on an explicit `validSince` update, so it
        # answers INVALID_REFRESH_TOKEN for both; production is expected to answer
        # TOKEN_EXPIRED (a validSince bump) and a DIFFERENT row here is the finding.
        _case(
            "refresh-after-password-reset-rejected",
            "refresh-refusal",
            "negative",
            "secure-token.refresh",
            "After an out-of-band password reset, the pre-reset refresh token is refused; a fresh sign-in on the same account still exchanges.",
            _refused("INVALID_REFRESH_TOKEN"),
            inputs={"credentialChange": "resetPassword"},
            fresh_control=_fresh_control(),
        ),
        _case(
            "refresh-after-explicit-valid-since-rejected",
            "refresh-refusal",
            "negative",
            "secure-token.refresh",
            "After an explicit administrative validSince update two seconds after sign-in, the earlier refresh token is refused; a fresh sign-in on the same account still exchanges.",
            _refused("INVALID_REFRESH_TOKEN"),
            inputs={"credentialChange": "validSince", "validSinceMinusAuthTimeSeconds": 2},
            fresh_control=_fresh_control(),
        ),
    ]


def control_members(case: dict[str, Any]) -> dict[str, Any]:
    """The row members a case's declared controls add when they hold as required.

    A refusal row with a fresh control records `freshSessionRefresh`; a test or a
    reviewer building the expected row from the case list gets the member from here
    rather than restating the control's shape.
    """
    fresh = case.get("freshControl")
    if fresh is None:
        return {}
    if fresh["requires"] == "accepted":
        return {"freshSessionRefresh": {"status": 200, "errorCode": None}}
    return {"freshSessionRefresh": {"status": 400, "errorCode": "TOKEN_EXPIRED"}}


def revocation_refusal_codes(operation: str) -> tuple[str, ...]:
    """The refusals that prove an expiry for one operation; empty when none is documented."""
    return REVOCATION_REFUSAL_CODES.get(operation, ())


def case_by_id(case_id: str) -> dict[str, Any]:
    """Return one case, failing closed on an unknown identifier."""
    for case in observation_cases():
        if case["id"] == case_id:
            return case
    raise KeyError(case_id)
