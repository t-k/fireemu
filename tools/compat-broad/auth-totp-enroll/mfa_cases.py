"""Observation cases for the next bounded MFA production campaign.

Every `expectedLocal` entry states what `fireemu` is predicted to answer and why that
prediction exists. `basis` is `source-read` until the local shadow actually observes the
row, at which point the shadow ledger records `shadow-observed` alongside it. No row
carries a production expectation: production is unobserved for all of them, and this
package must not invent one.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Any

CAMPAIGN_ID = "AUTH-MFA-AGE-TOTP-01"
# No Identity Platform lifetime is published for `mfaPendingCredential` or for the TOTP
# enrollment `sessionInfo`, so these ages bracket an empirical boundary rather than test a
# documented one. Under the monotonicity assumption they can localise it to (300, 450] or
# (450, 600], or report "greater than 600".
SAMPLED_AGES_SECONDS = (300, 450, 600)
# An age production has already been observed to refuse, carried as an in-run positive
# control for the refusal direction. Without it, a run in which every sampled age is
# accepted cannot distinguish a longer-than-believed lifetime from a sampler that never
# aged anything.
REFUSAL_DIRECTION_CONTROL_AGE_SECONDS = 1800
AGED_PENDING_SAMPLES = (*SAMPLED_AGES_SECONDS, REFUSAL_DIRECTION_CONTROL_AGE_SECONDS)
# One TOTP step has to roll over before the sign-in finalize, so the code that enrolled the
# factor is not the code that signs in with it.
TOTP_STEP_ROLLOVER_SECONDS = 30

SOURCES = MappingProxyType(
    {
        "mfa-enrollment-start": "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/accounts.mfaEnrollment/start",
        "mfa-enrollment-finalize": "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/accounts.mfaEnrollment/finalize",
        "mfa-enrollment-withdraw": "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/accounts.mfaEnrollment/withdraw",
        "mfa-signin-start": "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/accounts.mfaSignIn/start",
        "mfa-signin-finalize": "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/accounts.mfaSignIn/finalize",
        "accounts-lookup": "https://firebase.google.com/docs/reference/rest/auth",
        "project-config": "https://docs.cloud.google.com/identity-platform/docs/reference/rest/v2/projects/getConfig",
        "rfc-6238": "https://www.rfc-editor.org/rfc/rfc6238",
    }
)

FAMILIES = (
    "pending-age-causality",
    "totp-lifecycle",
    "enrollment-session-age",
    "interaction",
)
BASES = ("control", "diagnostic", "negative")

# Local predictions are read from the fireemu sources named in the campaign document:
# the pending sign-in lifetime is a 3600-second local policy, the TOTP enrollment session
# lifetime is 300 seconds with one further lifetime of grace, and the acceptance window is
# one step either side of the current 30-second step.
_LOCAL_PENDING_TTL_SECONDS = 3600
_LOCAL_ENROLLMENT_TTL_SECONDS = 300


def _case(
    identifier: str,
    family: str,
    basis: str,
    endpoint: str,
    source: str,
    account: str,
    obligation: str,
    status: int,
    error_code: str | None,
    age_seconds: int | None = None,
    due_offset_seconds: int | None = None,
) -> dict[str, Any]:
    if family not in FAMILIES or basis not in BASES or source not in SOURCES:
        raise ValueError(f"malformed case definition: {identifier}")
    return {
        "id": identifier,
        "family": family,
        "basis": basis,
        "endpoint": endpoint,
        "source": source,
        "account": account,
        "ageSeconds": age_seconds,
        # Seconds after the common acquisition origin at which this row becomes due. Every
        # aged resource is acquired at the origin, so the ages elapse concurrently and the
        # run's critical path is the largest offset rather than their sum.
        "dueOffsetSeconds": due_offset_seconds,
        "obligation": obligation,
        "expectedLocal": {
            "status": status,
            "errorCode": error_code,
            "basis": "source-read",
        },
        "productionExpectation": "unobserved",
    }


def _pending_age_case_group(age: int) -> list[dict[str, Any]]:
    """The three rows one aged pending credential produces, all due at the same offset."""
    account = f"pending-age-{age}"
    accepted = age <= _LOCAL_PENDING_TTL_SECONDS
    control = age == REFUSAL_DIRECTION_CONTROL_AGE_SECONDS
    purpose = (
        "This age has already been refused in production, so it is the run's positive "
        "control for the refusal direction: if it is accepted too, the run aged nothing "
        "and no boundary may be read from the other samples. "
        if control
        else ""
    )
    return [
        _case(
            f"age-{age}s-start",
            "pending-age-causality",
            "control" if control else "diagnostic",
            "accounts/mfaSignIn:start",
            "mfa-signin-start",
            account,
            purpose
            + f"A pending credential untouched for at least {age} seconds is offered to "
            "start; acceptance and classified refusal are both observations and neither "
            "proves expiry.",
            200 if accepted else 400,
            None if accepted else "INVALID_MFA_PENDING_CREDENTIAL",
            age,
            age,
        ),
        _case(
            f"age-{age}s-finalize",
            "pending-age-causality",
            "control" if control else "diagnostic",
            "accounts/mfaSignIn:finalize",
            "mfa-signin-finalize",
            account,
            f"A session opened from the {age}-second pending is finalized with a fresh "
            "code; it is skipped when its start was refused.",
            200 if accepted else 400,
            None if accepted else "INVALID_MFA_PENDING_CREDENTIAL",
            age,
            age,
        ),
        _case(
            f"age-{age}s-same-account-fresh-control",
            "pending-age-causality",
            "control",
            "accounts/mfaSignIn:finalize",
            "mfa-signin-finalize",
            account,
            f"Immediately after the {age}-second attempt, the same account signs in again "
            "and completes MFA with a newly acquired pending credential. A refusal above "
            "paired with success here isolates pending age from account, enrollment and "
            "project configuration state; it still assumes the aged pending was untouched.",
            200,
            None,
            0,
            age,
        ),
    ]


def _enrollment_session_age_case(age: int) -> dict[str, Any]:
    """One aged TOTP enrollment session, due at the same offset as its pending sibling."""
    # Each sample is taken just past its target age, as the production recorder does.
    # fireemu keeps an expired session for one further lifetime so a late finalize answers
    # SESSION_EXPIRED, then reaps it and answers INVALID_SESSION_INFO. Both are declared
    # local policies, not production claims.
    within_ttl = age < _LOCAL_ENROLLMENT_TTL_SECONDS
    reaped = age >= 2 * _LOCAL_ENROLLMENT_TTL_SECONDS
    expired_code = "INVALID_SESSION_INFO" if reaped else "SESSION_EXPIRED"
    return _case(
        f"totp-enroll-session-age-{age}s",
        "enrollment-session-age",
        "diagnostic",
        "accounts/mfaEnrollment:finalize",
        "mfa-enrollment-finalize",
        f"enrollment-age-{age}",
        f"A TOTP enrollment session untouched for at least {age} seconds is finalized with "
        "a code that is correct for the moment of submission, so only the session age can "
        "explain a refusal.",
        200 if within_ttl else 400,
        None if within_ttl else expired_code,
        age,
        age,
    )


def _aged_cases() -> list[dict[str, Any]]:
    """The aged rows, interleaved by due offset so the walk never arrives late.

    Every aged resource is acquired at a common origin. The collector walks the case list
    in order and waits for the first step that is not yet due, so the offsets have to be
    non-decreasing: if a later-listed row were due earlier, the walk would reach it after
    its target age had already passed and the sample would be wrong.
    """
    cases: list[dict[str, Any]] = []
    for age in AGED_PENDING_SAMPLES:
        cases.extend(_pending_age_case_group(age))
        if age in SAMPLED_AGES_SECONDS:
            cases.append(_enrollment_session_age_case(age))
    return cases


def _totp_cases() -> list[dict[str, Any]]:
    account = "totp-lifecycle"
    return [
        _case(
            "totp-enroll-start",
            "totp-lifecycle",
            "diagnostic",
            "accounts/mfaEnrollment:start",
            "mfa-enrollment-start",
            account,
            "A TOTP enrollment start returns a shared secret, code length, hashing algorithm, "
            "period and session identifier. The secret is used in memory and never recorded.",
            200,
            None,
        ),
        _case(
            "totp-enroll-wrong-code",
            "totp-lifecycle",
            "negative",
            "accounts/mfaEnrollment:finalize",
            "mfa-enrollment-finalize",
            account,
            "A deterministically wrong code, chosen so that no step inside the acceptance window "
            "can match it, is refused.",
            400,
            "INVALID_CODE",
        ),
        _case(
            "totp-enroll-retry-same-session",
            "totp-lifecycle",
            "diagnostic",
            "accounts/mfaEnrollment:finalize",
            "mfa-enrollment-finalize",
            account,
            "The same enrollment session accepts one correct code after the wrong one. This is the "
            "distinct obligation inherited from AUTH-MFA-TOTP-ENROLL-RETRY-01.",
            200,
            None,
        ),
        _case(
            "totp-enroll-replay-finalized-session",
            "totp-lifecycle",
            "negative",
            "accounts/mfaEnrollment:finalize",
            "mfa-enrollment-finalize",
            account,
            "Replaying the session identifier after a successful finalize is refused.",
            400,
            "INVALID_SESSION_INFO",
        ),
        _case(
            "totp-enroll-factor-readback",
            "totp-lifecycle",
            "diagnostic",
            "accounts:lookup",
            "accounts-lookup",
            account,
            "The account reports exactly one enrolled TOTP factor with an enrollment identifier "
            "and an enrolled-at time.",
            200,
            None,
        ),
        # Declared where it executes: the account has to hold exactly one TOTP factor,
        # so this row belongs after the readback and before the withdrawal rows remove
        # it. The declared order is the execution order, and the recorder follows it.
        _case(
            "second-factor-limit",
            "interaction",
            "negative",
            "accounts/mfaEnrollment:start",
            "mfa-enrollment-start",
            "totp-lifecycle",
            "Starting a second TOTP enrollment on an account that already has one is refused; "
            "fireemu refuses at start, so the step production refuses at is worth recording.",
            400,
            "SECOND_FACTOR_EXISTS",
        ),
        _case(
            "totp-signin-start",
            "totp-lifecycle",
            "negative",
            "accounts/mfaSignIn:start",
            "mfa-signin-start",
            account,
            "Offering a TOTP enrollment identifier to the sign-in start step records what the "
            "service answers; fireemu refuses because TOTP has no start step.",
            400,
            "INVALID_ARGUMENT",
        ),
        _case(
            "totp-signin-finalize",
            "totp-lifecycle",
            "diagnostic",
            "accounts/mfaSignIn:finalize",
            "mfa-signin-finalize",
            account,
            "A TOTP second factor completes sign-in directly at finalize and the returned token "
            "carries the second-factor claim.",
            200,
            None,
        ),
        _case(
            "totp-signin-replay-same-code",
            "totp-lifecycle",
            "negative",
            "accounts/mfaSignIn:finalize",
            "mfa-signin-finalize",
            account,
            "Submitting the code that was just consumed is refused rather than accepted twice.",
            400,
            "INVALID_CODE",
        ),
        _case(
            "totp-withdraw",
            "totp-lifecycle",
            "diagnostic",
            "accounts/mfaEnrollment:withdraw",
            "mfa-enrollment-withdraw",
            account,
            "Withdrawing the enrolled TOTP factor succeeds and returns refreshed tokens.",
            200,
            None,
        ),
        _case(
            "totp-withdraw-readback",
            "totp-lifecycle",
            "diagnostic",
            "accounts:lookup",
            "accounts-lookup",
            account,
            "After withdrawal the account reports no enrolled second factor.",
            200,
            None,
        ),
        _case(
            "totp-withdraw-unknown",
            "totp-lifecycle",
            "negative",
            "accounts/mfaEnrollment:withdraw",
            "mfa-enrollment-withdraw",
            account,
            "Withdrawing an enrollment identifier that no longer exists is refused.",
            400,
            "MFA_ENROLLMENT_NOT_FOUND",
        ),
    ]


def _interaction_cases() -> list[dict[str, Any]]:
    return [
        _case(
            "unverified-email-enroll-refusal",
            "interaction",
            "negative",
            "accounts/mfaEnrollment:start",
            "mfa-enrollment-start",
            "interaction-unverified",
            "TOTP enrollment on an account whose email is not verified is refused.",
            400,
            "UNVERIFIED_EMAIL",
        ),
        _case(
            "ineligible-first-factor-refusal",
            "interaction",
            "negative",
            "accounts/mfaEnrollment:start",
            "mfa-enrollment-start",
            "interaction-anonymous",
            "TOTP enrollment from an anonymous first factor is refused.",
            400,
            "UNSUPPORTED_FIRST_FACTOR",
        ),
        _case(
            "missing-id-token-refusal",
            "interaction",
            "negative",
            "accounts/mfaEnrollment:start",
            "mfa-enrollment-start",
            "interaction-unverified",
            "TOTP enrollment without an ID token is refused; fireemu deliberately differs from the "
            "official emulator here, so the production code is worth recording.",
            400,
            "INVALID_ID_TOKEN",
        ),
        _case(
            "project-mfa-config-readback",
            "interaction",
            "control",
            "projects:getConfig",
            "project-config",
            "project",
            "The project configuration is read before and after the run so the multi-factor state "
            "and enabled providers the campaign relied on are part of the receipt. fireemu models "
            "no project multi-factor configuration, so this row is expected to differ.",
            200,
            None,
        ),
    ]


def observation_cases() -> list[dict[str, Any]]:
    """Return the observation cases in execution order."""
    cases = (
        [
            _case(
                "baseline-fresh-finalize",
                "pending-age-causality",
                "control",
                "accounts/mfaSignIn:finalize",
                "mfa-signin-finalize",
                "pending-control",
                "A pending credential used immediately completes MFA and returns a "
                "verified identity.",
                200,
                None,
                0,
            )
        ]
        + _aged_cases()
        + [
            _case(
                "final-fresh-finalize",
                "pending-age-causality",
                "control",
                "accounts/mfaSignIn:finalize",
                "mfa-signin-finalize",
                "pending-control",
                "A closing fresh completion shows the configuration still worked at the "
                "end of the run.",
                200,
                None,
                0,
            )
        ]
        + _totp_cases()
        + _interaction_cases()
    )
    identifiers = [case["id"] for case in cases]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("observation case identifiers must be unique")
    offsets = [case["dueOffsetSeconds"] for case in cases if case["dueOffsetSeconds"]]
    if offsets != sorted(offsets):
        raise ValueError("aged cases must be listed in non-decreasing due order")
    return cases


def critical_path_seconds() -> int:
    """Return the wall-clock aging one run needs when every aged resource is acquired first."""
    offsets = [case["dueOffsetSeconds"] or 0 for case in observation_cases()]
    return max(offsets) + TOTP_STEP_ROLLOVER_SECONDS


def serial_aging_seconds() -> int:
    """Return what the same run would cost if each aged resource were acquired in turn.

    The cost is per aged resource, not per row: the three rows that share one aged pending
    credential age it once between them, so summing the rows' offsets would count the same
    wait three times.
    """
    return (
        sum(AGED_PENDING_SAMPLES)
        + sum(SAMPLED_AGES_SECONDS)
        + TOTP_STEP_ROLLOVER_SECONDS
    )


CASE_IDS: tuple[str, ...] = tuple(case["id"] for case in observation_cases())


def owned_accounts() -> tuple[str, ...]:
    """Return the distinct owned account roles the campaign creates."""
    roles = {case["account"] for case in observation_cases()} - {"project"}
    return tuple(sorted(roles))
