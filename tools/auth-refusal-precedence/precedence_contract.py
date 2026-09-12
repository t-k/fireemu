"""Finite observations of overlapping refusals on one MFA finalize and one client update.

Which refusal wins is the observation. No row encodes the local order: diagnostic rows
accept either outcome, and only the controls must succeed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import require

# Two owned accounts with a phone factor. Baseline finalizes succeed. A tampered ID token
# of A is sent to the client `accounts:update` together with an administrator-only field
# before anything is disabled, so the only overlap is an invalid signature against a
# privileged field; the fields are chosen so that an unexpected acceptance cannot change
# A's MFA eligibility (custom claims and a photo URL, never the verified email). Both
# accounts then hold a pending credential and an SMS session, both are disabled and read
# back, and the same session is finalized with a wrong code for A and the correct code
# for B. After re-enablement the same pending credential and session are finalized with
# the correct code, showing whether the earlier refusal consumed them. Fresh finalizes
# close the run.
CASES = (
    "baseline-a-fresh-finalize",
    "baseline-b-fresh-finalize",
    "invalid-token-admin-field-update",
    "disabled-a-wrong-code-finalize",
    "disabled-b-correct-code-finalize",
    "reenabled-a-held-finalize",
    "reenabled-b-held-finalize",
    "final-a-fresh-finalize",
    "final-b-fresh-finalize",
)
DIAGNOSTIC = tuple(
    name
    for name in CASES
    if name.startswith(("invalid-token-", "disabled-", "reenabled-"))
)
DIAGNOSTIC_FINALIZES = tuple(n for n in DIAGNOSTIC if n.endswith("-finalize"))
CORPUS = {"slice": "auth-refusal-precedence", "revision": 1, "cases": list(CASES)}
ERRORS = {
    "INVALID_MFA_PENDING_CREDENTIAL",
    "INVALID_SESSION_INFO",
    "INVALID_CODE",
    "SESSION_EXPIRED",
    "MFA_ENROLLMENT_NOT_FOUND",
    "MISSING_RECAPTCHA_TOKEN",
    "INVALID_RECAPTCHA_TOKEN",
    "CAPTCHA_CHECK_FAILED",
    "OPERATION_NOT_ALLOWED",
    "TOKEN_EXPIRED",
    "INVALID_ID_TOKEN",
    "INVALID_REFRESH_TOKEN",
    "CREDENTIAL_TOO_OLD_LOGIN_AGAIN",
    "PERMISSION_DENIED",
    "USER_DISABLED",
    "USER_NOT_FOUND",
}
FINALIZE_CHECKS = {
    "noError",
    "idTokenPresent",
    "refreshTokenPresent",
    "claimSubMatches",
    "claimEmailMatches",
    "secondFactorClaim",
    "derivedLookup",
}
# An accepted update with a tampered token would be the surprising outcome; the row then
# records whether the privileged field and the client field were applied (either value).
UPDATE_CHECKS = {"noError", "customAttributesApplied", "photoUrlApplied"}
TEST_PHONES = {"a": "+15555550100", "b": "+15555550101"}
TEST_CODE = "135790"
# Syntactically valid six digits that differ from the test code in every position.
WRONG_CODE = "246801"
# Sentinels for the tampered-token row: a custom claim (administrator-only) and a photo
# URL (client-permitted). Neither affects MFA eligibility, ownership markers or cleanup.
CLAIM_SENTINEL_KEY = "fireemuPrecedence"
PHOTO_SENTINEL_PREFIX = "https://example.test/precedence-"


def error_code(value):
    error = value.get("error") if isinstance(value, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    message = message.split(" : ", 1)[0] if isinstance(message, str) else None
    return (
        message
        if isinstance(message, str) and message in ERRORS
        else "UNCLASSIFIED_ERROR"
    )


def validate_row(row, name):
    require(
        name in CASES
        and isinstance(row, dict)
        and set(row)
        == {
            "id",
            "httpStatus",
            "outcome",
            "observedError",
            "checks",
            "elapsedMs",
            "skipped",
        }
    )
    require(row["id"] == name and type(row["elapsedMs"]) is int)
    require(0 <= row["elapsedMs"] <= 600000 and row["skipped"] is False)
    require(type(row["httpStatus"]) is int)
    if row["outcome"] == "refused":
        require(name in DIAGNOSTIC)
        require(row["httpStatus"] in {400, 403} and row["observedError"] in ERRORS)
        require(row["checks"] == {})
        return
    require(row["outcome"] == "accepted")
    require(row["httpStatus"] == 200 and row["observedError"] is None)
    require(isinstance(row["checks"], dict) and row["checks"] != {})
    if name == "invalid-token-admin-field-update":
        require(set(row["checks"]) == UPDATE_CHECKS)
        require(row["checks"]["noError"] is True)
        require(all(type(row["checks"][k]) is bool for k in UPDATE_CHECKS))
        return
    require(set(row["checks"]) == FINALIZE_CHECKS)
    if name in DIAGNOSTIC_FINALIZES:
        # An unexpected acceptance is an observation: every token check is recorded as a
        # boolean, including a derived lookup that the account state may refuse.
        require(all(type(v) is bool for v in row["checks"].values()))
        return
    require(all(v is True for v in row["checks"].values()))


def complete(report):
    try:
        require(
            not any(
                k in report
                for k in ("failure", "cleanupFailure", "configRestoreFailure")
            )
        )
        require(
            report["status"] == "observed"
            and [r["id"] for r in report["cases"]] == list(CASES)
        )
        for row, name in zip(report["cases"], CASES, strict=True):
            validate_row(row, name)
        require(report["setup"] == {"a": True, "b": True})
        require(report["held"] == {"a": True, "b": True})
        # The tampered-token row is followed by an administrative readback of A; whether
        # the privileged field or the sentinel was applied is an observation, so only the
        # presence of the projection is required, and it must agree with the row.
        update = report["cases"][CASES.index("invalid-token-admin-field-update")]
        require(type(report["invalidTokenStateUnchanged"]) is bool)
        if update["outcome"] == "refused":
            require(report["invalidTokenStateUnchanged"] is True)
        else:
            applied = update["checks"]
            require(
                report["invalidTokenStateUnchanged"]
                == (
                    not applied["customAttributesApplied"]
                    and not applied["photoUrlApplied"]
                )
            )
        require(
            report["transitions"]
            == [
                {"disabled": True, "targetReadback": True},
                {"disabled": False, "targetReadback": True},
            ]
        )
        require(report["cleanup"] == {"uidAbsent": True, "emailAbsent": True})
        require(report["configRestored"] is True)
        require(report["configDigestMatches"] is True)
    except (KeyError, TypeError, ValueError):
        return False
    return True


def semantic_rows(rows):
    """Elapsed timing is retained but not required to be identical across runs."""
    return [{k: v for k, v in row.items() if k != "elapsedMs"} for row in rows]
