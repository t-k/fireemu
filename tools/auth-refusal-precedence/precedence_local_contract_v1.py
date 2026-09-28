"""Version 1 of the private local valid-token safety contract.

The historical refusal-precedence contract remains frozen for its published receipt
and comparison. This extension applies only to new owned local observations.
"""

from precedence_contract import FINALIZE_CHECKS, complete, require

# Local-only safety coverage. These observations deliberately stay outside CASES and
# CORPUS: production revision 1 records only the tampered-token overlap, while the
# valid-token authorization answers are checked against the local policy and API spec.
LOCAL_VALID_ACTIVE_FIELDS = (
    "customAttributes",
    "emailVerified",
    "mfa",
    "linkProviderUserInfo",
    "disableUser",
)
LOCAL_VALID_ACTIVE_REFUSED_FIELDS = (
    "customAttributes",
    "mfa",
    "linkProviderUserInfo",
)
LOCAL_VALID_ACTIVE_ERRORS = {
    "customAttributes": "INSUFFICIENT_PERMISSION",
    "mfa": "OPERATION_NOT_ALLOWED",
    "linkProviderUserInfo": "OPERATION_NOT_ALLOWED",
    "disableUser": "OPERATION_NOT_ALLOWED",
}


def validate_local_active_token(extension):
    fields = (
        *LOCAL_VALID_ACTIVE_REFUSED_FIELDS,
        "emailVerified",
        "disableUser:true",
        "disableUser:null",
    )
    require(
        [(row["account"], row["field"]) for row in extension["fields"]]
        == [(account, field) for account in ("a", "b") for field in fields]
    )

    def continuity(checks):
        require(isinstance(checks, dict))
        require(set(checks) == {*FINALIZE_CHECKS, "finalizeHttpStatus"})
        require(all(value is True for value in checks.values()))

    for row in extension["fields"]:
        field = row["field"]
        if field in (*LOCAL_VALID_ACTIVE_REFUSED_FIELDS, "disableUser:true"):
            expected_error = LOCAL_VALID_ACTIVE_ERRORS[field.split(":")[0]]
            require(row["httpStatus"] == 400 and row["outcome"] == "refused")
            require(row["observedError"] == expected_error)
            require(row["allAccountStateUnchanged"] is True)
        else:
            require(row["httpStatus"] == 200 and row["outcome"] == "accepted")
            require(row["observedError"] is None)
            for check in (
                "displayNameApplied",
                "ownerOtherStateUnchanged",
                "otherAccountUnchanged",
                "allAccountStateRestored",
                "emailVerifiedUnchanged"
                if field == "emailVerified"
                else "disableStateUnchanged",
            ):
                require(row[check] is True)
        if field.startswith("disableUser:"):
            continuity(row["heldMfaContinuity"])
    require(
        [row["account"] for row in extension["ordinaryFieldControls"]] == ["a", "b"]
    )
    for row in extension["ordinaryFieldControls"]:
        require(row["field"] == "displayName")
        require(row["httpStatus"] == 200 and row["outcome"] == "accepted")
        require(row["observedError"] is None and row["accountStateRestored"] is True)
    require(isinstance(extension["heldCredentialsAndSessions"], dict))
    require(set(extension["heldCredentialsAndSessions"]) == {"a", "b"})
    for checks in extension["heldCredentialsAndSessions"].values():
        continuity(checks)


def complete_local_v1(report):
    """Require the historical corpus and every local v1 safety projection."""
    try:
        require(report["target"] == "local")
        require(complete(report))
        validate_local_active_token(report["localValidActiveToken"])
    except (KeyError, TypeError, ValueError):
        return False
    return True
