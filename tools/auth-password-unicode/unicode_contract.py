"""Finite input families distinguish counting hypotheses, not all Unicode behavior."""

import re
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth-password-maximum"))
from maximum_contract import POLICY_ERRORS, tokens


def require(condition):
    if not condition:
        raise ValueError("Unicode observation contract failed")


SAMPLES = {
    "ascii-at": ("a", 4064),
    "ascii-over": ("a", 4065),
    "bmp-byte-at": ("\u00e9", 2032),
    "bmp-byte-over": ("\u00e9", 2033),
    "astral-unit-at": ("\U00010400", 2032),
    "astral-unit-over": ("\U00010400", 2033),
    "bmp-scalar-at": ("\u00e9", 4064),
    "bmp-scalar-over": ("\u00e9", 4065),
}
CASES = tuple(SAMPLES)
SHAPES = {
    name: {
        "scalars": 32 + count,
        "utf8Bytes": 32 + count * len(char.encode("utf-8")),
        "utf16Units": 32 + count * len(char.encode("utf-16-le")) // 2,
    }
    for name, (char, count) in SAMPLES.items()
}


def generate(name):
    char, count = SAMPLES[name]
    value = secrets.token_urlsafe(24) + char * count
    input_shape(name, value)
    return value


def input_shape(name, value):
    char, count = SAMPLES[name]
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{32}", value[:32]))
    require(value[32:] == char * count)
    shape = {
        "scalars": len(value),
        "utf8Bytes": len(value.encode("utf-8")),
        "utf16Units": len(value.encode("utf-16-le")) // 2,
    }
    require(shape == SHAPES[name])
    return shape


def hypotheses(outcomes):
    if set(outcomes) != set(CASES) or any(
        v not in {"accepted", "refused"} for v in outcomes.values()
    ):
        return []
    return [
        metric
        for metric in ("scalars", "utf8Bytes", "utf16Units")
        if all(
            outcomes[name] == ("accepted" if shape[metric] <= 4096 else "refused")
            for name, shape in SHAPES.items()
        )
    ]


STATE_CHECKS = {
    "baselineLookup",
    "baselineRefreshLookup",
    "postLookup",
    "postSigninLookup",
    "postRefreshLookup",
    "deleted",
}
TOKEN_NAMES = {
    "signup",
    "baseline-signin",
    "baseline-refresh",
    "post-signin",
    "post-refresh",
}


def token_flags(name):
    return set(tokens({}, "uid", "email", refresh=name.endswith("refresh"))) | {
        "httpOk"
    }


def validate_case(row, name):
    require(
        isinstance(row, dict)
        and set(row)
        == {
            "id",
            "inputShape",
            "outcome",
            "httpStatus",
            "observedError",
            "checks",
            "tokenChecks",
            "cleanup",
        }
    )
    require(row["id"] == name and name in CASES)
    shape = row["inputShape"]
    require(
        isinstance(shape, dict)
        and set(shape) == set(SHAPES[name])
        and all(type(v) is int for v in shape.values())
        and shape == SHAPES[name]
    )
    accepted = row["outcome"] == "accepted"
    require(
        row["outcome"] in {"accepted", "refused"} and type(row["httpStatus"]) is int
    )
    require(row["httpStatus"] == (200 if accepted else 400))
    require(
        row["observedError"] is None
        if accepted
        else row["observedError"] in POLICY_ERRORS
    )
    require(
        isinstance(row["checks"], dict)
        and set(row["checks"]) == STATE_CHECKS
        and all(v is True for v in row["checks"].values())
    )
    observations = row["tokenChecks"]
    require(
        isinstance(observations, dict)
        and set(observations) == TOKEN_NAMES | ({"update"} if accepted else set())
    )
    for key, obs in observations.items():
        require(
            isinstance(obs, dict)
            and set(obs) == {"httpStatus", "checks", "expirySeconds"}
        )
        require(
            type(obs["httpStatus"]) is int
            and obs["httpStatus"] == 200
            and obs["expirySeconds"] == "3600"
        )
        require(
            isinstance(obs["checks"], dict)
            and set(obs["checks"]) == token_flags(key)
            and all(v is True for v in obs["checks"].values())
        )
    require(
        isinstance(row["cleanup"], dict)
        and set(row["cleanup"]) == {"uidAbsent", "emailAbsent"}
        and all(v is True for v in row["cleanup"].values())
    )


def complete(report):
    if any(
        key in report for key in ("failure", "cleanupFailure", "childCleanupFailure")
    ):
        return False
    try:
        require(report["status"] == "observed" and len(report["cases"]) == len(CASES))
        for row, name in zip(report["cases"], CASES, strict=True):
            validate_case(row, name)
        require(
            set(report["cleanup"]) == {"uidAbsent", "emailAbsent"}
            and all(v is True for v in report["cleanup"].values())
        )
    except (KeyError, TypeError, ValueError):
        return False
    return True
