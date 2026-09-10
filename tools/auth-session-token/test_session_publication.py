"""Diagnostic outcomes never become an approval or universal revocation result."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-session-token.py"
    assert path.exists(), "Session diagnostic publisher required"
    spec = importlib.util.spec_from_file_location("session_publication", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_no_incomplete_private_report_is_publishable():
    p = publisher()
    with pytest.raises(ValueError):
        p.project(
            {
                "schemaVersion": 2,
                "acceptance": "candidate",
                "target": "local",
                "status": "incomplete",
            },
            "local",
        )


def test_comparison_keeps_differences_and_control_failures_distinct():
    p = publisher()
    a = {
        "quality": "observed",
        "response": {"outcome": "accepted", "error": None},
        "followup": None,
    }
    b = {**a, "response": {"outcome": "auth-rejected", "error": "TOKEN_EXPIRED"}}
    assert p.comparison(a, a, True) == "Same observed result"
    assert p.comparison(a, b, True) == "Different observations"
    assert p.comparison(a, b, False) == "Inconclusive (controls/timing)"
    assert (
        p.comparison({**a, "quality": "late"}, b, True)
        == "Inconclusive (controls/timing)"
    )


def test_frozen_password_evidence_is_not_used_as_session_evidence():
    p = publisher()
    value = json.loads(
        (p.ROOT / "spec/compatibility/evidence/auth-password/receipt.json").read_bytes()
    )
    with pytest.raises(ValueError):
        p.validate(copy.deepcopy(value))


def synthetic_receipt(p):
    # Synthetic validator fixture only, never saved as live observation.
    import base64

    from session_contract import CASES, SAMPLES, kind_for, response

    value = json.loads(
        (p.ROOT / "spec/compatibility/evidence/auth-password/receipt.json").read_bytes()
    )
    value.update(
        scope=p.SCOPE,
        corpus=copy.deepcopy(p.CORPUS),
        probeInputs=p.inputs(),
        sourceReviewSha256=p.digest(json.loads(p.REVIEW.read_bytes())),
        publicationContractSha256=p.publication_contract_sha(),
    )
    for target in ("local", "production"):
        rows = []
        for name in CASES:
            kind = kind_for(name)
            issued = 200 if name in {"change-password", "new-password-signin"} else 100
            token = (
                "e30."
                + base64.urlsafe_b64encode(
                    json.dumps({"iat": issued, "auth_time": 100}).encode()
                )
                .decode()
                .rstrip("=")
                + ".unused"
            )
            raw = {
                "idToken": token,
                "refreshToken": "refresh",
                "localId": "uid",
                "email": "email",
                "expiresIn": "3600",
                "id_token": token,
                "refresh_token": "refresh",
                "user_id": "uid",
                "token_type": "Bearer",
                "expires_in": "3600",
                "users": [{"localId": "uid", "email": "email"}],
                "uidAbsent": True,
                "emailAbsent": True,
            }
            start = int(name.split("@")[1]) if name in SAMPLES else 10000
            if name == "signin-a":
                start = 1000
            if name == "signin-b":
                start = 3150
            if name == "b-refresh-baseline-2":
                start = 16850
            if name == "change-password":
                start = 20000
            row = {
                "id": name,
                "response": response(200, raw, kind, "uid", "email"),
                "followup": response(200, raw, "lookup", "uid", "email")
                if kind == "refresh"
                else None,
                "rotated": False if kind == "refresh" else None,
                "startMs": start,
                "primaryEndMs": start + 50 if kind == "refresh" else start + 100,
                "endMs": start + 100,
                "followupStartMs": start + 50 if kind == "refresh" else None,
                "followupEndMs": start + 100 if kind == "refresh" else None,
                "credentialUnchanged": True,
                "quality": "observed",
            }
            rows.append(row)
        value[target].update(
            cases=rows,
            status="observed",
            timing={
                "sessionsSeparated": True,
                "issueGapMs": 2050,
                "preChangeWaitMs": 3050,
                "mutationStartMs": 20000,
                "mutationEndMs": 20100,
                "latestPreIssuedAt": 100,
                "changedIssuedAt": 200,
                "orderEstablished": True,
            },
        )
    return value


def test_tampered_timing_and_provenance_are_rejected():
    p = publisher()
    original = synthetic_receipt(p)
    p.validate(original)
    for path, invalid in [
        (("acceptance",), "approved"),
        (("corpus", "deadlineMs"), 999999),
        (("probeInputs",), {}),
        (("publicationContractSha256",), "0" * 64),
        (("local", "timing", "issueGapMs"), 100),
        (("local", "timing", "changedIssuedAt"), 100),
        (("local", "timing", "orderEstablished"), 1),
        (("local", "ownedProcess", "exitCode"), 2),
        (("production", "cases", 10, "credentialUnchanged"), False),
        (("production", "cases", 10, "startMs"), 45000),
        (("production", "cases", 10, "response", "idToken"), "SECRET"),
        (("production", "cleanup", "emailAbsent"), 1),
    ]:
        changed = copy.deepcopy(original)
        parent = changed
        for key in path[:-1]:
            parent = parent[key]
        parent[path[-1]] = invalid
        with pytest.raises(ValueError):
            p.validate(changed)


def test_failed_fresh_control_suppresses_apparent_agreement():
    p = publisher()
    from session_contract import response

    value = synthetic_receipt(p)
    for target in ("local", "production"):
        row = value[target]["cases"][14]
        row["response"] = response(
            400, {"error": {"message": "TOKEN_EXPIRED"}}, "lookup", "uid", "email"
        )
        row["quality"] = "inconclusive"
        value[target]["status"] = "inconclusive"
    page = p.render(value)
    assert "Inconclusive (controls/timing)" in page
    assert "candidate, not approved" in page


def test_refresh_requires_its_own_primary_completion_time():
    p = publisher()
    original = synthetic_receipt(p)
    row = original["local"]["cases"][4]
    row.pop("primaryEndMs", None)
    with pytest.raises(ValueError):
        p.validate(original)


@pytest.mark.parametrize("field", ["issueGapMs", "preChangeWaitMs"])
def test_separation_claim_must_agree_with_actual_intervals(field):
    p = publisher()
    value = synthetic_receipt(p)
    value["local"]["timing"][field] = 9999
    with pytest.raises(ValueError):
        p.validate(value)
