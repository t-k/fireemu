"""Bounded Auth conditions preserve ownership without inventing oracle answers."""

import copy
import importlib.util


def module():
    assert importlib.util.find_spec("auth_conditions"), (
        "Auth condition catalog required"
    )
    import auth_conditions

    return auth_conditions


def states():
    return {
        "a": {"localId": "A", "emailVerified": True, "displayName": "A-before"},
        "b": {"localId": "B", "emailVerified": True, "displayName": "B-before"},
    }


def test_catalog_has_real_anonymous_and_verified_password_conditions():
    cases = module().cases()
    assert len(cases) == len({c["id"] for c in cases}) == 8
    assert {(c["principal"], c["selector"], c["emailVerified"]) for c in cases} == {
        (principal, selector, verified)
        for principal in ["verified-password", "signed-anonymous"]
        for selector in ["self", "foreign"]
        for verified in [True, False]
    }
    assert all(c["productionExpectation"] is None for c in cases)


def test_success_and_refusal_are_observations_but_cross_account_writes_fail():
    assess = module().assess
    before = states()
    after = copy.deepcopy(before)
    after["b"]["displayName"] = "new"
    assert all(assess(200, before, after).values())
    assert all(assess(400, before, before).values())
    assert not all(assess(400, before, after).values())
    after["a"]["displayName"] = "foreign-write"
    assert not all(assess(200, before, after).values())


def test_verified_baseline_cannot_be_cleared_or_anonymous_elevated():
    assess = module().assess
    for verified in [True, False]:
        before = states()
        before["b"]["emailVerified"] = verified
        after = copy.deepcopy(before)
        after["b"]["emailVerified"] = not verified
        assert not assess(200, before, after)["noPrivilegeChange"]
    for status in [0, 99, 600]:
        assert not all(assess(status, states(), states()).values())
    assert not all(assess(200, states(), {"a": states()["a"]}).values())


def test_redaction_preserves_distinct_anonymous_owner_and_field_presence():
    redact = module().public_state
    users = {
        "a": {"uid": "private-a", "email": "private@example.invalid"},
        "b": {"uid": "private-b"},
    }
    value = {
        "a": {"localId": "private-a", "email": "private@example.invalid"},
        "b": {"localId": "private-b", "emailVerified": False},
    }
    result = redact(value, users)
    assert result["a"]["localId"] != result["b"]["localId"]
    assert "email" not in result["b"]
    assert "private" not in str(result)


def test_signed_principal_requires_audience_shape_and_anonymous_provider():
    import base64
    import json

    from batch_contract import PROJECT

    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    header = part({"alg": "RS256"})
    payload = part(
        {"sub": "B", "aud": PROJECT, "firebase": {"sign_in_provider": "anonymous"}}
    )
    token = header + "." + payload + ".shape-only"
    assert module().signed_principal(token, "B", "anonymous")
    assert not module().signed_principal(token, "A", "anonymous")
    assert not module().signed_principal(token, "B", "password")
    assert not module().signed_principal(header + "." + payload + ".", "B", "anonymous")


def test_public_observations_never_publish_credential_bytes():
    users = {"a": {"uid": "private-a"}, "b": {"uid": "private-b"}}
    public = module().public_state(
        {
            "response": {
                "localId": "private-b",
                "idToken": "private-token",
                "refreshToken": "private-refresh",
                "passwordHash": "private-hash",
            }
        },
        users,
    )
    assert "private" not in str(public)
    assert public["response"]["localId"] == {"$account": "b"}


def test_profile_update_cannot_link_or_remove_a_provider():
    before = states()
    after = copy.deepcopy(before)
    after["b"]["providerUserInfo"] = [{"providerId": "password"}]
    assert not all(module().assess(200, before, after).values())


def test_provider_display_name_mirror_is_not_an_identity_change():
    before = states()
    before["b"]["providerUserInfo"] = [
        {"providerId": "password", "rawId": "B", "displayName": "B-before"}
    ]
    after = copy.deepcopy(before)
    after["b"]["displayName"] = "updated"
    after["b"]["providerUserInfo"][0]["displayName"] = "updated"
    assert all(module().assess(200, before, after).values())
    assert not all(module().assess(400, before, after).values())
    for mutation in ["identity", "missing", "duplicate"]:
        changed = copy.deepcopy(after)
        if mutation == "identity":
            changed["b"]["providerUserInfo"][0]["rawId"] = "other"
        elif mutation == "missing":
            del changed["b"]["providerUserInfo"][0]["rawId"]
        else:
            changed["b"]["providerUserInfo"].append(
                copy.deepcopy(changed["b"]["providerUserInfo"][0])
            )
        assert not all(module().assess(200, before, changed).values())


def test_successful_profile_update_keeps_credential_value_and_presence():
    for field in ["passwordHash", "salt", "passwordUpdatedAt", "validSince"]:
        for value in ["original", None, 123]:
            before = states()
            before["b"][field] = value
            unchanged = copy.deepcopy(before)
            unchanged["b"]["displayName"] = "updated"
            assert all(module().assess(200, before, unchanged).values())
            changed = copy.deepcopy(unchanged)
            changed["b"][field] = "replacement"
            assert not all(module().assess(200, before, changed).values())
            del changed["b"][field]
            assert not all(module().assess(200, before, changed).values())
        before = states()
        changed = copy.deepcopy(before)
        changed["b"][field] = None
        assert not all(module().assess(200, before, changed).values())
