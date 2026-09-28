import importlib.util
import json
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("auth_v2_contract.py")
    assert path.exists(), "Auth lifecycle contracts must exist"
    spec = importlib.util.spec_from_file_location("auth_basic_contract", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_absence_requires_a_successful_well_formed_lookup():
    c = contract()
    assert c.users(200, {}) == []
    assert c.users(200, {"users": []}) == []
    for status, value in [
        (403, {}),
        (200, None),
        (200, {"error": {}}),
        (200, {"users": None}),
        (200, {"users": [None]}),
    ]:
        with pytest.raises(ValueError):
            c.users(status, value)


def test_owned_identity_requires_exact_email_marker_and_uid():
    c = contract()
    user = {"localId": "uid", "email": "random@example.test", "displayName": "marker"}
    assert c.owned([user], user["email"], "marker", "uid") == "uid"
    for field in user:
        changed = {**user, field: "someone-else"}
        with pytest.raises(ValueError):
            c.owned([changed], user["email"], "marker", "uid")
    for values in [[], [user, user]]:
        with pytest.raises(ValueError):
            c.owned(values, user["email"], "marker")


def test_projection_never_copies_secret_values_or_unknown_fields():
    c = contract()
    value = {
        "idToken": "SECRET",
        "refreshToken": "SECRET",
        "localId": "uid",
        "email": "random@example.test",
        "expiresIn": "3600",
        "extra": "SECRET",
    }
    result = c.tokens(value, "uid", "random@example.test")
    assert all(result.values())
    assert "SECRET" not in json.dumps(result)
    refresh = {
        "id_token": "SECRET",
        "refresh_token": "SECRET",
        "user_id": "uid",
        "expires_in": "3600",
        "token_type": "Bearer",
    }
    assert all(c.tokens(refresh, "uid", "random@example.test", refresh=True).values())
    assert (
        c.error_code({"error": {"message": "INVALID_LOGIN_CREDENTIALS : SECRET"}})
        == "INVALID_LOGIN_CREDENTIALS"
    )
    assert c.error_code({"error": {"message": "SECRET@EMAIL"}}) == "UNCLASSIFIED_ERROR"


def test_token_shape_checks_do_not_confuse_bool_or_empty_with_valid_values():
    c = contract()
    for value in [{}, {"idToken": True, "refreshToken": "", "expiresIn": True}]:
        assert not all(c.tokens(value, "uid", "email").values())


def test_observation_completion_is_not_semantic_agreement():
    c = contract()
    report = {
        "status": "failed",
        "cases": [{"id": name, "passed": False} for name in c.CASES],
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
    }
    assert c.complete(report)
    for field in ["failure", "cleanupFailure", "childCleanupFailure"]:
        assert not c.complete({**report, field: "failure"})
    assert not c.complete({**report, "status": "owned-run-failed"})
    assert not c.complete(
        {**report, "cleanup": {"uidAbsent": False, "emailAbsent": True}}
    )
    assert not c.complete({**report, "cases": report["cases"][:-1]})


def test_indeterminate_create_cannot_be_proven_clean_by_empty_lookups():
    c = contract()
    assert hasattr(c, "cleanup_confirmed"), "Cleanup must model unresolved creation"
    # Exhaust the bounded state space, including delayed commit after empty reads.
    for known_uid in [None, "uid"]:
        for uid_absent in [False, True]:
            for email_absent in [False, True]:
                assert c.cleanup_confirmed(known_uid, uid_absent, email_absent) is (
                    known_uid is not None and uid_absent and email_absent
                )


def test_cleanup_state_model_kills_removed_identity_and_absence_guards():
    import inspect

    c = contract()
    source = inspect.getsource(c.cleanup_confirmed)
    guards = [
        "isinstance(uid, str)",
        "bool(uid)",
        "uid_absent is True",
        "email_absent is True",
    ]
    for guard in guards:
        assert guard in source
        namespace = {}
        exec(source.replace(guard, "True", 1), namespace)  # noqa: S102 -- Bounded mutation of repository source, not external input.
        mutant = namespace["cleanup_confirmed"]
        killed = any(
            mutant(uid, uid_absent, email_absent)
            != c.cleanup_confirmed(uid, uid_absent, email_absent)
            for uid in [None, "", 123, "uid"]
            for uid_absent in [False, True]
            for email_absent in [False, True]
        )
        assert killed, f"Surviving cleanup guard mutant: {guard}"
