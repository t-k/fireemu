"""A no-change control cannot establish continuity by matching token rejection."""

import ast
import importlib.util
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("continuity_contract.py")
    assert path.exists(), "Independent no-change contract required"
    spec = importlib.util.spec_from_file_location("continuity_contract", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_corpus_is_no_change_and_finite():
    c = contract()
    assert c.CORPUS["slice"] == "auth-session-continuity"
    assert c.CORPUS["revision"] == 1
    assert len(c.CASES) == 34
    assert c.CASES[9] == "reference-refresh"
    assert c.CASES[28:30] == ("final-signin", "final-lookup")
    assert c.OFFSETS == (0, 10000, 30000)
    assert c.DEADLINE_MS == 45000


@pytest.mark.parametrize(
    "action", ["update", "resetPassword", "disableUser", "revokeTokens"]
)
def test_mutation_routes_are_rejected(action):
    with pytest.raises(ValueError):
        contract().validate_client_action(action)


def test_only_existing_lifecycle_and_read_routes_are_allowed():
    c = contract()
    for action in ("signUp", "signInWithPassword", "lookup", "delete"):
        assert c.validate_client_action(action) == action


def test_continuity_requires_accepted_primary_and_derived_lookup_in_every_lane():
    c = contract()
    good = {"outcome": "accepted"}
    for lane in c.LANES:
        follow = good if "refresh" in lane else None
        assert c.sample_quality(good, follow, 0, 100, 0, lane) == "observed"
        for outcome in (
            "auth-rejected",
            "unexpected",
            "transport-failure",
            "not-sampled",
        ):
            assert (
                c.sample_quality({"outcome": outcome}, None, 0, 100, 0, lane)
                == "inconclusive"
            )
            if "refresh" in lane:
                assert (
                    c.sample_quality(good, {"outcome": outcome}, 0, 100, 0, lane)
                    == "inconclusive"
                )


def test_offset_model_does_not_extend_to_reach_success():
    c = contract()
    good = {"outcome": "accepted"}
    for offset in c.OFFSETS:
        for start in (offset, offset + 2000, offset + 2001, 44999, 45000, 60000):
            quality = c.sample_quality(good, None, start, start + 1, offset, "a-id")
            assert (quality == "observed") is (
                offset <= start <= offset + 2000 and start + 1 <= 45000
            )
    assert not c.may_start(45000)


def test_recorder_client_is_guarded_and_contains_no_password_mutation_route():
    path = Path(__file__).with_name("continuity_recorder.py")
    assert path.exists()
    tree = ast.parse(path.read_text())
    client = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "client"
    )
    assert "validate_client_action(action)" in ast.unparse(client)
    route_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "client"
    ]
    assert route_calls
    c = contract()
    for call in route_calls:
        assert isinstance(call.args[0], ast.Constant)
        c.validate_client_action(call.args[0].value)
    assert "replacement" not in ast.unparse(tree)


def test_response_projection_preserves_identity_and_excludes_secrets():
    c = contract()
    raw = {
        "users": [
            {
                "localId": "uid",
                "email": "email",
                "passwordHash": "SECRET",
                "validSince": "123",
            }
        ]
    }
    value = c.response(200, raw, "lookup", "uid", "email")
    c.validate_response(value, "lookup")
    assert value["outcome"] == "accepted"
    assert "SECRET" not in str(value)
    assert c.response(200, raw, "lookup", "wrong", "email")["outcome"] == "unexpected"
    with pytest.raises(ValueError):
        c.validate_response({**value, "idToken": "SECRET"}, "lookup")
    for kind in ("token", "lookup", "refresh", "delete", "absence"):
        for outcome in ("not-sampled", "transport-failure"):
            missing = c.unavailable(kind, outcome)
            c.validate_response(missing, kind)
            assert missing["outcome"] != "auth-rejected"
