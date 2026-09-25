"""A refusal alone cannot establish preserved credentials or a working update route."""

import ast
import importlib.util
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("rejection_contract.py")
    assert path.exists(), "Independent rejection contract required"
    spec = importlib.util.spec_from_file_location("rejection_contract", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_recorder_keeps_original_refresh_and_requires_working_update_control():
    source = Path(__file__).with_name("rejection_recorder.py").read_text()
    tree = ast.parse(source)
    refresh = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "refresh_original"
    )
    assert "baseline['refreshToken']" in ast.unparse(refresh)
    assert "secrets.token_hex(3)[:5]" in ast.unparse(tree)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert [
        node.args[0].value
        for node in calls
        if isinstance(node.func, ast.Name)
        and node.func.id == "refresh_original"
        and isinstance(node.args[0], ast.Constant)
    ] == ["baseline-refresh", "original-token-refresh"]
    updates = [
        node
        for node in calls
        if isinstance(node.func, ast.Name)
        and node.func.id == "client"
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "update"
    ]
    assert len(updates) == 2
    assert "weak" in ast.unparse(updates[0])
    assert "replacement" in ast.unparse(updates[1])


def test_case_set_includes_refusal_preservation_and_valid_change():
    c = contract()
    assert len(c.CASES) == 16
    assert c.CASES[4:7] == (
        "weak-password-rejected",
        "unchanged-state",
        "original-password-signin",
    )
    assert "original-token-refresh" in c.CASES
    assert "valid-password-change" in c.TOKEN_CASES
    assert "weak-password-rejected" not in c.TOKEN_CASES


@pytest.mark.parametrize(
    "status,error,passed",
    [
        (400, "WEAK_PASSWORD", True),
        (200, "WEAK_PASSWORD", False),
        (400, "INVALID_ID_TOKEN", False),
        (500, "WEAK_PASSWORD", False),
    ],
)
def test_rejection_projection_retains_code_without_raw_message(status, error, passed):
    c = contract()
    row = c.rejection(status, {"error": {"message": error + " : SECRET"}})
    assert row["passed"] is passed
    assert row["observedError"] == error
    assert "SECRET" not in str(row)
    c.validate_case(row, "weak-password-rejected")
    row["observedError"] = (
        "TOKEN_EXPIRED" if error == "WEAK_PASSWORD" else "WEAK_PASSWORD"
    )
    with pytest.raises(ValueError):
        c.validate_case(row, "weak-password-rejected")


def test_selected_state_keeps_presence_and_json_types():
    c = contract()
    assert c.selected_state({}) != c.selected_state({"disabled": None})
    assert c.selected_state({"disabled": False}) != c.selected_state({"disabled": 0})


def test_cleanup_failure_is_not_observation_completion():
    c = contract()
    value = {
        "status": "passed",
        "cases": [{"id": name, "passed": True} for name in c.CASES],
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
    }
    assert c.complete(value)
    for key in ("failure", "cleanupFailure", "childCleanupFailure"):
        assert not c.complete({**value, key: "ValueError"})


def test_unknown_uppercase_message_is_not_a_public_error_code():
    c = contract()
    row = c.rejection(400, {"error": {"message": "PRIVATE_ACCOUNT_MARKER"}})
    assert row["observedError"] == "UNCLASSIFIED_ERROR"
    assert "PRIVATE_ACCOUNT_MARKER" not in str(row)
    c.validate_case(row, "weak-password-rejected")
    row["observedError"] = "PRIVATE_ACCOUNT_MARKER"
    with pytest.raises(ValueError):
        c.validate_case(row, "weak-password-rejected")
