"""The minimum acceptance experiment cannot silently use a longer password."""

import ast
import importlib.util
import sys
from pathlib import Path

import pytest


def recorder():
    path = Path(__file__).with_name("minimum_recorder.py")
    assert path.exists(), "Independent minimum recorder required"
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("minimum_recorder", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_explicit_policy_and_minimum_shape():
    r = recorder()
    pair = ("Aa9!" + "a" * 43, "aB9_-z")
    assert r.password_policy(200, r.PASSWORD_POLICY, pair) == r.PASSWORD_POLICY
    assert r.input_shape(*pair) == {
        "originalPasswordLength": 47,
        "replacementPasswordLength": 6,
        "replacementAscii": True,
        "distinct": True,
    }
    for value in (
        {},
        None,
        {**r.PASSWORD_POLICY, "schemaVersion": True},
        {**r.PASSWORD_POLICY, "enforcementState": "OFF"},
    ):
        with pytest.raises(ValueError):
            r.password_policy(200, value, pair)
    with pytest.raises(ValueError):
        r.password_policy(403, r.PASSWORD_POLICY, pair)


@pytest.mark.parametrize(
    "replacement", ["abcde", "abcdefg", "あいうえおか", "", "Aa9!" + "a" * 43]
)
def test_nonminimum_inputs_cannot_enter_capture(replacement):
    r = recorder()
    with pytest.raises(ValueError):
        r.password_policy(200, r.PASSWORD_POLICY, ("Aa9!" + "a" * 43, replacement))


def test_generator_produces_six_ascii_characters():
    r = recorder()
    for _ in range(16):
        value = r.minimum_password()
        assert len(value) == 6 and value.isascii()
        r.password_policy(200, r.PASSWORD_POLICY, ("Aa9!" + "a" * 43, value))


def test_actual_update_and_signin_use_generated_minimum():
    tree = ast.parse(Path(__file__).with_name("minimum_recorder.py").read_text())
    source = ast.unparse(tree)
    assert "replacement = minimum_password()" in source
    assert "report['inputShape'] = input_shape(password, replacement)" in source
    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "client"
    ]
    update = next(
        n
        for n in calls
        if isinstance(n.args[0], ast.Constant) and n.args[0].value == "update"
    )
    assert "'password': replacement" in ast.unparse(update)
    assert any(
        "'password': replacement" in ast.unparse(n)
        and "signInWithPassword" in ast.unparse(n)
        for n in calls
    )
