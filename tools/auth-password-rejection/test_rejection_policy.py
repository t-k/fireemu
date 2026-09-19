"""Creation eligibility is bounded to an explicit client policy readback."""

import importlib.util
import sys
from pathlib import Path

import pytest


def recorder():
    path = Path(__file__).with_name("rejection_recorder.py")
    assert path.exists(), "Password recorder is required"
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("rejection_recorder", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_explicit_default_policy_not_inferred_from_missing_admin_policy():
    r = recorder()
    passwords = ("Aa9!" + "a" * 43, "Aa9!" + "b" * 43)
    assert r.password_policy(200, r.PASSWORD_POLICY, passwords) == r.PASSWORD_POLICY
    for value in [
        {},
        None,
        {**r.PASSWORD_POLICY, "schemaVersion": True},
        {**r.PASSWORD_POLICY, "enforcementState": "OFF"},
        {
            **r.PASSWORD_POLICY,
            "customStrengthOptions": {"minPasswordLength": 6, "maxPasswordLength": 30},
        },
        {**r.PASSWORD_POLICY, "unexpected": "SECRET"},
    ]:
        with pytest.raises(ValueError):
            r.password_policy(200, value, passwords)
    with pytest.raises(ValueError):
        r.password_policy(403, r.PASSWORD_POLICY, passwords)


def test_passwords_are_distinct_long_and_have_all_character_categories():
    r = recorder()
    for pair in [
        ("short", "short"),
        ("Aa9!" + "a" * 43,) * 2,
        ("A9!" + "a" * 44, "Aa9!" + "b" * 43),
    ]:
        with pytest.raises(ValueError):
            r.password_policy(200, r.PASSWORD_POLICY, pair)
