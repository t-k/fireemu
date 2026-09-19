import importlib.util
import sys
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-basic.py"
    assert path.exists(), "Auth publication needs an offline validator"
    sys.path.insert(0, str(Path(__file__).parent))
    spec = importlib.util.spec_from_file_location("auth_basic_publication", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_unknown_and_secret_fields_are_never_publishable():
    p = publisher()
    for value in [
        {"idToken": "secret"},
        {"checks": {"secret": "value"}},
        {"checks": {"a": True}, "passed": False},
    ]:
        with pytest.raises(ValueError):
            p.validate_case(value, "signup")


def test_published_case_verdict_is_recomputed_from_fixed_checks():
    p = publisher()
    checks = {key: True for key in p.CHECKS["signup"]}
    row = {"id": "signup", "httpStatus": 200, "checks": checks, "passed": True}
    p.validate_case(row, "signup")
    for mutation in [
        {**row, "passed": False},
        {**row, "checks": {}},
        {**row, "httpStatus": True},
    ]:
        with pytest.raises(ValueError):
            p.validate_case(mutation, "signup")


def test_checked_in_auth_observations_are_candidates_with_current_inputs():
    p = publisher()
    assert p.BUNDLE.exists(), "Bounded observations must be captured before publication"
    text = p.render()
    assert "not approved" in text
    assert "9/9" in text
