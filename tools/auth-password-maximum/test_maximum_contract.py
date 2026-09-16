"""Maximum input relationships and policy rejection are distinct from authentication errors."""

import importlib.util
import sys
from pathlib import Path

import pytest


def load(name):
    path = Path(__file__).with_name(name + ".py")
    assert path.exists(), "Independent maximum boundary module required"
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_inputs_have_exact_boundary_and_prefix_relationships():
    r = load("maximum_recorder")
    maximum, tail, prefix, oversize = r.boundary_passwords()
    assert len(maximum) == 4096 and maximum.isascii()
    assert len(tail) == 4096 and maximum[:-1] == tail[:-1] and maximum[-1] != tail[-1]
    assert prefix == maximum[:-1] and oversize[:-1] == maximum and len(oversize) == 4097
    shape = r.input_shape("Aa9!" + "a" * 43, maximum, tail, prefix, oversize)
    assert shape["maximumLength"] == 4096 and shape["oversizeLength"] == 4097
    with pytest.raises(ValueError):
        r.input_shape("Aa9!" + "a" * 43, maximum, maximum, prefix, oversize)


@pytest.mark.parametrize(
    "code,expected",
    [
        ("PASSWORD_DOES_NOT_MEET_REQUIREMENTS", True),
        ("WEAK_PASSWORD", True),
        ("INVALID_ID_TOKEN", False),
        ("TOO_MANY_ATTEMPTS_TRY_LATER", False),
        ("PRIVATE_SECRET", False),
    ],
)
def test_oversize_refusal_is_not_any_error(code, expected):
    c = load("maximum_contract")
    row = c.rejection(
        "oversize-password-rejected",
        400,
        {"error": {"message": code + " : PRIVATE_SECRET"}},
    )
    assert row["passed"] is expected
    assert "PRIVATE_SECRET" not in str(row)
    c.validate_case(row, row["id"])
    row["checks"]["expectedError"] = not expected
    with pytest.raises(ValueError):
        c.validate_case(row, row["id"])


def test_tail_and_prefix_require_bad_credentials_not_policy_failure():
    c = load("maximum_contract")
    for name in ("tail-password-rejected", "prefix-password-rejected"):
        assert c.rejection(
            name, 400, {"error": {"message": "INVALID_LOGIN_CREDENTIALS"}}
        )["passed"]
        assert not c.rejection(name, 400, {"error": {"message": "WEAK_PASSWORD"}})[
            "passed"
        ]
    assert len(c.CASES) == 21
