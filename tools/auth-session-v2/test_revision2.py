"""New invalid-input controls stay distinct from revoked-session observations."""

import importlib.util
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("session_v2_contract.py")
    assert path.exists(), "Independent revision 2 contract required"
    spec = importlib.util.spec_from_file_location("session_v2_contract", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision2_adds_fixed_invalid_input_controls():
    c = contract()
    assert c.CORPUS["revision"] == 2
    assert len(c.CASES) == 34
    assert c.CASES[-4:-2] == ("malformed-refresh", "unknown-refresh")


@pytest.mark.parametrize(
    "status,error,expected",
    [
        (400, "INVALID_REFRESH_TOKEN", "observed"),
        (400, "TOKEN_EXPIRED", "inconclusive"),
        (403, "INVALID_REFRESH_TOKEN", "inconclusive"),
        (500, "INTERNAL", "inconclusive"),
    ],
)
def test_invalid_control_cannot_pass_with_revoked_or_transport_error(
    status, error, expected
):
    c = contract()
    value = c.response(status, {"error": {"message": error}}, "refresh", "uid", "email")
    assert c.invalid_control_quality(value) == expected
