"""Actual byte/scalar/UTF16 contrasts, without password material in projections."""

import importlib.util
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("boundary_contract.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("boundary_contract", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_three_actual_input_shapes_distinguish_counting_rules():
    c = contract()
    assert len(c.CASES) == 3
    for name in c.CASES:
        password = c.generate(name)
        shape = c.input_shape(name, password)
        assert shape == c.SHAPES[name]
        assert shape["scalars"] == len(password)
        assert shape["utf8Bytes"] == len(password.encode("utf-8"))
        assert shape["utf16Units"] == len(password.encode("utf-16-le")) // 2
        assert set(shape) == {"scalars", "utf8Bytes", "utf16Units"}
        with pytest.raises(ValueError):
            c.input_shape(name, password + "a")
        with pytest.raises(ValueError):
            c.input_shape(name, "!" + password[1:])


def test_counting_hypotheses_are_distinct_and_require_every_sample():
    c = contract()
    for metric in ("scalars", "utf8Bytes", "utf16Units"):
        outcomes = {
            name: "accepted" if shape[metric] <= 4096 else "refused"
            for name, shape in c.SHAPES.items()
        }
        assert c.hypotheses(outcomes) == [metric]
    assert c.hypotheses({}) == []


def test_projection_requires_real_controls_and_exact_shape():
    import copy

    c = contract()
    name = c.CASES[0]
    row: dict = {
        "id": name,
        "inputShape": c.SHAPES[name],
        "outcome": "accepted",
        "httpStatus": 200,
        "observedError": None,
        "checks": {key: True for key in c.STATE_CHECKS},
        "tokenChecks": {
            key: {
                "httpStatus": 200,
                "checks": {flag: True for flag in c.token_flags(key)},
                "expirySeconds": "3600",
            }
            for key in c.TOKEN_NAMES | {"update"}
        },
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
    }
    c.validate_case(row, name)
    for change in ("secret", "false", "cleanup", "wrong-error", "expiry", "shape"):
        bad = copy.deepcopy(row)
        if change == "secret":
            bad["token"] = "secret"
        elif change == "false":
            bad["checks"]["postLookup"] = False
        elif change == "cleanup":
            bad["cleanup"]["uidAbsent"] = False
        elif change == "wrong-error":
            bad["observedError"] = "INVALID_ID_TOKEN"
        elif change == "expiry":
            bad["tokenChecks"]["signup"]["expirySeconds"] = "1"
        else:
            bad["inputShape"]["scalars"] = True
        with pytest.raises(ValueError):
            c.validate_case(bad, name)
