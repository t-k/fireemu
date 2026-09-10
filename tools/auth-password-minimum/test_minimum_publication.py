"""Minimum input shape and prior evidence are never interchangeable."""

import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-password-minimum.py"
    spec = importlib.util.spec_from_file_location("minimum_publisher", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_prior_password_evidence_is_not_minimum_evidence():
    p = publisher()
    value = json.loads(
        (p.ROOT / "spec/compatibility/evidence/auth-password/receipt.json").read_bytes()
    )
    with pytest.raises(ValueError):
        p.validate(value)
