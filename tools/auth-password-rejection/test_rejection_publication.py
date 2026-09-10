"""A new refusal slice cannot reinterpret an earlier approved password receipt."""

import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-password-rejection.py"
    spec = importlib.util.spec_from_file_location("rejection_publisher", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_previous_password_receipt_is_not_this_candidate():
    p = publisher()
    old = json.loads(
        (p.ROOT / "spec/compatibility/evidence/auth-password/receipt.json").read_bytes()
    )
    with pytest.raises(ValueError):
        p.validate(old)
