"""No-change evidence has its own subject, never inherited password-change approval."""

import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-session-continuity.py"
    assert path.exists(), "Independent continuity publisher required"
    spec = importlib.util.spec_from_file_location("continuity_publisher", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_changed_password_receipt_is_not_no_change_evidence():
    p = publisher()
    receipt = json.loads(
        (
            p.ROOT / "spec/compatibility/evidence/auth-session-v2/receipt.json"
        ).read_bytes()
    )
    with pytest.raises(ValueError):
        p.validate(receipt)
