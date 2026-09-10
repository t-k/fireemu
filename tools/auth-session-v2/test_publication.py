"""The new publisher must not reinterpret revision 1 evidence."""

import importlib.util
import json
from pathlib import Path

import pytest


def publisher():
    path = Path(__file__).parents[1] / "publish-auth-session-v2.py"
    assert path.exists(), "New publisher required"
    spec = importlib.util.spec_from_file_location("session_v2_publisher", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_revision1_receipt_is_not_revision2_evidence():
    p = publisher()
    original = json.loads(
        (
            p.ROOT / "spec/compatibility/evidence/auth-session-token/receipt.json"
        ).read_bytes()
    )
    with pytest.raises(ValueError):
        p.validate(original)
