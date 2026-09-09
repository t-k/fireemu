"""Durable journals must survive invalid replacement data."""

import json

import pytest
from evidence_common import save


def test_failed_serialization_preserves_previous_recovery_journal(tmp_path):
    path = tmp_path / "receipt.json"
    save(path, {"attempted": ["owned"]})
    with pytest.raises(ValueError):
        save(path, {"bad": float("nan")})
    assert json.loads(path.read_bytes()) == {"attempted": ["owned"]}
