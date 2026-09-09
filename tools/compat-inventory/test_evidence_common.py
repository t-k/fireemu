"""Durable journals must survive invalid replacement data."""

import json

import pytest
from evidence_common import read, save


def test_failed_serialization_preserves_previous_recovery_journal(tmp_path):
    path = tmp_path / "receipt.json"
    save(path, {"attempted": ["owned"]})
    with pytest.raises(ValueError):
        save(path, {"bad": float("nan")})
    assert json.loads(path.read_bytes()) == {"attempted": ["owned"]}


def test_bundle_paths_cannot_escape_the_evidence_root(tmp_path):
    root = tmp_path / "bundle"
    root.mkdir()
    outside = tmp_path / "outside.json"
    save(outside, {"private": True})
    (root / "link.json").symlink_to(outside)
    for name in ["../outside.json", str(outside), "link.json"]:
        with pytest.raises(ValueError):
            read(root, name)
