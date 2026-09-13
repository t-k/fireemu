"""Durable journals must survive invalid replacement data."""

import json

import pytest
from evidence_common import (
    AGGREGATION_PROBE_FILES_V1,
    ROOT,
    probe_inputs,
    probe_inputs_at_commit,
    read,
    save,
    sha,
)


def test_versioned_aggregation_identity_ignores_unrelated_source_files(tmp_path):
    source = tmp_path / "compat-inventory"
    source.mkdir()
    for name in AGGREGATION_PROBE_FILES_V1:
        (source / name).write_bytes(name.encode())
    (source / "unrelated.py").write_bytes(b"new helper")

    identity = probe_inputs("aggregation-v1", source)

    assert set(identity) == set(AGGREGATION_PROBE_FILES_V1)
    assert identity == {name: sha(name.encode()) for name in AGGREGATION_PROBE_FILES_V1}


def test_historical_aggregation_identity_replays_the_recorded_commit():
    receipt = json.loads(
        (ROOT / "spec/compatibility/evidence/aggregation/local.json").read_bytes()
    )

    assert (
        probe_inputs_at_commit("aggregation-v1", receipt["probeSource"]["commit"])
        == receipt["probeSource"]["files"]
    )


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
