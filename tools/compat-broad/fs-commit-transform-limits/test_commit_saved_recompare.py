"""Offline recompare of a saved receipt under a repaired comparator."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import commit_acquisition as acquisition
import commit_saved_recompare as recompare
from commit_reserved_adapter import ROOT
from test_commit_acquisition import fixture
from test_transform_comparator import _recovery_rows, _rows

LANE = ROOT / "tools/compat-broad/fs-commit-transform-limits"


def _saved(tmp_path, monkeypatch):
    inputs, _, _, kwargs = fixture(tmp_path, monkeypatch)
    output = tmp_path / "output"
    released = acquisition.run_acquisition(output, inputs, **kwargs)
    assert released["reservationReleased"] is True
    plan = inputs["plan"]
    reference = tmp_path / "reference.json"
    reference.write_text(
        json.dumps({"plan": plan, "rows": _rows(plan), "cleanup": _recovery_rows(plan)})
    )
    return inputs, output, reference


def test_saved_recompare_binds_both_comparators_without_production(
    tmp_path, monkeypatch
):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    record = recompare.recompare_saved(
        output,
        reference,
        expected_inputs_digest=inputs["inputsDigest"],
        comparator_root=LANE,
        expected_execution_kind="injected-transport",
    )
    assert record["newProductionRequests"] == 0
    assert record["productionExecuted"] is False
    assert record["frozen"]["classification"] == "MATCH"
    assert record["repaired"]["classification"] == "MATCH"
    assert sum(record["repaired"]["rowClassificationCounts"].values()) == 17
    binding = record["binding"]
    assert binding["expectedInputsDigest"] == inputs["inputsDigest"]
    assert set(binding["comparatorSourceSha256"]) == {
        "transform_comparator.py",
        "transform_compiler.py",
    }
    assert (
        binding["comparatorSourceSha256"]["transform_comparator.py"]
        == binding["frozenComparatorSourceSha256"]["transform_comparator.py"]
    )


def test_saved_recompare_still_validates_the_immutable_saved_records(
    tmp_path, monkeypatch
):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    (output / "collection/observation-00.json").write_text("{}")
    with pytest.raises(ValueError, match="saved row journal differs"):
        recompare.recompare_saved(
            output,
            reference,
            expected_inputs_digest=inputs["inputsDigest"],
            comparator_root=LANE,
            expected_execution_kind="injected-transport",
        )


def test_saved_recompare_refuses_a_comparator_root_without_sources(
    tmp_path, monkeypatch
):
    inputs, output, reference = _saved(tmp_path, monkeypatch)
    empty = tmp_path / "empty-comparator-root"
    empty.mkdir()
    with pytest.raises(subprocess.CalledProcessError):
        recompare.recompare_saved(
            output,
            reference,
            expected_inputs_digest=inputs["inputsDigest"],
            comparator_root=empty,
            expected_execution_kind="injected-transport",
        )
