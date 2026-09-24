"""Tests for the bounded offline c1 transaction-stream comparison."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
AUTHORITY = HERE / "c1_current_authority.py"
WORKTREE_ROOT = HERE.parents[2]
INPUT_ROOT = Path(
    os.environ.get(
        "FIREEMU_C1_AUTHORITY_INPUT_ROOT", "/Users/tk/work/firebase-emulator"
    )
)
AUTHORITY_COMMIT = os.environ.get("FIREEMU_C1_AUTHORITY_COMMIT", "")
PRIVATE = os.environ.get("FIREEMU_C1_AUTHORITY_PRIVATE_TESTS") == "1"


def run_authority(
    root: Path, input_root: Path, output: Path, *extra: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(AUTHORITY),
            "--root",
            str(root),
            "--input-root",
            str(input_root),
            "--authority-commit",
            AUTHORITY_COMMIT or "0" * 40,
            "--output",
            str(output),
            *extra,
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )


def test_missing_roots_refuse_without_output(tmp_path: Path) -> None:
    result = run_authority(tmp_path, tmp_path, tmp_path / "out.json")
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()
    assert result.stderr.startswith("c1 current authority refused (")


@pytest.mark.skipif(not PRIVATE, reason="private saved receipts are not enabled")
def test_private_saved_pair_is_bound_and_comparison_is_preserved(
    tmp_path: Path,
) -> None:
    assert AUTHORITY_COMMIT
    result = run_authority(WORKTREE_ROOT, INPUT_ROOT, tmp_path / "out.json")
    assert result.returncode == 0, result.stderr
    summary = json.loads((tmp_path / "out.json").read_text())
    assert summary["kind"] == "fs-write-txn-c1-current-authority-v1"
    assert summary["acquisitionValidated"] is True
    assert summary["promotionReady"] is False
    assert summary["classification"] == "EXPECTED_NONDETERMINISM"
    assert summary["v1Classification"] == "SEMANTIC_MISMATCH"
    assert summary["productionExecuted"] is False
    assert summary["rowCounts"] == {
        "observations": 15,
        "recoveryObservations": 10,
        "gateEvents": 23,
        "v1ComparedSlotCount": 15,
        "v1DifferingSlotCount": 5,
        "v1DifferenceLeafCount": 32,
        "indeterminate": 0,
    }
    assert (
        summary["bindings"]["runtimeSourceCommit"]
        == "c1d24250a62d23b38bcfed6da51f1ba4ed5798bb"
    )
    assert summary["bindings"]["runtimeInputCount"] == 434
    assert stat.S_IMODE((tmp_path / "out.json").stat().st_mode) == 0o600


@pytest.mark.skipif(not PRIVATE, reason="private saved receipts are not enabled")
@pytest.mark.parametrize(
    "flag", ["artifact", "build-manifest", "receipt", "production"]
)
def test_private_mutated_trust_roots_refuse_without_output(
    tmp_path: Path, flag: str
) -> None:
    mutated = tmp_path / flag
    mutated.write_bytes(b"substituted trust root")
    result = run_authority(
        WORKTREE_ROOT, INPUT_ROOT, tmp_path / "out.json", f"--{flag}", str(mutated)
    )
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()
    assert result.stderr.startswith("c1 current authority refused (")


@pytest.mark.skipif(not PRIVATE, reason="private saved receipts are not enabled")
def test_private_preexisting_output_is_not_replaced(tmp_path: Path) -> None:
    output = tmp_path / "out.json"
    output.write_text("sentinel\n")
    result = run_authority(WORKTREE_ROOT, INPUT_ROOT, output)
    assert result.returncode == 2
    assert output.read_text() == "sentinel\n"
