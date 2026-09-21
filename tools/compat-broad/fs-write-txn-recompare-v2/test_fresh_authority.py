"""Tests for the source-bound fresh stream authority."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
AUTHORITY = HERE / "fresh_authority.py"


def run_authority(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(AUTHORITY), "--root", str(tmp_path), "--runtime-source", str(tmp_path), "--output", str(tmp_path / "out.json"), *extra],
        text=True,
        capture_output=True,
        check=False,
    )


def test_missing_configured_root_refuses_without_output(tmp_path: Path) -> None:
    result = run_authority(tmp_path)
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()
    assert result.stderr.strip() == "Fresh stream authority refused (FileNotFoundError)."


@pytest.mark.skipif(
    not os.environ.get("FIREEMU_FRESH_STREAM_ROOT")
    or not os.environ.get("FIREEMU_FRESH_STREAM_RUNTIME_SOURCE"),
    reason="retained private fresh stream inputs were not supplied",
)
def test_retained_fresh_receipt_uses_real_authority(tmp_path: Path) -> None:
    root = Path(os.environ["FIREEMU_FRESH_STREAM_ROOT"])
    runtime = Path(os.environ["FIREEMU_FRESH_STREAM_RUNTIME_SOURCE"])
    result = run_authority(tmp_path, "--runtime-source", str(runtime), "--input-root", str(root))
    assert result.returncode == 0, result.stderr
    value = json.loads((tmp_path / "out.json").read_text())
    assert value["acquisitionValidated"] is True
    assert value["promotionReady"] is False
    assert value["classification"] in {"EXPECTED_NONDETERMINISM", "SEMANTIC_MISMATCH"}
    assert value["rowCounts"]["indeterminate"] == 0
    assert value["rowCounts"]["v1DifferenceCount"] == 15


@pytest.mark.skipif(
    not os.environ.get("FIREEMU_FRESH_STREAM_ROOT")
    or not os.environ.get("FIREEMU_FRESH_STREAM_RUNTIME_SOURCE"),
    reason="retained private fresh stream inputs were not supplied",
)
def test_mutated_receipt_refuses_before_output(tmp_path: Path) -> None:
    root = Path(os.environ["FIREEMU_FRESH_STREAM_ROOT"])
    runtime = Path(os.environ["FIREEMU_FRESH_STREAM_RUNTIME_SOURCE"])
    receipt = root / "docs.local/runs/cx-write-stream-0591-20260922/receipt.json"
    mutated = tmp_path / "receipt.json"
    mutated.write_bytes(receipt.read_bytes() + b"\n")
    result = subprocess.run(
        [
            sys.executable,
            str(AUTHORITY),
            "--root",
            str(tmp_path),
            "--input-root",
            str(root),
            "--runtime-source",
            str(runtime),
            "--receipt",
            str(mutated),
            "--output",
            str(tmp_path / "out.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()


@pytest.mark.skipif(
    not os.environ.get("FIREEMU_FRESH_STREAM_ROOT")
    or not os.environ.get("FIREEMU_FRESH_STREAM_RUNTIME_SOURCE"),
    reason="retained private fresh stream inputs were not supplied",
)
def test_receipt_symlink_refuses_before_comparison(tmp_path: Path) -> None:
    root = Path(os.environ["FIREEMU_FRESH_STREAM_ROOT"])
    runtime = Path(os.environ["FIREEMU_FRESH_STREAM_RUNTIME_SOURCE"])
    alias = tmp_path / "receipt-alias.json"
    alias.symlink_to(root / "docs.local/runs/cx-write-stream-0591-20260922/receipt.json")
    result = subprocess.run(
        [
            sys.executable,
            str(AUTHORITY),
            "--root",
            str(tmp_path),
            "--input-root",
            str(root),
            "--runtime-source",
            str(runtime),
            "--receipt",
            str(alias),
            "--output",
            str(tmp_path / "out.json"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()
