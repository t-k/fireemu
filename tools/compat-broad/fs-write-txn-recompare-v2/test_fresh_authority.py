"""Tests for the source-bound fresh stream authority."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
AUTHORITY = HERE / "fresh_authority.py"
REVIEWED_COMMIT = os.environ.get("FIREEMU_FRESH_AUTHORITY_COMMIT", "0" * 40)


def private_inputs() -> tuple[Path, Path, str]:
    root = Path(os.environ["FIREEMU_FRESH_STREAM_ROOT"])
    runtime = Path(os.environ["FIREEMU_FRESH_STREAM_RUNTIME_SOURCE"])
    return root, runtime, REVIEWED_COMMIT


def copy_fixture_root(tmp_path: Path, root: Path) -> Path:
    fixture = tmp_path / "inputs"
    for relative in (
        "docs.local/artifacts/cx-limits-nx-20260922-record-20260922-030423/fireemu",
        "docs.local/artifacts/cx-limits-nx-20260922-record-20260922-030423/manifest.json",
        "docs.local/runs/cx-write-stream-0591-20260922/receipt.json",
        "docs.local/logs/2026-09-17/stream-production-preflight/execution-dee737c14/receipt.json",
    ):
        source = root / relative
        target = fixture / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return fixture


def run_authority(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(AUTHORITY), "--root", str(tmp_path), "--runtime-source", str(tmp_path), "--authority-commit", REVIEWED_COMMIT, "--output", str(tmp_path / "out.json"), *extra],
        cwd=tmp_path,
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
    or not os.environ.get("FIREEMU_FRESH_STREAM_RUNTIME_SOURCE")
    or not os.environ.get("FIREEMU_FRESH_AUTHORITY_COMMIT"),
    reason="retained private fresh stream inputs were not supplied",
)
def test_retained_fresh_receipt_uses_real_authority(tmp_path: Path) -> None:
    root, runtime, reviewed_commit = private_inputs()
    result = run_authority(tmp_path, "--runtime-source", str(runtime), "--input-root", str(root), "--authority-commit", reviewed_commit)
    assert result.returncode == 0, result.stderr
    value = json.loads((tmp_path / "out.json").read_text())
    assert value["acquisitionValidated"] is True
    assert value["promotionReady"] is False
    assert value["classification"] in {"EXPECTED_NONDETERMINISM", "SEMANTIC_MISMATCH"}
    assert value["rowCounts"]["indeterminate"] == 0
    assert value["rowCounts"]["v1DifferenceCount"] == 15


@pytest.mark.skipif(
    not os.environ.get("FIREEMU_FRESH_STREAM_ROOT")
    or not os.environ.get("FIREEMU_FRESH_STREAM_RUNTIME_SOURCE")
    or not os.environ.get("FIREEMU_FRESH_AUTHORITY_COMMIT"),
    reason="retained private fresh stream inputs were not supplied",
)
def test_mutated_receipt_refuses_before_output(tmp_path: Path) -> None:
    root, runtime, reviewed_commit = private_inputs()
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
            "--authority-commit",
            reviewed_commit,
            "--receipt",
            str(mutated),
            "--output",
            str(tmp_path / "out.json"),
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()


@pytest.mark.skipif(
    not os.environ.get("FIREEMU_FRESH_STREAM_ROOT")
    or not os.environ.get("FIREEMU_FRESH_STREAM_RUNTIME_SOURCE")
    or not os.environ.get("FIREEMU_FRESH_AUTHORITY_COMMIT"),
    reason="retained private fresh stream inputs were not supplied",
)
def test_receipt_symlink_refuses_before_comparison(tmp_path: Path) -> None:
    root, runtime, reviewed_commit = private_inputs()
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
            "--authority-commit",
            reviewed_commit,
            "--receipt",
            str(alias),
            "--output",
            str(tmp_path / "out.json"),
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()


@pytest.mark.skipif(
    not os.environ.get("FIREEMU_FRESH_STREAM_ROOT")
    or not os.environ.get("FIREEMU_FRESH_STREAM_RUNTIME_SOURCE")
    or not os.environ.get("FIREEMU_FRESH_AUTHORITY_COMMIT"),
    reason="retained private fresh stream inputs were not supplied",
)
@pytest.mark.parametrize("mutation", ["artifact", "manifest", "production", "runtime-input", "extra-key"])
def test_copied_trust_root_mutations_refuse(tmp_path: Path, mutation: str) -> None:
    root, runtime, reviewed_commit = private_inputs()
    fixture = copy_fixture_root(tmp_path, root)
    if mutation == "artifact":
        target = fixture / "docs.local/artifacts/cx-limits-nx-20260922-record-20260922-030423/fireemu"
        target.chmod(target.stat().st_mode | stat.S_IWUSR)
        target.write_bytes(target.read_bytes() + b"mutation")
    elif mutation == "manifest":
        target = fixture / "docs.local/artifacts/cx-limits-nx-20260922-record-20260922-030423/manifest.json"
        target.write_bytes(target.read_bytes() + b"mutation")
    elif mutation == "production":
        target = fixture / "docs.local/logs/2026-09-17/stream-production-preflight/execution-dee737c14/receipt.json"
        target.write_bytes(target.read_bytes() + b"mutation")
    else:
        target = fixture / "docs.local/artifacts/cx-limits-nx-20260922-record-20260922-030423/manifest.json"
        value = json.loads(target.read_text())
        if mutation == "runtime-input":
            key = next(iter(value["runtimeInputs"]))
            value["runtimeInputs"][key] = "0" * 64
        else:
            value["runtimeInputs"]["extra"] = "0" * 64
        target.write_text(json.dumps(value, sort_keys=True) + "\n")
    result = run_authority(
        tmp_path,
        "--runtime-source",
        str(runtime),
        "--input-root",
        str(fixture),
        "--authority-commit",
        reviewed_commit,
    )
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()


@pytest.mark.skipif(
    not os.environ.get("FIREEMU_FRESH_STREAM_ROOT")
    or not os.environ.get("FIREEMU_FRESH_STREAM_RUNTIME_SOURCE")
    or not os.environ.get("FIREEMU_FRESH_AUTHORITY_COMMIT"),
    reason="retained private fresh stream inputs were not supplied",
)
def test_runtime_source_commit_mutation_refuses(tmp_path: Path) -> None:
    root, _, reviewed_commit = private_inputs()
    result = run_authority(
        tmp_path,
        "--runtime-source",
        str(AUTHORITY.parents[3]),
        "--input-root",
        str(root),
        "--authority-commit",
        reviewed_commit,
    )
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()
