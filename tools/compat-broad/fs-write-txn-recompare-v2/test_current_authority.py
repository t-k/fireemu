"""Tests for the bounded current-artifact Write-stream authority."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
AUTHORITY = HERE / "current_authority.py"
REPOSITORY_ROOT = HERE.parents[2].parents[1]
ROOT = Path(
    os.environ.get("FIREEMU_WRITE_CURRENT_ROOT", str(REPOSITORY_ROOT))
).resolve()
RUNTIME = (
    Path(os.environ["FIREEMU_WRITE_CURRENT_RUNTIME_SOURCE"]).resolve()
    if "FIREEMU_WRITE_CURRENT_RUNTIME_SOURCE" in os.environ
    else None
)
ARTIFACT = Path(
    os.environ.get(
        "FIREEMU_WRITE_CURRENT_ARTIFACT",
        str(
            REPOSITORY_ROOT
            / "docs.local/runs/saved-runtime-20260922-approved/projection-e896/fireemu"
        ),
    )
).resolve()
MANIFEST = Path(
    os.environ.get(
        "FIREEMU_WRITE_CURRENT_MANIFEST",
        str(
            REPOSITORY_ROOT
            / "docs.local/runs/saved-runtime-20260922-approved/build/build-local.json"
        ),
    )
).resolve()
RECEIPT = Path(
    os.environ.get(
        "FIREEMU_WRITE_CURRENT_RECEIPT",
        str(
            REPOSITORY_ROOT
            / "docs.local/runs/write-txn-e896-2a1e95a98-retry01/receipt.json"
        ),
    )
).resolve()
PRODUCTION = Path(
    os.environ.get(
        "FIREEMU_WRITE_CURRENT_PRODUCTION",
        str(
            REPOSITORY_ROOT
            / "docs.local/logs/2026-09-17/stream-production-preflight/execution-dee737c14/receipt.json"
        ),
    )
).resolve()
PRIVATE = os.environ.get("FIREEMU_WRITE_CURRENT_PRIVATE_TESTS") == "1"


def run_authority(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(AUTHORITY),
            "--root",
            str(tmp_path),
            "--runtime-source",
            str(tmp_path),
            "--authority-commit",
            "2a1e95a9835094ad640b4f012c8dddf9557e5647",
            "--production",
            str(tmp_path / "production.json"),
            "--output",
            str(tmp_path / "out.json"),
            *extra,
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )


def run_private(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(AUTHORITY),
            "--root",
            str(ROOT),
            "--runtime-source",
            str(RUNTIME or ROOT),
            "--artifact",
            str(ARTIFACT),
            "--build-manifest",
            str(MANIFEST),
            "--receipt",
            str(RECEIPT),
            "--production",
            str(PRODUCTION),
            "--authority-commit",
            "2a1e95a9835094ad640b4f012c8dddf9557e5647",
            "--output",
            str(tmp_path / "out.json"),
            *extra,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def assert_refused(result: subprocess.CompletedProcess[str], output: Path) -> None:
    assert result.returncode == 2
    assert not output.exists()
    assert result.stderr.startswith("Current write authority refused (")


def test_regular_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"private")
    alias = tmp_path / "alias"
    alias.symlink_to(target)
    with pytest.raises(ValueError, match="regular trust root"):
        __import__("current_authority").regular(alias)


def test_read_snapshot_refuses_mutation(tmp_path: Path) -> None:
    authority = __import__("current_authority")
    path = tmp_path / "input"
    path.write_bytes(b"before")
    snapshots = {}
    authority.read(path, snapshots=snapshots)
    path.write_bytes(b"after")
    with pytest.raises(ValueError, match="input changed"):
        authority.read(path, snapshots=snapshots)


def test_projection_metrics_identical_projections_have_no_differences() -> None:
    authority = __import__("current_authority")
    projection = [{"events": [{"type": "status", "value": {"code": 5}}]}]
    assert authority.v1_projection_metrics(
        {"differences": {"production": projection, "local": projection}}
    ) == {
        "v1ComparedSlotCount": 1,
        "v1DifferingSlotCount": 0,
        "v1DifferenceLeafCount": 0,
    }


def test_projection_metrics_count_single_and_multiple_leaves() -> None:
    authority = __import__("current_authority")
    comparison = {
        "differences": {
            "production": [{"status": {"code": 5, "message": "a"}}, {"value": 1}],
            "local": [{"status": {"code": 5, "message": "b"}}, {"value": 2}],
        }
    }
    assert authority.v1_projection_metrics(comparison) == {
        "v1ComparedSlotCount": 2,
        "v1DifferingSlotCount": 2,
        "v1DifferenceLeafCount": 2,
    }


def test_projection_metrics_count_missing_array_items_and_typed_values() -> None:
    authority = __import__("current_authority")
    comparison = {
        "differences": {
            "production": [{"values": [False, {"present": True}]}],
            "local": [{"values": [0]}],
        }
    }
    assert authority.v1_projection_metrics(comparison) == {
        "v1ComparedSlotCount": 1,
        "v1DifferingSlotCount": 1,
        "v1DifferenceLeafCount": 2,
    }


@pytest.mark.parametrize(
    ("production", "local"),
    [
        (False, 0),
        ({"value": {"enabled": False}}, {"value": {"enabled": 0}}),
    ],
)
def test_projection_metrics_typed_boolean_number_differences_count_slots(
    production: object, local: object
) -> None:
    authority = __import__("current_authority")
    assert authority.v1_projection_metrics(
        {"differences": {"production": [production], "local": [local]}}
    ) == {
        "v1ComparedSlotCount": 1,
        "v1DifferingSlotCount": 1,
        "v1DifferenceLeafCount": 1,
    }


def test_missing_configured_root_refuses_without_output(tmp_path: Path) -> None:
    result = run_authority(tmp_path)
    assert result.returncode == 2
    assert not (tmp_path / "out.json").exists()
    assert (
        result.stderr.strip() == "Current write authority refused (FileNotFoundError)."
    )


@pytest.mark.skipif(
    not PRIVATE, reason="private saved receipt and clean runtime are not enabled"
)
def test_private_current_receipt_is_sanitized_and_bounded(tmp_path: Path) -> None:
    result = run_private(tmp_path)
    assert result.returncode == 0, result.stderr
    summary = json.loads((tmp_path / "out.json").read_text())
    assert summary["kind"] == "stream-current-authority-v2"
    assert summary["acquisitionValidated"] is True
    assert summary["promotionReady"] is False
    assert summary["classification"] in {"MATCH", "MISMATCH", "EXPECTED_NONDETERMINISM"}
    assert summary["classification"] != "INDETERMINATE"
    assert summary["rowCounts"]["observations"] == 15
    assert summary["rowCounts"]["recoveryObservations"] == 10
    assert summary["rowCounts"]["gateEvents"] == 23
    assert summary["rowCounts"]["v1ComparedSlotCount"] == 15
    assert summary["rowCounts"]["v1DifferingSlotCount"] == 5
    assert summary["rowCounts"]["v1DifferenceLeafCount"] == 32
    assert "v1DifferenceCount" not in summary["rowCounts"]
    assert summary["rowCounts"]["indeterminate"] == 0
    assert summary["bindings"]["runtimeInputCount"] == 430
    assert summary["productionExecuted"] is False
    assert stat.S_IMODE((tmp_path / "out.json").stat().st_mode) == 0o600


@pytest.mark.skipif(
    not PRIVATE, reason="private saved receipt and clean runtime are not enabled"
)
def test_private_preexisting_output_refuses_without_replacement(tmp_path: Path) -> None:
    output = tmp_path / "out.json"
    output.write_text("sentinel\n")
    result = run_private(tmp_path)
    assert result.returncode == 2
    assert result.stderr.startswith("Current write authority refused (")
    assert output.read_text() == "sentinel\n"


@pytest.mark.skipif(
    not PRIVATE, reason="private saved receipt and clean runtime are not enabled"
)
@pytest.mark.parametrize("flag", ["artifact", "build-manifest"])
def test_private_artifact_and_manifest_mutations_refuse(
    tmp_path: Path, flag: str
) -> None:
    mutated = tmp_path / flag
    mutated.write_bytes(b"mutated")
    result = run_private(tmp_path, f"--{flag}", str(mutated))
    assert_refused(result, tmp_path / "out.json")


@pytest.mark.skipif(
    not PRIVATE, reason="private saved receipt and clean runtime are not enabled"
)
@pytest.mark.parametrize("flag", ["receipt", "production"])
def test_private_receipt_and_production_mutations_refuse(
    tmp_path: Path, flag: str
) -> None:
    mutated = tmp_path / flag
    mutated.write_bytes(b"mutated")
    result = run_private(tmp_path, f"--{flag}", str(mutated))
    assert_refused(result, tmp_path / "out.json")


@pytest.mark.skipif(
    not PRIVATE, reason="private saved receipt and clean runtime are not enabled"
)
def test_private_symlink_alias_refuses(tmp_path: Path) -> None:
    alias = tmp_path / "receipt-alias"
    alias.symlink_to(RECEIPT)
    result = run_private(tmp_path, "--receipt", str(alias))
    assert_refused(result, tmp_path / "out.json")
