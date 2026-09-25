"""Run the immutable v1 comparison, then write a separately bound v2 analysis."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

SIBLING = Path(__file__).resolve().parent.parent / "fs-write-limits"
sys.path.insert(0, str(SIBLING))
sys.path.insert(0, str(SIBLING.parent))

import production as _production
from broad_contract import digest
from v2_kernel import V2_SOURCE_SHA256 as V2_KERNEL_SOURCE_SHA256
from v2_kernel import compare_rows

VERSION = "fs-write-limits-recompare-v2"
V2_ENTRY_SOURCE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
V2_SOURCE_SHA256 = hashlib.sha256(
    json.dumps(
        {
            "recompare.py": V2_ENTRY_SOURCE_SHA256,
            "v2_kernel.py": V2_KERNEL_SOURCE_SHA256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()


def sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json_hashed(path: Path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("symlink evidence input refused")
    data = path.read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()


def _capture_file(source: Path, destination: Path) -> str:
    """Capture one stable regular-file read and return its captured digest."""
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode) or source.is_symlink():
        raise ValueError("regular local evidence file required")
    data = source.read_bytes()
    after = source.lstat()
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise ValueError("local evidence changed during capture")
    digest = hashlib.sha256(data).hexdigest()
    with destination.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return digest


def capture_local_bundle(directory: Path, artifact: Path, root: Path):
    """Snapshot each bundle input and the artifact exactly once."""
    root = Path(root)
    if not root.exists():
        root.mkdir(mode=0o700, exist_ok=False)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("private snapshot root must be a directory")
    snapshot = root / "local"
    snapshot.mkdir(mode=0o700)
    names = ("manifest.json", "cases.json", "result.json", "shadow-binding.json")
    hashes = {
        name: _capture_file(Path(directory) / name, snapshot / name) for name in names
    }
    artifact_snapshot = root / "artifact"
    artifact_hash = _capture_file(Path(artifact), artifact_snapshot)
    return snapshot, artifact_snapshot, hashes, artifact_hash


def create_output_directory(path: Path) -> Path:
    """Create one exclusive regular directory for all derived output."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("output is not a regular directory")
    return path


def save_json(path: Path, value) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _invalid_v2(v1_result):
    return {
        "kind": VERSION,
        "promotionReady": False,
        "acquisitionValidated": False,
        "classification": "INDETERMINATE",
        "originalContract": v1_result.get("kind"),
        "derivedAnalysis": True,
        "v1Classification": v1_result.get("classification", "INDETERMINATE"),
    }


def recompare(
    production_directory,
    local_directory,
    artifact,
    output,
    original_comparison=None,
):
    """Write v1 result first; v2 is emitted only after v1 acquisition validates."""
    output = create_output_directory(Path(output))
    v1_path = output / "v1-result.json"
    _production.compare(
        Path(production_directory), Path(local_directory), Path(artifact), v1_path
    )
    v1_result, v1_hash = read_json_hashed(v1_path)
    v2_result = _invalid_v2(v1_result)
    original_hash = None
    inputs_hash = None
    receipt_hash = None
    artifact_hash = None
    local_digest = None
    if original_comparison is not None:
        _, original_hash = read_json_hashed(Path(original_comparison))
    if v1_result.get("acquisitionValidated") is True:
        directory = Path(production_directory)
        inputs, inputs_hash = read_json_hashed(directory / "inputs.json")
        receipt, receipt_hash = read_json_hashed(directory / "receipt.json")
        if (
            v1_result.get("frozenInputsSha256") != inputs_hash
            or v1_result.get("productionReceiptSha256") != receipt_hash
        ):
            raise ValueError("v1 comparison bindings changed before v2 analysis")
        production_plan = _production.validate_saved_acquisition(
            receipt, inputs, receipt_hash, inputs_hash
        )
        with tempfile.TemporaryDirectory(prefix="fs-write-limits-v2-") as temporary:
            snapshot, artifact_snapshot, captured_hashes, artifact_hash = (
                capture_local_bundle(
                    Path(local_directory), Path(artifact), Path(temporary)
                )
            )
            if artifact_hash != v1_result.get("artifactSha256"):
                raise ValueError("artifact changed before v2 analysis")
            captured_digest = digest(captured_hashes)
            if captured_digest != v1_result.get("localBundleDigest"):
                raise ValueError("local bundle changed before v2 analysis")
            local = _production.comparison_local_bundle(snapshot, artifact_snapshot)
            local_digest = local["digest"]
            if local_digest != captured_digest:
                raise ValueError("local bundle changed before v2 analysis")
            v2_result = compare_rows(
                production_plan,
                receipt["collection"]["rows"],
                local["plan"],
                local["result"]["rows"],
            )
        v2_result.update(
            {
                "originalContract": v1_result["kind"],
                "derivedAnalysis": True,
                "v1Classification": v1_result["classification"],
                "comparisonOrigin": "new-local-v1-comparison",
            }
        )
    if v1_result.get("acquisitionValidated") is not True:
        v2_result["comparisonOrigin"] = "new-local-v1-comparison"
    save_json(output / "v2-result.json", v2_result)
    binding = {
        "kind": "fs-write-limits-recompare-binding-v2",
        "version": VERSION,
        "promotionReady": False,
        "originalContract": v1_result.get("kind"),
        "derivedAnalysis": True,
        "comparisonOrigin": "new-local-v1-comparison",
        "originalFrozenComparisonSha256": original_hash,
        "v2ResultSha256": sha_file(output / "v2-result.json"),
        "productionReceiptSha256": receipt_hash
        if v1_result.get("acquisitionValidated")
        else None,
        "frozenInputsSha256": inputs_hash
        if v1_result.get("acquisitionValidated")
        else None,
        "v1ResultSha256": v1_hash,
        "artifactSha256": artifact_hash
        if v1_result.get("acquisitionValidated")
        else None,
        "localBundleDigest": local_digest
        if v1_result.get("acquisitionValidated")
        else None,
        "v2KernelSourceSha256": V2_KERNEL_SOURCE_SHA256,
        "v2EntrySourceSha256": V2_ENTRY_SOURCE_SHA256,
        "v2SourceSha256": V2_SOURCE_SHA256,
        "classification": v2_result["classification"],
        "acquisitionValidated": v1_result.get("acquisitionValidated") is True,
    }
    save_json(output / "binding.json", binding)
    return v2_result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", type=Path, required=True)
    parser.add_argument("--local", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original-comparison", type=Path)
    args = parser.parse_args(argv)
    result = recompare(
        args.production,
        args.local,
        args.artifact,
        args.output,
        args.original_comparison,
    )
    print(json.dumps({"classification": result["classification"]}))
    return 0 if result["classification"] in {"MATCH", "EXPECTED_NONDETERMINISM"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
