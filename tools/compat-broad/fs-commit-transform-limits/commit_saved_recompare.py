"""Saved-reference recompare of an immutable production receipt.

A production receipt is immutable once published, and so is the comparison the
comparator frozen with it produced. When that comparator is later repaired, the
repair must be demonstrated against the same saved records rather than against a
new production run. This module does exactly that and nothing else.

`recompare_saved` first replays `commit_acquisition.compare_saved`, which
validates the saved receipt, release record, bounded credential journals and
every row journal, and runs the comparator frozen inside the output directory.
That result is the immutable one and is carried through unchanged. The repaired
comparator is then executed on the same plan, rows and saved local reference in a
separate isolated subprocess, and both results are bound together with the source
digests of each comparator.

No production request is made, no credential is read, and no current permission,
checkout or artifact is consulted. The saved output directory is only read.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))

from broad_contract import digest  # noqa: E402
from commit_acquisition import compare_saved  # noqa: E402

_KERNEL = (
    "import json,sys;sys.path.insert(0,sys.argv[1]);"
    "from transform_comparator import compare_rows;v=json.load(sys.stdin);"
    "print(json.dumps(compare_rows(v['plan'],v['rows'],v['reference']['plan'],"
    "v['reference']['rows'],left_recovery=v['cleanup'],"
    "right_recovery=v['reference']['cleanup'])))"
)

_SOURCES = ("transform_comparator.py", "transform_compiler.py")


def _read(path: Path) -> Any:
    return json.loads(Path(path).read_text())


def _source_digest(path: Path) -> str:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError("comparator source required")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["classification"]] = counts.get(row["classification"], 0) + 1
    return dict(sorted(counts.items()))


def _summary(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "classification": result["classification"],
        "errors": result["errors"],
        "kind": result["kind"],
        "rowClassificationCounts": _counts(result["rows"]),
        "rows": [
            {"classification": row["classification"], "index": row["index"]}
            for row in result["rows"]
        ],
    }


def recompare_saved(
    output,
    reference_path,
    *,
    expected_inputs_digest: str,
    comparator_root,
    expected_execution_kind: str = "fixed-production-wire",
) -> dict[str, Any]:
    """Compare one saved receipt under both the frozen and repaired comparator.

    `comparator_root` is the directory holding the repaired comparator sources.
    It is never written to, and it does not have to be the frozen checkout: the
    point of the record this returns is to say exactly which comparator bytes
    produced the repaired classification.
    """
    output, comparator_root = Path(output), Path(comparator_root)
    frozen = compare_saved(
        output,
        reference_path,
        expected_inputs_digest=expected_inputs_digest,
        expected_execution_kind=expected_execution_kind,
    )
    inputs = _read(output / "inputs.json")
    receipt = _read(output / "receipt.json")
    collection = _read(output / "collection/collection.json")
    reference = _read(reference_path)
    payload = json.dumps(
        {
            "plan": inputs["plan"],
            "rows": collection["rows"],
            "cleanup": collection["cleanup"],
            "reference": reference,
        }
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", _KERNEL, str(comparator_root.resolve())],
        input=payload,
        text=True,
        capture_output=True,
        timeout=15,
        check=True,
        env={},
    )
    repaired = json.loads(completed.stdout)
    if len(repaired["rows"]) != len(frozen["rows"]):
        raise ValueError("repaired comparator changed the compared row set")
    return {
        "binding": {
            "comparatorSourceSha256": {
                name: _source_digest(comparator_root / name) for name in _SOURCES
            },
            "expectedInputsDigest": expected_inputs_digest,
            "frozenComparatorSourceSha256": {
                name: _source_digest(output / name) for name in _SOURCES
            },
            "inputsDigest": inputs["inputsDigest"],
            "permissionDigest": receipt["permissionDigest"],
            "planDigest": receipt["planDigest"],
            "receiptSha256": _source_digest(output / "receipt.json"),
            "referenceSha256": _source_digest(reference_path),
            "sourceCommit": receipt["generation"]["sourceCommit"],
        },
        "executionKind": frozen["executionKind"],
        "frozen": _summary(frozen),
        "kind": "fs-commit-transform-saved-reference-recompare-v1",
        "newProductionRequests": 0,
        "productionExecuted": frozen["productionExecuted"],
        "receiptDigest": digest(receipt),
        "repaired": _summary(repaired),
    }
