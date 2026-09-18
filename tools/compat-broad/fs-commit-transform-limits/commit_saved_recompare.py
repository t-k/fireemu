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

The record only means something if the digests it publishes are the digests of
the bytes that actually produced the classification, so nothing it names is read
twice. The repaired comparator sources are copied into a private read-only
snapshot before anything runs, the snapshot is what the subprocess executes and
what the record hashes, and the snapshot holds the complete lane import closure
so the child cannot reach back into a mutable directory. Every saved input is
read once, and the parsed values and the published digests both come from that
one read. `comparator_root` need not be a frozen checkout, so every path this
run depended on is compared against its original bytes at the end; anything that
changed underneath refuses the whole recompare rather than returning a record
whose result and digests describe different bytes.

No production request is made, no credential is read, and no current permission,
checkout or artifact is consulted. The saved output directory is only read.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))

from broad_contract import digest
from commit_acquisition import compare_saved

_KERNEL = (
    "import json,sys;sys.path.insert(0,sys.argv[1]);"
    "from transform_comparator import compare_rows;v=json.load(sys.stdin);"
    "print(json.dumps(compare_rows(v['plan'],v['rows'],v['reference']['plan'],"
    "v['reference']['rows'],left_recovery=v['cleanup'],"
    "right_recovery=v['reference']['cleanup'])))"
)

# The complete lane import closure of the comparator kernel: the comparator and
# the compiler it validates plans against. The child runs with an isolated
# interpreter and only the snapshot on its path, so a comparator that grows a
# new lane import fails to import rather than silently loading it from a
# directory this run does not hash.
_SOURCES = ("transform_comparator.py", "transform_compiler.py")


def _read_bytes(path) -> bytes:
    """Read one regular file exactly once; its bytes are what gets hashed."""
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError("comparator source required")
    return path.read_bytes()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def _snapshot(
    source_root: Path, snapshot: Path
) -> tuple[dict[str, str], dict[Path, bytes]]:
    """Copy the executable closure into a read-only directory and hash it there.

    The bytes are written through an exclusive create and then read back out of
    the snapshot, so the digests describe the file the subprocess will import
    and not the source it was copied from. The single read of each source is
    returned alongside, so the caller never opens those paths a second time.
    """
    digests, sources = {}, {}
    for name in _SOURCES:
        data = _read_bytes(source_root / name)
        handle = os.open(snapshot / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        written = _read_bytes(snapshot / name)
        if written != data:
            raise ValueError("comparator snapshot differs from its source")
        digests[name] = _sha256(written)
        sources[source_root / name] = data
    return digests, sources


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
    It is never written to, and it does not have to be the frozen checkout, so
    it is snapshotted before use: the point of the record this returns is to say
    exactly which comparator bytes produced the repaired classification.
    """
    output = Path(output)
    comparator_root = Path(comparator_root)
    reference_path = Path(reference_path)

    # Everything this run depends on is read here, once. `witness` keeps the
    # exact bytes so the closing check can tell a stable input from one that was
    # replaced underneath us.
    witness = {
        path: _read_bytes(path)
        for path in (
            output / "inputs.json",
            output / "receipt.json",
            output / "collection/collection.json",
            output / "transform_comparator.py",
            output / "transform_compiler.py",
            reference_path,
        )
    }
    inputs = json.loads(witness[output / "inputs.json"])
    receipt = json.loads(witness[output / "receipt.json"])
    collection = json.loads(witness[output / "collection/collection.json"])
    reference = json.loads(witness[reference_path])
    payload = json.dumps(
        {
            "plan": inputs["plan"],
            "rows": collection["rows"],
            "cleanup": collection["cleanup"],
            "reference": reference,
        }
    )

    snapshot = Path(tempfile.mkdtemp(prefix="commit-saved-recompare-"))
    try:
        os.chmod(snapshot, 0o700)
        repaired_sources, snapshotted = _snapshot(comparator_root, snapshot)
        witness.update(snapshotted)

        frozen = compare_saved(
            output,
            reference_path,
            expected_inputs_digest=expected_inputs_digest,
            expected_execution_kind=expected_execution_kind,
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-c", _KERNEL, str(snapshot)],
            input=payload,
            text=True,
            capture_output=True,
            timeout=15,
            check=True,
            env={},
        )
    finally:
        shutil.rmtree(snapshot, ignore_errors=True)

    repaired = json.loads(completed.stdout)
    if len(repaired["rows"]) != len(frozen["rows"]):
        raise ValueError("repaired comparator changed the compared row set")

    # The snapshot makes the repaired half self-consistent by construction, but
    # `compare_saved` reads the saved records and the reference itself, so a
    # replacement anywhere still splits the result from its digests. Refuse
    # instead of publishing a record that cannot be reproduced from its hashes.
    for path, original in witness.items():
        if _read_bytes(path) != original:
            raise ValueError(f"{path.name} changed while the recompare ran")

    return {
        "binding": {
            "comparatorSourceSha256": repaired_sources,
            "expectedInputsDigest": expected_inputs_digest,
            "frozenComparatorSourceSha256": {
                name: _sha256(witness[output / name]) for name in _SOURCES
            },
            "inputsDigest": inputs["inputsDigest"],
            "permissionDigest": receipt["permissionDigest"],
            "planDigest": receipt["planDigest"],
            "receiptSha256": _sha256(witness[output / "receipt.json"]),
            "referenceSha256": _sha256(witness[reference_path]),
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
