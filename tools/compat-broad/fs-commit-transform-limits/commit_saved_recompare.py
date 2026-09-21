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
twice. Every saved input is read once and the parsed values, the published
digests and the executed sources all come from that one read. The repaired
comparator sources are written into a private snapshot from those same bytes as
read-only files, the snapshot is what the subprocess imports and what the record
hashes, and it holds the complete lane import closure. The child runs with
`-I -S -B`, so neither the environment, nor user site, nor site-packages is on
its path and the snapshot is the only place a lane module can come from: a
comparator that grows a new lane import fails to import rather than loading it
from a directory this run does not hash.

`compare_saved` runs before that read and opens the saved records and the
reference for itself, and its refusal for an invalid saved directory has to
reach the caller unchanged, so the pre-image taken ahead of it is only a probe
that never raises. Comparing the probe with the real read closes the window
around the validator. `comparator_root` need not be a frozen checkout, so every
path this run read is compared against its bytes again at the end. That covers
what `compare_saved` reads as well as what this module parses: the release
record, both bounded OAuth charge and receipt journals and every per-row
journal, none of whose digests the published record carries but on which the
frozen classification depends. Those are witnessed only if they are there,
because which files a saved directory must contain is `compare_saved`'s question
and this module adds no requirement of its own. Anything that changed underneath
refuses the whole recompare rather than returning a record whose result and
digests describe different bytes.

Two limits are worth stating. A file replaced and restored within the run is
invisible to a closing byte comparison; the repaired half is immune because the
snapshot is what ran, but the frozen half, which `compare_saved` imports
straight out of the saved directory, has only this detection. And the snapshot
directory is owner-writable while the run is in flight even though its files are
not, so a process under the same account could add a module ahead of the
comparator on the child's path.

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
_COMPILER_INPUT = "tools/compat-broad/fs-commit-transform-limits/transform_compiler.py"


def _read_bytes(path) -> bytes:
    """Read one regular file exactly once; its bytes are what gets hashed."""
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"{Path(path).name}: regular non-empty file required")
    return path.read_bytes()


def _probe(path) -> bytes | None:
    """Read a path without committing to it, for the pre-image only.

    This runs before the saved-acquisition validator, which owns the refusal
    for a saved directory that is missing or invalid. A probe therefore never
    raises: an unreadable path yields no pre-image and the validator, or the
    real read afterwards, reports it.
    """
    try:
        return _read_bytes(path)
    except (OSError, ValueError):
        return None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _required_paths(output: Path, comparator_root: Path, reference_path: Path):
    """The paths this module parses or publishes a digest for.

    These are the only files it insists on. Which files a saved directory must
    contain is `compare_saved`'s question, not this module's, so everything else
    is witnessed only if it is there.
    """
    return (
        output / "inputs.json",
        output / "receipt.json",
        output / "collection/collection.json",
        output / "transform_comparator.py",
        output / "transform_compiler.py",
        reference_path,
        *(comparator_root / name for name in _SOURCES),
    )


def _validator_paths(output: Path):
    """Fixed paths `compare_saved` reads that this module does not parse.

    The frozen classification depends on the release record and both bounded
    OAuth charge and receipt journals, so a replacement after the validator read
    them has to be caught even though the published record carries no digest for
    them. The per-row journals belong to the same set and come from
    `_journal_paths` once the collection is known.
    """
    return (
        output / "release.json",
        *(
            output / "coordinator" / f"oauth-{slot}-{record}.json"
            for slot in ("refresh", "tokeninfo")
            for record in ("charge", "receipt")
        ),
    )


def _journal_paths(output: Path, collection: Any):
    """The per-row journals `compare_saved` checks, named by the collection."""
    if not isinstance(collection, dict):
        return ()
    return tuple(
        output / "collection" / f"{phase}-{index:02d}.json"
        for phase, key in (("observation", "rows"), ("recovery", "cleanup"))
        for index in range(len(collection.get(key) or []))
        if isinstance(collection.get(key), list)
    )


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


def _snapshot(sources: dict[str, bytes], snapshot: Path) -> dict[str, str]:
    """Write the executable closure into a read-only directory and hash it there.

    The caller has already read each source exactly once and passes those bytes
    in. They are written through an exclusive create and then read back out of
    the snapshot, so the digests describe the file the subprocess will import
    rather than a source that may since have been replaced.
    """
    digests = {}
    for name, source in sources.items():
        handle = os.open(snapshot / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
        with os.fdopen(handle, "wb") as stream:
            stream.write(source)
            stream.flush()
            os.fsync(stream.fileno())
        written = _read_bytes(snapshot / name)
        if written != source:
            raise ValueError("comparator snapshot differs from its source")
        digests[name] = _sha256(written)
    return digests


def recompare_saved(
    output,
    reference_path,
    *,
    expected_inputs_digest: str,
    comparator_root,
    historical_compiler_path=None,
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
    historical_compiler = (
        Path(historical_compiler_path) if historical_compiler_path is not None else None
    )
    depends_on = _required_paths(output, comparator_root, reference_path)
    if historical_compiler is not None:
        depends_on += (historical_compiler,)

    # The pre-image is taken first, but only as a probe, because
    # `compare_saved` owns the refusal for an invalid saved directory and that
    # refusal has to reach the caller unchanged rather than being masked by a
    # read of our own. `compare_saved` opens these same paths for itself, so
    # comparing the probe with the real read below is what closes the window
    # around it. The row journals are named by the collection, so they can only
    # be probed once it parses; a collection that does not parse is the
    # validator's refusal to make.
    probe = {path: _probe(path) for path in depends_on}
    probed = probe[output / "collection/collection.json"]
    try:
        probed_collection = json.loads(probed) if probed is not None else None
    except ValueError:
        probed_collection = None
    probe.update(
        {
            path: _probe(path)
            for path in (
                *_validator_paths(output),
                *_journal_paths(output, probed_collection),
            )
        }
    )

    frozen = compare_saved(
        output,
        reference_path,
        expected_inputs_digest=expected_inputs_digest,
        expected_execution_kind=expected_execution_kind,
    )

    # Everything this run depends on is now read for real, once. `witness`
    # keeps the exact bytes: the parsed values, the published digests and the
    # snapshot all come from here and nothing is opened again until the closing
    # check.
    witness = {path: _read_bytes(path) for path in depends_on}
    collection = json.loads(witness[output / "collection/collection.json"])
    for path in (*_validator_paths(output), *_journal_paths(output, collection)):
        present = _probe(path)
        if present is not None:
            witness[path] = present
    for path, current in witness.items():
        before = probe.get(path)
        if before is not None and before != current:
            raise ValueError(f"{path.name} changed while the recompare ran")
    inputs = json.loads(witness[output / "inputs.json"])
    receipt = json.loads(witness[output / "receipt.json"])
    reference = json.loads(witness[reference_path])
    if historical_compiler is not None:
        expected_compiler_sha = inputs.get("sourceInputs", {}).get(_COMPILER_INPUT)
        if not isinstance(expected_compiler_sha, str):
            raise ValueError("saved compiler source binding is missing")
        compiler_bytes = witness[historical_compiler]
        if _sha256(compiler_bytes) != expected_compiler_sha:
            raise ValueError("historical compiler source binding differs")
    else:
        compiler_bytes = witness[comparator_root / "transform_compiler.py"]
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
        repaired_sources = _snapshot(
            {
                "transform_comparator.py": witness[comparator_root / "transform_comparator.py"],
                "transform_compiler.py": compiler_bytes,
            },
            snapshot,
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", "-c", _KERNEL, str(snapshot)],
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
            "historicalCompilerSourceSha256": (
                _sha256(compiler_bytes) if historical_compiler is not None else None
            ),
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
