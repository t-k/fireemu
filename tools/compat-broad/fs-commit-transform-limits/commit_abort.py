"""Build and independently verify the no-data abort record for a held reservation.

A reservation is retired by proving the source closure the ROW recorded, not the
closure the aborting process happens to be built from. Those two differ as soon
as anything in the closure is fixed, which is exactly the situation a failed
attempt leaves behind. The run's own `receipt.json` is what carries the row's
generation forward, so every field of the record is derived from it here; no
value is retyped by a caller.

`verify_generation_in_commit` is the separate, independent half: it re-reads each
closure file out of the frozen commit with `git show` and checks the digests the
generation names. That check deliberately lives here and not in the shared
Ledger, because the Ledger must not run a subprocess against a caller supplied
directory. It proves the generation names real bytes in the named commit; it
does not establish that those bytes were reviewed.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(HERE))

from broad_contract import digest
from commit_acquisition import ABORT_CLOSURE_SOURCES

ABORT_RECORD_KIND = "shared-no-data-abort-v1"
RECEIPT_KIND = "commit-acquisition-receipt-v2"
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
GENERATION_FIELDS = ("sourceCommit", "collectorSourceDigest", "sourceDigests")
# Basename to repository path for every file a Commit generation names. The
# generation records basenames only, so the path a digest is checked against has
# to come from here rather than from the caller.
CLOSURE_PATHS = {Path(name).name: name for name in ABORT_CLOSURE_SOURCES}


def _read_receipt(receipt_path):
    path = Path(receipt_path)
    if (
        path.is_symlink()
        or not path.is_file()
        or path.name != "receipt.json"
        or path.stat().st_size > MAX_RECEIPT_BYTES
    ):
        raise ValueError("persisted canonical receipt required")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or value.get("kind") != RECEIPT_KIND:
        raise ValueError("persisted canonical receipt required")
    return value


def build_abort_record(receipt_path):
    """Derive the complete abort record from one persisted run receipt.

    Every field, the generation included, comes from the receipt. A caller who
    does not hold the receipt of the run that made the reservation cannot build
    a record the shared Ledger will accept.
    """
    receipt = _read_receipt(receipt_path)
    generation = receipt.get("generation")
    if not isinstance(generation, dict) or set(generation) != set(GENERATION_FIELDS):
        raise ValueError("receipt records no acquisition generation")
    gate = receipt.get("gate")
    if not isinstance(gate, dict):
        raise ValueError("receipt records no Gate snapshot")  # noqa: TRY004 -- refusal class, not a type report
    return {
        "kind": ABORT_RECORD_KIND,
        "ticket": receipt["ticket"],
        "planDigest": receipt["planDigest"],
        "gateDigest": digest(gate),
        "receiptPath": str(Path(receipt_path).resolve()),
        "receiptDigest": digest(receipt),
        "collectorSourceDigest": generation["collectorSourceDigest"],
        "sourceCommit": generation["sourceCommit"],
        "sourceDigests": generation["sourceDigests"],
    }


def verify_generation_in_commit(generation, *, source_root):
    """Re-read every closure file out of the frozen commit and check its digest.

    Returns the verified basename to digest mapping. Raises when the generation
    names a file the closure does not contain, a commit the checkout does not
    have, or bytes whose digest differs.
    """
    if not isinstance(generation, dict) or set(generation) != set(GENERATION_FIELDS):
        raise ValueError("closed source generation required")
    digests = generation["sourceDigests"]
    commit = generation["sourceCommit"]
    if (
        not isinstance(digests, dict)
        or not digests
        or set(digests) - set(CLOSURE_PATHS)
        or not isinstance(commit, str)
        or len(commit) != 40
    ):
        raise ValueError("generation names a file outside the abort closure")
    root = Path(source_root).resolve()
    verified = {}
    for name in sorted(digests):
        blob = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{CLOSURE_PATHS[name]}"],
            capture_output=True,
            check=False,
            timeout=30,
        )
        if blob.returncode != 0:
            raise ValueError("frozen closure source missing from the named commit")
        observed = hashlib.sha256(blob.stdout).hexdigest()
        if observed != digests[name]:
            raise ValueError("frozen closure source digest differs")
        verified[name] = observed
    return verified
