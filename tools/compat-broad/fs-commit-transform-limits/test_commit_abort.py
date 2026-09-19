"""Retirement of a held reservation by proving the closure the row recorded.

No production request and no credential is used. The canonical Ledger is read
but never written: the real held row is reproduced in a temporary Ledger and the
real Gate directory is copied before anything is retired.
"""

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "production-admission"))
sys.path.insert(0, str(HERE))

import commit_abort
from broad_contract import digest
from reservations import Ledger
from shared_gate import _save

CANONICAL_LEDGER = Path(
    os.environ.get(
        "FIREEMU_CANONICAL_LEDGER",
        Path.home() / ".local/state/fireemu-broad/production-admission-v1",
    )
)


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def synthetic_commit(tmp_path):
    """A repository carrying the abort closure files at a known commit."""
    root = tmp_path / "checkout"
    for name in commit_abort.CLOSURE_PATHS.values():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {name}\n")
    _git(root.parent, "init", "-q", root.name)
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "test")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "closure")
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    digests = {
        name: digest_of(root / path)
        for name, path in commit_abort.CLOSURE_PATHS.items()
    }
    return root, {
        "sourceCommit": commit,
        "collectorSourceDigest": digest(digests),
        "sourceDigests": digests,
    }


def digest_of(path):
    import hashlib

    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_a_generation_is_verified_against_the_frozen_commit(tmp_path):
    root, generation = synthetic_commit(tmp_path)
    assert (
        commit_abort.verify_generation_in_commit(generation, source_root=root)
        == generation["sourceDigests"]
    )


@pytest.mark.parametrize(
    "damage",
    [
        {"sourceCommit": "0" * 40},
        {"sourceDigests": {"shared_gate.py": "0" * 64}},
        {"sourceDigests": {"unrelated.py": "0" * 64}},
        {"sourceDigests": {}},
    ],
    ids=["unknown-commit", "wrong-digest", "outside-closure", "empty"],
)
def test_a_generation_that_the_commit_does_not_contain_is_refused(tmp_path, damage):
    root, generation = synthetic_commit(tmp_path)
    with pytest.raises(ValueError):
        commit_abort.verify_generation_in_commit(
            {**generation, **damage}, source_root=root
        )


def test_an_abort_record_is_derived_only_from_the_persisted_receipt(tmp_path):
    receipt = {
        "kind": "commit-acquisition-receipt-v2",
        "ticket": {"reservation": "a" * 64},
        "planDigest": "b" * 64,
        "gate": {"total": 5},
        "generation": {
            "sourceCommit": "c" * 40,
            "collectorSourceDigest": "d" * 64,
            "sourceDigests": {"shared_gate.py": "e" * 64},
        },
    }
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt))
    record = commit_abort.build_abort_record(path)
    assert record["kind"] == "shared-no-data-abort-v1"
    assert record["receiptDigest"] == digest(receipt)
    assert record["gateDigest"] == digest(receipt["gate"])
    assert {key: record[key] for key in commit_abort.GENERATION_FIELDS} == receipt[
        "generation"
    ]


@pytest.mark.parametrize(
    "damage",
    [
        {"generation": None},
        {"generation": {"sourceCommit": "c" * 40}},
        {"kind": "other-receipt-v1"},
        {"gate": None},
    ],
    ids=["no-generation", "partial-generation", "wrong-kind", "no-gate"],
)
def test_an_abort_record_is_refused_without_a_complete_receipt(tmp_path, damage):
    receipt = {
        "kind": "commit-acquisition-receipt-v2",
        "ticket": {"reservation": "a" * 64},
        "planDigest": "b" * 64,
        "gate": {"total": 5},
        "generation": {
            "sourceCommit": "c" * 40,
            "collectorSourceDigest": "d" * 64,
            "sourceDigests": {"shared_gate.py": "e" * 64},
        },
    }
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps({**receipt, **damage}))
    with pytest.raises(ValueError):
        commit_abort.build_abort_record(path)


FIXTURE = HERE / "fixtures/commit-v10-held-reservation.json"


def held_fixture():
    """The v10 attempt as it stood while its reservation was held.

    The canonical row has since been retired and its Gate directory stopped, so
    the live Ledger can no longer stand in for this: a retired row proves
    nothing about whether a held one can still be retired. The snapshot carries
    no credential material; a response journal is not part of a receipt.
    """
    return json.loads(FIXTURE.read_text())


def _write_gate(path, state):
    """Reproduce a Gate directory from the snapshot a receipt recorded."""
    path.mkdir(mode=0o700, parents=True)
    (path / "lock").touch(mode=0o600)
    _save(path, state)


def test_the_held_v10_row_retires_on_the_closure_it_recorded(tmp_path):
    """A held reservation is retirable although this source tree has moved on.

    The row records the closure of the frozen checkout `ff1211f17`, which no
    longer matches the current sources: the fix to the evidence contract changed
    `reservations.py` itself. What retires the row is the run's own receipt,
    which carried that closure forward.
    """
    fixture = held_fixture()
    row, receipt = fixture["row"], fixture["receipt"]
    assert row["state"] == "held"
    assert receipt["generation"] == row["generation"]

    # The generation names bytes that really are in the frozen commit, and that
    # commit is not the one this branch is built from.
    verified = commit_abort.verify_generation_in_commit(
        row["generation"], source_root=ROOT
    )
    assert verified == row["generation"]["sourceDigests"]
    assert (
        row["generation"]["sourceCommit"]
        != subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )

    run = tmp_path / "run"
    run.mkdir()
    claim = copy.deepcopy(row["claim"])
    claim["gatePath"] = str((run / "gate").resolve())
    # Only the window moves, so the test does not expire with the permission.
    window = {"issuedAt": 1000.0, "expiresAt": 1000.0 + 86400}
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(
        {**copy.deepcopy(fixture["envelope"]), **window},
        claim,
        copy.deepcopy(receipt["gate"]["plan"]),
        generation=copy.deepcopy(row["generation"]),
        now=1100,
    )
    # The Gate is built only after the reservation exists, because a reservation
    # refuses a Gate directory that is already present.
    _write_gate(run / "gate", copy.deepcopy(receipt["gate"]))

    spent = copy.deepcopy(receipt)
    spent["ticket"] = ticket
    spent["claimDigest"] = ticket["claimDigest"]
    (run / "receipt.json").write_text(json.dumps(spent))

    record = commit_abort.build_abort_record(run / "receipt.json")
    assert {key: record[key] for key in commit_abort.GENERATION_FIELDS} == row[
        "generation"
    ]
    # This is the evidence shape the old contract refused: the attempt stopped
    # at the third preflight gate, so it observed project, database and auth.
    assert [item["id"] for item in spent["metadata"]] == [
        "observation:project",
        "observation:database",
        "observation:auth",
    ]

    ledger.abort_no_data(ticket, record)
    retired = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert retired["state"] == "aborted-no-data"
    assert retired["generation"] == row["generation"]
    assert json.loads((run / "gate" / "state.json").read_text())["stopped"] is True


def test_the_held_fixture_still_describes_the_canonical_reservation():
    """A drift guard on the snapshot, independent of the row's current state."""
    fixture = held_fixture()
    state_path = CANONICAL_LEDGER / "state.json"
    if not state_path.is_file():
        pytest.skip("the canonical Ledger is host local")
    row = json.loads(state_path.read_text())["reservations"].get(fixture["reservation"])
    if row is None:
        pytest.skip("the canonical Ledger does not carry this reservation")
    assert row["claimDigest"] == fixture["row"]["claimDigest"]
    assert row["envelopeDigest"] == fixture["row"]["envelopeDigest"]
    assert row["generation"] == fixture["row"]["generation"]
    # The committed snapshot slots host-specific paths so the published tree carries no
    # personal directory; compare the claim with those two fields slotted the same way.
    def slotted(claim):
        return {**claim, "gatePath": "<run>/gate", "ledgerPath": "<canonical-ledger>"}

    assert slotted(row["claim"]) == slotted(fixture["row"]["claim"])
