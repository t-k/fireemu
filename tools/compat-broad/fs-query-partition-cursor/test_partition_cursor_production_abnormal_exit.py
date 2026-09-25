"""Regression coverage for the abnormal-exit journal-finalization path.

Owner review of 23672693d (docs.local/reviews/2026-09-21/owner-review-23672693d
in the fireemu checkout, not shipped here): `_Journal.summary()` raises
RuntimeError when `evidence_complete()` has not run on it first. `execute()`
only called `evidence_complete()` on the happy path, at the end of the try
block, so an exception between a journal's creation and that point (a
collector-start failure; a residual-directory creation failure) reached the
except/finally with an unverified journal still open. The finally block closed
it anyway, and the receipt assembly's `ladder.summary()` (or
`residual.summary()`) then raised, so `routes.json` and `gate-snapshot.json`
were written but `receipt.json` never was and the Ledger reservation was never
released -- a run that failed silently instead of failing to a named receipt.

The two tests below reproduce the owner's two failing scenarios end-to-end
through the real `execute()` and a real, temporary Ledger and Gate (offline
production oracle, no socket, no credential, no Ledger the emulator itself
uses). They use this file's own `built`/`run`/`oracle_wire` fixtures rather
than the review's ast-extracted `_Journal`/`execute` copy with fake Admission,
Ledger, Gate and collector doubles, since the real modules are available here.

The owner's two control scenarios (an exception before any journal exists; a
normal finalization of an incomplete run) are not duplicated here because this
suite already carries them: `test_a_credential_refusal_is_named_and_sends_nothing`
in test_partition_cursor_production.py fails before the ladder journal is
created (mirrors "before-journal-error") and reaches receipt.json exactly as
asserted below; `test_a_journal_raw_write_failure_makes_raw_complete_false_and_matches_evidence_complete`
in the same file calls `evidence_complete()` then `summary()` on the normal
path and asserts the raw-evidence verdict they must agree on (mirrors the
review's direct `_Journal` control).
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import o4_partition_cursor_descriptor as campaign
import partition_cursor_admission as admission
import reservations
from test_partition_cursor_production import built, offline, oracle_wire, run  # noqa: F401

__all__ = ["built", "offline", "oracle_wire", "run"]


def _spy_revoke(monkeypatch):
    """Count `revoke_production_capability` calls without changing its behavior.

    `execute()`'s own finally and the O8 launcher's outer finally
    (partition_cursor_o8.py) both call this unconditionally and it is
    idempotent (`_ISSUED.discard` / `_CAPABILITY_STATE.pop(..., None)`), so a
    run through `run()` always revokes twice; that double call is pre-existing
    and unrelated to this fix. What matters here is that `execute()`'s own
    revoke keeps happening on the abnormal-exit path (it must not be skipped
    by the journal-verification bug this file regression-tests), so callers
    assert `len(revoked) == 2`, not that revoke is only ever called once.
    """
    calls = []
    real_revoke = admission.revoke_production_capability

    def spy(capability):
        calls.append(capability)
        return real_revoke(capability)

    monkeypatch.setattr(admission, "revoke_production_capability", spy)
    return calls


def test_a_collector_start_failure_still_publishes_a_failure_receipt(
    built, tmp_path, monkeypatch
):
    """P17 (owner 23672693d, collector-directory-error): a PermissionError
    raised the instant the collector starts happens after the ladder journal
    exists and before it is ever verified. The finally teardown must still
    verify it, close it, revoke the capability and reach the failure receipt
    with the reservation held, not a RuntimeError that swallows all of it."""
    oracle_wire(monkeypatch, built.plan)
    revoked = _spy_revoke(monkeypatch)

    def raise_on_start(plan, transmit, output):
        raise PermissionError("injected collector-start failure")

    monkeypatch.setattr(campaign, "collector", raise_on_start)
    result = run(built, tmp_path)
    assert result["failure"] == "PermissionError"
    assert result["reservationReleased"] is False
    assert len(revoked) == 2
    output = tmp_path / "output"
    assert (output / "routes.json").exists()
    assert (output / "gate-snapshot.json").exists()
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["failure"] == "PermissionError"
    assert receipt["releaseEligible"] is False
    assert receipt["releaseRecord"] is None
    # The ladder journal was created before the collector ran; the residual
    # journal never was.
    assert receipt["ladder"] is not None
    assert receipt["residual"] is None
    assert not (output / "release.json").exists()
    ledger = reservations.Ledger(built.ledger)
    row = ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]
    assert row["state"] == "held"


def test_a_residual_directory_conflict_still_publishes_a_failure_receipt(
    built, tmp_path, monkeypatch
):
    """P18 (owner 23672693d, residual-directory-error): the collector finishes
    normally, but a conflicting path at `output/residual` makes the residual
    journal's own `directory.mkdir()` raise FileExistsError before it is ever
    verified. By then the ladder journal has real recorded rows and was never
    verified either. The finally teardown must verify both, close them, and
    still reach the failure receipt with the reservation held."""
    oracle_wire(monkeypatch, built.plan)
    revoked = _spy_revoke(monkeypatch)
    real_collector = campaign.collector

    def occupy_residual_then_collect(plan, transmit, output):
        # `output` here is `<run output>/collection`; the run's own output
        # directory -- where the residual journal is about to be created --
        # is its parent.
        (output.parent / "residual").write_text("occupied", encoding="utf-8")
        return real_collector(plan, transmit, output)

    monkeypatch.setattr(campaign, "collector", occupy_residual_then_collect)
    result = run(built, tmp_path)
    assert result["failure"] == "FileExistsError"
    assert result["reservationReleased"] is False
    assert len(revoked) == 2
    output = tmp_path / "output"
    assert (output / "routes.json").exists()
    assert (output / "gate-snapshot.json").exists()
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["failure"] == "FileExistsError"
    assert receipt["releaseEligible"] is False
    assert receipt["releaseRecord"] is None
    assert receipt["ladder"] is not None
    assert receipt["residual"] is None
    assert not (output / "release.json").exists()
    ledger = reservations.Ledger(built.ledger)
    row = ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]
    assert row["state"] == "held"
