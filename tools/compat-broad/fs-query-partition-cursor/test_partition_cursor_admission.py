"""Unit tests of the stop classification and the owner-declared reservation.

Each clause of `classify_stop` is exercised on a synthetic receipt so that it
is load-bearing on its own; the integration tests reach the same dispositions
end to end, but several clauses shadow each other there (a residual finding,
for example, is refused before the ladder clause is consulted). The docstrings
name the review mutants each test kills.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import partition_cursor_admission as admission


def receipt(**overrides):
    value = {
        "stopPoint": "observation-incomplete",
        "mayHaveCreated": True,
        "ladderAbsenceComplete": True,
        "creationProofCount": 21,
        "resourceCount": 21,
        "residualSummary": {"complete": False, "documents": None},
        "productionExecuted": True,
        "collection": {"status": "incomplete"},
        "dataDispatches": 30,
    }
    value.update(overrides)
    return value


def test_a_fully_created_and_fully_absent_abandoned_run_closes_after_abandon():
    verdict = admission.classify_stop(receipt())
    assert verdict["disposition"] == "abandoned-cleanup-close"
    assert verdict["retirableAsNoData"] is False


def test_an_incomplete_ladder_is_never_the_abandoned_close():
    """A01: `ladderAbsenceComplete` is load-bearing on its own."""
    verdict = admission.classify_stop(receipt(ladderAbsenceComplete=False))
    assert verdict["disposition"] == "owner-escalation"
    assert "did not prove every one absent" in verdict["reason"]


def test_a_partial_creation_is_never_the_abandoned_close():
    """A01b: proofs must cover every resource, as the shared Ledger requires."""
    for proofs in (1, 20, None, "21"):
        verdict = admission.classify_stop(receipt(creationProofCount=proofs))
        assert verdict["disposition"] == "owner-escalation"
        assert "partially created" in verdict["reason"]


def test_a_residual_finding_is_the_owners():
    """A01c: a completed residual scan with documents refuses the close."""
    verdict = admission.classify_stop(
        receipt(
            stopPoint="recovery-incomplete",
            residualSummary={"complete": True, "documents": 1},
        )
    )
    assert verdict["disposition"] == "owner-escalation"
    assert "residual scan" in verdict["reason"]
    clean = admission.classify_stop(
        receipt(
            stopPoint="recovery-incomplete",
            residualSummary={"complete": True, "documents": 0},
        )
    )
    assert clean["disposition"] == "abandoned-cleanup-close"


@pytest.mark.parametrize("stop", ["create-uncertain", "seed-uncertain"])
def test_an_uncertain_stop_is_the_owners_even_when_nothing_is_known_to_exist(stop):
    """A02: the stop point alone decides; `mayHaveCreated` is not consulted."""
    verdict = admission.classify_stop(receipt(stopPoint=stop, mayHaveCreated=False))
    assert verdict["disposition"] == "owner-escalation"
    assert "may have been applied" in verdict["reason"]
    with pytest.raises(ValueError, match="not a no-data stop"):
        admission.validate_no_data_receipt(
            receipt(stopPoint=stop, mayHaveCreated=False)
        )


def test_the_preflight_read_stop_is_escalation_only():
    """A05: one non-creating read was sent; the shared no-data contract
    cannot retire a receipt that carries a bundle."""
    verdict = admission.classify_stop(
        receipt(stopPoint="preflight-absence", mayHaveCreated=False, dataDispatches=1)
    )
    assert verdict["disposition"] == "owner-escalation"
    assert verdict["retirableAsNoData"] is False


def test_a_no_data_stop_requires_no_dispatch_no_bundle_and_no_creation():
    """A03: every clause of the no-data shape is load-bearing."""
    clean = receipt(
        stopPoint="schedule-not-started",
        mayHaveCreated=False,
        productionExecuted=False,
        collection=None,
        dataDispatches=0,
        ladderAbsenceComplete=False,
        creationProofCount=0,
    )
    assert admission.classify_stop(clean)["retirableAsNoData"] is True
    for damage in (
        {"dataDispatches": 1},
        {"productionExecuted": True},
        {"collection": {"status": "incomplete"}},
        {"mayHaveCreated": True},
    ):
        verdict = admission.classify_stop({**clean, **damage})
        assert verdict["retirableAsNoData"] is False, damage
        assert verdict["disposition"] == "owner-escalation"


def test_an_unknown_stop_point_is_refused():
    with pytest.raises(ValueError, match="unknown"):
        admission.classify_stop(
            receipt(stopPoint="somewhere-else", mayHaveCreated=False)
        )


def test_the_stop_point_sets_are_disjoint_and_complete():
    sets = admission.stop_points()
    names = [name for group in sets.values() for name in group]
    assert len(names) == len(set(names))
    assert set(names) == {
        "schedule-not-started",
        "preflight-absence",
        "create-uncertain",
        "seed-uncertain",
        "observation-incomplete",
        "recovery-incomplete",
    }


@pytest.mark.parametrize(
    "slot", [1.0, 5.0, 5.99, 0, -1, True, float("nan"), float("inf"), "6"]
)
def test_a_slot_reservation_below_the_wire_ceiling_plus_slack_is_refused(slot):
    """A04: the floor is the whole-worker ceiling plus one second."""
    with pytest.raises(ValueError):
        admission.gate_reservations(
            {
                "gateReservationSeconds": {
                    "slot": slot,
                    "slotBasis": admission.PLANNING_ASSUMPTION,
                }
            }
        )
    assert (
        admission.gate_reservations(
            {
                "gateReservationSeconds": {
                    "slot": 6.0,
                    "slotBasis": admission.PLANNING_ASSUMPTION,
                }
            }
        )["slot"]
        == 6.0
    )


def test_a_measured_reservation_must_name_its_record_and_a_planning_one_must_not():
    with pytest.raises(ValueError, match="must name its record"):
        admission.gate_reservations(
            {
                "gateReservationSeconds": {
                    "slot": 6.0,
                    "slotBasis": admission.MEASURED_SHADOW,
                }
            }
        )
    with pytest.raises(ValueError, match="names no record"):
        admission.gate_reservations(
            {
                "gateReservationSeconds": {
                    "slot": 6.0,
                    "slotBasis": admission.PLANNING_ASSUMPTION,
                    "slotBasisRecord": "x",
                }
            }
        )
    with pytest.raises(ValueError, match="declared basis"):
        admission.gate_reservations(
            {"gateReservationSeconds": {"slot": 6.0, "slotBasis": "guess"}}
        )
