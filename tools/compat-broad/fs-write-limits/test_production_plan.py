"""Offline production allocation; never grants permission or sends requests."""

from production_plan import production_plan
from shared_gate import Gate, create


def test_metadata_and_data_are_both_reserved(tmp_path):
    proposal = production_plan("a" * 32)
    plan = proposal["gatePlan"]
    assert len(plan["jobs"]["limits"]["observation"]) == 16
    assert len(plan["jobs"]["limits"]["recovery"]) == 12
    assert plan["observationRequests"] == 22
    assert proposal["totalRequestUpperBound"] == 40
    assert len(plan["management"]["observation"]) == 6
    assert len(plan["management"]["recovery"]) == 6
    create(tmp_path / "gate", plan)
    assert Gate(tmp_path / "gate", "limits").snapshot()["reservedRecovery"] == 18
    assert proposal["productionReady"] is False


def test_phase_bounds_cover_reserved_durations():
    plan = production_plan("b" * 32)["gatePlan"]
    for phase, seconds in [("observation", 600), ("recovery", 360)]:
        entries = plan["management"][phase]
        count = len(plan["jobs"]["limits"][phase])
        required = sum(max(e["duration"] + 1, e["timeout"]) for e in entries)
        required += count * 13 + (len(entries) + count) * plan["intervalSeconds"]
        assert required <= seconds
    assert plan["wallSeconds"] == 960
    assert plan["recoverySeconds"] == 360


def test_locks_cover_shared_reads_and_only_owned_writes():
    proposal = production_plan("c" * 32)
    locks = proposal["resourceLocks"]
    writes = [lock for lock in locks if lock["mode"] != "READ"]
    assert len(writes) == 1
    assert "/oracle/" + "c" * 32 + "/limits-02/" in writes[0]["key"]
    assert all("fireemu-35fe6" in lock["key"] for lock in locks)
    assert {lock["key"].split("/")[-1] for lock in locks if lock["mode"] == "READ"} >= {
        "indexes",
        "ruleset",
        "config",
        "database",
    }
