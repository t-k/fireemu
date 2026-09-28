"""Receipt and real Gate lifecycle checks; no production or network simulation."""

from __future__ import annotations

import copy

import pytest
from compiler import compile_limits_plan
from rehearsal import validate_rehearsal
from shadow import REHEARSAL, rehearsal_fault, should_interrupt, validate_local_receipt
from test_shadow import fixture_receipt


@pytest.fixture
def plan():
    return compile_limits_plan("demo-firestore-probe", "(default)", "a" * 32)


def rehearsal_fixture(plan):
    receipt = fixture_receipt(plan)
    receipt.update(
        rows=receipt["rows"][:8],
        recordingComplete=False,
        stateValidation=False,
        completed=False,
        formalCompatibilityClaim=False,
        semanticMismatches=[],
        infrastructureFailures=[],
        injectedFault={
            "name": REHEARSAL,
            "afterObservationIndex": 7,
            "triggered": True,
        },
    )
    receipt["gate"]["jobs"]["limits"]["observation"] = 8
    receipt["manifest"] = {"injectedFault": receipt["injectedFault"]}
    report = {
        "status": "incomplete",
        "productionExecuted": False,
        "stopReason": "child-completed",
        "exitCode": 0,
        "ownedProcess": {"stopped": True, "listenersClosed": True},
        "manifest": receipt["manifest"],
    }
    return receipt, report, {"bound": True}


def test_fixed_interruption_requires_validated_controls(plan):
    rows = fixture_receipt(plan)["rows"]
    assert should_interrupt(REHEARSAL, rows[:8], plan)
    assert not should_interrupt(None, rows[:8], plan)
    assert not should_interrupt(REHEARSAL, rows[:7], plan)
    rows[7]["body"] = {}
    assert not should_interrupt(REHEARSAL, rows[:8], plan)
    with pytest.raises(ValueError, match="unsupported rehearsal"):
        rehearsal_fault("arbitrary-stop")


def test_rehearsal_success_is_not_campaign_completion(plan):
    receipt, report, binding = rehearsal_fixture(plan)
    assert validate_rehearsal(receipt, report, binding, plan)
    assert not validate_local_receipt(receipt, plan)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-row",
        "cleanup",
        "fault",
        "semantic",
        "infrastructure",
        "listener",
        "binding",
        "normal-completion",
    ],
)
def test_rehearsal_rejects_incomplete_or_unproven_recovery(plan, mutation):
    receipt, report, binding = copy.deepcopy(rehearsal_fixture(plan))
    if mutation == "missing-row":
        receipt["rows"].pop()
    elif mutation == "cleanup":
        receipt["cleanup"].pop()
    elif mutation == "fault":
        receipt["injectedFault"]["triggered"] = False
    elif mutation == "semantic":
        receipt["rows"][7]["body"] = {}
    elif mutation == "infrastructure":
        receipt["infrastructureFailures"] = [{"failure": "deadline"}]
    elif mutation == "listener":
        report["ownedProcess"]["listenersClosed"] = False
    elif mutation == "binding":
        binding["bound"] = False
    else:
        report["status"] = "completed"
    assert not validate_rehearsal(receipt, report, binding, plan)


def test_gate_refuses_unowned_delete_before_send(tmp_path, plan):
    from shadow import resolve_recovery
    from shared_gate import Gate, create

    create(tmp_path / "gate", plan["localGatePlan"])
    gate = Gate(tmp_path / "gate", "limits")
    gate.claim()
    recovery = plan["localGatePlan"]["jobs"]["limits"]["recovery"]
    document = plan["documents"]["exact-document-boundary"]
    body = {
        "name": document["resource"],
        "fields": document["fields"],
        "updateTime": "2026-09-17T00:00:00Z",
    }
    gate.dispatch(recovery[0], True, lambda: (200, body))
    sent = []

    def forbidden_send():
        sent.append(True)
        raise AssertionError("unowned deletion reached transport")

    operation = resolve_recovery(recovery[1], [{"status": 200, "body": body}])
    with pytest.raises(ValueError, match="journaled creation ownership/version"):
        gate.dispatch(operation, True, forbidden_send)
    assert sent == []
    state = gate.snapshot()["jobs"]["limits"]
    assert state["creationProofs"] == {}
    assert state["absent"] == []
    assert state["recovery"] == 1
    assert state["complete"] is False
