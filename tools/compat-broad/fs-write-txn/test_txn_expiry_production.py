"""Offline O8 integration: real Gate journals, a temporary Ledger, no credential.

The full thirteen-case proof runs in this process through `rehearse` with the
documented `Rehearsal` switch shortening the real sleeper. The two stop proofs
that retire a reservation run the real launcher in a subprocess, because the
Ledger proves the coordinator process is gone before it retires a row.
"""

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import reservations
import shared_gate
import txn_expiry_admission as admission
import txn_expiry_cases as cases
import txn_expiry_comparison as comparison
import txn_expiry_descriptor as campaign
import txn_expiry_gate as gate_module
import txn_expiry_o8 as launcher
import txn_expiry_offline_backend as offline
import txn_expiry_preflight
import txn_expiry_production as production
import txn_expiry_remote_transport as remote
from broad_contract import digest
from test_txn_expiry_admission import Admission


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("network forbidden in O8 regression")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


@pytest.fixture
def built(tmp_path):
    fixture = Admission(tmp_path)
    (fixture.ledger / "state.json").unlink()
    fixture.ledger.rmdir()
    reservations.Ledger.create(fixture.ledger)
    return fixture


def _rehearse(built, tmp_path, backend, **extra):
    return production.rehearse(
        inputs=built.inputs,
        permission=built.permission,
        ledger_root=built.ledger,
        output=tmp_path / "output",
        transport=backend.transport,
        management_transport=backend.management,
        token=offline.TOKEN,
        **extra,
    )


def test_the_rehearsal_reaches_all_thirteen_cases_and_releases_the_temporary_ledger(
    built, tmp_path
):
    backend = offline.Backend()
    seen = {}

    def after_reservation():
        state = reservations.Ledger(built.ledger).snapshot()
        seen["rows"] = len(state["reservations"])
        row = next(iter(state["reservations"].values()))
        seen["state"] = row["state"]
        seen["claimed"] = shared_gate.Gate(
            tmp_path / "output/gate", gate_module.JOB
        ).snapshot()["jobs"][gate_module.JOB]["pid"]

    result = _rehearse(
        built,
        tmp_path,
        backend,
        rehearsal=production.Rehearsal(sleep_scale=0.001),
        after_reservation=after_reservation,
    )
    # The reservation and the Gate claim precede the credential.
    assert seen == {"rows": 1, "state": "held", "claimed": os.getpid()}
    collection = result["collection"]
    observed = {row["caseId"] for row in collection["rows"] if row["caseId"]}
    assert observed == {case["id"] for case in cases.CASES}
    assert collection["complete"] is True
    assert collection["unrecovered"] == [] and collection["openTransactions"] == []
    assert collection["timing"] == "wall-clock" and collection["target"] == "production"
    assert result["reservationReleased"] is True and result["failure"] is None
    assert result["executionKind"] == production.INJECTED_EXECUTION
    assert result["productionExecuted"] is True
    assert backend.documents == {}
    assert backend.management_calls == [
        ("observation", slot)
        for slot in ("oauth-tokeninfo", "project", "database", "auth")
    ] + [("recovery", slot) for slot in ("project", "database", "auth")]
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    release = json.loads((output / "release.json").read_bytes())
    gate = shared_gate.Gate(output / "gate", gate_module.JOB).snapshot()
    job = gate["jobs"][gate_module.JOB]
    assert job["complete"] and set(job["absent"]) == set(job["resources"])
    assert set(job["creationProofs"]) == set(job["resources"])
    shared_gate.validate_absence_proofs(gate, gate_module.JOB)
    assert shared_gate.unconfirmed_creates(gate, gate_module.JOB) == 0
    assert gate["total"] == len(receipt["dataRoutes"]) + 7
    assert receipt["chargedCalls"] == gate["total"]
    assert (
        receipt["dataRequestsSent"] == collection["requestCount"] == len(backend.calls)
    )
    # The two transactions whose case refused their commit and rollback (a and
    # b) were still open at cleanup and were rolled back there; the twelve
    # other release slots were consumed without a wire call.
    skips = [
        skip
        for skip in gate.get("skips", [])
        if skip.get("note") == "transaction-not-open-at-cleanup"
    ]
    assert sorted(
        entry["transaction"] for entry in collection["transactionReleases"]
    ) == ["a", "b"]
    assert all(entry["released"] for entry in collection["transactionReleases"])
    assert len(skips) == 14 - 2
    assert [skip["reason"] for skip in gate["skips"]] == [
        shared_gate.ZERO_WIRE_REASON
    ] * len(gate["skips"])
    assert release["receiptDigest"] == digest(receipt)
    final = reservations.Ledger(built.ledger).snapshot()["reservations"][
        receipt["ticket"]["reservation"]
    ]
    assert final["state"] == "released"
    assert final["finalGateDigest"] == receipt["gateDigest"]
    assert offline.TOKEN not in (output / "receipt.json").read_text()
    assert offline.TOKEN not in (output / "gate-snapshot.json").read_text()
    # The rehearsal waited real, shortened seconds: the receipt records them and
    # the comparator refuses the receipt on exactly that.
    waited = [row["waited"] for row in collection["rows"] if row["waited"]]
    assert waited and all(
        0 < entry["measuredSeconds"] < entry["requestedSeconds"] for entry in waited
    )
    assert (
        comparison.local_self_contract(collection)["classification"]
        == comparison.INDETERMINATE
    )
    verdict = campaign.comparator(collection)
    assert verdict["classification"] == comparison.INDETERMINATE
    codes = {reason["code"] for reason in verdict["comparison"]["reasons"]}
    assert "wait-shorter-than-requested" in codes
    assert verdict["formalCompatibilityClaim"] is False
    with pytest.raises(ValueError, match="saved acquisition binding differs"):
        production.verify_saved(
            output,
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )


def test_the_rehearsal_switch_is_refused_on_the_production_wire(built, tmp_path):
    gate_plan = admission.gate_plan_for(built.inputs, built.permission)
    shared_gate.create(tmp_path / "gate", gate_plan)
    gate = gate_module.TxnGate(tmp_path / "gate", gate_module.JOB)

    def production_wire(request, deadline):
        return remote.request(
            {"request": request, "token": offline.TOKEN}, deadline=deadline
        )

    with pytest.raises(ValueError, match="must not reach the production wire"):
        production.run_collection(
            gate,
            built.execution_plan,
            tmp_path / "collection",
            transmit=production_wire,
            rehearsal=production.Rehearsal(sleep_scale=0.01),
        )
    with pytest.raises(ValueError):
        production.Rehearsal(sleep_scale=0)
    with pytest.raises(ValueError):
        production.Rehearsal(sleep_scale=2)
    with pytest.raises(ValueError, match="production wire"):
        production.rehearse(
            inputs=built.inputs,
            permission=built.permission,
            ledger_root=built.ledger,
            output=tmp_path / "output",
            transport=production_wire,
            management_transport=offline.Backend().management,
            token=offline.TOKEN,
        )
    # The collector options a production run uses can only be wall-clock.
    options = campaign.collector_options(built.execution_plan)
    assert options["timing"] == "wall-clock" and options["target"] == "production"
    import txn_expiry_collector as collector

    with pytest.raises(ValueError, match="cannot be simulated"):
        collector.validate_collector_options(
            {**options, "timing": collector.CONTROL_CLOCK}
        )


def _patched_production(monkeypatch, mode):
    backend = offline.Backend(mode)

    def request(value, *, deadline, **_kwargs):
        return backend.transport(value["request"], value["token"], float(deadline))

    def management_transport(slot, token, *, deadline, **_kwargs):
        return backend.management(
            {
                "kind": "management",
                "phase": "patched",
                "slot": slot,
                "token": token,
                "deadline": deadline,
            }
        )

    monkeypatch.setattr(remote, "request", request)
    monkeypatch.setattr(
        txn_expiry_preflight.preflight, "management_transport", management_transport
    )
    return backend


def test_a_credential_refusal_stops_before_any_data_call(built, tmp_path, monkeypatch):
    backend = _patched_production(monkeypatch, "tokeninfo-401")
    code = launcher.main(built.argv(tmp_path))
    assert code == 1
    assert backend.calls == []
    assert backend.management_calls == [("patched", "oauth-tokeninfo")]
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["stopPoint"] == "management-preflight"
    assert receipt["productionExecuted"] is False and receipt["collection"] is None
    assert receipt["dataRequestsSent"] == 0
    gate = json.loads((tmp_path / "output/gate-snapshot.json").read_bytes())
    assert gate["credentialRejected"] is True and gate["events"] == []
    row = next(
        iter(reservations.Ledger(built.ledger).snapshot()["reservations"].values())
    )
    assert row["state"] == "held"


def test_a_binding_change_is_refused_before_any_wire(built, tmp_path, monkeypatch):
    backend = _patched_production(monkeypatch, "complete")
    drifted = built.source / campaign.WORKER_ENTRY
    drifted.write_bytes(drifted.read_bytes() + b"\n")
    code = launcher.main(built.argv(tmp_path))
    assert code == 2
    assert backend.calls == [] and backend.management_calls == []
    assert not (tmp_path / "output").exists()
    assert reservations.Ledger(built.ledger).snapshot()["reservations"] == {}


def test_a_foreign_handoff_is_refused_after_the_reservation_with_nothing_sent(
    built, tmp_path, monkeypatch
):
    backend = _patched_production(monkeypatch, "complete")
    built.handoff_path.write_text(
        json.dumps(
            {
                "kind": launcher.HANDOFF_KIND,
                "permissionDigest": "0" * 64,
                "token": offline.TOKEN,
            }
        )
    )
    code = launcher.main(built.argv(tmp_path))
    assert code == 1
    assert backend.calls == [] and backend.management_calls == []
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert (
        receipt["failure"] == "ValueError"
        and receipt["stopPoint"] == "management-preflight"
    )
    assert admission.classify_stop(receipt)["retirableAsNoData"] is True


DRIVER = r"""
import sys
sys.path.insert(0, sys.argv[1])
import txn_expiry_offline_backend as backend
backend.install(sys.argv[2])
import txn_expiry_o8
raise SystemExit(txn_expiry_o8.main(sys.argv[3:]))
"""


def _run_launcher_in_subprocess(built, tmp_path, mode):
    result = subprocess.run(
        [sys.executable, "-c", DRIVER, str(HERE), mode, *built.argv(tmp_path)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ, "PYTHONHASHSEED": "0"},
    )
    return result


def test_an_early_stop_before_any_create_retires_as_no_data(built, tmp_path):
    result = _run_launcher_in_subprocess(built, tmp_path, "preflight-failure")
    assert result.returncode == 1, result.stderr
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["stopPoint"] == "ownership-preflight"
    assert receipt["productionExecuted"] is False and receipt["collection"] is None
    assert receipt["dataRequestsSent"] == 1
    assert receipt["collectorReceiptFile"] == "collection/result.json"
    assert receipt["timing"] == "wall-clock"
    ledger = reservations.Ledger(built.ledger)
    before = ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]
    assert before["state"] == "held"
    with pytest.raises(ProcessLookupError):
        os.kill(
            json.loads((output / "gate-snapshot.json").read_bytes())["coordinatorPid"],
            0,
        )
    record = admission.build_abort_record(output)
    ledger.abort_no_data(receipt["ticket"], record)
    after = ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]
    assert after["state"] == "aborted-no-data"
    assert json.loads((output / "gate/state.json").read_bytes())["stopped"] is True
    with pytest.raises(ValueError):
        admission.build_abandon_record(output)


def test_a_stop_after_the_first_case_recovers_the_created_documents(built, tmp_path):
    result = _run_launcher_in_subprocess(built, tmp_path, "stop-after-first-case")
    assert result.returncode == 1, result.stderr
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    assert receipt["stopPoint"] == admission.ABANDONED_STOP_POINT
    collection = receipt["collection"]
    observed = [row["caseId"] for row in collection["rows"] if row["caseId"]]
    assert observed == ["idle-expiry/lock-held-before-idle"]
    assert collection["failure"] == "incomplete-response"
    assert collection["unrecovered"] == [] and collection["openTransactions"] == []
    assert sorted(
        entry["transaction"] for entry in collection["transactionReleases"]
    ) == ["a", "b", "c", "d"]
    assert all(entry["released"] for entry in collection["transactionReleases"])
    gate = json.loads((output / "gate-snapshot.json").read_bytes())
    job = gate["jobs"][gate_module.JOB]
    assert job["stopReason"].startswith("collector-stopped:incomplete-response")
    assert set(job["absent"]) == set(job["resources"]) == set(job["creationProofs"])
    assert job["scheduleDone"] == len(gate["plan"]["jobs"][gate_module.JOB]["schedule"])
    assert shared_gate.abandoned_cleanup_complete(gate) == sorted(job["resources"])
    verdict = admission.classify_stop(receipt)
    assert verdict["disposition"] == "closed-after-abandon"
    with pytest.raises(ValueError):
        admission.build_abort_record(output)
    ledger = reservations.Ledger(built.ledger)
    ledger.close_after_abandon(
        receipt["ticket"], admission.build_abandon_record(output)
    )
    final = ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]
    assert final["state"] == "closed-after-abandon"


def test_a_rehearsal_receipt_is_never_production_evidence(built, tmp_path):
    result = _rehearse(
        built,
        tmp_path,
        offline.Backend(),
        rehearsal=production.Rehearsal(sleep_scale=0.001),
    )
    assert result["reservationReleased"] is True
    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    assert receipt["executionKind"] == production.INJECTED_EXECUTION
    with pytest.raises(ValueError):
        production.verify_saved(
            tmp_path / "output",
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )
    with pytest.raises(ValueError):
        production.recover_release(
            tmp_path / "output",
            expected_inputs_digest=built.inputs["inputsDigest"],
            ledger_root=built.ledger,
        )


def test_a_typed_503_on_a_begin_still_recovers_every_document(built, tmp_path):
    """Should Fix 1: one unconfirmed transaction start must not strand the cleanup.

    The begin answered 503 may have started a transaction the run cannot name;
    it holds no document, expires on its own, and the receipt records it as an
    unconfirmed start. The five documents are recovered and the row closes
    through the abandoned-cleanup exit.
    """
    result = _run_launcher_in_subprocess(built, tmp_path, "begin-503")
    assert result.returncode == 1, result.stderr
    assert "retirement path closed-after-abandon" in result.stderr
    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    collection = receipt["collection"]
    assert collection["failure"] == "precondition-not-established"
    assert collection["unconfirmedTransactionStarts"] == ["b"]
    assert collection["unrecovered"] == [] and collection["openTransactions"] == []
    assert sorted(
        entry["transaction"] for entry in collection["transactionReleases"]
    ) == ["a"]
    gate = json.loads((output / "gate-snapshot.json").read_bytes())
    assert shared_gate.unconfirmed_creates(gate, gate_module.JOB) == 0
    assert shared_gate.abandoned_cleanup_complete(gate) == sorted(
        gate["jobs"][gate_module.JOB]["resources"]
    )
    assert receipt["retirement"]["disposition"] == "closed-after-abandon"
    assert "expires on its own" in receipt["retirement"]["reason"]
    ledger = reservations.Ledger(built.ledger)
    ledger.close_after_abandon(
        receipt["ticket"], admission.build_abandon_record(output)
    )
    assert (
        ledger.snapshot()["reservations"][receipt["ticket"]["reservation"]]["state"]
        == "closed-after-abandon"
    )


def test_classify_stop_names_every_disposition():
    base = {"stopPoint": admission.ABANDONED_STOP_POINT, "productionExecuted": True}
    assert (
        admission.classify_stop({**base, "collection": None})["disposition"]
        == "owner-escalation"
    )
    recovered = {
        "unrecovered": [],
        "openTransactions": [],
        "unconfirmedTransactionStarts": [],
    }
    assert (
        admission.classify_stop({**base, "collection": recovered})["disposition"]
        == "closed-after-abandon"
    )
    assert (
        admission.classify_stop(
            {**base, "collection": {**recovered, "openTransactions": ["a"]}}
        )["disposition"]
        == "owner-escalation"
    )
    # The Gate snapshot, when present, must agree: no proofs means no abandoned close.
    empty_gate = {
        "jobs": {
            gate_module.JOB: {
                "observation": 1,
                "recovery": 0,
                "creationProofs": {},
                "complete": False,
                "stopReason": "x",
            }
        },
        "plan": {
            "jobs": {
                gate_module.JOB: {"schedule": [], "observation": [], "recovery": []}
            }
        },
        "events": [],
    }
    assert (
        admission.classify_stop({**base, "collection": recovered, "gate": empty_gate})[
            "disposition"
        ]
        == "owner-escalation"
    )
    assert (
        admission.classify_stop({"stopPoint": None, "releaseEligible": True})[
            "disposition"
        ]
        == "released"
    )
    assert (
        admission.classify_stop({"stopPoint": admission.UNCERTAIN_STOP_POINT})[
            "disposition"
        ]
        == "owner-escalation"
    )
    assert (
        admission.classify_stop(
            {
                "stopPoint": "ownership-preflight",
                "productionExecuted": False,
                "collection": None,
            }
        )["retirableAsNoData"]
        is True
    )
    with pytest.raises(ValueError):
        admission.classify_stop({"stopPoint": "elsewhere"})


def test_the_adapter_returns_an_incomplete_answer_for_a_gate_side_skip(built):
    """A shared-Gate zero-wire skip (no `send`) is never turned into an answer."""
    gate_plan = admission.gate_plan_for(built.inputs, built.permission)
    job = gate_plan["jobs"][gate_module.JOB]

    class SkippingGate:
        def snapshot(self):
            return {
                "plan": gate_plan,
                "jobs": {gate_module.JOB: {"observation": 0, "recovery": 0}},
                "events": [],
            }

        def dispatch(self, operation, recovery, send):
            return (None, {"skipped": "fixture"})

    rows = []
    adapter = production.GateAdapter(
        SkippingGate(), gate_plan, lambda request, deadline: None, rows=rows
    )
    response = adapter(
        {
            "rpc": "GetDocument",
            "site": job["observation"][0]["site"],
            "name": job["observation"][0]["resource"],
            "query": None,
        }
    )
    assert response["complete"] is False and response["blocked"] == "gate-skipped"
    assert rows == []
