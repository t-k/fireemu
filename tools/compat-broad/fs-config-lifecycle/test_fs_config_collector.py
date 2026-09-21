from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fs_config_lifecycle import lifecycle_gate
from fs_config_lifecycle.cases import compile_cases
from fs_config_lifecycle.fake_admin import FakeAdmin, saved_projection
from fs_config_lifecycle.lifecycle_collector import (
    RESULT_KIND,
    UNRECOVERED_KIND,
    collect,
    http_request,
    shape,
)
from fs_config_lifecycle.lifecycle_gate import (
    APPLY_REFUSED,
    NOT_APPLIED,
    RESTORED,
    REVERT_REFUSED,
    ConfigurationGate,
    create,
    gate_plan,
    validate_plan,
)
from fs_config_lifecycle.surface_matrix import digest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from batch_contract import database_evidence

NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
BASELINE = database_evidence(saved_projection())["projectionDigest"]


def _gate(tmp_path: Path, plan=None) -> ConfigurationGate:
    plan = plan or gate_plan(NONCE, baseline_projection_digest=BASELINE)
    create(tmp_path / "gate", plan)
    return ConfigurationGate(tmp_path / "gate")


def _no_sleep(_seconds: float) -> None:
    return None


# -- gate -------------------------------------------------------------------


def test_the_gate_plan_is_bounded_and_refuses_a_foreign_step_list() -> None:
    plan = gate_plan(NONCE, baseline_projection_digest=BASELINE)
    validate_plan(plan)
    assert (
        plan["maxRequests"] * plan["requestCostMicrousd"] <= plan["costCeilingMicrousd"]
    )
    assert plan["recoverySeconds"] < plan["wallSeconds"] <= 1200
    other = gate_plan("f" * 32, baseline_projection_digest=BASELINE)
    forged = {**plan, "steps": other["steps"]}
    with pytest.raises(ValueError):
        validate_plan(forged)
    with pytest.raises(ValueError):
        validate_plan({**plan, "maxRequests": 10**9})
    with pytest.raises(ValueError):
        gate_plan(NONCE, baseline_projection_digest="short")


def test_the_gate_charges_before_send_and_refuses_beyond_the_request_bound(
    tmp_path: Path,
) -> None:
    plan = gate_plan(NONCE, baseline_projection_digest=BASELINE)
    plan["maxRequests"] = plan["observationRequests"] = 2
    plan["costMicrousd"] = 2 * plan["requestCostMicrousd"]
    gate = _gate(tmp_path, plan)
    request = {"case": "OC-01", "role": "case", "method": "GET", "path": "/v1/x"}
    seen = []

    def send(deadline):
        # The journal is already persisted when the transport runs; read the file
        # directly because the gate holds its lock across the send.
        saved = json.loads((tmp_path / "gate/state.json").read_bytes())
        seen.append(saved["total"])
        return {"status": 200, "body": {}, "complete": True, "failure": None}

    gate.charge("observation", request, send)
    gate.charge("observation", request, send)
    assert seen == [1, 2]
    with pytest.raises(ValueError, match="request bound"):
        gate.charge("observation", request, send)
    state = gate.snapshot()
    assert state["stopped"] and state["stopReason"] == "request-bound"
    assert state["total"] == 2
    assert state["costMicrousd"] == 2 * plan["requestCostMicrousd"]


def test_the_gate_keeps_the_recovery_reserve_free_of_observation_requests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gate = _gate(tmp_path)
    plan = gate.plan
    started = gate.snapshot()["started"]
    request = {"case": "OC-13", "role": "case", "method": "GET", "path": "/v1/x"}
    observation_end = started + plan["wallSeconds"] - plan["recoverySeconds"]
    monkeypatch.setattr(lifecycle_gate.time, "monotonic", lambda: observation_end - 1.0)
    with pytest.raises(ValueError, match="observation wall"):
        gate.charge("observation", request, lambda _d: None)
    assert gate.snapshot()["stopReason"] == "observation-wall"
    gate.begin_recovery()
    receipt = gate.charge(
        "recovery",
        request,
        lambda _d: {"status": 200, "body": {}, "complete": True, "failure": None},
    )
    assert receipt["status"] == 200


def test_the_gate_refuses_a_request_past_the_owner_permission_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = gate_plan(
        NONCE, baseline_projection_digest=BASELINE, permission_expires_at=1000.0
    )
    gate = _gate(tmp_path, plan)
    monkeypatch.setattr(lifecycle_gate.time, "time", lambda: 999.0)
    with pytest.raises(ValueError, match="permission expires"):
        gate.charge("observation", {"case": "OC-01"}, lambda _d: None)


def test_a_credential_refusal_latches_and_stops_the_observation(tmp_path: Path) -> None:
    gate = _gate(tmp_path)
    request = {"case": "OC-01", "role": "case", "method": "GET", "path": "/v1/x"}
    gate.charge(
        "observation",
        request,
        lambda _d: {
            "status": 403,
            "body": {"error": {}},
            "complete": True,
            "failure": None,
        },
    )
    state = gate.snapshot()
    assert state["credentialRejected"] is True
    assert state["stopReason"] == "credential-refused"
    with pytest.raises(ValueError, match="observation stopped"):
        gate.charge("observation", request, lambda _d: None)


def test_a_malformed_or_oversized_receipt_is_a_stop_not_a_journal_entry(
    tmp_path: Path,
) -> None:
    gate = _gate(tmp_path)
    request = {"case": "OC-01", "role": "case", "method": "GET", "path": "/v1/x"}
    with pytest.raises(ValueError, match="bounded configuration receipt"):
        gate.charge("observation", request, lambda _d: {"status": 200})
    assert gate.snapshot()["stopped"] is True


def test_finish_requires_every_step_restored_and_a_reconciliation(
    tmp_path: Path,
) -> None:
    gate = _gate(tmp_path)
    with pytest.raises(ValueError, match="quiet recovery"):
        gate.finish()
    gate.begin_recovery()
    gate.record_step("ttl", restore="applied")
    with pytest.raises(ValueError, match="restore incomplete"):
        gate.finish()
    gate.record_step("ttl", restore=RESTORED, verifyDigest="x")
    with pytest.raises(ValueError, match="reconciliation incomplete"):
        gate.finish()
    gate.record_reconciliation({"ok": True})
    gate.finish()
    assert gate.snapshot()["complete"] is True
    with pytest.raises(ValueError):
        gate.record_step("ttl", restore=NOT_APPLIED)
    with pytest.raises(ValueError, match="closed restore state"):
        gate.record_step("exemption", restore="whatever")


def test_a_tampered_gate_plan_is_refused(tmp_path: Path) -> None:
    gate = _gate(tmp_path)
    state = json.loads((tmp_path / "gate/state.json").read_text())
    state["plan"]["maxRequests"] = 10**6
    (tmp_path / "gate/state.json").write_text(json.dumps(state))
    with pytest.raises(ValueError, match="gate plan changed"):
        gate.snapshot()


# -- collector --------------------------------------------------------------


def test_every_case_maps_to_a_rest_request_the_discovery_method_implies() -> None:
    for case in compile_cases(NONCE):
        extra = {
            "operation_name": "projects/fireemu-35fe6/databases/(default)/operations/o"
        }
        request = (
            http_request(case, **extra) if case["id"] == "OC-22" else http_request(case)
        )
        assert request["path"].startswith("/v1/projects/fireemu-35fe6/")
        assert request["method"] in {"GET", "PATCH"}
        assert (request["method"] == "PATCH") == case["method"].endswith(".patch")
    with pytest.raises(ValueError, match="operation poll"):
        http_request(next(c for c in compile_cases(NONCE) if c["id"] == "OC-22"))


def test_shape_keeps_presence_types_and_enums_but_never_values() -> None:
    body = {
        "name": "projects/x",
        "ttlConfig": {"state": "ACTIVE"},
        "n": 3,
        "b": True,
        "l": [1],
    }
    assert shape(body) == {
        "b": "boolean",
        "l": ["number"],
        "n": "number",
        "name": "string",
        "ttlConfig": {"state": {"enum": "ACTIVE"}},
    }
    assert "projects/x" not in json.dumps(shape(body))


def test_a_clean_run_observes_every_case_restores_both_fields_and_reconciles(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin(poll_rounds=2)
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["kind"] == RESULT_KIND
    assert result["completed"] is True
    assert result["cleanupComplete"] is True
    assert result["restoreVerified"] is True
    assert result["unrecovered"] == []
    assert result["stopPoint"] is None
    assert set(result["observedCases"]) == {c["id"] for c in compile_cases(NONCE)}
    for name in ("ttl", "exemption"):
        step = result["steps"][name]
        assert step["restore"] == RESTORED
        assert step["preDigest"] == step["verifyDigest"]
        assert step["postDigest"] != step["preDigest"]
        assert step["appliedOperation"] and step["revertOperation"]
    assert result["reconciliation"]["ok"] is True
    assert result["chargedRequests"] == result["rowCount"] == len(admin.requests)
    assert result["chargedMicrousd"] == result["rowCount"]
    assert gate.snapshot()["complete"] is True
    # Both fields are back exactly where they started.
    for name, field in admin.fields.items():
        assert "ttlConfig" not in field
        assert field["indexConfig"]["usesAncestorConfig"] is True
    # The ledger names the patches in order: apply, revert, apply, revert.
    masks = [(mask, body) for _n, mask, body in admin.patches]
    assert masks == [
        ("ttlConfig", {}),
        ("ttlConfig", None),
        ("indexConfig", {"indexes": []}),
        ("indexConfig", {}),
    ]
    assert NONCE not in json.dumps(result)


def test_raw_bodies_stay_in_the_private_run_directory_and_out_of_the_result(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin()
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    collection = tmp_path / "run"
    assert (collection / "result.json").stat().st_mode & 0o077 == 0
    bodies = sorted(collection.glob("response-*.body"))
    assert len(bodies) == result["rowCount"]
    for body in bodies:
        assert body.stat().st_mode & 0o077 == 0
    serialized = json.dumps(result)
    projection = saved_projection()
    assert projection["uid"] not in serialized
    assert projection["etag"] not in serialized
    # The projection body is in the private row file, by digest in the result.
    row = json.loads((collection / "row-000.json").read_text())
    assert row["bodyDigest"] == digest(projection)
    assert result["rows"][0]["bodyDigest"] == digest(projection)
    assert "body" not in result["rows"][0]


def test_projection_drift_stops_before_any_mutation(tmp_path: Path) -> None:
    drifted = saved_projection()
    drifted["locationId"] = "europe-west1"
    admin = FakeAdmin(projection=drifted)
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["stopPoint"] == "projection-drift"
    assert result["completed"] is False
    assert admin.patches == []
    assert all(step["restore"] == NOT_APPLIED for step in result["steps"].values())
    assert result["restoreVerified"] is True
    assert (
        result["cleanupComplete"] is False
    )  # no enumeration was captured to reconcile
    assert result["unrecovered"] == []


def test_a_stop_after_the_ttl_patch_reverts_it_in_recovery_and_never_touches_the_exemption(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin(poll_rounds=1, fail_at={"OC-15": "incomplete"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["completed"] is False
    assert result["stopPoint"] == "injected-timeout"
    last_observed = [row for row in result["rows"] if row["phase"] == "observation"][-1]
    assert (last_observed["case"], last_observed["complete"]) == ("OC-15", False)
    assert result["steps"]["ttl"]["restore"] == RESTORED
    assert result["steps"]["exemption"]["restore"] == NOT_APPLIED
    assert result["restoreVerified"] is True
    assert result["cleanupComplete"] is True
    assert result["unrecovered"] == []
    recovery_rows = [row for row in result["rows"] if row["phase"] == "recovery"]
    assert [row["case"] for row in recovery_rows][:1] == ["OC-16"]
    assert not any(row["case"] in {"OC-17", "OC-18", "OC-20"} for row in result["rows"])
    masks = [mask for _n, mask, _b in admin.patches]
    assert masks == ["ttlConfig", "ttlConfig"]
    assert "ttlConfig" not in admin.fields[result["steps"]["ttl"]["resource"]]


def test_a_refused_revert_is_unrecovered_with_a_typed_record(tmp_path: Path) -> None:
    admin = FakeAdmin(refuse_revert={"OC-16"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["completed"] is False
    assert result["stopPoint"] == "ttl-revert-refused"
    assert result["steps"]["ttl"]["restore"] == REVERT_REFUSED
    assert result["restoreVerified"] is False
    assert result["cleanupComplete"] is False
    assert [item["step"] for item in result["unrecovered"]] == ["ttl"]
    record = result["unrecoveredRecord"]
    assert record["kind"] == UNRECOVERED_KIND
    assert record["reservation"] == "held"
    assert record["resources"][0]["refusal"]["status"] == "FAILED_PRECONDITION"
    assert result["steps"]["ttl"]["preBodyRef"]["file"].startswith("response-")
    assert gate.snapshot()["complete"] is False
    # A non-permanent refusal gets exactly one recovery attempt, then reconciliation
    # sees the policy under the TTL filter, not under the index filter.
    assert result["steps"]["ttl"]["revertAttempts"] == 2
    reverts = [row for row in result["rows"] if row["case"] == "OC-16"]
    assert [row["phase"] for row in reverts] == ["observation", "recovery"]
    listings = result["reconciliation"]["fieldListings"]
    assert listings["ttl:ttlConfig"]["nonDefaultFields"] == 1
    assert listings["ttl:indexConfig"]["nonDefaultFields"] == 0
    assert result["reconciliation"]["ok"] is False


def test_a_refused_exemption_patch_is_an_observed_deviation_not_a_cleanup_failure(
    tmp_path: Path,
) -> None:
    """The local runtime answers UNIMPLEMENTED for indexConfig (FS-CONFIG-RT-004)."""
    admin = FakeAdmin(refuse_apply={"OC-18"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["steps"]["exemption"]["restore"] == APPLY_REFUSED
    assert result["refusedApplies"] == ["OC-18"]
    assert result["deviations"][0]["error"]["status"] == "UNIMPLEMENTED"
    assert result["cleanupComplete"] is True
    assert result["restoreVerified"] is True
    assert result["completed"] is False  # OC-19 and OC-20 were never observed
    assert "OC-19" not in result["observedCases"]
    assert gate.snapshot()["complete"] is True


def test_an_operation_that_never_finishes_stops_at_the_poll_bound_and_reverts(
    tmp_path: Path,
) -> None:
    ttl_field = next(
        s
        for s in gate_plan(NONCE, baseline_projection_digest=BASELINE)["steps"]
        if s["id"] == "ttl"
    )["resource"]
    admin = FakeAdmin(never_done={ttl_field})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["stopPoint"] == "ttl-operation-deadline"
    polls = [
        row
        for row in result["rows"]
        if row["case"] == "OC-22" and row["phase"] == "observation"
    ]
    assert len(polls) == gate.plan["pollAttempts"]
    # The revert's own operation is also never done, so the field stays unverified.
    assert result["steps"]["ttl"]["restore"] == "unverified"
    assert result["unrecovered"][0]["restore"] == "unverified"
    assert result["chargedRequests"] <= gate.plan["maxRequests"]


def test_a_transport_exception_after_the_exemption_patch_still_reverts_both_fields(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin(fail_at={"OC-19": "raise"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["failure"] == "ConnectionResetError"
    assert result["steps"]["ttl"]["restore"] == RESTORED
    assert result["steps"]["exemption"]["restore"] == RESTORED
    assert result["cleanupComplete"] is True
    assert all(
        field["indexConfig"]["usesAncestorConfig"] for field in admin.fields.values()
    )


def test_a_credential_refusal_mid_run_still_attempts_the_revert_and_reports_it(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin(credential_refuse_at="OC-15")
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["stopPoint"] == "credential-refused"
    assert gate.snapshot()["credentialRejected"] is True
    # The recovery revert was charged and sent; the fake accepts it, so it restores.
    assert result["steps"]["ttl"]["restore"] == RESTORED
    assert any(
        row["phase"] == "recovery" and row["case"] == "OC-16" for row in result["rows"]
    )


def test_a_changed_enumeration_fails_reconciliation_and_holds(tmp_path: Path) -> None:
    admin = FakeAdmin(drift_enumeration_after=1)
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["restoreVerified"] is True
    assert result["reconciliation"]["enumeration"]["equal"] is False
    assert result["cleanupComplete"] is False
    assert gate.snapshot()["complete"] is False


def test_the_collector_refuses_a_reused_output_directory(tmp_path: Path) -> None:
    (tmp_path / "run").mkdir()
    with pytest.raises(ValueError, match="fresh collection output"):
        collect(NONCE, FakeAdmin().transmit, tmp_path / "run", gate=_gate(tmp_path))


# -- ownership is journaled before the patch leaves (review Must Fix 1) ----------


def _ttl_field(admin: FakeAdmin) -> dict:
    name = next(name for name in admin.fields if "fsconfig_ttl_" in name)
    return admin.fields[name]


def test_a_patch_whose_answer_raised_is_owned_and_reverted_in_recovery(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin(raise_after_apply={"OC-14"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["failure"] == "ConnectionResetError"
    assert result["steps"]["ttl"]["restore"] == RESTORED
    assert [m for _n, m, _b in admin.patches] == ["ttlConfig", "ttlConfig"]
    assert "ttlConfig" not in _ttl_field(admin)
    reverts = [row for row in result["rows"] if row["case"] == "OC-16"]
    assert [row["phase"] for row in reverts] == ["recovery"]
    assert result["cleanupComplete"] is True


def test_a_2xx_patch_answer_without_an_owned_operation_is_owned_not_ignored(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin(answer_without_operation={"OC-14"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["stopPoint"] == "ttl-apply-unparsed"
    assert result["steps"]["ttl"]["restore"] == RESTORED
    assert "ttlConfig" not in _ttl_field(admin)
    assert result["steps"]["exemption"]["restore"] == NOT_APPLIED
    assert not any(row["case"] == "OC-18" for row in result["rows"])


def test_a_5xx_typed_answer_to_a_patch_is_apply_uncertain_not_apply_refused(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin(answer_5xx={"OC-14"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["stopPoint"] == "ttl-apply-uncertain"
    assert result["refusedApplies"] == []
    assert result["steps"]["ttl"]["restore"] == RESTORED
    assert "ttlConfig" not in _ttl_field(admin)


def test_a_typed_unimplemented_answer_still_proves_the_patch_was_not_applied(
    tmp_path: Path,
) -> None:
    """501 UNIMPLEMENTED says the method is not served; 500/503/504 do not."""
    admin = FakeAdmin(refuse_apply={"OC-18"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["steps"]["exemption"]["restore"] == APPLY_REFUSED
    assert not any(row["case"] == "OC-20" for row in result["rows"])


def test_a_gate_refusal_before_the_wire_leaves_the_step_not_applied(
    tmp_path: Path,
) -> None:
    plan = gate_plan(NONCE, baseline_projection_digest=BASELINE)
    # Two controls and the baseline read fit; the TTL patch itself is refused by
    # the request bound before it is sent, so nothing is owned.
    plan["maxRequests"] = plan["observationRequests"] = 3
    plan["costMicrousd"] = 3 * plan["requestCostMicrousd"]
    admin = FakeAdmin()
    gate = _gate(tmp_path, plan)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["stopPoint"] == "request-bound"
    assert result["steps"]["ttl"]["restore"] == NOT_APPLIED
    assert admin.patches == []
    assert result["restoreVerified"] is True


def test_a_revert_acknowledged_but_not_applied_is_unverified_and_holds(
    tmp_path: Path,
) -> None:
    """Kills the mutants that drop the verify read or its digest comparison."""
    admin = FakeAdmin(ignore_revert={"OC-16"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["steps"]["ttl"]["restore"] == "unverified"
    assert result["steps"]["ttl"]["verifyDigest"] != result["steps"]["ttl"]["preDigest"]
    assert [item["step"] for item in result["unrecovered"]] == ["ttl"]
    assert result["cleanupComplete"] is False
    assert gate.snapshot()["complete"] is False
    assert "ttlConfig" in _ttl_field(admin)
    # The recovery re-revert of an unverified step fits inside the operation bound.
    assert result["steps"]["ttl"]["revertAttempts"] == 2
    assert gate.snapshot()["operationsSeen"] <= gate.plan["maxOperations"]
    assert result["recoveryFailures"] == []


def test_a_revert_that_raised_after_the_wire_is_revert_uncertain_then_retried(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin(fail_at={"OC-16": "raise"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    # Both the observation-phase and the recovery-phase revert raise, so the step
    # ends revert-uncertain with two journaled attempts and stays owned.
    assert result["steps"]["ttl"]["restore"] == "revert-uncertain"
    assert result["steps"]["ttl"]["revertAttempts"] == 2
    assert result["recoveryFailures"] == [
        {"step": "ttl", "failure": "ConnectionResetError"}
    ]
    assert result["cleanupComplete"] is False


def test_a_permanent_refusal_of_a_revert_is_not_retried(tmp_path: Path) -> None:
    admin = FakeAdmin(credential_refuse_at="OC-16")
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["steps"]["ttl"]["restore"] == REVERT_REFUSED
    assert result["steps"]["ttl"]["refusal"]["code"] == 401
    assert result["steps"]["ttl"]["revertAttempts"] == 1
    assert result["cleanupComplete"] is False


def test_reconciliation_lists_ttl_overrides_with_the_ttl_filter(tmp_path: Path) -> None:
    admin = FakeAdmin(ignore_revert={"OC-16"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    listings = result["reconciliation"]["fieldListings"]
    assert set(listings) == {
        "ttl:indexConfig",
        "ttl:ttlConfig",
        "exemption:indexConfig",
        "exemption:ttlConfig",
    }
    assert listings["ttl:ttlConfig"]["nonDefaultFields"] == 1
    assert listings["ttl:indexConfig"]["nonDefaultFields"] == 0
    assert result["reconciliation"]["ok"] is False


def test_every_poll_after_the_declared_one_is_labelled_a_poll_row(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin(poll_rounds=2)
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    polls = [row for row in result["rows"] if row["case"] == "OC-22"]
    assert [row["role"] for row in polls][:1] == ["case"]
    assert all(row["role"] == "poll" for row in polls[1:])
    assert len(polls) == 8


def test_a_recovery_re_revert_after_both_steps_ran_fits_the_operation_bound(
    tmp_path: Path,
) -> None:
    admin = FakeAdmin(ignore_revert={"OC-20"})
    gate = _gate(tmp_path)
    result = collect(
        NONCE, admin.transmit, tmp_path / "run", gate=gate, sleeper=_no_sleep
    )
    assert result["steps"]["exemption"]["revertAttempts"] == 2
    assert result["steps"]["exemption"]["restore"] == "unverified"
    assert result["recoveryFailures"] == []
    assert gate.snapshot()["operationsSeen"] == 5 <= gate.plan["maxOperations"]
