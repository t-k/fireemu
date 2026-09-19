from __future__ import annotations

import json

import pytest
from fs_config_lifecycle.comparator import COMPARISON_CONTRACT, compare
from fs_config_lifecycle.manifest import compile_manifest
from fs_config_lifecycle.shadow import run_shadow, served_case_count

NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def _pair() -> tuple[dict, dict, dict]:
    return compile_manifest(NONCE), run_shadow(NONCE), run_shadow(NONCE)


def test_two_identical_preparation_receipts_still_produce_no_semantic_result() -> None:
    manifest, left, right = _pair()
    result = compare(manifest, left, right, NONCE)
    assert result["classification"] == "PREPARATION_ONLY"
    assert result["promotionReady"] is False
    assert result["acquisitionValidated"] is False
    assert result["rows"] == []
    assert result["errors"] == ["preparation-only"]
    assert result["productionUnobservedConditionsReduced"] == 0


def test_a_production_shaped_receipt_is_refused_rather_than_compared() -> None:
    manifest, left, right = _pair()
    forged = json.loads(json.dumps(left))
    forged["responses"] = [{"status": 200, "body": {"name": "projects/x/databases/y"}}]
    result = compare(manifest, forged, right, NONCE)
    assert "observation-shaped-fields" in result["errors"]
    assert result["rows"] == []
    assert result["promotionReady"] is False


def test_a_forged_source_binding_cannot_enable_a_semantic_comparison() -> None:
    manifest, left, right = _pair()
    forged = json.loads(json.dumps(left))
    forged["sourceBinding"] = {"commit": "0" * 40, "artifactSha256": "a" * 64}
    result = compare(manifest, forged, right, NONCE)
    assert "source-binding" in result["errors"]
    assert result["classification"] == "PREPARATION_ONLY"


def test_a_receipt_claiming_execution_is_refused() -> None:
    manifest, left, right = _pair()
    executed = json.loads(json.dumps(left))
    executed["productionExecuted"] = True
    result = compare(manifest, executed, right, NONCE)
    assert "production-executed" in result["errors"]


def test_a_receipt_bound_to_a_different_manifest_is_refused() -> None:
    manifest, left, _ = _pair()
    other = run_shadow("f" * 32)
    result = compare(manifest, left, other, NONCE)
    assert "manifest-binding" in result["errors"]


def test_a_drifted_manifest_stops_the_comparison_before_the_receipts() -> None:
    manifest, left, right = _pair()
    drifted = json.loads(json.dumps(manifest))
    drifted["budget"]["maxRequests"] = 9999
    assert compare(drifted, left, right, NONCE)["errors"] == ["manifest-drift"]
    assert compare({}, left, right, NONCE)["errors"] == ["manifest-invalid"]


def test_the_manifest_gate_cannot_be_skipped_by_omitting_the_nonce() -> None:
    manifest, left, right = _pair()
    with pytest.raises(TypeError):
        compare(manifest, left, right)  # type: ignore[call-arg]
    drifted = json.loads(json.dumps(manifest))
    drifted["permissionEnvelope"]["required"].append("datastore.entities.get")
    assert compare(drifted, left, right, NONCE)["errors"] == ["manifest-drift"]
    assert compare(manifest, left, right, "z" * 32)["errors"] == ["nonce-invalid"]


def test_the_comparison_contract_names_its_normalized_and_significant_fields() -> None:
    contract = COMPARISON_CONTRACT
    assert "earliestVersionTime" in contract["valueNormalizedFields"]
    assert "etag" in contract["valueNormalizedFields"]
    assert "uid" in contract["valueNormalizedFields"]
    assert "field presence and absence" in contract["significant"]
    assert "array order" in contract["significant"]
    assert contract["acceptableTerminalStates"]["ttlConfig.state"] == ["ACTIVE"]
    assert contract["matchRequires"]
    assert contract["indeterminate"]


def test_the_shadow_declares_local_expectations_without_running_anything() -> None:
    receipt = run_shadow(NONCE)
    assert receipt["localExecuted"] is False
    assert receipt["productionExecuted"] is False
    assert receipt["status"] == "PREPARATION_ONLY"
    assert receipt["sourceBinding"] == {"commit": None, "artifactSha256": None}
    assert receipt["notProven"]
    assert not {"responses", "collector", "transport"} & set(receipt.keys())
    for row in receipt["expectedCaseOutcomes"]:
        assert row["executed"] is False
        assert row["expectedLocalOutcome"] in {"served", "not-served"}


def test_only_the_locally_served_methods_are_expected_to_answer_locally() -> None:
    """The served set is the database inventory, the field configuration and its operations.

    fields.patch is partial: the ttlConfig transition is driven at runtime, the indexConfig
    one is refused with UNIMPLEMENTED (FS-CONFIG-RT-004). operations.get and operations.list
    answer only the field-configuration operations this runtime produced.
    """
    receipt = run_shadow(NONCE)
    served = {
        row["method"]
        for row in receipt["expectedCaseOutcomes"]
        if row["expectedLocalOutcome"] == "served"
    }
    assert served == {
        "firestore.projects.databases.get",
        "firestore.projects.databases.list",
        "firestore.projects.databases.collectionGroups.fields.get",
        "firestore.projects.databases.collectionGroups.fields.list",
        "firestore.projects.databases.collectionGroups.fields.patch",
        "firestore.projects.databases.operations.get",
    }
    assert served_case_count(receipt) > 0


def test_the_control_scenario_is_a_strict_subset_of_the_declared_one() -> None:
    declared = run_shadow(NONCE)
    control = run_shadow(NONCE, "control")
    assert len(control["expectedCaseOutcomes"]) < len(declared["expectedCaseOutcomes"])
    assert all(row["kind"] == "control" for row in control["expectedCaseOutcomes"])
    with pytest.raises(ValueError):
        run_shadow(NONCE, "production")
