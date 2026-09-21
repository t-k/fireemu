from __future__ import annotations

import copy
import json
from pathlib import Path

from fs_config_lifecycle.comparator import (
    COMPARISON_CONTRACT,
    EXPECTED_LOCAL_DEVIATION,
    INDETERMINATE,
    LOCAL_KIND,
    MATCH,
    MISMATCH,
    PRODUCTION_KIND,
    SCHEMA,
    compare,
    compare_rows,
)
from fs_config_lifecycle.fake_admin import FakeAdmin
from fs_config_lifecycle.lifecycle_collector import collect
from fs_config_lifecycle.manifest import compile_manifest
from fs_config_lifecycle.test_fs_config_collector import _gate, _no_sleep

NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def _collection(tmp_path: Path, name: str, **admin) -> dict:
    gate = _gate(tmp_path / name)
    return collect(
        NONCE,
        FakeAdmin(**admin).transmit,
        tmp_path / name / "run",
        gate=gate,
        sleeper=_no_sleep,
    )


def _record(kind: str, collection: dict) -> dict:
    return {"executionKind": kind, "collection": collection}


def test_the_comparator_refuses_a_drifted_manifest_and_an_invalid_nonce(
    tmp_path: Path,
) -> None:
    manifest = compile_manifest(NONCE)
    assert compare({}, None, None, NONCE)["errors"] == ["manifest-invalid"]
    assert compare(manifest, None, None, "zz")["errors"] == ["nonce-invalid"]
    drifted = json.loads(json.dumps(manifest))
    drifted["budget"]["maxRequests"] = 9999
    assert compare(drifted, None, None, NONCE)["errors"] == ["manifest-drift"]


def test_two_local_records_can_never_be_classified_as_a_match(tmp_path: Path) -> None:
    manifest = compile_manifest(NONCE)
    collection = _collection(tmp_path, "a")
    result = compare(
        manifest,
        _record(LOCAL_KIND, collection),
        _record(LOCAL_KIND, collection),
        NONCE,
    )
    assert result["kind"] == SCHEMA
    assert result["classification"] == "PREPARATION_ONLY"
    assert result["errors"] == ["preparation-only"]
    assert result["rows"] == []
    assert result["promotionReady"] is False
    assert result["contract"] == COMPARISON_CONTRACT


def test_a_forged_execution_kind_or_collection_shape_is_named(tmp_path: Path) -> None:
    manifest = compile_manifest(NONCE)
    collection = _collection(tmp_path, "a")
    result = compare(
        manifest,
        _record("fixed-production-wire-ish", collection),
        {"executionKind": PRODUCTION_KIND, "collection": {}},
        NONCE,
    )
    assert result["errors"] == ["local-execution-kind", "production-collection-shape"]


def test_identical_shapes_on_the_production_wire_classify_as_a_match(
    tmp_path: Path,
) -> None:
    manifest = compile_manifest(NONCE)
    local = _collection(tmp_path, "local")
    production = _collection(tmp_path, "production")
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, production),
        NONCE,
    )
    assert result["classification"] == MATCH
    assert {row["classification"] for row in result["rows"]} == {MATCH}
    assert len(result["rows"]) == 12
    assert result["acquisitionValidated"] is True
    assert result["promotionReady"] is False
    assert result["productionUnobservedConditionsReduced"] == 0


def test_the_local_unimplemented_exemption_patch_is_an_expected_deviation(
    tmp_path: Path,
) -> None:
    manifest = compile_manifest(NONCE)
    local = _collection(tmp_path, "local", refuse_apply={"OC-18"})
    production = _collection(tmp_path, "production")
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, production),
        NONCE,
    )
    by_case = {row["case"]: row for row in result["rows"]}
    assert by_case["OC-18"]["classification"] == EXPECTED_LOCAL_DEVIATION
    assert "FS-CONFIG-RT-004" in by_case["OC-18"]["reason"]
    # OC-19 and OC-20 were never reached locally, so they are indeterminate.
    assert by_case["OC-19"]["classification"] == INDETERMINATE
    assert by_case["OC-20"]["classification"] == INDETERMINATE
    assert by_case["OC-14"]["classification"] == MATCH
    assert result["classification"] == INDETERMINATE


def test_a_differing_status_or_shape_is_a_mismatch_naming_what_differs(
    tmp_path: Path,
) -> None:
    manifest = compile_manifest(NONCE)
    local = _collection(tmp_path, "local")
    production = copy.deepcopy(local)
    for row in production["rows"]:
        if row["case"] == "OC-15":
            row["shape"]["ttlConfig"]["state"] = {"enum": "CREATING"}
        if row["case"] == "OC-21":
            row["status"] = 404
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, production),
        NONCE,
    )
    by_case = {row["case"]: row for row in result["rows"]}
    assert by_case["OC-15"]["classification"] == MISMATCH
    assert by_case["OC-15"]["differs"] == ["shape"]
    assert by_case["OC-21"]["differs"] == ["status"]
    assert result["classification"] == MISMATCH


def test_an_incomplete_cleanup_on_either_side_makes_the_whole_comparison_indeterminate(
    tmp_path: Path,
) -> None:
    manifest = compile_manifest(NONCE)
    local = _collection(tmp_path, "local")
    production = _collection(tmp_path, "production", refuse_revert={"OC-20"})
    assert production["cleanupComplete"] is False
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, production),
        NONCE,
    )
    assert result["classification"] == INDETERMINATE
    assert result["productionCleanupComplete"] is False
    assert result["acquisitionValidated"] is False


def test_row_summaries_carry_digests_and_never_a_body(tmp_path: Path) -> None:
    local = _collection(tmp_path, "local")
    rows = compare_rows(local, local, NONCE)
    for row in rows:
        assert set(row["local"]) == {"status", "typedError", "shapeDigest", "complete"}
        assert len(row["local"]["shapeDigest"]) == 64
    assert "projects/fireemu-35fe6" not in json.dumps(rows)


def test_the_comparator_does_not_mask_a_production_refusal_behind_an_expected_deviation(
    tmp_path: Path,
) -> None:
    manifest = compile_manifest(NONCE)
    local = _collection(tmp_path, "local", refuse_apply={"OC-18"})
    same_refusal = _collection(tmp_path, "same", refuse_apply={"OC-18"})
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, same_refusal),
        NONCE,
    )
    by_case = {row["case"]: row for row in result["rows"]}
    # Both sides refused identically: a match on the refusal, visibly, not a
    # deviation the local side declared for itself.
    assert by_case["OC-18"]["classification"] == MATCH
    other_refusal = copy.deepcopy(same_refusal)
    for row in other_refusal["rows"]:
        if row["case"] == "OC-18":
            row["status"] = 400
            row["typedError"] = {"code": 400, "status": "INVALID_ARGUMENT"}
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, other_refusal),
        NONCE,
    )
    by_case = {row["case"]: row for row in result["rows"]}
    assert by_case["OC-18"]["classification"] == MISMATCH
    assert result["classification"] in (MISMATCH, INDETERMINATE)
