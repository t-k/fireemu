from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from fs_config_lifecycle import lifecycle_production, lifecycle_remote_transport
from fs_config_lifecycle.comparator import (
    COMPARISON_CONTRACT,
    EXPECTED_LOCAL_DEVIATION,
    INDETERMINATE,
    LOCAL_KIND,
    MATCH,
    MISMATCH,
    PRODUCTION_KIND,
    PRODUCTION_ORIGIN,
    REFUSED,
    SCHEMA,
    VerifiedAcquisition,
    compare,
    compare_rows,
)
from fs_config_lifecycle.fake_admin import FakeAdmin
from fs_config_lifecycle.lifecycle_collector import collect
from fs_config_lifecycle.manifest import compile_manifest
from fs_config_lifecycle.surface_matrix import digest
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


def _unregistered(collection: dict, **overrides) -> VerifiedAcquisition:
    """An acquisition object shaped like the one `lifecycle_production.verify_saved`
    returns, bound to `collection`, but constructed here: the boundary never saw it."""
    values = {
        "campaign_id": "FS-CONFIG-LIFECYCLE-01",
        "execution_kind": PRODUCTION_KIND,
        "endpoint": PRODUCTION_ORIGIN,
        "reservation": "c" * 64,
        "ledger_identity": "proof",
        "receipt_digest": "d" * 64,
        "gate_digest": "e" * 64,
        "artifact_sha256": "f" * 64,
        "worker_sha256": lifecycle_remote_transport._WORKER_SHA256,
        "collection_digest": digest(collection),
        "synthetic": False,
    }
    values.update(overrides)
    return VerifiedAcquisition(**values)


def _acquisition(collection: dict, **overrides) -> VerifiedAcquisition:
    """The same object, registered through the boundary's private registry so the
    semantic tests here can run without a receipt directory. The registry is the
    only thing that makes it acceptable; the boundary's binding checks and the
    real registration path are proven in test_fs_config_o8."""
    return lifecycle_production._register(_unregistered(collection, **overrides))


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


def test_identical_shapes_on_a_verified_acquisition_classify_as_a_match(
    tmp_path: Path,
) -> None:
    """Positive control. Both collections come from FakeAdmin; what makes the right
    side production here is the verified-acquisition object bound to it, which the
    O8 boundary produces only from a saved receipt directory and its Ledger row. The
    earlier version of this test asserted acquisitionValidated from the label alone."""
    manifest = compile_manifest(NONCE)
    local = _collection(tmp_path, "local")
    production = _collection(tmp_path, "production")
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, production),
        NONCE,
        acquisition=_acquisition(production),
    )
    assert result["classification"] == MATCH
    assert {row["classification"] for row in result["rows"]} == {MATCH}
    assert len(result["rows"]) == 12
    assert result["acquisitionValidated"] is True
    assert result["acquisition"] == {
        "reservation": "c" * 64,
        "ledgerIdentity": "proof",
        "receiptDigest": "d" * 64,
        "gateDigest": "e" * 64,
        "artifactSha256": "f" * 64,
        "workerSha256": lifecycle_remote_transport._WORKER_SHA256,
        "endpoint": "https://firestore.googleapis.com",
        "collectionDigest": digest(production),
        "synthetic": False,
    }
    assert result["syntheticAnchor"] is False
    assert result["promotionReady"] is False
    assert result["productionUnobservedConditionsReduced"] == 0


def test_a_hand_constructed_acquisition_with_plausible_digests_is_refused(
    tmp_path: Path,
) -> None:
    """Reviewer Should Fix 1: the object must be the one the boundary registered.
    A VerifiedAcquisition built here with well-formed hex strings and the right
    collection digest is a construction, not a verification."""
    manifest = compile_manifest(NONCE)
    local = _collection(tmp_path, "local")
    production = _collection(tmp_path, "production")
    plausible = _unregistered(
        production,
        reservation="f" * 64,
        ledger_identity="x",
        receipt_digest="f" * 64,
        gate_digest="f" * 64,
        artifact_sha256="f" * 64,
        worker_sha256="f" * 64,
    )
    assert lifecycle_production.verified(plausible) is False
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, production),
        NONCE,
        acquisition=plausible,
    )
    assert result["classification"] == REFUSED
    assert result["errors"] == ["production-acquisition-unverified"]
    assert result["rows"] == []
    assert result["acquisitionValidated"] is False
    # Registration is by identity: an equal-looking second instance stays refused.
    registered = _acquisition(production)
    twin = _unregistered(production)
    assert lifecycle_production.verified(registered) is True
    assert lifecycle_production.verified(twin) is False
    assert (
        compare(
            manifest,
            _record(LOCAL_KIND, local),
            _record(PRODUCTION_KIND, production),
            NONCE,
            acquisition=twin,
        )["classification"]
        == REFUSED
    )


def test_a_synthetic_anchor_yields_the_semantic_result_but_never_validates_acquisition(
    tmp_path: Path,
) -> None:
    """Reviewer Should Fix 2: an acquisition anchored in a proof Ledger is reported
    as synthetic on the object and on the comparison, and acquisitionValidated
    stays False whatever the rows say."""
    manifest = compile_manifest(NONCE)
    local = _collection(tmp_path, "local")
    production = _collection(tmp_path, "production")
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, production),
        NONCE,
        acquisition=_acquisition(production, synthetic=True),
    )
    assert result["classification"] == MATCH
    assert result["syntheticAnchor"] is True
    assert result["acquisition"]["synthetic"] is True
    assert result["acquisitionValidated"] is False
    assert result["promotionReady"] is False
    mismatched = copy.deepcopy(production)
    mismatched["rows"][0]["status"] = 418
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, mismatched),
        NONCE,
        acquisition=_acquisition(mismatched, synthetic=True),
    )
    assert result["classification"] == MISMATCH
    assert result["acquisitionValidated"] is False
    # A non-boolean synthetic marker is a broken binding, not a production anchor.
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, production),
        NONCE,
        acquisition=_acquisition(production, synthetic=0),
    )
    assert result["classification"] == REFUSED
    assert result["errors"] == ["production-acquisition-binding"]


def test_a_relabelled_local_collection_is_refused_as_production_acquisition(
    tmp_path: Path,
) -> None:
    """Owner review d7f7ce184 finding 2: an exact copy of the local collection, labelled
    fixed-production-wire with the matching campaignId, must never read as a validated
    production comparison. Without the O8 boundary's acquisition object the comparator
    refuses with a named reason and computes no rows."""
    manifest = compile_manifest(NONCE)
    local = _collection(tmp_path, "only-local")
    relabelled = copy.deepcopy(local)
    assert relabelled["campaignId"] == "FS-CONFIG-LIFECYCLE-01"
    result = compare(
        manifest,
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, relabelled),
        NONCE,
    )
    assert result["classification"] == REFUSED
    assert result["errors"] == ["production-acquisition-unverified"]
    assert result["rows"] == []
    assert result["acquisitionValidated"] is False
    assert result["syntheticAnchor"] is None
    assert result["promotionReady"] is False
    assert "acquisition" not in result


def test_a_dict_shaped_acquisition_or_an_unbound_one_is_refused(
    tmp_path: Path,
) -> None:
    """The acquisition input must be the boundary's own object and must be bound to
    the collection handed in; a serialized copy, another collection's binding, another
    campaign, another endpoint or a malformed digest is refused. Whether the digests
    name the reviewed worker, the receipt on disk and the Ledger row is the O8
    boundary's check, proven in test_fs_config_o8."""
    manifest = compile_manifest(NONCE)
    local = _collection(tmp_path, "local")
    production = _collection(tmp_path, "production")
    other = copy.deepcopy(production)
    other["rows"][0]["status"] = 418
    genuine = _acquisition(production)
    as_dict = dict(genuine.__dict__)
    refused = [
        (as_dict, "production-acquisition-unverified"),
        (None, "production-acquisition-unverified"),
        (_acquisition(other), "production-acquisition-binding"),
        (
            _acquisition(production, campaign_id="OTHER-01"),
            "production-acquisition-binding",
        ),
        (
            _acquisition(production, execution_kind=LOCAL_KIND),
            "production-acquisition-binding",
        ),
        (
            _acquisition(production, endpoint="http://127.0.0.1:1"),
            "production-acquisition-binding",
        ),
        (
            _acquisition(production, worker_sha256="xyz"),
            "production-acquisition-binding",
        ),
        (
            _acquisition(production, receipt_digest="short"),
            "production-acquisition-binding",
        ),
        (_acquisition(production, reservation=""), "production-acquisition-binding"),
        (_acquisition(production, gate_digest=None), "production-acquisition-binding"),
        (
            _acquisition(production, artifact_sha256="G" * 64),
            "production-acquisition-binding",
        ),
    ]
    for acquisition, reason in refused:
        result = compare(
            manifest,
            _record(LOCAL_KIND, local),
            _record(PRODUCTION_KIND, production),
            NONCE,
            acquisition=acquisition,
        )
        assert result["classification"] == REFUSED, reason
        assert result["errors"] == [reason]
        assert result["rows"] == []
        assert result["acquisitionValidated"] is False
    with pytest.raises((AttributeError, TypeError)):
        genuine.collection_digest = digest(other)  # type: ignore[misc]
    assert PRODUCTION_ORIGIN == lifecycle_remote_transport.ORIGIN


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
        acquisition=_acquisition(production),
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
        acquisition=_acquisition(production),
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
        acquisition=_acquisition(production),
    )
    assert result["classification"] == INDETERMINATE
    assert result["productionCleanupComplete"] is False
    # The acquisition is bound and reported, but an indeterminate run is not a
    # validated production comparison.
    assert result["acquisition"]["collectionDigest"] == digest(production)
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
        acquisition=_acquisition(same_refusal),
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
        acquisition=_acquisition(other_refusal),
    )
    by_case = {row["case"]: row for row in result["rows"]}
    assert by_case["OC-18"]["classification"] == MISMATCH
    assert result["classification"] in (MISMATCH, INDETERMINATE)
