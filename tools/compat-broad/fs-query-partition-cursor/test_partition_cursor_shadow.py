"""Contract tests for the local shadow expectation table and its transport guard."""

from __future__ import annotations

import pytest
from partition_cursor_case import OBSERVATION_COUNT, RECOVERY_COUNT
from partition_cursor_collector import collect_local
from partition_cursor_offline_fixture import Transport, plan
from partition_cursor_shadow import (
    KNOWN_LOCAL_DIFFERENCES,
    loopback_transport,
    shadow_contract,
    validate_shadow,
)


def bundle(tmp_path, **kwargs) -> dict:
    value = plan()
    return collect_local(value, Transport(value, **kwargs), tmp_path / "out")


def test_the_contract_lists_every_compiled_slot_with_its_expectation() -> None:
    contract = shadow_contract(plan())
    assert len(contract["observation"]) == OBSERVATION_COUNT
    assert len(contract["recovery"]) == RECOVERY_COUNT
    for row in contract["observation"] + contract["recovery"]:
        assert row["expectation"] in {
            "accepted-documents",
            "accepted-partitions",
            "accepted-reconstruction",
            "typed-refusal",
            "typed-absence",
            "owned-write",
        }


def test_the_contract_is_never_a_receipt() -> None:
    contract = shadow_contract(plan())
    assert contract["status"] == "PREPARATION_ONLY"
    assert contract["productionExecuted"] is False
    assert contract["promotionReady"] is False
    assert contract["planDigest"] == plan()["planDigest"]


def test_the_contract_names_the_expected_documents_for_every_cursor_case() -> None:
    contract = shadow_contract(plan())
    cursors = [
        row for row in contract["observation"] if row["kind"].startswith("cursor-")
    ]
    assert len(cursors) == 12
    accepted = [row for row in cursors if row["expectation"] == "accepted-documents"]
    assert len(accepted) == 8
    assert [row["expectedDocuments"] for row in accepted] == [5, 4, 4, 3, 5, 3, 2, 3]


def test_a_drifted_plan_has_no_contract() -> None:
    value = plan()
    value["recovery"].pop()
    with pytest.raises(ValueError):
        shadow_contract(value)


def test_a_passing_bundle_validates_against_the_contract(tmp_path) -> None:
    result = validate_shadow(bundle(tmp_path), plan())
    assert result["status"] == "MATCHED"
    assert result["differences"] == []
    assert result["promotionReady"] is False
    assert result["productionExecuted"] is False


def test_a_mismatched_bundle_names_every_differing_slot(tmp_path) -> None:
    collected = bundle(tmp_path)
    by_kind = {row["kind"]: row for row in collected["rows"]}
    by_kind["cursor-start-at-value"]["status"] = "mismatch"
    by_kind["cursor-end-before-value"]["status"] = "failed"
    result = validate_shadow(collected, plan())
    assert result["status"] == "DIFFERENT"
    assert [difference["kind"] for difference in result["differences"]] == [
        "cursor-start-at-value",
        "cursor-end-before-value",
    ]


def test_an_incomplete_cleanup_is_a_difference(tmp_path) -> None:
    collected = bundle(tmp_path)
    collected["cleanup"]["complete"] = False
    result = validate_shadow(collected, plan())
    assert result["status"] == "DIFFERENT"
    assert any(
        difference["reason"] == "cleanup-incomplete"
        for difference in result["differences"]
    )


def test_a_bundle_for_another_plan_is_indeterminate(tmp_path) -> None:
    collected = bundle(tmp_path)
    collected["planDigest"] = "0" * 64
    result = validate_shadow(collected, plan())
    assert result["status"] == "INDETERMINATE"


def test_a_production_marked_bundle_is_indeterminate(tmp_path) -> None:
    collected = bundle(tmp_path)
    collected["productionExecuted"] = True
    result = validate_shadow(collected, plan())
    assert result["status"] == "INDETERMINATE"


def test_a_malformed_bundle_is_indeterminate() -> None:
    assert validate_shadow(["rows"], plan())["status"] == "INDETERMINATE"
    assert validate_shadow({}, plan())["status"] == "INDETERMINATE"


@pytest.mark.parametrize(
    "origin",
    [
        "https://firestore.googleapis.com",
        "http://10.0.0.1:8080",
        "http://firestore.example.test",
        "ftp://127.0.0.1",
        42,
    ],
)
def test_the_shadow_transport_refuses_any_non_loopback_origin(origin) -> None:
    with pytest.raises(PermissionError):
        loopback_transport(origin)


def test_the_shadow_transport_accepts_a_loopback_origin() -> None:
    assert callable(loopback_transport("http://127.0.0.1:9099"))


def test_only_ticketed_local_differences_are_classified_as_known(tmp_path) -> None:
    collected = bundle(tmp_path)
    by_kind = {row["kind"]: row for row in collected["rows"]}
    for kind in KNOWN_LOCAL_DIFFERENCES:
        by_kind[kind]["status"] = "mismatch"
    result = validate_shadow(collected, plan())
    assert result["status"] == "DIFFERENT_KNOWN"
    assert {difference["ticket"] for difference in result["differences"]} == set(
        KNOWN_LOCAL_DIFFERENCES.values()
    )


def test_one_unticketed_difference_downgrades_the_whole_run(tmp_path) -> None:
    collected = bundle(tmp_path)
    by_kind = {row["kind"]: row for row in collected["rows"]}
    for kind in KNOWN_LOCAL_DIFFERENCES:
        by_kind[kind]["status"] = "mismatch"
    by_kind["baseline-collection-order"]["status"] = "mismatch"
    assert validate_shadow(collected, plan())["status"] == "DIFFERENT"


def test_every_known_difference_names_a_compiled_case() -> None:
    kinds = {operation["kind"] for operation in plan()["observation"]}
    assert set(KNOWN_LOCAL_DIFFERENCES) <= kinds


def test_the_artifact_binding_names_the_bytes_and_the_source_commit() -> None:
    from pathlib import Path

    from partition_cursor_shadow import artifact_binding

    binding = artifact_binding(Path(__file__))
    assert len(binding["sha256"]) == 64
    assert len(binding["sourceCommit"]) == 40
    assert binding["reproducible"] is False
    assert isinstance(binding["sourceTreeClean"], bool)
    assert not binding["path"].startswith("/")


def test_an_artifact_outside_this_worktree_is_refused(tmp_path) -> None:
    from partition_cursor_shadow import artifact_binding

    foreign = tmp_path / "fireemu"
    foreign.write_bytes(b"not ours")
    with pytest.raises(ValueError):
        artifact_binding(foreign)
