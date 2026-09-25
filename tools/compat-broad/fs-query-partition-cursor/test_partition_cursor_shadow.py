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
    collected["status"] = "incomplete"
    result = validate_shadow(collected, plan())
    assert result["status"] == "DIFFERENT"
    assert [difference["kind"] for difference in result["differences"]] == [
        "cursor-start-at-value",
        "cursor-end-before-value",
    ]


def test_an_incomplete_cleanup_is_a_difference(tmp_path) -> None:
    collected = bundle(tmp_path)
    collected["cleanup"]["complete"] = False
    collected["status"] = "incomplete"
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
    collected["status"] = "incomplete"
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
    collected["status"] = "incomplete"
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


def test_a_bundle_with_no_retained_wire_bytes_is_never_matched(tmp_path) -> None:
    """M1 reproduction: the offline fixture retains nothing, so no verdict holds."""
    value = plan()
    transport = Transport(value)
    transport.raw = False
    collected = collect_local(value, transport, tmp_path / "out")
    assert collected["raw"] == {"complete": False, "bindings": 0}
    result = validate_shadow(collected, value)
    assert result["status"] == "INDETERMINATE"
    assert result["reason"] == "incomplete-retention"


def test_a_binding_count_below_the_dispatched_rows_is_indeterminate(tmp_path) -> None:
    collected = bundle(tmp_path)
    collected["raw"]["bindings"] -= 1
    result = validate_shadow(collected, plan())
    assert result["status"] == "INDETERMINATE"
    assert result["reason"] == "raw-bindings-below-dispatched-rows"


def test_a_dispatched_row_without_a_sidecar_is_indeterminate(tmp_path) -> None:
    collected = bundle(tmp_path)
    next(row for row in collected["rows"] if row["status"] != "skipped")["raw"] = {
        "present": False,
        "reason": "no-transport-bytes",
    }
    assert validate_shadow(collected, plan())["status"] == "INDETERMINATE"


def test_an_incomplete_publication_is_indeterminate(tmp_path) -> None:
    collected = bundle(tmp_path)
    collected["publication"]["complete"] = False
    result = validate_shadow(collected, plan())
    assert result["status"] == "INDETERMINATE"
    assert result["reason"] == "incomplete-retention"


def test_a_passing_row_set_that_disagrees_with_the_bundle_status_is_indeterminate(
    tmp_path,
) -> None:
    collected = bundle(tmp_path)
    collected["status"] = "incomplete"
    result = validate_shadow(collected, plan())
    assert result["status"] == "INDETERMINATE"
    assert result["reason"] == "status-disagrees-with-rows"


def test_the_residual_scan_refuses_to_read_absence_from_a_failed_root_read() -> None:
    """M2 reproduction: a 500 on the root read is unknown, never zero."""
    from partition_cursor_shadow import residual_documents

    value = plan()

    def transmit(request: dict) -> dict:
        if request["kind"] == "residual-root":
            return {"status": 500, "body": {"error": {"status": "INTERNAL"}}}
        return {"status": 200, "body": [{"readTime": "2026-09-18T00:00:00Z"}]}

    assert residual_documents(transmit, value) is None


def test_the_residual_scan_counts_a_present_root_and_proves_absence_with_404() -> None:
    from partition_cursor_shadow import residual_documents

    value = plan()

    def retained(status, body):
        # Match the actual transport contract; no reconstructed/omitted bytes.
        import json
        raw = json.dumps(body).encode("utf-8")
        return {"status": status, "body": body, "rawBody": raw, "byteCount": len(raw),
                "complete": True, "contentType": "application/json"}

    def present(request: dict) -> dict:
        if request["kind"] == "residual-root":
            return retained(200, {"name": value["ownedScope"]})
        return retained(200, [{"readTime": "2026-09-18T00:00:00Z"}])

    def absent(request: dict) -> dict:
        if request["kind"] == "residual-root":
            return retained(404, {"error": {"status": "NOT_FOUND", "code": 404}})
        return retained(200, [{"readTime": "2026-09-18T00:00:00Z"}])

    assert residual_documents(present, value) == 1
    assert residual_documents(absent, value) == 0


def test_a_failed_group_or_cursor_scan_is_also_unknown() -> None:
    from partition_cursor_shadow import residual_documents

    value = plan()

    def broken(request: dict) -> dict:
        if request["kind"] == "residual-scan":
            return {"status": 503, "body": None}
        return {"status": 200, "body": []}

    assert residual_documents(broken, value) is None


def test_the_committed_shadow_record_binds_a_real_artifact_and_commit() -> None:
    """M3: the published claim lives in the record, not in prose."""
    import json
    import re
    import subprocess

    from partition_cursor_shadow import SHADOW_RECORD

    record = json.loads(SHADOW_RECORD.read_bytes())
    artifact = record["artifact"]
    assert re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
    assert re.fullmatch(r"[0-9a-f]{40}", artifact["sourceCommit"])
    assert artifact["reproducible"] is False
    assert artifact["sourceTreeClean"] is True
    assert not artifact["path"].startswith("/")
    root = SHADOW_RECORD.resolve().parents[2]
    subprocess.run(
        ["git", "cat-file", "-e", artifact["sourceCommit"] + "^{commit}"],
        cwd=root,
        check=True,
    )


def test_the_committed_shadow_record_agrees_with_the_compiled_plan() -> None:
    import json

    from partition_cursor_shadow import SHADOW_RECORD

    record = json.loads(SHADOW_RECORD.read_bytes())
    run = record["run"]
    assert record["productionExecuted"] is False
    assert record["promotionReady"] is False
    assert record["target"] == "owned-local-artifact"
    assert run["observationRows"] == OBSERVATION_COUNT
    assert run["recoveryRows"] == RECOVERY_COUNT
    assert run["rawBindings"] == OBSERVATION_COUNT + RECOVERY_COUNT
    assert run["rawComplete"] is True
    assert run["publicationComplete"] is True
    assert run["cleanupComplete"] is True
    assert run["residualDocuments"] == 0
    assert run["reconstruction"]["matches"] is True
    assert run["ownedProcess"]["stopped"] is True
    assert run["ownedProcess"]["listenersClosed"] is True


def test_the_current_committed_shadow_record_is_matched() -> None:
    import json

    from partition_cursor_shadow import SHADOW_RECORD

    record = json.loads(SHADOW_RECORD.read_bytes())
    assert record["run"]["validation"] == "MATCHED"
    assert record["differences"] == []


def test_the_withdrawn_ticket_is_no_longer_claimed_anywhere() -> None:
    """O4-REPAIR-001 was a misattribution; the corrected case now passes."""
    import json

    from partition_cursor_shadow import SHADOW_RECORD

    assert "O4-REPAIR-001" not in KNOWN_LOCAL_DIFFERENCES.values()
    assert "O4-REPAIR-001" not in SHADOW_RECORD.read_text()
    record = json.loads(SHADOW_RECORD.read_bytes())
    assert "cursor-too-many-values" not in {
        difference["kind"] for difference in record["differences"]
    }


def test_a_broken_reconstruction_is_never_a_verdict(tmp_path) -> None:
    """R1 reproduction: every row passes, but the ranges do not rebuild the
    baseline, so the bundle status disagrees with the rows."""
    value = plan()

    class Truncated(Transport):
        def _body(self, request: dict) -> tuple[int, dict]:
            status, body = super()._body(request)
            if request["kind"] == "partition-reconstruction-range-0":
                body = body[:2]
            return status, body

    collected = collect_local(value, Truncated(value), tmp_path / "out")
    assert collected["reconstruction"]["matches"] is False
    assert all(
        row["status"] in ("pass", "skipped")
        for row in collected["rows"] + collected["cleanup"]["rows"]
    )
    result = validate_shadow(collected, value)
    assert result["status"] == "INDETERMINATE"
    assert result["reason"] == "status-disagrees-with-rows"


def test_the_status_guard_fires_when_differences_are_present_too(tmp_path) -> None:
    collected = bundle(tmp_path)
    by_kind = {row["kind"]: row for row in collected["rows"]}
    for kind in KNOWN_LOCAL_DIFFERENCES:
        by_kind[kind]["status"] = "mismatch"
    collected["status"] = "pass"
    result = validate_shadow(collected, plan())
    assert result["status"] == "INDETERMINATE"
    assert result["reason"] == "status-disagrees-with-rows"


def test_the_committed_shadow_record_carries_the_lane_code_it_ran() -> None:
    """R2: the retraction is reproducible from the recorded commit and digests."""
    import json

    from partition_cursor_manifest import source_inputs
    from partition_cursor_shadow import SHADOW_RECORD

    record = json.loads(SHADOW_RECORD.read_bytes())
    assert record["sourceInputs"] == source_inputs()
    assert any(
        name.endswith("partition_cursor_case.py") for name in record["sourceInputs"]
    )
    assert any(
        name.endswith("partition_cursor_collector.py")
        for name in record["sourceInputs"]
    )
