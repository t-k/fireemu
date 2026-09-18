"""Contract tests for the offline production/local comparator."""

from __future__ import annotations

import copy
import json

from partition_cursor_case import compile_plan
from partition_cursor_collector import collect_local
from partition_cursor_comparator import compare_evidence
from partition_cursor_offline_fixture import Transport, plan

OTHER_NONCE = "b" * 32


def bundle(tmp_path, name: str, **kwargs) -> dict:
    value = plan()
    return collect_local(value, Transport(value, **kwargs), tmp_path / name)


def other_bundle(tmp_path, name: str, **kwargs) -> dict:
    value = compile_plan("demo-project", "(default)", OTHER_NONCE)
    return collect_local(value, Transport(value, **kwargs), tmp_path / name)


def row_named(value: dict, kind: str) -> dict:
    return next(row for row in value["rows"] if row["kind"] == kind)


def retime(value: dict, stamp: str) -> None:
    def walk(node):
        if isinstance(node, dict):
            for key, item in node.items():
                if key in ("createTime", "updateTime", "readTime", "commitTime"):
                    node[key] = stamp
                else:
                    walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(value["rows"])
    walk(value["cleanup"]["rows"])


def test_two_identical_bundles_are_equivalent(tmp_path) -> None:
    result = compare_evidence(bundle(tmp_path, "a"), bundle(tmp_path, "b"))
    assert result["classification"] == "EQUIVALENT"
    assert result["differences"] == []
    assert result["rows"] == 37


def test_the_comparator_never_promotes_or_validates_acquisition(tmp_path) -> None:
    result = compare_evidence(bundle(tmp_path, "a"), bundle(tmp_path, "b"))
    assert result["promotionReady"] is False
    assert result["acquisitionValidated"] is False
    assert result["productionExecuted"] is False


def test_a_production_marked_side_is_reported_without_promotion(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    left["productionExecuted"] = True
    left["target"] = "production"
    result = compare_evidence(left, bundle(tmp_path, "b"))
    assert result["productionExecuted"] is True
    assert result["promotionReady"] is False


def test_server_assigned_timestamps_are_expected_nondeterminism(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    right = copy.deepcopy(left)
    retime(right, "2027-01-02T03:04:05.000009Z")
    result = compare_evidence(left, right)
    assert result["classification"] == "EQUIVALENT"
    assert result["nondeterministic"] > 0


def test_a_run_with_another_nonce_is_still_equivalent(tmp_path) -> None:
    result = compare_evidence(bundle(tmp_path, "a"), other_bundle(tmp_path, "b"))
    assert result["classification"] == "EQUIVALENT"


def test_opaque_page_tokens_are_compared_by_presence_only(tmp_path) -> None:
    value = plan()
    left = collect_local(value, Transport(value, page_token="left"), tmp_path / "a")
    right = collect_local(value, Transport(value, page_token="right"), tmp_path / "b")
    assert compare_evidence(left, right)["classification"] == "EQUIVALENT"


def test_a_missing_page_token_on_one_side_is_a_semantic_difference(tmp_path) -> None:
    value = plan()
    left = collect_local(value, Transport(value, page_token="left"), tmp_path / "a")
    right = collect_local(value, Transport(value), tmp_path / "b")
    result = compare_evidence(left, right)
    assert result["classification"] == "SEMANTIC_MISMATCH"
    assert any(
        difference["kind"] == "partition-page-token-continuation"
        for difference in result["differences"]
    )


def test_a_differing_document_set_is_a_semantic_difference(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    right = copy.deepcopy(left)
    row_named(right, "cursor-start-at-value")["receipt"]["body"] = []
    result = compare_evidence(left, right)
    assert result["classification"] == "SEMANTIC_MISMATCH"
    assert [difference["kind"] for difference in result["differences"]] == [
        "cursor-start-at-value"
    ]


def test_a_differing_typed_error_is_a_semantic_difference(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    right = copy.deepcopy(left)
    row = row_named(right, "cursor-negative-offset")
    row["receipt"]["body"]["error"]["status"] = "FAILED_PRECONDITION"
    assert compare_evidence(left, right)["classification"] == "SEMANTIC_MISMATCH"


def test_a_differing_document_order_is_a_semantic_difference(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    right = copy.deepcopy(left)
    row = row_named(right, "cursor-start-at-value")
    row["receipt"]["body"] = list(reversed(row["receipt"]["body"]))
    assert compare_evidence(left, right)["classification"] == "SEMANTIC_MISMATCH"


def test_a_differing_partition_count_is_a_semantic_difference(tmp_path) -> None:
    value = plan()
    left = collect_local(value, Transport(value, partitions=1), tmp_path / "a")
    right = collect_local(value, Transport(value), tmp_path / "b")
    assert compare_evidence(left, right)["classification"] == "SEMANTIC_MISMATCH"


def test_a_bundle_whose_digest_does_not_match_its_identity_is_indeterminate(
    tmp_path,
) -> None:
    left = bundle(tmp_path, "a")
    right = copy.deepcopy(left)
    right["planDigest"] = "0" * 64
    assert compare_evidence(left, right)["classification"] == "INDETERMINATE"


def test_a_relabelled_owned_scope_is_indeterminate(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    right = copy.deepcopy(left)
    right["ownedScope"] = right["ownedScope"] + "/elsewhere/x"
    assert compare_evidence(left, right)["classification"] == "INDETERMINATE"


def test_a_malformed_bundle_is_indeterminate(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    assert compare_evidence(left, "not a bundle")["classification"] == "INDETERMINATE"
    assert compare_evidence({}, left)["classification"] == "INDETERMINATE"
    assert compare_evidence(left, json.loads("{}"))["classification"] == "INDETERMINATE"


def test_a_truncated_row_list_is_indeterminate(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    right = copy.deepcopy(left)
    right["rows"].pop()
    assert compare_evidence(left, right)["classification"] == "INDETERMINATE"


def test_a_transport_failure_on_one_side_is_indeterminate(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    right = copy.deepcopy(left)
    row_named(right, "cursor-offset-limit")["status"] = "failed"
    assert compare_evidence(left, right)["classification"] == "INDETERMINATE"


def test_a_health_skip_on_one_side_is_indeterminate(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    right = copy.deepcopy(left)
    row = row_named(right, "cursor-offset-limit")
    row.update(status="skipped", skipReason="aborted-after-failure", receipt=None)
    assert compare_evidence(left, right)["classification"] == "INDETERMINATE"


def test_matching_response_derived_skips_are_equivalent(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    right = bundle(tmp_path, "b")
    assert row_named(left, "partition-page-token-continuation")["skipReason"] == (
        "no-page-token"
    )
    assert compare_evidence(left, right)["classification"] == "EQUIVALENT"


def test_a_side_with_no_retained_bytes_is_indeterminate(tmp_path) -> None:
    value = plan()
    transport = Transport(value)
    transport.raw = False
    empty = collect_local(value, transport, tmp_path / "empty")
    result = compare_evidence(bundle(tmp_path, "a"), empty)
    assert result["classification"] == "INDETERMINATE"
    assert result["reason"] == "raw-bindings-below-dispatched-rows"


def test_a_local_artifact_bundle_may_not_claim_production(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    left["productionExecuted"] = True
    result = compare_evidence(left, bundle(tmp_path, "b"))
    assert result["classification"] == "INDETERMINATE"
    assert result["reason"] == "local-artifact-claims-production"


def test_retained_bytes_are_rebound_to_each_receipt(tmp_path) -> None:
    left = bundle(tmp_path, "a")
    right = bundle(tmp_path, "b")
    result = compare_evidence(
        left,
        right,
        production_directory=tmp_path / "a",
        local_directory=tmp_path / "b",
    )
    assert result["classification"] == "EQUIVALENT"


def test_a_receipt_that_the_retained_bytes_do_not_reproduce_is_indeterminate(
    tmp_path,
) -> None:
    left = bundle(tmp_path, "a")
    right = copy.deepcopy(left)
    row_named(right, "cursor-start-at-value")["receipt"]["body"] = []
    result = compare_evidence(left, right, local_directory=tmp_path / "a")
    assert result["classification"] == "INDETERMINATE"
    assert result["reason"] == "retained-bytes-disagree-with-receipt"


def test_a_missing_sidecar_file_is_reported_by_the_verifier(tmp_path) -> None:
    from partition_cursor_comparator import verify_retained_bytes

    left = bundle(tmp_path, "a")
    (tmp_path / "a" / "raw" / "observation-00.raw").unlink()
    faults = verify_retained_bytes(left, tmp_path / "a")
    assert faults == ["observation-0:unreadable"]
