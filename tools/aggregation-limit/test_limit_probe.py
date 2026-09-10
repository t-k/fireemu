"""Discriminating controls must preserve the old failing input and reject malformed data."""

from copy import deepcopy

import pytest
from probe_limit import cases, corpus, document_ids


def test_extended_controls_preserve_baseline_and_cover_cursor_and_field_order():
    rows = cases("compat_" + "a" * 32, extended=True)
    assert rows[:15] == cases("compat_" + "a" * 32)
    assert len(rows) == 27
    assert len({row["id"] for row in rows}) == 27
    by_id = {row["id"]: row["body"]["structuredAggregationQuery"] for row in rows[15:]}
    assert len(by_id["cursor-value-name"]["structuredQuery"]["startAt"]["values"]) == 2
    assert (
        by_id["multi-reversed"]["aggregations"][0]["avg"]["field"]["fieldPath"] == "y"
    )


def test_offset_metadata_has_a_bounded_integer_and_read_time():
    metadata = {"readTime": "2026-09-09T00:00:00Z", "skippedResults": 2}
    assert document_ids([metadata], "unused") == []
    for bad in [True, -1, 2147483648, "2", None]:
        with pytest.raises(ValueError):
            document_ids([{**metadata, "skippedResults": bad}], "unused")
    with pytest.raises(ValueError):
        document_ids([{"skippedResults": 2}], "unused")


def test_invalid_timestamp_offset_is_not_normalized_into_valid_metadata():
    with pytest.raises(ValueError):
        document_ids([{"readTime": "2026-09-09T00:00:00+00:60"}], "unused")


def test_orders_and_transports_are_crossed_without_changing_the_baseline():
    rows = cases("compat_" + "a" * 32)
    assert len(rows) == 15
    assert len({r["id"] for r in rows}) == 15
    assert rows[0]["body"]["structuredAggregationQuery"]["structuredQuery"] == {
        "from": [{"collectionId": "compat_" + "a" * 32}],
        "limit": 2,
    }
    assert {r["method"] for r in rows} == {"runQuery", "runAggregationQuery"}
    offset = next(r for r in rows if r["id"] == "x-asc-offset-count-sum")
    assert (
        offset["body"]["structuredAggregationQuery"]["structuredQuery"]["offset"] == 2
    )
    descending = next(r for r in rows if r["id"] == "x-desc-documents")
    assert (
        descending["body"]["structuredQuery"]["orderBy"][0]["direction"] == "DESCENDING"
    )
    rows[0]["body"]["structuredAggregationQuery"]["structuredQuery"]["limit"] = 99
    assert (
        cases("compat_" + "a" * 32)[0]["body"]["structuredAggregationQuery"][
            "structuredQuery"
        ]["limit"]
        == 2
    )


def test_document_stream_rejects_errors_foreign_names_and_partial_shapes():
    prefix = "projects/fireemu-35fe6/databases/(default)/documents/compat_" + "a" * 32
    row: dict = {
        "document": {
            "name": prefix + "/A",
            "fields": {
                **corpus()["fixtures"]["A"],
                "__fireemuOracleOwner": {"stringValue": "b" * 32},
            },
            "createTime": "2026-09-09T00:00:00Z",
            "updateTime": "2026-09-09T00:00:00Z",
        },
        "readTime": "2026-09-09T00:00:00Z",
    }
    assert document_ids([row], prefix) == ["A"]
    for key, value in [
        ("fields", {"x": []}),
        ("createTime", "invalid"),
        ("updateTime", "2026-09-09T00:00:00+00:60"),
    ]:
        invalid = deepcopy(row)
        invalid["document"][key] = value
        with pytest.raises(ValueError):
            document_ids([invalid], prefix)
    incomplete = deepcopy(row)
    del incomplete["document"]["createTime"]
    with pytest.raises(ValueError):
        document_ids([incomplete], prefix)
    for bad in [None, {}, {"error": {"code": 13}}, {"document": {"name": "foreign/A"}}]:
        with pytest.raises((ValueError, TypeError)):
            document_ids([row, bad], prefix)
