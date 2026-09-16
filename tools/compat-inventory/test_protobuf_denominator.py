"""Tests for the versioned Firestore protobuf denominator companion."""

import hashlib
import json

import protobuf_denominator as denominator
import pytest


def source(*locators: tuple[str, str]) -> dict:
    return {
        "schemaVersion": 1,
        "upstreamCommit": "a" * 40,
        "descriptorSha256": "b" * 64,
        "sources": [],
        "surfaces": [
            {
                "locator": locator,
                "kind": kind,
                "transport": "gRPC",
                "classification": "unknown",
                "requirements": [],
            }
            for locator, kind in locators
        ],
    }


def test_build_marks_pipeline_rows_and_keeps_standard_rows_structural():
    value = denominator.build(
        source(
            ("google.firestore.v1.Firestore.RunQuery", "method"),
            ("google.firestore.v1.Firestore.ExecutePipeline", "method"),
            ("google.firestore.v1.Pipeline", "message"),
            ("google.firestore.v1.Value.pipeline_value", "field"),
        ),
        source_path="spec/compatibility/upstream/firestore-protobuf.json",
        source_sha256="c" * 64,
        generator_sha256="d" * 64,
    )

    assert value["denominatorVersion"] == denominator.VERSION
    assert value["summary"] == {
        "surfaceCount": 4,
        "targetCount": 1,
        "excludedSurfaceCount": 3,
        "excludedBy": {
            "enterprise-pipeline": 3,
            "enterprise-full-text": 0,
            "mongodb-compatibility": 0,
            "datastore-mode": 0,
        },
    }
    pipeline = [row for row in value["surfaces"] if row["scope"] == "enterprise-only"]
    assert {row["locator"] for row in pipeline} == {
        "google.firestore.v1.Firestore.ExecutePipeline",
        "google.firestore.v1.Pipeline",
        "google.firestore.v1.Value.pipeline_value",
    }
    standard = next(row for row in value["surfaces"] if row["scope"] == "target")
    assert standard["kind"] == "method"
    assert standard["transport"] == "gRPC"
    assert standard["evidenceState"] == "waiting-oracle"


def test_build_keeps_explicit_zero_surface_exclusions_and_bounded_sdk_debt():
    value = denominator.build(
        source(("google.firestore.v1.Firestore.RunQuery", "method")),
        source_path="pinned.json",
        source_sha256="c" * 64,
        generator_sha256="d" * 64,
    )

    assert [row["id"] for row in value["exclusions"]] == [
        "enterprise-pipeline",
        "enterprise-full-text",
        "mongodb-compatibility",
        "datastore-mode",
    ]
    assert all(row["surfaceIds"] == [] for row in value["exclusions"])
    assert value["coverageDebt"] == [
        {
            "id": "firestore-sdk-inventory",
            "bounded": True,
            "status": "debt",
            "scope": "Firestore SDK/platform combinations",
            "surfaceCount": 0,
            "reason": "Pinned protobuf descriptors do not enumerate SDK packages or platform transports.",
            "nextAction": "Inventory pinned SDK package/platform combinations and bind each to a separate source snapshot.",
        }
    ]


def test_validate_rejects_stale_source_and_reclassification():
    source_value = source(("google.firestore.v1.Firestore.RunQuery", "method"))
    value = denominator.build(
        source_value,
        source_path="pinned.json",
        source_sha256="c" * 64,
        generator_sha256="d" * 64,
    )
    with pytest.raises(denominator.ValidationError, match="source digest"):
        denominator.validate(value, source_value, "e" * 64)

    value["surfaces"][0]["scope"] = "enterprise-only"
    with pytest.raises(denominator.ValidationError, match="scope classification"):
        denominator.validate(value, source_value, "c" * 64)


def test_current_companion_is_reproducible_and_immutable():
    source_path = denominator.ROOT / denominator.SOURCE_PATH
    output_path = denominator.ROOT / denominator.OUTPUT_PATH
    source_value = json.loads(source_path.read_text())
    expected = denominator.build(
        source_value,
        source_path=denominator.SOURCE_PATH,
        source_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
        generator_sha256=hashlib.sha256(
            denominator.SOURCE_FILE.read_bytes()
        ).hexdigest(),
    )
    actual = json.loads(output_path.read_text())
    assert actual == expected
    denominator.validate(
        actual,
        source_value,
        hashlib.sha256(source_path.read_bytes()).hexdigest(),
    )
    with pytest.raises(ValueError, match="immutable denominator version"):
        denominator.write_immutable(
            output_path, denominator.serialized({"changed": True})
        )
