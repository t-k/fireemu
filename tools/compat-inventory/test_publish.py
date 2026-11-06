"""Offline receipt validation must reject false passes and cleanup gaps."""

import copy
import json

import pytest
from probe import DATABASE, NUMBER, PROJECT
from publish import (
    AGGREGATIONS,
    OBSERVATION_INPUTS,
    REFUSAL,
    UNCHANGED,
    read_public_observations,
    validate_aggregation,
    validate_identity,
    validate_timestamps,
    write_index,
    write_public_observations,
)


def test_local_receipt_cannot_be_published_as_production():
    row = {"corpus": "aggregation", "target": "production"}
    index = {
        "files": {"tools/compat-inventory/probe.py": "tool"},
        "binarySha256": "binary",
    }
    value = {
        "acceptance": "candidate",
        "project": PROJECT,
        "probeSha256": "tool",
        "projectNumberVerified": True,
        "kind": "live-production",
        "profile": "production",
        "binarySha256": "binary",
        "expectedProjectNumber": NUMBER,
        "database": {
            "name": DATABASE,
            "type": "FIRESTORE_NATIVE",
            "databaseEdition": "STANDARD",
        },
    }
    validate_identity(row, value, index)
    # An immutable old receipt is bound to its archived harness, not today's tool.
    archived = {
        **index,
        "files": {
            "tools/compat-inventory/probe.py": "new-tool",
            "archive/probe.py": "tool",
        },
        "historicalTools": {"tools/compat-inventory/probe.py": "archive/probe.py"},
    }
    validate_identity(row, value, archived)
    with pytest.raises(ValueError):
        validate_identity(row, {**value, "probeSha256": "new-tool"}, archived)
    for key, wrong in [
        ("kind", "live-fireemu"),
        ("projectNumberVerified", False),
        ("profile", "strict"),
        ("database", {}),
        ("probeSha256", "different"),
    ]:
        with pytest.raises(ValueError):
            validate_identity(row, {**value, key: wrong}, index)


def test_auth_claim_requires_the_actual_config_403():
    row = {"corpus": "auth", "target": "production"}
    index = {"files": {"tools/compat-inventory/auth_probe.py": "tool"}}
    value = {
        "acceptance": "candidate",
        "project": PROJECT,
        "probeSha256": "tool",
        "projectNumberVerified": True,
        "target": "production",
        "configReadback": {"httpStatus": 403, "available": False},
    }
    validate_identity(row, value, index)
    for readback in [
        {},
        {"httpStatus": 200, "available": True},
        {"httpStatus": 500, "available": False},
    ]:
        with pytest.raises(ValueError):
            validate_identity(row, {**value, "configReadback": readback}, index)


def test_aggregation_rejects_incomplete_or_false_pass_receipts():
    value = {
        "status": "passed",
        "executedCases": 6,
        "cases": [
            {
                "id": name,
                "passed": True,
                "httpStatus": 200,
                "actual": expected,
                "expected": expected,
            }
            for name, expected in AGGREGATIONS.items()
        ]
        + [
            {
                "id": REFUSAL,
                "passed": True,
                "httpStatus": 409,
                "code": "ALREADY_EXISTS",
            },
            {"id": UNCHANGED, "passed": True},
        ],
        "ownedResources": [str(i) for i in range(4)],
        "cleanup": [{"name": str(i), "confirmedMissing": True} for i in range(4)],
        "stateBefore": {str(i): {"fields": {}} for i in range(4)},
        "stateAfter": {str(i): {"fields": {}} for i in range(4)},
    }
    validate_aggregation(value)
    for mutation in [
        "case",
        "cleanup",
        "count",
        "duplicate",
        "unknown",
        "missing-actual",
        "status",
        "state",
        "refusal",
    ]:
        bad = copy.deepcopy(value)
        if mutation == "case":
            bad["cases"][0]["passed"] = False
        elif mutation == "cleanup":
            bad["cleanup"].pop()
        elif mutation == "count":
            bad["executedCases"] = 60
        elif mutation == "duplicate":
            bad["cases"][0]["id"] = bad["cases"][1]["id"]
        elif mutation == "unknown":
            bad["cases"][0]["id"] = "arbitrary"
        elif mutation == "missing-actual":
            del bad["cases"][0]["actual"]
        elif mutation == "status":
            bad["cases"][0]["httpStatus"] = 403
        elif mutation == "state":
            bad["stateAfter"]["0"] = {"fields": {"x": 99}}
        else:
            bad["cases"][4]["code"] = "PERMISSION_DENIED"
        with pytest.raises(ValueError):
            validate_aggregation(bad)


def test_timestamp_empty_report_cannot_become_sixty_passes():
    with pytest.raises(ValueError):
        validate_timestamps({"results": [], "cleanup": []})


def test_public_index_sink_validates_before_truncation_and_preserves_json_bytes(tmp_path):
    destination = tmp_path / "acquisition.json"
    destination.write_text("keep existing bytes", encoding="utf-8")
    with pytest.raises(ValueError, match="public evidence path validation failed"):
        write_index({"path": "../../outside.json"}, destination)
    assert destination.read_text(encoding="utf-8") == "keep existing bytes"

    value = {"schemaVersion": 1, "snapshot": "snapshot-a"}
    write_index(value, destination)
    assert destination.read_text(encoding="utf-8") == json.dumps(value, indent=2) + "\n"


def test_public_observation_copies_validate_all_bytes_before_creating_destination(tmp_path):
    private_input = tmp_path / "private-input"
    destination = tmp_path / "public-observations"
    private_input.mkdir()
    expected = {}
    for name, _, _ in OBSERVATION_INPUTS:
        raw = b'{"receipt":"safe"}\r\n'
        (private_input / name).write_bytes(raw)
        expected[name] = raw
    (private_input / "auth-production-final.json").write_bytes(
        b'{"path":"../../outside.json"}\n'
    )
    with pytest.raises(ValueError, match="public evidence path validation failed"):
        read_public_observations(private_input)
    assert not destination.exists()

    (private_input / "auth-production-final.json").write_bytes(expected["auth-production-final.json"])
    observations = read_public_observations(private_input)
    write_public_observations(observations, destination)
    assert {path.name: path.read_bytes() for path in destination.iterdir()} == expected
