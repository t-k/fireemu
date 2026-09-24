import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from request_bytes_compiler import (
    CATALOG_MAXIMUM,
    DOCUMENT_COUNT,
    DOCUMENT_SAFETY_MARGIN,
    REQUEST_TARGETS,
    compact_utf8,
    compile_request_bytes_plan,
    compile_request_bytes_sentinel_plan,
    document_size_bytes,
    validate_request_bytes_plan,
    validate_request_bytes_sentinel_plan,
)

NONCE = "a" * 32


def test_three_independent_canonical_sizes_and_json_parity() -> None:
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    assert plan["catalogMaximum"] == CATALOG_MAXIMUM == 10_485_760
    assert [probe["bodyBytes"] for probe in plan["probes"]] == list(REQUEST_TARGETS)
    for probe, target in zip(plan["probes"], REQUEST_TARGETS):
        assert len(compact_utf8(probe["body"])) == target
        assert json.loads(compact_utf8(probe["body"])) == probe["body"]


def test_probe_scopes_are_equal_length_disjoint_and_conditionally_create() -> None:
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    scopes = [probe["scope"] for probe in plan["probes"]]
    assert [len(scope.encode()) for scope in scopes] == [len(scopes[0].encode())] * 3
    assert len(plan["ownedResources"]) == 51
    for probe in plan["probes"]:
        assert len(probe["resources"]) == DOCUMENT_COUNT
        assert (
            len({write["update"]["name"] for write in probe["body"]["writes"]})
            == DOCUMENT_COUNT
        )
        assert all(
            write["currentDocument"] == {"exists": False}
            for write in probe["body"]["writes"]
        )


def test_every_probe_document_is_owned_and_below_safety_margin() -> None:
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    for probe in plan["probes"]:
        for write in probe["body"]["writes"]:
            update = write["update"]
            assert update["name"].startswith(probe["scope"] + "/")
            assert update["fields"]["_owner"] == {"stringValue": NONCE}
            assert (
                document_size_bytes(update["name"], update["fields"])
                < DOCUMENT_SAFETY_MARGIN
            )


def test_per_probe_expected_states_are_explicit() -> None:
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    for probe in plan["probes"]:
        expected = probe["expected"]
        assert expected["prior"] == "all-absent"
        assert [doc["name"] for doc in expected["accepted"]["all"]] == probe[
            "resources"
        ]
        assert expected["refused"] == {"all": "absent"}
        assert all(
            row["probe"] == probe["label"]
            for row in plan["observation"]
            if row["probe"] == probe["label"]
        )


def test_schedule_and_bounds_are_conservative_and_complete() -> None:
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    assert len(plan["observation"]) == 105
    assert len(plan["recovery"]) == 153
    assert plan["bounds"]["totalRequestBound"] == 258
    assert plan["bounds"]["peakLiveDocumentCount"] == 17
    validate_request_bytes_plan(plan)


def test_validator_rejects_endpoint_foreign_cleanup_precondition_and_distribution_drift() -> (
    None
):
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    plan["probes"][0]["path"] = "/v1/projects/demo/databases/(default):commit"
    with pytest.raises(ValueError, match="commit endpoint"):
        validate_request_bytes_plan(plan)
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    plan["recovery"][0]["resource"] = (
        "projects/demo/databases/(default)/documents/foreign/victim"
    )
    with pytest.raises(ValueError, match="foreign target"):
        validate_request_bytes_plan(plan)
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    plan["probes"][0]["body"]["writes"][0]["currentDocument"] = {"exists": True}
    with pytest.raises(ValueError, match="exists-false"):
        validate_request_bytes_plan(plan)


def test_validator_rejects_payload_byte_and_operation_count_drift() -> None:
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    plan["probes"][1]["body"]["writes"][1]["update"]["fields"]["blob"][
        "stringValue"
    ] += "x"
    with pytest.raises(ValueError, match="byte length"):
        validate_request_bytes_plan(plan)
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    plan["recovery"].pop()
    with pytest.raises(ValueError, match="operation count"):
        validate_request_bytes_plan(plan)
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    first = plan["probes"][0]["body"]["writes"][1]["update"]["fields"]["blob"][
        "stringValue"
    ]
    second = plan["probes"][0]["body"]["writes"][2]["update"]["fields"]["blob"][
        "stringValue"
    ]
    plan["probes"][0]["body"]["writes"][1]["update"]["fields"]["blob"][
        "stringValue"
    ] = first + "x" * 400_000
    plan["probes"][0]["body"]["writes"][2]["update"]["fields"]["blob"][
        "stringValue"
    ] = second[:-400_000]
    with pytest.raises(ValueError, match="safety margin"):
        validate_request_bytes_plan(plan)


def test_validator_rejects_final_only_readback_manifest() -> None:
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    plan["probes"][0]["expected"]["accepted"] = plan["probes"][1]["expected"][
        "accepted"
    ]
    with pytest.raises(ValueError, match="per-probe expected state"):
        validate_request_bytes_plan(plan)


@pytest.mark.parametrize(
    "project,database,nonce",
    [
        ("", "(default)", NONCE),
        ("demo", "bad/name", NONCE),
        ("demo", "(default)", "A" * 32),
    ],
)
def test_rejects_malformed_targets(project: str, database: str, nonce: str) -> None:
    with pytest.raises(ValueError):
        compile_request_bytes_plan(project, database, nonce)


def test_deterministic_and_nonce_isolated() -> None:
    first = compile_request_bytes_plan("demo", "(default)", NONCE)
    assert first == compile_request_bytes_plan("demo", "(default)", NONCE)
    assert NONCE not in json.dumps(
        compile_request_bytes_plan("demo", "(default)", "b" * 32), sort_keys=True
    )


def test_document_paths_have_even_nonempty_relative_segments():
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    for name in plan["ownedResources"]:
        segments = name.split("/documents/", 1)[1].split("/")
        assert all(segments) and len(segments) % 2 == 0


@pytest.mark.parametrize(
    "phase,index,key,value",
    [
        (
            "recovery",
            1,
            "path",
            "/v1/projects/foreign/databases/(default)/documents/foreign/victim",
        ),
        ("observation", 17, "path", "/v1/projects/demo/databases/(default):commit"),
        ("observation", 17, "body", {"writes": []}),
        ("observation", 0, "method", "DELETE"),
        (
            "observation",
            0,
            "resource",
            "projects/foreign/databases/(default)/documents/foreign/victim",
        ),
        ("observation", 18, "privileged", False),
    ],
)
def test_validator_rejects_actual_wire_operation_mutations(phase, index, key, value):
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    plan[phase][index][key] = value
    with pytest.raises(ValueError):
        validate_request_bytes_plan(plan)


def test_explicit_schedule_requires_cleanup_before_next_probe():
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    schedule = plan.get("executionSchedule")
    assert schedule is not None
    assert len(schedule) == 258
    live = set()
    peak = 0
    for step in schedule:
        row = plan[step["phase"]][step["index"]]
        if row["kind"] == "conditional-create-commit":
            live.update(w["update"]["name"] for w in row["body"]["writes"])
        if row["kind"] == "cleanup-verify-absence":
            live.discard(row["resource"])
        peak = max(peak, len(live))
    assert peak == plan["bounds"]["peakLiveDocumentCount"] == 17
    assert not live
    plan["executionSchedule"] = sorted(schedule, key=lambda step: step["phase"])
    with pytest.raises(ValueError):
        validate_request_bytes_plan(plan)


def test_frozen_plan_does_not_duplicate_whole_probe_state_for_every_read():
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    # Stream encoding avoids allocating the previously 660 MiB serialized plan.
    size = sum(
        len(chunk.encode())
        for chunk in json.JSONEncoder(separators=(",", ":")).iterencode(plan)
    )
    assert size < 70 * 1024 * 1024


@pytest.mark.parametrize(
    "key,value",
    [
        ("schemaVersion", 2),
        ("catalogId", "FS-UNRELATED"),
        ("catalogMaximum", 11_534_336),
        ("protocol", "gRPC"),
        ("metric", "proven backend bytes"),
        ("ownershipRequirements", []),
    ],
)
def test_validator_rejects_evidence_contract_mutations(key, value):
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    plan[key] = value
    with pytest.raises(ValueError):
        validate_request_bytes_plan(plan)


def test_validator_rejects_document_size_manifest_tamper():
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    plan["documents"][plan["ownedResources"][0]]["logicalBytes"] = 1
    with pytest.raises(ValueError, match="manifest"):
        validate_request_bytes_plan(plan)


def test_sentinel_keeps_the_general_catalog_maximum():
    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    assert plan["catalogMaximum"] == CATALOG_MAXIMUM == 10_485_760
    plan["catalogMaximum"] = 11_534_336
    with pytest.raises(ValueError, match="metric contract"):
        validate_request_bytes_sentinel_plan(plan)


def _refresh_probe_field_snapshots(plan, probe):
    import hashlib

    for write, expected in zip(
        probe["body"]["writes"], probe["expected"]["accepted"]["all"]
    ):
        update = write["update"]
        encoded = json.dumps(
            update["fields"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        digest = hashlib.sha256(encoded).hexdigest()
        expected["fieldsSha256"] = digest
        plan["documents"][update["name"]].update(
            fieldsSha256=digest,
            logicalBytes=document_size_bytes(update["name"], update["fields"]),
        )


@pytest.mark.parametrize("mutation", ["transaction", "unknownField", "numericFalse"])
def test_validator_rejects_non_byte_wire_axes_even_at_exact_target(mutation):
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    probe = plan["probes"][0]
    if mutation == "numericFalse":
        probe["body"]["writes"][0]["currentDocument"]["exists"] = 0
    else:
        probe["body"][mutation] = "x"
    field = probe["body"]["writes"][1]["update"]["fields"]["blob"]
    difference = probe["bodyBytes"] - len(compact_utf8(probe["body"]))
    field["stringValue"] = "x" * (len(field["stringValue"]) + difference)
    _refresh_probe_field_snapshots(plan, probe)
    assert len(compact_utf8(probe["body"])) == probe["bodyBytes"]
    with pytest.raises(ValueError):
        validate_request_bytes_plan(plan)


@pytest.mark.parametrize(
    "key,value",
    [("readbackRequirements", []), ("claims", ["production authority granted"])],
)
def test_validator_rejects_state_or_authority_contract_drift(key, value):
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    plan[key] = value
    with pytest.raises(ValueError):
        validate_request_bytes_plan(plan)


def test_logical_snapshot_digest_is_independent_of_map_order():
    plan = compile_request_bytes_plan("demo", "(default)", NONCE)
    probe = plan["probes"][0]
    update = probe["body"]["writes"][0]["update"]
    update["fields"] = dict(reversed(list(update["fields"].items())))
    # Wire order may differ but logical field ownership must not depend on it.
    validate_request_bytes_plan(plan)
