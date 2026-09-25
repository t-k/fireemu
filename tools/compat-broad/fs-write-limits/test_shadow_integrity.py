"""Control admission and local receipts share the Gate's typed evidence rules.

Synthetic records and the real collector/Gate are exercised here. These tests do
not assert that a Rust artifact or production API has been observed.
"""
from __future__ import annotations

import copy

import pytest

from broad_contract import digest
from broad import INDEX_NX_LOCAL_SHA256, index_bytes_for_profile
from collector import collect, writes_safe
from compiler import compile_limits_plan
from rehearsal import validate_rehearsal
from shadow import (
    _validate_cleanup, evaluate_rows, resolve_recovery,
    validate_local_receipt,
)
from test_collection_recording_recovery import scenario as scenario
from test_rehearsal import rehearsal_fixture
from test_shadow import fixture_receipt, fixture_rows


@pytest.fixture(scope="module")
def plan():
    return compile_limits_plan("demo-firestore-probe", "(default)", "a" * 32)


def test_nx_local_shadow_profile_binds_the_declared_after_digest():
    _bytes, digest_value, source_commit = index_bytes_for_profile("nx-local")
    assert digest_value == INDEX_NX_LOCAL_SHA256
    assert source_commit is None


def test_positive_local_receipt_and_rehearsal_are_preserved(plan):
    assert validate_local_receipt(fixture_receipt(plan), plan)
    receipt, parent, binding = rehearsal_fixture(plan)
    assert validate_rehearsal(receipt, parent, binding, plan)
    assert not validate_local_receipt(receipt, plan)


@pytest.mark.parametrize("mutation", ["error-plus-document", "float-code", "boolean-index", "coerced-request"])
def test_unproven_namespace_cannot_authorize_writes(plan, mutation):
    rows = copy.deepcopy(fixture_rows(plan)[:4])
    if mutation == "error-plus-document":
        rows[0]["body"]["fields"] = {}
    elif mutation == "float-code":
        rows[0]["body"]["error"]["code"] = 404.0
    elif mutation == "boolean-index":
        rows[0]["index"] = False
    else:
        rows[0]["request"]["privileged"] = 1
    assert not writes_safe(rows, plan)
    assert evaluate_rows(rows, plan)


@pytest.mark.parametrize("version", ["not-a-version", "2026-02-30T00:00:00Z", "2026-09-19T12:00:60Z", "2026-09-19T12:00:00+00:00", "2026-09-19T12:00:00.1234567890Z"])
def test_invalid_control_versions_do_not_authorize_more_writes(plan, version):
    rows = copy.deepcopy(fixture_rows(plan)[:6])
    for row in rows[4:6]:
        row["body"]["updateTime"] = version
    assert not writes_safe(rows, plan)
    assert evaluate_rows(rows, plan)


@pytest.mark.parametrize("error", [None, {}, {"code": 500, "status": "INTERNAL"}])
def test_success_control_with_error_is_not_write_authority(plan, error):
    rows = copy.deepcopy(fixture_rows(plan)[:6])
    rows[4]["body"]["error"] = error
    assert not writes_safe(rows, plan)
    assert evaluate_rows(rows, plan)


@pytest.mark.parametrize("mutation", ["error-plus-document", "float-code"])
def test_real_collector_stops_before_patch_on_unproven_preflight(scenario, mutation):
    compiled, gate, live, calls, wire, output = scenario
    def anomalous(operation, recovery, index, request_index):
        value = wire(operation, recovery, index, request_index)
        if not recovery and index == 0:
            if mutation == "float-code": value["body"]["error"]["code"] = 404.0
            else: value["body"]["fields"] = {}
        return value
    result = collect(gate, compiled, output, anomalous)
    assert not any(not phase and op["method"] == "PATCH" for phase, _, op in calls)
    assert result["recordingComplete"] is False
    assert result["collectionComplete"] is False
    assert result["infrastructureFailures"]
    assert live == {}


@pytest.mark.parametrize("mutation", [
    "float-absence-code", "contradictory-absence", "delete-error", "delete-scalar",
    "delete-array", "read-error", "coerced-request", "boolean-row-index",
    "boolean-cleanup-index", "float-gate-count", "integer-absence-map",
    "invalid-version", "contradictory-negative", "null-cleanup-row",
    "null-observation-row", "null-proof-map", "string-skip",
])
def test_invalid_local_receipt_never_passes_or_raises(plan, mutation):
    receipt = copy.deepcopy(fixture_receipt(plan))
    if mutation == "float-absence-code": receipt["cleanup"][2]["body"]["error"]["code"] = 404.0
    elif mutation == "contradictory-absence": receipt["cleanup"][2]["body"]["fields"] = {}
    elif mutation == "delete-error": receipt["cleanup"][1]["body"] = {"error": {"code": 500, "status": "INTERNAL"}}
    elif mutation == "delete-scalar": receipt["cleanup"][1]["body"] = None
    elif mutation == "delete-array": receipt["cleanup"][1]["body"] = []
    elif mutation == "read-error": receipt["cleanup"][0]["body"]["error"] = None
    elif mutation == "coerced-request": receipt["rows"][0]["request"]["privileged"] = 1
    elif mutation == "boolean-row-index": receipt["rows"][0]["index"] = False
    elif mutation == "boolean-cleanup-index": receipt["cleanup"][0]["index"] = False
    elif mutation == "float-gate-count": receipt["gate"]["jobs"]["limits"]["observation"] = 16.0
    elif mutation == "integer-absence-map": receipt["resourceAbsence"] = dict.fromkeys(receipt["resourceAbsence"], 1)
    elif mutation == "invalid-version": receipt["rows"][4]["body"]["updateTime"] = "invalid"
    elif mutation == "contradictory-negative": receipt["rows"][8]["body"]["writeResults"] = [{}]
    elif mutation == "null-cleanup-row": receipt["cleanup"][0] = None
    elif mutation == "null-observation-row": receipt["rows"][0] = None
    elif mutation == "null-proof-map": receipt["gate"]["jobs"]["limits"]["creationProofs"] = None
    elif mutation == "string-skip": receipt["cleanup"][1]["skipped"] = "false"
    assert validate_local_receipt(receipt, plan) is False


@pytest.mark.parametrize("extra", ["message", "details", "errors"])
def test_diagnostics_inside_error_remain_supported(plan, extra):
    receipt = fixture_receipt(plan)
    for row in [*receipt["rows"], *receipt["cleanup"]]:
        if isinstance(row["body"], dict) and "error" in row["body"]:
            row["body"]["error"][extra] = "diagnostic" if extra == "message" else []
    assert validate_local_receipt(receipt, plan)


@pytest.mark.parametrize("value", [None, [], "invalid", 1])
def test_malformed_receipt_container_returns_false(plan, value):
    assert validate_local_receipt(value, plan) is False
    assert _validate_cleanup(value, plan) is False
    assert validate_rehearsal(value, {}, {}, plan) is False


@pytest.mark.parametrize("location", ["receipt", "manifest", "parent", "exit", "absence"])
def test_rehearsal_does_not_coerce_flags_or_counters(plan, location):
    receipt, parent, binding = copy.deepcopy(rehearsal_fixture(plan))
    if location == "receipt": receipt["injectedFault"] = {**receipt["injectedFault"], "triggered": 1}
    elif location == "manifest": receipt["manifest"]["injectedFault"] = {**receipt["manifest"]["injectedFault"], "triggered": 1}
    elif location == "parent": parent["manifest"]["injectedFault"] = {**parent["manifest"]["injectedFault"], "triggered": 1}
    elif location == "exit": parent["exitCode"] = False
    elif location == "absence": receipt["resourceAbsence"] = dict.fromkeys(receipt["resourceAbsence"], 1)
    assert validate_rehearsal(receipt, parent, binding, plan) is False


@pytest.mark.parametrize("source", [-1, True, 1.0, "0"])
def test_version_source_must_be_a_nonnegative_integer(source):
    declared = {"path": "/v1/doc", "versionFrom": source}
    with pytest.raises(ValueError): resolve_recovery(declared, [{"status": 200, "body": {"updateTime": "2026-09-19T00:00:00Z"}}])


@pytest.mark.parametrize("version,error", [("bad", False), ("2026-09-19T00:00:00Z", True)])
def test_invalid_read_cannot_supply_a_conditional_delete_version(version, error):
    body = {"updateTime": version}
    if error: body["error"] = None
    declared = {"path": "/v1/doc", "versionFrom": 0}
    assert resolve_recovery(declared, [{"status": 200, "body": body}])["path"] == "/v1/doc"


def test_recomputed_hashes_do_not_legitimize_contradictory_create(plan):
    receipt = copy.deepcopy(fixture_receipt(plan))
    row = receipt["rows"][4]
    row["body"]["error"] = {"code": 500, "status": "INTERNAL"}
    proof = receipt["gate"]["jobs"]["limits"]["creationProofs"][row["body"]["name"]]
    proof["responseDigest"] = digest(row["body"])
    assert _validate_cleanup(receipt, plan) is False
    assert validate_local_receipt(receipt, plan) is False


def test_cleanup_admission_does_not_erase_a_semantic_mismatch(plan):
    # A real typed 400 refusal with a differing message is a semantic difference,
    # not lost transport or a reason to invent a successful local response.
    receipt = fixture_receipt(plan)
    receipt["rows"][8]["body"]["error"]["message"] = "independently retained diagnostic"
    assert _validate_cleanup(receipt, plan)
    assert receipt["rows"][8]["body"]["error"]["message"]


def test_unexpected_negative_success_can_still_have_complete_acquisition(scenario):
    compiled, gate, live, calls, wire, output = scenario
    def accept_all(operation, recovery, index, request_index):
        value = wire(operation, recovery, index, request_index)
        if operation["method"] == "PATCH" and value["status"] == 400:
            name = operation["path"].split("?", 1)[0].removeprefix("/v1/")
            body = {**copy.deepcopy(operation["body"]), "updateTime": "2026-09-19T00:00:00Z"}
            live[name] = body
            return {"status": 200, "body": copy.deepcopy(body), "complete": True, "failure": None}
        return value
    result = collect(gate, compiled, output, accept_all)
    assert result["collectionComplete"] is True
    assert result["cleanupComplete"] is True
    assert result["expectationMismatches"]
    assert _validate_cleanup(result, compiled) is True
    assert live == {}
    assert validate_local_receipt({**result, "productionExecuted": False,
        "completed": True, "stateValidation": True}, compiled) is False


@pytest.mark.parametrize("phase", ["rows", "cleanup"])
def test_stale_success_flag_cannot_cover_recording_failure(plan, phase):
    receipt = fixture_receipt(plan)
    receipt[phase][0]["recordingFailure"] = "OSError"
    assert not validate_local_receipt(receipt, plan)
    assert not _validate_cleanup(receipt, plan)


@pytest.mark.parametrize("value", [0, None, ""])
def test_skipped_annotation_cannot_use_false_like_non_booleans(plan, value):
    receipt = fixture_receipt(plan)
    receipt["cleanup"][1]["skipped"] = value
    assert not validate_local_receipt(receipt, plan)
