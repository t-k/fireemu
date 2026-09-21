"""Record-join unit tests. No credential, wire, ledger or acquisition is created.

The compiler and registration answers are doubles, deliberately: these tests run
against the full real comparator but test its record/semantic boundary, not O8.
A separate integration file uses the lane's real collector and FakeAdmin.
"""

from __future__ import annotations

import copy

import pytest
from fs_config_lifecycle import comparator as cmp
from fs_config_lifecycle.surface_matrix import digest

NONCE = "a" * 32
OTHER_NONCE = "b" * 32
ORDER = (
    "OC-01",
    "OC-02",
    "OC-13",
    "OC-14",
    "OC-22",
    "OC-15",
    "OC-16",
    "OC-17",
    "OC-18",
    "OC-19",
    "OC-20",
    "OC-21",
)


def _manifest(nonce):
    if type(nonce) is not str or len(nonce) != 32:
        raise ValueError("test nonce")
    return {"schema": cmp.MANIFEST_SCHEMA, "nonceDigest": digest(nonce), "version": 1}


@pytest.fixture(autouse=True)
def compiler(monkeypatch):
    monkeypatch.setattr(
        cmp,
        "compile_cases",
        lambda nonce: [
            {
                "id": name,
                "expectedLocal": {
                    "outcome": "not-served" if name == "OC-18" else "served",
                    "refusalReason": "unit-only expected deviation",
                },
            }
            for name in ORDER
        ],
    )
    monkeypatch.setattr(cmp, "compile_manifest", _manifest)


def collection():
    rows = [
        {
            "index": i,
            "phase": "observation",
            "role": "case",
            "case": name,
            "complete": True,
            "status": 200,
            "typedError": None,
            "shape": {"state": {"enum": "READY"}},
            "failure": None,
        }
        for i, name in enumerate(ORDER)
    ]
    return {
        "campaignId": cmp.CASE_ID,
        "nonceDigest": digest(NONCE),
        "completed": True,
        "cleanupComplete": True,
        "stopPoint": None,
        "failure": None,
        "rowCount": len(rows),
        "rows": rows,
    }


def reindex(col):
    col["rowCount"] = len(col["rows"])
    for i, row in enumerate(col["rows"]):
        row["index"] = i
    return col


def comparison(
    monkeypatch, local=None, production=None, *, nonce=NONCE, local_nonce=None
):
    local = collection() if local is None else local
    production = collection() if production is None else production
    acquisition = cmp.VerifiedAcquisition(
        campaign_id=cmp.CASE_ID,
        execution_kind=cmp.PRODUCTION_KIND,
        endpoint=cmp.PRODUCTION_ORIGIN,
        reservation="a" * 64,
        ledger_identity="unit-test-only",
        receipt_digest="b" * 64,
        gate_digest="c" * 64,
        artifact_sha256="d" * 64,
        worker_sha256="e" * 64,
        collection_digest=digest(production),
        synthetic=True,
    )
    monkeypatch.setattr(cmp, "_registered", lambda value: value is acquisition)
    return cmp.compare(
        _manifest(nonce),
        {"executionKind": cmp.LOCAL_KIND, "collection": local},
        {"executionKind": cmp.PRODUCTION_KIND, "collection": production},
        nonce,
        acquisition=acquisition,
        local_nonce=local_nonce,
    )


def assert_unknown(result):
    assert result["classification"] == cmp.INDETERMINATE
    assert result["acquisitionValidated"] is False
    assert result["promotionReady"] is False


def test_unchanged_observations_still_match_but_are_only_synthetic(monkeypatch):
    result = comparison(monkeypatch)
    assert result["classification"] == cmp.MATCH
    assert result["syntheticAnchor"] is True
    assert result["acquisitionValidated"] is False
    assert result["promotionReady"] is False
    assert len(result["rows"]) == 12


@pytest.mark.parametrize("side", ["local", "production"])
@pytest.mark.parametrize("nonce", [None, "", "0" * 64, digest(OTHER_NONCE)])
def test_mixed_or_unbound_nonces_are_not_comparable(monkeypatch, side, nonce):
    col = collection()
    col["nonceDigest"] = nonce
    result = comparison(monkeypatch, **{side: col})
    assert_unknown(result)
    assert f"{side}-collection-nonce" in result["errors"]


def test_both_saved_runs_cannot_be_joined_to_a_different_manifest(monkeypatch):
    result = comparison(monkeypatch, nonce=OTHER_NONCE)
    assert_unknown(result)
    assert set(result["errors"]) == {
        "local-collection-nonce",
        "production-collection-nonce",
    }


@pytest.mark.parametrize("at_end", [False, True])
@pytest.mark.parametrize("changed", [False, True])
def test_duplicate_observation_is_never_resolved_by_selecting_first(
    monkeypatch, at_end, changed
):
    col = collection()
    duplicate = copy.deepcopy(col["rows"][0])
    if changed:
        duplicate["status"] = 404
    col["rows"].insert(len(col["rows"]) if at_end else 1, duplicate)
    result = comparison(monkeypatch, reindex(col))
    assert_unknown(result)
    assert "local-duplicate-observation:OC-01" in result["errors"]


def test_reordered_observation_identity_is_unknown(monkeypatch):
    col = collection()
    col["rows"][0], col["rows"][1] = col["rows"][1], col["rows"][0]
    result = comparison(monkeypatch, reindex(col))
    assert_unknown(result)
    assert "local-observation-order" in result["errors"]


def test_unknown_case_is_not_ignored(monkeypatch):
    col = collection()
    col["rows"].append({**col["rows"][0], "case": "OC-99"})
    result = comparison(monkeypatch, reindex(col))
    assert_unknown(result)
    assert "local-unknown-case" in result["errors"]


def test_recovery_does_not_replace_a_missing_observation(monkeypatch):
    col = collection()
    col["rows"][0]["phase"] = "recovery"
    result = comparison(monkeypatch, col)
    assert_unknown(result)
    first = result["rows"][0]
    assert first["classification"] == cmp.INDETERMINATE
    assert first["errors"] == ["local:missing-observation"]


def test_recovery_retry_after_an_observation_is_not_a_duplicate(monkeypatch):
    col = collection()
    col["rows"].append({**col["rows"][0], "phase": "recovery", "status": 200})
    result = comparison(monkeypatch, reindex(col))
    # This test is about row selection; no real recovery success is asserted.
    assert result["classification"] == cmp.MATCH
    assert result["acquisitionValidated"] is False


@pytest.mark.parametrize("role", ["poll", "verify", "reconcile", "preflight"])
def test_noncase_rows_do_not_replace_or_duplicate_cases(monkeypatch, role):
    col = collection()
    extra = {**col["rows"][0], "role": role}
    if role == "preflight":
        col["rows"].insert(0, extra)
    else:
        col["rows"].append(extra)
    assert comparison(monkeypatch, reindex(col))["classification"] == cmp.MATCH


@pytest.mark.parametrize(
    "key,value",
    [
        ("completed", False),
        ("completed", 1),
        ("failure", "TimeoutError"),
        ("stopPoint", "cancelled"),
        ("cleanupComplete", False),
        ("cleanupComplete", 1),
    ],
)
def test_completed_rows_do_not_override_run_failure(monkeypatch, key, value):
    col = collection()
    col[key] = value
    assert_unknown(comparison(monkeypatch, col))


@pytest.mark.parametrize(
    "key", ["completed", "failure", "stopPoint", "cleanupComplete"]
)
def test_missing_run_state_is_not_assumed_success(monkeypatch, key):
    col = collection()
    del col[key]
    assert_unknown(comparison(monkeypatch, col))


@pytest.mark.parametrize("value", [False, 0, 1, "false", None])
def test_only_literal_true_means_complete(monkeypatch, value):
    col = collection()
    col["rows"][0]["complete"] = value
    assert_unknown(comparison(monkeypatch, col))


@pytest.mark.parametrize("value", [0, True, 99, 100, 600, "200", None])
def test_invalid_status_is_not_an_observation(monkeypatch, value):
    col = collection()
    col["rows"][0]["status"] = value
    assert_unknown(comparison(monkeypatch, col))


@pytest.mark.parametrize("status", [401, 403, 429])
def test_same_credential_or_quota_failure_is_not_compatibility(monkeypatch, status):
    left, right = collection(), collection()
    left["rows"][0]["status"] = right["rows"][0]["status"] = status
    assert_unknown(comparison(monkeypatch, left, right))


@pytest.mark.parametrize(
    "key", ["failure", "shape", "typedError", "complete", "status"]
)
def test_missing_response_members_are_unknown(monkeypatch, key):
    col = collection()
    del col["rows"][0][key]
    assert_unknown(comparison(monkeypatch, col))


def test_failure_flag_cannot_be_hidden_by_complete(monkeypatch):
    col = collection()
    col["rows"][0]["failure"] = "connection-reset"
    assert_unknown(comparison(monkeypatch, col))


@pytest.mark.parametrize(
    "typed_error",
    [
        [],
        1,
        "error",
        {"code": True, "status": "UNIMPLEMENTED"},
        {"code": 501},
        {"code": 501, "status": []},
    ],
)
def test_malformed_error_summary_is_not_comparable(monkeypatch, typed_error):
    col = collection()
    col["rows"][0]["typedError"] = typed_error
    assert_unknown(comparison(monkeypatch, col))


def test_ordinary_typed_refusal_can_still_match(monkeypatch):
    left, right = collection(), collection()
    for col in (left, right):
        col["rows"][0].update(
            status=404, typedError={"code": 404, "status": "NOT_FOUND"}
        )
    assert comparison(monkeypatch, left, right)["classification"] == cmp.MATCH


def test_known_semantic_difference_is_still_a_mismatch(monkeypatch):
    col = collection()
    col["rows"][0]["shape"] = {"state": {"enum": "CREATING"}}
    result = comparison(monkeypatch, col)
    assert result["classification"] == cmp.MISMATCH
    assert result["rows"][0]["differs"] == ["shape"]


def test_mismatch_and_missing_row_is_incomplete_not_completed_comparison(monkeypatch):
    col = collection()
    col["rows"][0]["status"] = 404
    col["rows"].pop()
    result = comparison(monkeypatch, reindex(col))
    assert_unknown(result)
    assert result["rows"][0]["classification"] == cmp.MISMATCH
    assert result["rows"][-1]["classification"] == cmp.INDETERMINATE


def test_expected_local_deviation_is_not_whole_run_match(monkeypatch):
    col = collection()
    col["rows"][8].update(
        status=501, typedError={"code": 501, "status": "UNIMPLEMENTED"}
    )
    result = comparison(monkeypatch, col)
    assert result["classification"] == cmp.EXPECTED_LOCAL_DEVIATION
    assert result["acquisitionValidated"] is False
    assert result["rows"][8]["classification"] == cmp.EXPECTED_LOCAL_DEVIATION


@pytest.mark.parametrize("status,code", [(500, 501), (501, 500), (400, 400)])
def test_deviation_needs_the_exact_declared_refusal(monkeypatch, status, code):
    col = collection()
    col["rows"][8].update(
        status=status, typedError={"code": code, "status": "UNIMPLEMENTED"}
    )
    result = comparison(monkeypatch, col)
    assert result["classification"] == cmp.MISMATCH


def test_json_key_order_is_not_a_difference(monkeypatch):
    col = collection()
    col["rows"][0] = dict(reversed(list(col["rows"][0].items())))
    assert comparison(monkeypatch, col)["classification"] == cmp.MATCH


def test_direct_row_comparison_does_not_raise_on_unusable_collection():
    for col in (None, [], {}, {"rows": [None]}, {"rows": "wrong"}):
        rows = cmp.compare_rows(col, collection(), NONCE)
        assert len(rows) == len(ORDER)
        assert {row["classification"] for row in rows} == {cmp.INDETERMINATE}


@pytest.mark.parametrize("value", [True, -1, 999, None, "12"])
def test_invalid_row_count_is_unknown(monkeypatch, value):
    col = collection()
    col["rowCount"] = value
    assert_unknown(comparison(monkeypatch, col))


@pytest.mark.parametrize(
    "key,value",
    [
        ("index", True),
        ("index", 99),
        ("phase", "missing"),
        ("role", []),
        ("role", "unknown"),
        ("case", []),
    ],
)
def test_invalid_row_identity_is_named(monkeypatch, key, value):
    col = collection()
    col["rows"][0][key] = value
    result = comparison(monkeypatch, col)
    assert_unknown(result)
    assert result["errors"]


def test_missing_acquisition_is_still_refused():
    col = collection()
    result = cmp.compare(
        _manifest(NONCE),
        {"executionKind": cmp.LOCAL_KIND, "collection": col},
        {"executionKind": cmp.PRODUCTION_KIND, "collection": copy.deepcopy(col)},
        NONCE,
    )
    assert result["classification"] == cmp.REFUSED
    assert result["errors"] == [cmp.ACQUISITION_UNVERIFIED]


def test_two_local_records_still_are_preparation_only():
    record = {"executionKind": cmp.LOCAL_KIND, "collection": collection()}
    result = cmp.compare(_manifest(NONCE), record, copy.deepcopy(record), NONCE)
    assert result["classification"] == cmp.PREPARATION_ONLY
    assert result["acquisitionValidated"] is False


def test_manifest_boolean_does_not_equal_numeric_version(monkeypatch):
    col = collection()
    bad = _manifest(NONCE)
    bad["version"] = True
    result = cmp.compare(
        bad,
        {"executionKind": cmp.LOCAL_KIND, "collection": col},
        {"executionKind": cmp.PRODUCTION_KIND, "collection": col},
        NONCE,
    )
    assert result["errors"] == ["manifest-drift"]


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), {1: "non-string-key"}, ()]
)
def test_non_json_input_is_refused_before_digest(value):
    col = collection()
    col["rows"][0]["shape"] = value
    rows = cmp.compare_rows(col, collection(), NONCE)
    assert {row["classification"] for row in rows} == {cmp.INDETERMINATE}


def test_cyclic_input_is_bounded():
    col = collection()
    col["cycle"] = col
    rows = cmp.compare_rows(col, collection(), NONCE)
    assert all(r["classification"] == cmp.INDETERMINATE for r in rows)


def test_empty_run_is_not_a_vacuous_match(monkeypatch):
    col = collection()
    col["rows"] = []
    col["rowCount"] = 0
    assert_unknown(comparison(monkeypatch, col, col))


def test_more_rows_than_gate_ceiling_are_unknown(monkeypatch):
    col = collection()
    col["rows"] = [
        {**col["rows"][0], "role": "poll"} for _ in range(cmp.MAX_REQUESTS + 1)
    ]
    assert_unknown(comparison(monkeypatch, reindex(col)))


def test_saved_local_nonce_may_differ_when_explicitly_bound(monkeypatch):
    local = collection()
    local["nonceDigest"] = digest(OTHER_NONCE)
    result = comparison(monkeypatch, local, local_nonce=OTHER_NONCE)
    assert result["classification"] == cmp.MATCH
    assert result["acquisitionValidated"] is False


def test_semantic_kernel_keeps_descriptor_saved_reference_nonce_contract():
    production = collection()
    production["nonceDigest"] = digest(OTHER_NONCE)
    rows = cmp.compare_rows(collection(), production, NONCE)
    assert all(row["classification"] == cmp.MATCH for row in rows)
    # Kernel returns rows only, never the acquisition-validated result object.
    assert all("acquisitionValidated" not in row for row in rows)
