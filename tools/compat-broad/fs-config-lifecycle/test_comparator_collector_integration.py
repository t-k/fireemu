"""Integration regression for the real collector and a credential-free FakeAdmin.

Requires the full repository's existing lifecycle/O8 test dependencies. All
acquisition objects here are synthetic test registrations, never production.
"""

from __future__ import annotations

import copy

from fs_config_lifecycle.comparator import (
    INDETERMINATE,
    LOCAL_KIND,
    MATCH,
    PRODUCTION_KIND,
    compare,
)
from fs_config_lifecycle.manifest import compile_manifest
from fs_config_lifecycle.test_fs_config_comparator import (
    NONCE,
    _acquisition,
    _collection,
    _record,
)


def _compare(local, reference):
    return compare(
        compile_manifest(NONCE),
        _record(LOCAL_KIND, local),
        _record(PRODUCTION_KIND, reference),
        NONCE,
        acquisition=_acquisition(reference, synthetic=True),
    )


def _reindex(collection):
    collection["rowCount"] = len(collection["rows"])
    for index, row in enumerate(collection["rows"]):
        row["index"] = index


def test_real_collector_normal_control_is_preserved(tmp_path):
    left = _collection(tmp_path, "left")
    right = _collection(tmp_path, "right")
    result = _compare(left, right)
    assert result["classification"] == MATCH
    assert result["syntheticAnchor"] is True
    assert result["acquisitionValidated"] is False
    assert result["promotionReady"] is False


def test_real_collector_duplicate_observation_is_not_silently_ignored(tmp_path):
    left = _collection(tmp_path, "left")
    right = _collection(tmp_path, "right")
    index = next(
        i
        for i, row in enumerate(left["rows"])
        if row["role"] == "case" and row["phase"] == "observation"
    )
    duplicate = copy.deepcopy(left["rows"][index])
    duplicate["status"] = 404
    left["rows"].insert(index + 1, duplicate)
    _reindex(left)
    result = _compare(left, right)
    assert result["classification"] == INDETERMINATE
    assert any("duplicate-observation" in error for error in result["errors"])


def test_real_collector_recovery_row_cannot_replace_observation(tmp_path):
    left = _collection(tmp_path, "left")
    right = _collection(tmp_path, "right")
    row = next(row for row in left["rows"] if row["role"] == "case")
    row["phase"] = "recovery"
    result = _compare(left, right)
    assert result["classification"] == INDETERMINATE
    assert any(
        "local:missing-observation" in row.get("errors", []) for row in result["rows"]
    )


def test_real_collector_clean_recovery_does_not_erase_abort(tmp_path):
    left = _collection(tmp_path, "left")
    right = _collection(tmp_path, "right")
    assert left["cleanupComplete"] is True
    left.update(completed=False, failure="TimeoutError", stopPoint="aborted")
    result = _compare(left, right)
    assert result["classification"] == INDETERMINATE
    assert result["acquisitionValidated"] is False


def test_real_collector_row_failure_is_not_compatible_success(tmp_path):
    left = _collection(tmp_path, "left")
    right = _collection(tmp_path, "right")
    row = next(row for row in left["rows"] if row["role"] == "case")
    row["failure"] = "connection-reset"
    result = _compare(left, right)
    assert result["classification"] == INDETERMINATE
    assert result["acquisitionValidated"] is False
