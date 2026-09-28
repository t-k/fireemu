"""Pure semantic regressions for ``o5_user_token_semantics``; no credential,
acquisition or network is used.

Adopted from the external RULES-SEMANTIC-REPAIR-006 deliverable and reduced
to the functions this lane installed (typed JSON, pre-redaction binding
capture, binding validation). Projection and observed-record schema stay
with the comparator and its own tests.
"""

from __future__ import annotations

import copy

import pytest
from o5_user_token_semantics import (
    MAX_DEPTH,
    MAX_INTEGER_BITS,
    MAX_NODES,
    MAX_STRING_LENGTH,
    binding_problem,
    capture_principal_fields,
    is_typed_json,
    same_typed_json,
)

REFS = {"owner-a", "other-b"}


def raw_pair(salt: str = "prod") -> tuple[dict, dict]:
    cleanup = {
        "accountSteps": [
            {
                "kind": "account-readback",
                "accountRef": ref,
                "failure": None,
                "observed": {"accountPresent": True, "uid": f"{salt}-{ref}"},
            }
            for ref in ("owner-a", "other-b")
        ]
    }
    row = {
        "observed": {
            "status": "OK",
            "code": 0,
            "documentPresent": True,
            "fields": {"ownerUid": f"{salt}-owner-a", "n": 1},
        }
    }
    return row, cleanup


def redacted(row: dict, cleanup: dict) -> tuple[dict, dict]:
    """Fixture-only spelling of the collector's exact-string uid substitution."""
    labels = {
        step["observed"]["uid"]: "principal:" + step["accountRef"]
        for step in cleanup["accountSteps"]
        if step.get("observed", {}).get("uid")
    }

    def apply(value):
        if type(value) is str:
            return labels.get(value, value)
        if type(value) is list:
            return [apply(item) for item in value]
        if type(value) is dict:
            return {key: apply(item) for key, item in value.items()}
        return value

    return apply(row), apply(cleanup)


def valid(salt: str = "prod", principal: str = "owner-a") -> tuple[dict, dict]:
    row, cleanup = raw_pair(salt)
    row["observed"]["fields"]["ownerUid"] = f"{salt}-{principal}"
    capture_principal_fields([row], cleanup)
    return redacted(row, cleanup)


# ---------------------------------------------------------------------------
# Typed JSON
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right"),
    [(True, 1), (False, 0), ([1], [True]), ({"a": [0]}, {"a": [False]})],
)
def test_boolean_is_not_integer(left, right) -> None:
    assert not same_typed_json(left, right)


def test_integer_is_not_float() -> None:
    assert not same_typed_json({"n": 1}, {"n": 1.0})


def test_large_integers_remain_exact() -> None:
    assert not same_typed_json(9007199254740992, 9007199254740993)
    assert same_typed_json(9223372036854775807, 9223372036854775807)


def test_keys_may_be_reordered() -> None:
    assert same_typed_json({"b": 2, "a": 1}, {"a": 1, "b": 2})


def test_array_order_and_multiplicity_matter() -> None:
    assert not same_typed_json([1, 2], [2, 1])
    assert not same_typed_json([1], [1, 1])


def test_null_and_absence_are_different() -> None:
    assert not same_typed_json({}, {"a": None})
    assert same_typed_json(None, None)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_values_cannot_match(value) -> None:
    assert not is_typed_json(value)
    assert not same_typed_json({"x": value}, {"x": value})


def test_non_json_objects_are_rejected() -> None:
    class IntChild(int):
        pass

    for value in [(1,), {1}, {1: "a"}, b"a", IntChild(1), object()]:
        assert not is_typed_json(value), type(value).__name__


def test_cycles_are_rejected() -> None:
    value: list = []
    value.append(value)
    assert not is_typed_json(value)


def test_repeated_noncyclic_nodes_are_allowed() -> None:
    child = {"a": 1}
    assert is_typed_json([child, child])


def test_depth_node_string_and_integer_bounds() -> None:
    value: object = 1
    for _ in range(MAX_DEPTH + 1):
        value = [value]
    for bad in [
        value,
        [None] * MAX_NODES,
        "x" * (MAX_STRING_LENGTH + 1),
        1 << MAX_INTEGER_BITS,
    ]:
        assert not is_typed_json(bad), type(bad).__name__
    assert is_typed_json("x" * MAX_STRING_LENGTH)
    assert is_typed_json((1 << MAX_INTEGER_BITS) - 1)


def test_same_typed_json_admits_the_projection_envelope() -> None:
    """The comparator wraps each admitted literal; the wider bound in the
    comparison must accept a maximum-depth value once wrapped."""
    value: object = 1
    for _ in range(MAX_DEPTH):
        value = [value]
    assert is_typed_json(value)
    wrapped = {"$literal": value}
    assert same_typed_json(wrapped, copy.deepcopy(wrapped))


# ---------------------------------------------------------------------------
# Pre-redaction binding capture
# ---------------------------------------------------------------------------


def test_bindings_come_from_actual_uid_readback() -> None:
    row, cleanup = raw_pair()
    capture_principal_fields([row], cleanup)
    assert row["principalFieldBindings"] == {
        "ownerUid": {"ref": "owner-a", "readbackIndex": 0}
    }
    assert row["observed"]["fields"]["ownerUid"] == "prod-owner-a"


@pytest.mark.parametrize(
    "value", ["unknown", "principal:owner-a", "", "prod-owner-a-suffix"]
)
def test_arbitrary_and_label_shaped_strings_are_not_bound(value) -> None:
    row, cleanup = raw_pair()
    row["observed"]["fields"]["ownerUid"] = value
    capture_principal_fields([row], cleanup)
    assert row["principalFieldBindings"] == {}


def test_known_wrong_principal_stays_wrong() -> None:
    row, cleanup = valid(principal="other-b")
    assert binding_problem(row, cleanup, REFS) is None
    assert row["principalFieldBindings"]["ownerUid"]["ref"] == "other-b"


def test_duplicate_uid_is_not_last_writer_wins() -> None:
    row, cleanup = raw_pair()
    cleanup["accountSteps"][1]["observed"]["uid"] = "prod-owner-a"
    capture_principal_fields([row], cleanup)
    assert row["principalFieldBindings"] == {}


def test_duplicate_ref_is_ambiguous() -> None:
    row, cleanup = raw_pair()
    cleanup["accountSteps"].append(copy.deepcopy(cleanup["accountSteps"][0]))
    capture_principal_fields([row], cleanup)
    assert row["principalFieldBindings"] == {}


@pytest.mark.parametrize(
    "update",
    [
        {"failure": "timeout"},
        {"observed": {"accountPresent": False, "uid": "prod-owner-a"}},
        {"kind": "account-delete"},
    ],
)
def test_failed_and_absent_readbacks_do_not_bind(update) -> None:
    row, cleanup = raw_pair()
    cleanup["accountSteps"][0].update(update)
    capture_principal_fields([row], cleanup)
    assert row["principalFieldBindings"] == {}


def test_no_accounts_still_writes_empty_metadata() -> None:
    row, _ = raw_pair()
    capture_principal_fields([row], {"accountSteps": []})
    assert row["principalFieldBindings"] == {}


def test_bindings_do_not_contain_raw_uids() -> None:
    row, cleanup = raw_pair()
    capture_principal_fields([row], cleanup)
    assert "prod-owner-a" not in str(row["principalFieldBindings"])


def test_preexisting_metadata_is_not_trusted() -> None:
    row, cleanup = raw_pair()
    row["principalFieldBindings"] = {"ownerUid": {"ref": "other-b", "readbackIndex": 1}}
    capture_principal_fields([row], cleanup)
    assert row["principalFieldBindings"]["ownerUid"]["ref"] == "owner-a"


def test_non_string_and_nested_values_are_not_bound() -> None:
    row, cleanup = raw_pair()
    row["observed"]["fields"] = {"n": 1, "nested": {"ownerUid": "prod-owner-a"}}
    capture_principal_fields([row], cleanup)
    assert row["principalFieldBindings"] == {}


# ---------------------------------------------------------------------------
# Binding validation on the redacted row
# ---------------------------------------------------------------------------


def test_a_valid_binding_has_no_problem() -> None:
    row, cleanup = valid()
    assert binding_problem(row, cleanup, REFS) is None


def test_an_unbound_field_is_not_a_binding_problem() -> None:
    """Whether an unbound principal slot matters is the comparator's call
    (it reports the slot unmapped); the binding check only refuses claims."""
    for value in ["unbound-uid", "principal:owner-a", ""]:
        row, cleanup = raw_pair()
        row["observed"]["fields"]["ownerUid"] = value
        capture_principal_fields([row], cleanup)
        row, cleanup = redacted(row, cleanup)
        assert row["principalFieldBindings"] == {}
        assert binding_problem(row, cleanup, REFS) is None


@pytest.mark.parametrize("bindings", [None, [], "x", {"ownerUid": 1}])
def test_missing_or_malformed_binding_metadata_is_named(bindings) -> None:
    row, cleanup = valid()
    row["principalFieldBindings"] = bindings
    expected = "missing" if type(bindings) is not dict else "ownerUid:invalid"
    assert binding_problem(row, cleanup, REFS) == expected


def test_binding_cannot_claim_wrong_readback() -> None:
    row, cleanup = valid()
    row["principalFieldBindings"]["ownerUid"]["readbackIndex"] = 1
    assert binding_problem(row, cleanup, REFS) == "ownerUid:readback-mismatch"


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        {"ref": "missing", "readbackIndex": 0},
        {"ref": "owner-a", "readbackIndex": True},
        {"ref": "owner-a", "readbackIndex": -1},
        {"ref": "owner-a", "readbackIndex": 100},
        {"ref": "owner-a", "readbackIndex": 0, "extra": True},
    ],
)
def test_malformed_binding_is_rejected(bad) -> None:
    row, cleanup = valid()
    row["principalFieldBindings"]["ownerUid"] = bad
    assert binding_problem(row, cleanup, REFS) == "ownerUid:invalid"


@pytest.mark.parametrize(
    ("field", "value"),
    [("failure", "timeout"), ("accountRef", "other-b"), ("kind", "account-delete")],
)
def test_readback_failure_or_absence_invalidates_binding(field, value) -> None:
    row, cleanup = valid()
    cleanup["accountSteps"][0][field] = value
    assert binding_problem(row, cleanup, REFS) == "ownerUid:readback-mismatch"


def test_an_absent_account_at_readback_invalidates_binding() -> None:
    row, cleanup = valid()
    cleanup["accountSteps"][0]["observed"]["accountPresent"] = False
    assert binding_problem(row, cleanup, REFS) == "ownerUid:readback-mismatch"


def test_a_readback_that_still_carries_a_uid_invalidates_binding() -> None:
    """After redaction the readback records the label; a raw identifier
    there is a redaction miss, and the binding cannot lean on it."""
    row, cleanup = valid()
    cleanup["accountSteps"][0]["observed"]["uid"] = "prod-owner-a"
    assert binding_problem(row, cleanup, REFS) == "ownerUid:readback-mismatch"


def test_metadata_for_missing_field_is_rejected() -> None:
    row, cleanup = valid()
    row["principalFieldBindings"]["missing"] = {"ref": "owner-a", "readbackIndex": 0}
    assert binding_problem(row, cleanup, REFS) == "missing:readback-mismatch"


def test_missing_readbacks_are_named() -> None:
    row, cleanup = valid()
    assert binding_problem(row, {}, REFS) == "readbacks-missing"
    assert binding_problem(row, None, REFS) == "readbacks-missing"


def test_binding_validation_does_not_modify_input() -> None:
    row, cleanup = valid()
    before = copy.deepcopy((row, cleanup))
    binding_problem(row, cleanup, REFS)
    assert (row, cleanup) == before
