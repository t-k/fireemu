"""Bounded, typed observations and principal field bindings for the Rules
user-token lane.

Adopted from the external RULES-SEMANTIC-REPAIR-006 deliverable (based on
d7f7ce184) and trimmed to what the collector and comparator v2 use. These are
semantic checks, not proof of production acquisition.

A principal field binding is recorded by the collector BEFORE redaction, from
the value's equality with the uid an account readback of the recovery phase
returned. The redaction then replaces that uid with ``principal:<ref>``
everywhere; the binding is what proves the label in a field came from the
uid and not from a literal that merely looks like a label. No non-empty
string, no ``principal:...`` literal and no upstream metadata creates a
binding.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from typing import Any

MAX_DEPTH = 64
MAX_NODES = 20_000
MAX_STRING_LENGTH = 65_536
MAX_INTEGER_BITS = 4096

# The metadata key a row carries next to ``observed``; refs and readback
# indexes only, never an account identifier.
BINDINGS_KEY = "principalFieldBindings"


def _is_typed_json(value: Any, max_depth: int, max_nodes: int) -> bool:
    remaining = max_nodes
    active: set[int] = set()

    def visit(node: Any, depth: int) -> bool:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > max_depth:
            return False
        kind = type(node)
        if node is None or kind is bool:
            return True
        if kind is str:
            return len(node) <= MAX_STRING_LENGTH
        if kind is int:
            return node.bit_length() <= MAX_INTEGER_BITS
        if kind is float:
            return math.isfinite(node)
        if kind not in (dict, list) or id(node) in active:
            return False
        active.add(id(node))
        try:
            if kind is dict:
                if any(
                    type(key) is not str or not visit(key, depth + 1) for key in node
                ):
                    return False
                return all(visit(item, depth + 1) for item in node.values())
            return all(visit(item, depth + 1) for item in node)
        finally:
            active.remove(id(node))

    return visit(value, 0)


def is_typed_json(value: Any) -> bool:
    """Accept bounded, finite, plain JSON values without bool/number coercion."""
    return _is_typed_json(value, MAX_DEPTH, MAX_NODES)


def same_typed_json(left: Any, right: Any) -> bool:
    """Compare typed JSON; malformed values cannot agree their way to a pass.

    bool, int and float stay distinct at every depth; lists and mappings are
    compared element by element. The bound is wider than ``is_typed_json``
    because the comparator's projection wraps each already-bounded literal
    in a small envelope, which must not turn an admitted maximum-size value
    into a false mismatch.
    """
    if not _is_typed_json(left, MAX_DEPTH + 4, MAX_NODES * 8) or not _is_typed_json(
        right, MAX_DEPTH + 4, MAX_NODES * 8
    ):
        return False
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def capture_principal_fields(
    rows: list[dict[str, Any]], cleanup: dict[str, Any]
) -> None:
    """Bind top-level field values to unique, successful account uid readbacks.

    Call this BEFORE the uid redaction. Only an observation value actually
    equal to a read-back uid acquires a binding; a literal that merely looks
    like a future label acquires none. No uid is copied to the binding.

    Duplicate uid or ref readbacks are ambiguous, not last-writer-wins.
    Failed and absent account readbacks cannot supply identity. This adds
    evidence; it neither authorizes cleanup nor changes the recovery outcome.
    """
    candidates: dict[str, list[tuple[str, int]]] = {}
    ref_counts: dict[str, int] = {}
    for index, step in enumerate(cleanup.get("accountSteps", [])):
        if type(step) is not dict or step.get("kind") != "account-readback":
            continue
        observed = step.get("observed")
        ref = step.get("accountRef")
        if (
            step.get("failure") is not None
            or type(observed) is not dict
            or observed.get("accountPresent") is not True
            or type(ref) is not str
            or not ref
        ):
            continue
        uid = observed.get("uid")
        if type(uid) is not str or not uid:
            continue
        candidates.setdefault(uid, []).append((ref, index))
        ref_counts[ref] = ref_counts.get(ref, 0) + 1
    unique = {
        uid: matches[0]
        for uid, matches in candidates.items()
        if len(matches) == 1 and ref_counts[matches[0][0]] == 1
    }
    for row in rows:
        bindings: dict[str, dict[str, Any]] = {}
        fields = (row.get("observed") or {}).get("fields")
        if type(fields) is dict:
            for field, value in fields.items():
                if type(value) is str and value in unique:
                    ref, index = unique[value]
                    bindings[field] = {"ref": ref, "readbackIndex": index}
        # An upstream or model-provided assertion is never retained as evidence.
        row[BINDINGS_KEY] = bindings


def binding_problem(
    row: Mapping[str, Any], cleanup: Any, principal_refs: set[str]
) -> str | None:
    """Validate one REDACTED row's principal field bindings against the
    recovery readbacks of the same bundle.

    Returns the name of the first problem, or ``None`` when every binding
    names an owned principal, points at a successful ``account-readback``
    step for that principal whose recorded identifier is the principal's
    label, and the bound field carries that label. The caller decides what
    an unbound field in a principal slot means; this function only refuses
    bindings that claim what the readbacks do not show.
    """
    observed = row.get("observed")
    fields = observed.get("fields") if isinstance(observed, Mapping) else None
    bindings = row.get(BINDINGS_KEY)
    if type(bindings) is not dict or not is_typed_json(bindings):
        return "missing"
    steps = cleanup.get("accountSteps") if type(cleanup) is dict else None
    if type(steps) is not list:
        return "readbacks-missing"
    for field, binding in bindings.items():
        if (
            type(binding) is not dict
            or set(binding) != {"ref", "readbackIndex"}
            or type(binding["ref"]) is not str
            or binding["ref"] not in principal_refs
            or type(binding["readbackIndex"]) is not int
            or not 0 <= binding["readbackIndex"] < len(steps)
        ):
            return f"{field}:invalid"
        ref = binding["ref"]
        step = steps[binding["readbackIndex"]]
        account = step.get("observed") if type(step) is dict else None
        if (
            type(step) is not dict
            or step.get("kind") != "account-readback"
            or step.get("accountRef") != ref
            or step.get("failure") is not None
            or type(account) is not dict
            or account.get("accountPresent") is not True
            or account.get("uid") != f"principal:{ref}"
            or type(fields) is not dict
            or fields.get(field) != f"principal:{ref}"
        ):
            return f"{field}:readback-mismatch"
    return None
