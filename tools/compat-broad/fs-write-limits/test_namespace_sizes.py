"""Independent arithmetic for limit recipes, not native/production observations."""
from __future__ import annotations

import base64
import hashlib
import json

import pytest
from compiler import DOCUMENT_MAX, _value_size, compile_limits_plan, document_name_size

NAMESPACES = [
    ("demo-app", "(default)"), ("documents", "(default)"),
    ("demo-app", "documents"), ("documents", "documents"),
    ("databases", "documents"), ("documents", "databases"),
]


@pytest.mark.parametrize("project,database", NAMESPACES)
@pytest.mark.parametrize("relative,expected", [
    ("a/b", 20), ("資料/利用者", 33), ("a/b/documents/c", 32),
])
def test_document_and_nested_reference_charges_ignore_namespace(
    project, database, relative, expected,
):
    resource = f"projects/{project}/databases/{database}/documents/{relative}"
    assert document_name_size(resource) == expected
    reference = {"referenceValue": resource}
    assert _value_size(reference) == expected
    assert _value_size({"arrayValue": {"values": [reference, reference]}}) == 2 * expected
    assert _value_size({"mapValue": {"fields": {"r": reference}}}) == 34 + expected


@pytest.mark.parametrize("project,database", NAMESPACES)
def test_compiled_documents_really_straddle_the_limit(project, database):
    plan = compile_limits_plan(project, database, "a" * 32)
    for label, wanted in [
        ("exact-document-boundary", DOCUMENT_MAX),
        ("over-document-boundary", DOCUMENT_MAX + 1),
    ]:
        doc = plan["documents"][label]
        prefix = f"projects/{project}/databases/{database}/documents/"
        relative = doc["resource"].removeprefix(prefix)
        assert relative != doc["resource"]
        # Independent of the compiler helpers and its reported size.
        name_bytes = 16 + sum(len(x.encode()) + 1 for x in relative.split("/"))
        payload = base64.b64decode(doc["fields"]["blob"]["bytesValue"], validate=True)
        assert 2 * name_bytes + 32 + 13 + 5 + len(payload) == wanted
        assert doc["logicalBytes"] == wanted
        assert doc["fields"]["_sharedOwner"]["referenceValue"] == doc["resource"]
        assert len(payload) <= 1_048_487
        assert plan["budgetAccounting"]["productionReady"] is False


@pytest.mark.parametrize("resource", [
    None, 1, {}, "", "a/b", "projects/p/databases/d/documents",
    "projects/p/databases/d/documents/c", "projects/p/databases/d/documents/c/",
    "projects/p/databases/d/documents/c//d", "projects//databases/d/documents/c/d",
    "projects/p/databases//documents/c/d", "not-projects/p/databases/d/documents/c/d",
    "projects/p/not-databases/d/documents/c/d", "projects/p/databases/d/not-documents/c/d",
    "projects/p/databases/d/documents/c/d/c",
])
def test_size_helpers_refuse_ambiguous_structure(resource):
    with pytest.raises(ValueError, match="malformed document resource"):
        document_name_size(resource)
    with pytest.raises(ValueError, match="malformed document resource"):
        _value_size({"referenceValue": resource})


def test_size_helper_can_measure_a_structural_over_limit_path():
    assert document_name_size(
        "projects/p/databases/d/documents/" + "c" * 1501 + "/d"
    ) == 1520


def test_previously_valid_fixed_plan_bytes_are_unchanged():
    plan = compile_limits_plan("demo-app", "(default)", "a" * 32)
    actual = hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    # Exact v7 compiler output, measured before this repair; not an approval.
    assert actual == "ffcf5d0dbaea77ef3bec1f1220467f25d5b3a4e61973c86c0a24cd43f9528cf9"
