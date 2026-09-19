"""Offline safety obligations for the O4 production preparation boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from query_in_compiler import compile_plan
from query_in_production import (
    AttemptLedger,
    CompactJournal,
    RawJournal,
    admission_status,
    source_inputs,
    validate_permission,
)

_DOC = "projects/fireemu-35fe6/databases/(default)/documents/cur/c"


def _plan():
    return compile_plan("fireemu-35fe6", "(default)", "a" * 32)


def test_no_unadmitted_production_entry_point() -> None:
    status = admission_status(_plan())
    assert status["productionReady"] is False
    assert "gate-contract" in status["blockers"]
    with pytest.raises(PermissionError):
        status["admit"]()


def test_exact_phase_cursor_and_zero_wire_recovery_skip() -> None:
    ledger = AttemptLedger()
    for index in range(2):
        ledger.reserve("oauth", index)
        ledger.commit()
    for index in range(4):
        ledger.reserve("preflight", index)
        ledger.commit()
    for index in range(6):
        ledger.reserve("observation", index)
        ledger.commit()
    for index in range(2):
        ledger.reserve("recovery", index)
        if index == 1:
            ledger.skip("already-absent")
        else:
            ledger.commit()
    ledger.reserve("recovery", 2)
    ledger.commit()
    for index in range(4):
        ledger.reserve("postflight", index)
        ledger.commit()
    assert ledger.snapshot()["actualSends"] == 18
    assert ledger.snapshot()["cursor"] == [2, 4, 6, 3, 4]
    with pytest.raises(ValueError):
        ledger.reserve("recovery", 2)


def test_pre_send_capacity_rejects_tenth_data_attempt() -> None:
    ledger = AttemptLedger()
    for phase, count in (
        ("oauth", 2),
        ("preflight", 4),
        ("observation", 6),
        ("recovery", 3),
        ("postflight", 4),
    ):
        for index in range(count):
            ledger.reserve(phase, index)
            ledger.commit()
    assert ledger.snapshot()["actualSends"] == 19
    with pytest.raises(ValueError):
        ledger.reserve("observation", 0)


def test_raw_sidecars_preserve_bytes_and_bind_projection(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = json.dumps(
        [
            {
                "document": {"name": _DOC, "fields": {"s": {"stringValue": "é"}}},
                "readTime": "2026-09-18T00:00:00.000000Z",
            }
        ]
    ).encode()
    binding = journal.add(
        "observation",
        2,
        200,
        body,
        complete=True,
        content_type="application/json; charset=UTF-8",
    )
    assert (tmp_path / "raw" / binding["path"]).read_bytes() == body
    view = journal.semantic_view(binding)
    assert view["documents"] == [{"name": _DOC, "fields": {"s": {"stringValue": "é"}}}]
    assert view["sourceRawSha256"] == hashlib.sha256(body).hexdigest()
    second = journal.add(
        "recovery", 0, 404, b"\xff", complete=False, content_type="application/json"
    )
    assert (tmp_path / "raw" / second["path"]).read_bytes() == b"\xff"
    with pytest.raises(ValueError):
        journal.semantic_view({**binding, "sha256": "0" * 64})
    with pytest.raises(ValueError):
        journal.semantic_view({**binding, "status": 500})
    with pytest.raises(ValueError):
        journal.semantic_view({**binding, "contentType": "text/html"})
    with pytest.raises(FileExistsError):
        journal.add(
            "observation", 2, 200, body, complete=True, content_type="application/json"
        )


def test_raw_journal_manifest_can_be_reloaded_after_publication(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = b'[{"readTime":"2026-09-18T00:00:00.000000Z"}]'
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    journal.close()

    reloaded = RawJournal.reload(tmp_path / "raw")
    assert reloaded.semantic_view(binding)["documents"] == []
    with pytest.raises(ValueError, match="immutable"):
        reloaded.add("observation", 3, 200, body, complete=True, content_type="application/json")
    reloaded.close()


def test_empty_json_array_is_not_a_typed_query_result(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    binding = journal.add(
        "observation", 2, 200, b"[]", complete=True, content_type="application/json"
    )
    assert journal.semantic_view(binding)["difference"] == "unexpected-query-row"
    journal.close()


@pytest.mark.parametrize(
    "body",
    [
        lambda: [
            {
                "document": {"name": _DOC, "fields": {"s": {"stringValue": "x"}}},
                "readTime": "2026-09-18T00:00:00.000000Z",
            },
            {"done": True},
        ],
        lambda: [{"readTime": "2026-09-18T00:00:00.000000Z"}],
    ],
)
def test_run_query_accepts_typed_terminal_and_empty_result_rows(
    tmp_path: Path, body: object
) -> None:
    journal = RawJournal(tmp_path / "raw")
    binding = journal.add(
        "observation",
        2,
        200,
        json.dumps(body()).encode(),
        complete=True,
        content_type="application/json",
    )
    journal.close()

    reloaded = RawJournal.reload(tmp_path / "raw")
    view = reloaded.semantic_view(binding)
    assert view["documents"] == (
        [{"name": _DOC, "fields": {"s": {"stringValue": "x"}}}]
        if len(body()) == 2
        else []
    )
    reloaded.close()


def test_run_query_rejects_terminal_row_before_following_rows(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = json.dumps(
        [
            {"done": True},
            {"readTime": "2026-09-18T00:00:00.000000Z"},
        ]
    ).encode()
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    assert journal.semantic_view(binding)["difference"] == "unexpected-query-row"
    journal.close()


@pytest.mark.parametrize("done", [False, "true", 1, None, {}])
def test_run_query_rejects_invalid_terminal_marker(tmp_path: Path, done: object) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = json.dumps(
        [{"readTime": "2026-09-18T00:00:00.000000Z", "done": done}]
    ).encode()
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    assert journal.semantic_view(binding)["difference"] == "unexpected-query-row"
    journal.close()


def test_raw_journal_reload_rejects_tampered_manifest_binding(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    journal.add("observation", 2, 200, b"[]", complete=True, content_type="application/json")
    journal.close()
    manifest_path = tmp_path / "raw" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["bindings"][0]["sha256"] = "0" * 63
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match="invalid raw journal binding"):
        RawJournal.reload(tmp_path / "raw")


@pytest.mark.parametrize("version", [True, 1.0])
def test_raw_journal_reload_requires_exact_manifest_version_type(
    tmp_path: Path, version: object
) -> None:
    journal = RawJournal(tmp_path / "raw")
    journal.add("observation", 2, 200, b"[]", complete=True, content_type="application/json")
    journal.close()
    manifest_path = tmp_path / "raw" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["version"] = version
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match="invalid raw journal manifest"):
        RawJournal.reload(tmp_path / "raw")


def test_raw_journal_reload_rejects_complete_binding_without_status(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    journal.add("observation", 2, 200, b"[]", complete=True, content_type="application/json")
    journal.close()
    manifest_path = tmp_path / "raw" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["bindings"][0]["status"] = None
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match="invalid raw journal binding"):
        RawJournal.reload(tmp_path / "raw")


def test_raw_journal_reload_rejects_manifest_over_byte_cap(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    journal.add("observation", 2, 200, b"[]", complete=True, content_type="application/json")
    journal.close()
    manifest_path = tmp_path / "raw" / "manifest.json"
    manifest_path.write_bytes(manifest_path.read_bytes() + b" " * 32768)

    with pytest.raises(ValueError, match="manifest capacity"):
        RawJournal.reload(tmp_path / "raw")


def test_complete_unexpected_query_is_preserved(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = json.dumps(
        [{"document": {"name": "unexpected", "fields": {}}}, {"unexpected": True}]
    ).encode()
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    view = journal.semantic_view(binding)
    assert view["difference"] == "unexpected-query-row"
    assert "documents" not in view
    assert (tmp_path / "raw" / binding["path"]).read_bytes() == body


@pytest.mark.parametrize(
    ("phase", "index", "status", "content_type", "body", "difference"),
    [
        (
            "observation",
            2,
            500,
            "application/json",
            b'[{"document":{"name":"x","fields":{}}}]',
            "unexpected-query-status",
        ),
        (
            "observation",
            2,
            200,
            "text/html",
            b'[{"document":{"name":"x","fields":{}}}]',
            "unexpected-query-content-type",
        ),
        (
            "observation",
            2,
            200,
            "application/problem+json",
            b'[{"document":{"name":"x","fields":{}}}]',
            "unexpected-query-content-type",
        ),
        (
            "observation",
            2,
            200,
            "application/json",
            b'{"document":{"name":"x","fields":{}}}',
            "unexpected-query-shape",
        ),
        (
            "observation",
            2,
            200,
            "application/json",
            b'[{"document":{"name":"x","fields":{}}},7]',
            "unexpected-query-row",
        ),
        (
            "observation",
            3,
            200,
            "application/json",
            b'[{"document":{"name":"x","fields":{}}}]',
            "not-positive-query-slot",
        ),
    ],
)
def test_only_typed_positive_query_projects_documents(
    tmp_path: Path,
    phase: str,
    index: int,
    status: int,
    content_type: str,
    body: bytes,
    difference: str,
) -> None:
    journal = RawJournal(tmp_path / "raw")
    binding = journal.add(
        phase, index, status, body, complete=True, content_type=content_type
    )
    view = journal.semantic_view(binding)
    assert view["difference"] == difference
    assert "documents" not in view
    assert (tmp_path / "raw" / binding["path"]).read_bytes() == body


def test_malformed_complete_json_remains_raw_without_projection(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = b"\xff"
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    view = journal.semantic_view(binding)
    assert view["difference"] == "malformed-query-json"
    assert "documents" not in view
    assert (tmp_path / "raw" / binding["path"]).read_bytes() == body


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
def test_nonfinite_json_constant_remains_raw_without_projection(
    tmp_path: Path, constant: bytes
) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = (
        b'[{"document":{"name":"x","fields":{"n":{"doubleValue":' + constant + b"}}}}]"
    )
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    view = journal.semantic_view(binding)
    assert view["difference"] == "malformed-query-json"
    assert "documents" not in view
    assert (tmp_path / "raw" / binding["path"]).read_bytes() == body


@pytest.mark.parametrize(
    ("body", "difference"),
    [
        (
            b'[{"document":{"name":"x","fields":{}},"document":{"name":"y","fields":{}}}]',
            "malformed-query-json",
        ),
        (b'[{"document":{"name":"x","name":"y","fields":{}}}]', "malformed-query-json"),
        (
            b'[{"document":{"name":"x","fields":{"n":{"integerValue":"1","integerValue":"2"}}}}]',
            "malformed-query-json",
        ),
        (
            b'[{"document":{"name":"x","fields":{}},"readTime":{}}]',
            "unexpected-query-row",
        ),
        (
            b'[{"document":{"name":"x","fields":{}},"skippedResults":"1"}]',
            "unexpected-query-row",
        ),
        (
            b'[{"document":{"name":"x","fields":{}},"transaction":{}}]',
            "unexpected-query-row",
        ),
        (
            b'[{"document":{"name":"x","fields":{}},"skippedResults":1}]',
            "unexpected-query-row",
        ),
        (
            b'[{"document":{"name":"x","fields":{}},"transaction":"YQ=="}]',
            "unexpected-query-row",
        ),
        (
            b'[{"document":{"name":"x","fields":{}},"readTime":"bad"}]',
            "unexpected-query-row",
        ),
        (
            b'[{"document":{"name":"x","fields":{}},"unrecognized":1}]',
            "unexpected-query-row",
        ),
    ],
)
def test_duplicate_keys_or_bad_metadata_never_project(
    tmp_path: Path, body: bytes, difference: str
) -> None:
    journal = RawJournal(tmp_path / "raw")
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    view = journal.semantic_view(binding)
    assert view["difference"] == difference
    assert "documents" not in view
    assert (tmp_path / "raw" / binding["path"]).read_bytes() == body


@pytest.mark.parametrize(
    "value",
    [
        None,
        True,
        1,
        "x",
        [],
        {},
        {"unknownValue": "x"},
        {"stringValue": "x", "integerValue": "1"},
        {"integerValue": True},
        {"integerValue": "01"},
        {"integerValue": "9223372036854775808"},
        {"integerValue": "9" * 5000},
        {"doubleValue": True},
        {"doubleValue": "1.5"},
        {"doubleValue": 10**309},
        {"timestampValue": "bad"},
        {"bytesValue": "***"},
        {"referenceValue": "x"},
        {"arrayValue": {"values": [3]}},
        {"arrayValue": {"values": [{"arrayValue": {"values": []}}]}},
        {"arrayValue": {"values": "bad"}},
        {"mapValue": {"fields": {"n": {"integerValue": "01"}}}},
        {"mapValue": {"fields": []}},
        {"geoPointValue": {"latitude": 91, "longitude": 0}},
        {"geoPointValue": {"latitude": 10**309, "longitude": 0}},
        {"geoPointValue": {"latitude": 0, "longitude": 10**309}},
        {"nullValue": "bad"},
        {"stringValue": "\ud800"},
    ],
)
def test_malformed_firestore_value_remains_raw(tmp_path: Path, value: object) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = json.dumps([{"document": {"name": _DOC, "fields": {"n": value}}}]).encode()
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    view = journal.semantic_view(binding)
    assert view["difference"] == "unexpected-query-row"
    assert "documents" not in view
    assert (tmp_path / "raw" / binding["path"]).read_bytes() == body


@pytest.mark.parametrize(
    "name",
    [
        "",
        "x",
        "projects/p/databases/(default)/documents/c",
        "projects/p/databases/(default)/documents/c/",
        "projects/p/databases/(default)/documents/c/.",
    ],
)
def test_noncanonical_document_name_remains_raw(tmp_path: Path, name: str) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = json.dumps([{"document": {"name": name, "fields": {}}}]).encode()
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    assert journal.semantic_view(binding)["difference"] == "unexpected-query-row"


@pytest.mark.parametrize("name", ["", "__reserved__", "x" * 1501, "\ud800"])
def test_noncanonical_field_name_remains_raw(tmp_path: Path, name: str) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = json.dumps(
        [{"document": {"name": _DOC, "fields": {name: {"stringValue": "x"}}}}]
    ).encode()
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    assert journal.semantic_view(binding)["difference"] == "unexpected-query-row"


def test_deep_nested_value_remains_raw(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    value: object = {"stringValue": "leaf"}
    for _ in range(40):
        value = {"mapValue": {"fields": {"n": value}}}
    body = json.dumps([{"document": {"name": _DOC, "fields": {"n": value}}}]).encode()
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    assert journal.semantic_view(binding)["difference"] == "unexpected-query-row"


def test_wide_value_exceeding_node_budget_remains_raw(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    values = [{"nullValue": "NULL_VALUE"}] * 1025
    body = json.dumps(
        [
            {
                "document": {
                    "name": _DOC,
                    "fields": {"n": {"arrayValue": {"values": values}}},
                }
            }
        ]
    ).encode()
    assert len(body) <= 65536
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    assert journal.semantic_view(binding)["difference"] == "unexpected-query-row"


@pytest.mark.parametrize(
    "value",
    [
        {"nullValue": "NULL_VALUE"},
        {"booleanValue": False},
        {"integerValue": "-9223372036854775808"},
        {"integerValue": "9223372036854775807"},
        {"doubleValue": 1.5},
        {"doubleValue": 10**308},
        {"doubleValue": "NaN"},
        {"timestampValue": "2026-09-18T00:00:00Z"},
        {"bytesValue": "YQ=="},
        {"referenceValue": _DOC},
        {"geoPointValue": {"latitude": 90, "longitude": -180}},
        {"arrayValue": {"values": [{"stringValue": "x"}]}},
        {
            "arrayValue": {
                "values": [
                    {
                        "mapValue": {
                            "fields": {
                                "n": {"arrayValue": {"values": [{"integerValue": "1"}]}}
                            }
                        }
                    }
                ]
            }
        },
        {"mapValue": {"fields": {"a": {"integerValue": "0"}}}},
    ],
)
def test_well_formed_value_remains_comparable(tmp_path: Path, value: object) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = json.dumps([{"document": {"name": _DOC, "fields": {"n": value}}}]).encode()
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    assert journal.semantic_view(binding)["documents"] == [
        {"name": _DOC, "fields": {"n": value}}
    ]


def test_other_well_formed_document_remains_comparable(tmp_path: Path) -> None:
    journal = RawJournal(tmp_path / "raw")
    other = "projects/other-project/databases/(default)/documents/cur/other"
    body = json.dumps(
        [
            {
                "document": {
                    "name": other,
                    "fields": {
                        "n": {"integerValue": "3"},
                        "nested": {
                            "mapValue": {
                                "fields": {
                                    "a": {
                                        "arrayValue": {
                                            "values": [{"booleanValue": True}]
                                        }
                                    }
                                }
                            }
                        },
                    },
                }
            }
        ]
    ).encode()
    binding = journal.add(
        "observation", 2, 200, body, complete=True, content_type="application/json"
    )
    assert journal.semantic_view(binding)["documents"][0]["name"] == other


@pytest.mark.parametrize("status", [200.0, True, "200"])
def test_numeric_or_boolean_status_cannot_become_typed_success(
    tmp_path: Path, status: object
) -> None:
    journal = RawJournal(tmp_path / "raw")
    body = b'[{"document":{"name":"x","fields":{}}}]'
    with pytest.raises(ValueError, match="typed HTTP status"):
        journal.add(
            "observation",
            2,
            status,
            body,
            complete=True,
            content_type="application/json",
        )
    assert not list((tmp_path / "raw").iterdir())


def test_permission_remains_closed_for_unbound_costs_and_nonfinite_expiry() -> None:
    for expiry in (float("nan"), float("inf"), 1_000_000_000_000):
        with pytest.raises(ValueError):
            validate_permission(
                {"expiresAt": expiry, "costAssumptions": {"ownerConfirmed": True}}
            )


def test_source_closure_includes_compiler_catalog_and_contract() -> None:
    sources = source_inputs()
    assert any(path.endswith("broad_contract.py") for path in sources)
    assert any(
        path.endswith("firestore-standard-query-2026-08-25.json") for path in sources
    )
    assert all(len(digest) == 64 for digest in sources.values())


def test_compact_journal_preserves_immutable_rows_and_enforces_byte_caps() -> None:
    journal = CompactJournal()
    row = {"index": 0, "phase": "observation", "rawSha256": "a" * 64}
    journal.append(row)
    row["index"] = 99
    assert journal.rows[0]["index"] == 0
    exposed = journal.rows
    exposed[0]["index"] = 98
    assert journal.rows[0]["index"] == 0
    with pytest.raises(ValueError):
        journal.append({"oversize": "é" * 5000})
    with pytest.raises(ValueError):
        journal.set_envelope({"oversize": "é" * 17000})
    journal.set_envelope({"scope": "offline"})
    assert len(journal.encoded()) < 131072
