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
    body = b'[{"document":{"name":"x","fields":{"s":{"stringValue":"\\u00e9"}}},"readTime":"t"}]'
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
    assert view["documents"] == [{"name": "x", "fields": {"s": {"stringValue": "é"}}}]
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
