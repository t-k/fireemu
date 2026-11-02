from __future__ import annotations

import json
import re
import subprocess

from fs_config_lifecycle.surface_matrix import (
    CLASSES,
    DISCOVERY_PATH,
    EXCLUDED_PREFIX,
    SPEC_PATH,
    build_matrix,
    class_counts,
    discovery_methods,
    repo_root,
    citation_resolves,
    validate_matrix,
)


def test_every_pinned_management_method_is_classified_once() -> None:
    matrix = build_matrix()
    classified = [row["locator"] for row in matrix["methods"]]
    assert len(classified) == len(set(classified))
    management = {m for m in discovery_methods() if not m.startswith(EXCLUDED_PREFIX)}
    assert set(classified) == management


def test_document_methods_are_excluded_explicitly() -> None:
    matrix = build_matrix()
    excluded = set(matrix["excluded"])
    management = {m for m in discovery_methods() if not m.startswith(EXCLUDED_PREFIX)}
    assert excluded == set(discovery_methods()) - management
    assert excluded
    assert len(excluded) + len(matrix["methods"]) == len(discovery_methods())
    assert matrix["excludedRationale"]


def test_classes_are_closed_and_each_row_carries_a_rationale_and_consequence() -> None:
    matrix = build_matrix()
    rows = matrix["methods"] + matrix["localSurfaces"] + matrix["databaseFields"]
    assert rows
    for row in rows:
        assert row["class"] in CLASSES
        assert isinstance(row["rationale"], str) and len(row["rationale"]) > 20
        assert isinstance(row["dataPlaneConsequence"], str)
        assert row["dataPlaneConsequence"]


def test_managed_infrastructure_rows_never_claim_a_local_obligation_to_serve() -> None:
    """A managed row may be partly served, but never claims to reproduce the managed surface.

    Classifying a method as managed-infrastructure says fireemu is not obliged to serve it.
    It does not forbid serving a bounded slice: the field-configuration operations the local
    runtime produced are answered at operations.get and operations.list so the name a patch
    returned can be polled. What stays forbidden is "implemented", which would claim the
    whole managed surface, including the operations, retention and scheduling only Google
    holds.
    """
    matrix = build_matrix()
    for row in matrix["methods"]:
        if row["class"] == "managed-infrastructure":
            assert row["local"]["status"] in {
                "not-implemented",
                "local-extension-only",
                "partial",
            }
            assert row["local"]["status"] != "implemented"


def test_every_local_citation_names_an_existing_symbol_in_this_checkout() -> None:
    matrix = build_matrix()
    rows = matrix["methods"] + matrix["localSurfaces"] + matrix["databaseFields"]
    seen = 0
    for row in rows:
        citations = row["local"]["citations"]
        assert isinstance(citations, list)
        if row["local"]["status"] == "not-implemented":
            assert citations == []
            continue
        assert citations
        for citation in citations:
            assert citation_resolves(citation), citation
            seen += 1
    assert seen >= 20


def test_every_citation_names_a_declared_symbol_and_not_a_line() -> None:
    """A citation survives unrelated edits only if it names the item, not its line.

    Each citation is `path.rs::symbol`, where the symbol is the enclosing named item
    (fn, impl, struct, enum, mod, ...) of the cited place. A repeated name in the same file
    carries a `#N` suffix from its second occurrence on. The symbol must still be declared in
    that file, so a rename or removal fails here instead of leaving a stale reference.
    """
    matrix = build_matrix()
    rows = matrix["methods"] + matrix["localSurfaces"] + matrix["databaseFields"]
    rows = rows + matrix["repairTickets"]
    checked = 0
    for row in rows:
        citations = row["local"]["citations"] if "local" in row else row["citations"]
        for citation in citations:
            if "::" not in citation:
                assert citation.endswith(".json"), citation
            else:
                assert re.fullmatch(
                    r"[\w/.-]+\.(rs|py)::[A-Za-z_]\w*(#[2-9][0-9]*)?", citation
                ), citation
            assert citation_resolves(citation), f"{citation} names no declaration"
            checked += 1
    assert checked >= 40


def test_a_citation_to_a_missing_or_absent_occurrence_is_rejected() -> None:
    assert not citation_resolves(
        "crates/fireemu-core-types/src/ids.rs::NoSuchSymbolInThisFile"
    )
    assert not citation_resolves("crates/fireemu-core-types/src/ids.rs::DatabaseId#2")
    assert not citation_resolves("crates/fireemu-core-types/src/absent.rs::DatabaseId")


def test_the_checked_in_specification_equals_the_compiled_matrix() -> None:
    path = repo_root() / SPEC_PATH
    assert path.is_file(), "run surface_matrix.py --write to publish the specification"
    assert json.loads(path.read_text(encoding="utf-8")) == build_matrix()


def test_the_matrix_is_bound_to_the_pinned_discovery_input_not_a_live_fetch() -> None:
    matrix = build_matrix()
    binding = matrix["discovery"]
    assert binding["path"] == DISCOVERY_PATH
    assert binding["id"] == "firestore-v1"
    assert binding["revision"] == "20260826"
    assert len(binding["sha256"]) == 64
    assert len(binding["methodListDigest"]) == 64
    raw = json.loads((repo_root() / DISCOVERY_PATH).read_text(encoding="utf-8"))
    pinned = next(d for d in raw["definitions"] if d["id"] == "firestore-v1")
    assert binding["sha256"] == pinned["sha256"]


def test_class_counts_match_the_published_summary_and_cover_the_denominator() -> None:
    matrix = build_matrix()
    counts = class_counts(matrix["methods"])
    assert counts == matrix["summary"]["methodsByClass"]
    assert sum(counts.values()) == len(matrix["methods"])
    assert set(counts) <= set(CLASSES)


def test_validation_rejects_a_mutated_or_truncated_matrix() -> None:
    matrix = build_matrix()
    assert validate_matrix(matrix)
    assert not validate_matrix({})
    dropped = json.loads(json.dumps(matrix))
    dropped["methods"] = dropped["methods"][:-1]
    assert not validate_matrix(dropped)
    reclassified = json.loads(json.dumps(matrix))
    original = reclassified["methods"][0]["class"]
    other = next(c for c in CLASSES if c != original)
    reclassified["methods"][0]["class"] = other
    assert not validate_matrix(reclassified)
    invented = json.loads(json.dumps(matrix))
    invented["methods"][0]["class"] = "verified"
    assert not validate_matrix(invented)


def test_the_matrix_claims_no_production_observation() -> None:
    matrix = build_matrix()
    assert matrix["status"] == "PREPARATION_ONLY"
    assert matrix["productionExecuted"] is False
    assert matrix["summary"]["productionUnobservedConditionsReduced"] == 0
    serialized = json.dumps(matrix).lower()
    for forbidden in ("compat_verified", "oracle_compared", "local_verified"):
        assert forbidden not in serialized
    statuses = {row["local"]["status"] for row in matrix["methods"]}
    assert statuses <= {
        "implemented",
        "partial",
        "not-implemented",
        "local-extension-only",
    }


def test_repair_tickets_are_reproducible_and_a_fixed_one_cites_its_commit() -> None:
    matrix = build_matrix()
    assert matrix["repairTickets"]
    states = {ticket["id"]: ticket["status"] for ticket in matrix["repairTickets"]}
    assert states == {
        "FS-CONFIG-RT-001": "FIXED",
        "FS-CONFIG-RT-002": "PARTIALLY_FIXED",
        "FS-CONFIG-RT-003": "FIXED",
        "FS-CONFIG-RT-004": "FIXED",
        "FS-CONFIG-RT-005": "OPEN",
    }
    assert matrix["summary"]["openRepairTickets"] == 1
    for ticket in matrix["repairTickets"]:
        assert ticket["id"].startswith("FS-CONFIG-RT-")
        assert ticket["reproduction"]
        if ticket["status"] == "OPEN":
            assert ticket["fixApplied"] is False
            assert ticket["fixedAt"] is None and ticket["resolution"] is None
        else:
            assert re.fullmatch(r"[0-9a-f]{40}", ticket["fixedAt"])
            assert ticket["resolution"]
            assert ticket["fixApplied"] is (ticket["status"] == "FIXED")
            subprocess.check_call(
                ["git", "-C", str(repo_root()), "cat-file", "-e", ticket["fixedAt"]]
            )
        for citation in ticket["citations"]:
            assert citation_resolves(citation), citation


def test_database_fields_cover_the_pinned_schema() -> None:
    raw = json.loads((repo_root() / DISCOVERY_PATH).read_text(encoding="utf-8"))
    pinned = next(d for d in raw["definitions"] if d["id"] == "firestore-v1")
    prefix = "schemas/GoogleFirestoreAdminV1Database/properties/"
    schema_fields = {
        surface["locator"][len(prefix) :]
        for surface in pinned["surfaces"]
        if surface["locator"].startswith(prefix)
        and "/" not in surface["locator"][len(prefix) :]
    }
    matrix = build_matrix()
    classified = {row["field"] for row in matrix["databaseFields"]}
    documented = {
        row["field"]
        for row in matrix["databaseFields"]
        if row["presentInPinnedDiscovery"]
    }
    extra = {
        row["field"]
        for row in matrix["databaseFields"]
        if not row["presentInPinnedDiscovery"]
    }
    assert documented == schema_fields
    assert classified == schema_fields | extra
    assert "enhancedTextSearchQueryMode" in extra
