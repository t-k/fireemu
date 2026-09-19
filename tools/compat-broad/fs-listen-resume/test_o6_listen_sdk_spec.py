import json
from pathlib import Path

from o6_listen_resume.export_spec import (
    BUDGET_SPEC,
    CASES_SPEC,
    budget_document,
    cases_document,
    render,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_checked_in_case_spec_matches_the_python_catalog():
    written = (REPO_ROOT / CASES_SPEC).read_text(encoding="utf-8")
    assert written == render(cases_document())


def test_checked_in_budget_spec_matches_the_frozen_budget():
    written = (REPO_ROOT / BUDGET_SPEC).read_text(encoding="utf-8")
    assert written == render(budget_document())


def test_the_node_collector_reads_the_same_case_identifiers():
    document = json.loads((REPO_ROOT / CASES_SPEC).read_text(encoding="utf-8"))
    assert [case["caseId"] for case in document["cases"]] == [
        case["caseId"] for case in cases_document()["cases"]
    ]
    assert document["catalogDigest"] == cases_document()["catalogDigest"]
