from __future__ import annotations

from fs_config_lifecycle.cases import compile_cases
from fs_config_lifecycle.doc_render import DOC_PATH, render
from fs_config_lifecycle.manifest import (
    FORBIDDEN_PERMISSIONS,
    REQUIRED_PERMISSIONS,
    compile_manifest,
)
from fs_config_lifecycle.surface_matrix import build_matrix, repo_root

CAMPAIGN_DOC = "docs/compatibility/fs-config-lifecycle-campaign-preparation.md"
NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def _read(path: str) -> str:
    return (repo_root() / path).read_text(encoding="utf-8")


def test_the_checked_in_classification_document_equals_the_rendered_one() -> None:
    assert (repo_root() / DOC_PATH).is_file(), "run doc_render.py --write"
    assert _read(DOC_PATH) == render()


def test_the_classification_document_lists_every_classified_method() -> None:
    text = render()
    for row in build_matrix()["methods"]:
        assert row["locator"].removeprefix("firestore.projects.") in text


def test_the_classification_document_states_the_unreduced_condition_count() -> None:
    text = _read(DOC_PATH)
    assert "Production-unobserved conditions reduced: **0**" in text
    assert "WAITING_ORACLE" in text
    assert "COMPAT_VERIFIED" not in text


def test_the_classification_document_carries_every_repair_ticket() -> None:
    text = _read(DOC_PATH)
    for ticket in build_matrix()["repairTickets"]:
        assert ticket["id"] in text
        assert ticket["title"] in text


def test_the_campaign_document_agrees_with_the_compiled_manifest() -> None:
    text = _read(CAMPAIGN_DOC)
    manifest = compile_manifest(NONCE)
    assert f"{manifest['caseCount']} abstract cases" in text
    assert f"US${manifest['budget']['hardCeilingUsd']}" in text
    assert f"{manifest['operationPolling']['deadlineSeconds']} seconds" in text
    assert f"{len(REQUIRED_PERMISSIONS)} permissions are required" in text
    assert f"{len(FORBIDDEN_PERMISSIONS)} permissions are explicitly excluded" in text


def test_the_campaign_document_lists_every_case_identifier() -> None:
    text = _read(CAMPAIGN_DOC)
    for case in compile_cases(NONCE):
        assert case["id"] in text


def test_the_campaign_document_claims_no_execution_and_no_credential() -> None:
    text = _read(CAMPAIGN_DOC)
    assert "Production-unobserved conditions reduced: **0**" in text
    assert "has not run" in text
    for forbidden in (
        "PRODUCTION_ORACLE_API_KEY",
        "gcloud auth",
        "service account key",
    ):
        assert forbidden not in text


def test_both_documents_are_written_in_english_without_emoji() -> None:
    for path in (DOC_PATH, CAMPAIGN_DOC):
        text = _read(path)
        assert text.isascii(), path
