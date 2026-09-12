"""The receipt carries only allowlisted fields of the private report, and names the
recorder that produced it separately from the contract that re-evaluated it."""

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
publisher = importlib.import_module("publish-auth-refusal-precedence")
from test_precedence_safety import complete_report


def private_report():
    report = complete_report()
    report.update(
        {
            "schemaVersion": 1,
            "acceptance": "candidate",
            "project": "fireemu-35fe6",
            "projectNumber": "592603257417",
            "corpus": publisher.CORPUS,
            "recordedAt": "2026-09-12T00:00:00+00:00",
            "probeSourceCommit": "0" * 40,
            "probeInputs": {path: "1" * 64 for path in publisher.RECORDER_FILES},
            "configReadback": {
                "sha256": "2" * 64,
                "emailEnabled": True,
                "passwordRequired": True,
                "improvedEmailPrivacy": True,
                "blockingTriggersAbsent": True,
                "adminPasswordPolicyAbsent": True,
            },
            "configEnabled": True,
            "configRestoredReadback": {
                "mfa": {"state": "DISABLED"},
                "phoneNumber": {},
                "smsRegionConfig": {"allowlistOnly": {}},
            },
            "cleanupAccounts": {"a": "absent", "b": "absent"},
            # Fields a run may leave behind that must never be published.
            "lastStep": "admin:lookup",
            "lastStatus": 200,
            "lastError": None,
            "lastErrorDetail": None,
            "idToken": "secret-token-value",
        }
    )
    return report


RECORDER, REEVALUATION = "5" * 40, "3" * 40


def fake_git(monkeypatch):
    contract_sha = publisher.working_tree_sha256(publisher.RECORDER_FILES[0])

    def blob(commit, path):
        if commit == RECORDER:
            return "1" * 64
        if commit == REEVALUATION and path == publisher.RECORDER_FILES[0]:
            return contract_sha
        return "f" * 64

    monkeypatch.setattr(publisher, "git_blob_sha256", blob)
    monkeypatch.setattr(
        publisher,
        "reevaluated_with",
        lambda: {"commit": REEVALUATION, "contractSha256": contract_sha},
    )


def published(monkeypatch):
    fake_git(monkeypatch)
    return publisher.project(private_report(), RECORDER)


def test_projection_keeps_only_allowlisted_fields(monkeypatch):
    out = published(monkeypatch)
    text = json.dumps(out)
    assert "secret-token-value" not in text and "lastStep" not in text
    assert set(out) == set(publisher.PROJECTED) | {
        "configuration",
        "privateReceiptSha256",
        "recordedWith",
        "reevaluatedWith",
    }
    assert out["recordedWith"]["recorderCommit"] == RECORDER
    assert out["recordedWith"]["probeSourceCommit"] == "0" * 40
    assert out["committedCheckout"] is True


def test_projection_refuses_a_recorder_that_does_not_match_the_named_commit(
    monkeypatch,
):
    monkeypatch.setattr(publisher, "git_blob_sha256", lambda commit, path: "9" * 64)
    with pytest.raises(ValueError):
        publisher.project(private_report(), RECORDER)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.__setitem__("configDigestMatches", False),
        lambda r: r.__setitem__("committedCheckout", False),
        lambda r: r.__setitem__("cleanupAccounts", {"a": "absent", "b": "unresolved"}),
        lambda r: r["configRestoredReadback"].__setitem__("extra", "REVIEW_SENTINEL"),
        lambda r: r["cases"].__setitem__(
            3,
            {
                "id": "disabled-a-wrong-code-finalize",
                "httpStatus": 429,
                "outcome": "refused",
                "observedError": "TOO_MANY_ATTEMPTS_TRY_LATER",
                "checks": {},
                "elapsedMs": 1,
                "skipped": False,
            },
        ),
    ],
)
def test_projection_refuses_an_incomplete_or_unclassified_report(monkeypatch, mutate):
    fake_git(monkeypatch)
    report = private_report()
    mutate(report)
    with pytest.raises(ValueError):
        publisher.project(report, RECORDER)


def test_validation_refuses_unknown_nested_fields_in_a_receipt(monkeypatch):
    out = published(monkeypatch)

    def check(mutate):
        value = json.loads(json.dumps(out))
        mutate(value)
        with pytest.raises(ValueError):
            publisher.validate_production(value)

    check(lambda v: v["configRestoredReadback"].__setitem__("extra", "REVIEW_SENTINEL"))
    check(lambda v: v["recordedWith"]["recorderInputs"].__setitem__("extra", "1" * 64))
    check(lambda v: v["cleanupAccounts"].__setitem__("c", "absent"))
    check(lambda v: v["configuration"].__setitem__("extra", True))


def test_validation_checks_reevaluation_sources_by_content(monkeypatch):
    out = published(monkeypatch)
    publisher.validate_production(json.loads(json.dumps(out)))
    for mutate in (
        lambda v: v["reevaluatedWith"].__setitem__("contractSha256", "0" * 64),
        lambda v: v["reevaluatedWith"].__setitem__("commit", RECORDER),
        lambda v: v.__setitem__("probeSourceCommit", "7" * 40),
    ):
        value = json.loads(json.dumps(out))
        mutate(value)
        with pytest.raises(ValueError):
            publisher.validate_production(value)


def test_render_names_every_observed_outcome(monkeypatch):
    out = published(monkeypatch)
    review = json.loads(publisher.REVIEW.read_bytes())
    value = {
        "schemaVersion": 1,
        "acceptance": "candidate",
        "scope": publisher.SCOPE,
        "corpus": publisher.CORPUS,
        "sourceReviewSha256": publisher.digest(review),
        "publicationContractSha256": publisher.publication_contract_sha(),
        "production": out,
    }
    page = publisher.render(value)
    assert "refused / INVALID_CODE" in page and "refused / USER_DISABLED" in page
    assert "candidate, not approved" in page
    assert "secret" not in page
