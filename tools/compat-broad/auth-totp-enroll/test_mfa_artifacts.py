"""The checked-in campaign artifacts must stay in step with the code that made them."""

from __future__ import annotations

import json
from pathlib import Path

from mfa_cases import CAMPAIGN_ID, CASE_IDS, observation_cases
from mfa_manifest import compile_campaign, validate_campaign
from mfa_provenance import repository_root

DOCUMENTATION_NONCE = "0" * 32
MANIFEST = "spec/compatibility/broad-runs/o2-mfa-next-campaign-manifest.json"
LEDGER = "spec/compatibility/broad-runs/o2-mfa-local-shadow.json"
DOCUMENT = "docs/compatibility/auth-mfa-next-campaign-preparation.md"


def load(relative: str) -> dict:
    return json.loads((repository_root() / relative).read_text(encoding="utf-8"))


def test_the_checked_in_manifest_recompiles_from_the_code() -> None:
    stored = load(MANIFEST)
    assert "documentationNonce" in stored
    del stored["documentationNonce"]
    assert stored == json.loads(json.dumps(compile_campaign(DOCUMENTATION_NONCE)))
    assert validate_campaign(stored) is True


def test_the_checked_in_ledger_covers_every_case_without_secret_material() -> None:
    ledger = load(LEDGER)
    assert ledger["campaignId"] == CAMPAIGN_ID
    assert ledger["side"] == "local" and ledger["productionExecuted"] is False
    assert [row["id"] for row in ledger["rows"]] == list(CASE_IDS)
    assert ledger["recordingComplete"] is True
    assert ledger["disagreements"] == []
    assert ledger["recovery"]["remainingOwnedResources"] == 0
    serialized = json.dumps(ledger).lower()
    for material in ("sharedsecretkey", "idtoken", "refreshtoken", "mfapendingcredential"):
        assert material not in serialized


def test_the_ledger_agrees_with_the_expected_local_results() -> None:
    expectations = {item["id"]: item for item in load(LEDGER)["expectations"]}
    for case in observation_cases():
        observed = expectations[case["id"]]
        assert observed["expected"] == case["expectedLocal"], case["id"]
        assert observed["agrees"] is True, case["id"]


def test_the_document_states_the_status_honestly() -> None:
    text = (repository_root() / DOCUMENT).read_text(encoding="utf-8")
    assert "WAITING_ORACLE" in text
    assert "`productionExecuted=false`" in text
    assert "Production-unobserved conditions reduced by this work: 0" in text
    for age in (300, 450, 600):
        assert str(age) in text
    assert Path(MANIFEST).name in text and Path(LEDGER).name in text
