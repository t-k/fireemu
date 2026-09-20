"""The checked-in campaign artifacts must stay in step with the code that made them."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mfa_cases import CAMPAIGN_ID, CASE_IDS, observation_cases, owned_accounts
from mfa_comparator import compare
from mfa_manifest import LIMITS, compile_campaign, validate_campaign
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
    assert ledger["recovery"]["configurationMutated"] is False
    assert ledger["recovery"]["ownedAccounts"] == len(owned_accounts())
    serialized = json.dumps(ledger).lower()
    for material in (
        "sharedsecretkey",
        "idtoken",
        "refreshtoken",
        "mfapendingcredential",
    ):
        assert material not in serialized


def test_the_ledger_stays_inside_the_declared_request_budget() -> None:
    ledger = load(LEDGER)
    assert ledger["maxRequests"] == LIMITS["maxRequests"]
    assert 0 < ledger["requestsCharged"] <= LIMITS["maxRequests"]
    # One notional request per case would understate the real traffic several times over.
    assert ledger["requestsCharged"] > len(CASE_IDS)


def test_historical_ledger_is_preserved_but_not_rebound_to_the_repaired_reaper() -> None:
    # The recorder changed; the old receipt remains true historical evidence,
    # not a newly executed local artifact. Do not replace its provenance hashes.
    raw = (repository_root() / LEDGER).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == (
        "811a5c652ab41f845f3c6b02249cac292d64a949e34d46cf8373dde5191946a9"
    )
    ledger = json.loads(raw)
    assert validate_campaign(ledger["campaign"]) is True
    other = json.loads(json.dumps(ledger)) | {"side": "production"}
    result = compare(ledger, other)
    assert result["classification"] == "INDETERMINATE"
    assert result["localProblems"] == ["provenance does not match the worktree"]
    assert result["productionProblems"] == ["provenance does not match the worktree"]


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
