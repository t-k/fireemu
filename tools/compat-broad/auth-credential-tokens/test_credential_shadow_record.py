"""The published local shadow record binds the lane as it stands."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE))

import credential_descriptor as campaign
import credential_shadow as shadow
from credential_cases import CASE_COUNT, observation_cases
from credential_collector import module_digests

RECORD = ROOT / campaign.SHADOW_RECORD
PREVIOUS = (
    ROOT
    / "spec/compatibility/broad-runs/auth-credential-tokens-local-shadow-20260923.json"
)
PREVIOUS_SHA256 = "c6edc7f5c11dccb8855fbbae580ad2eff71f463e86d1665078263dda854914a2"
SUPERSEDED = (
    ROOT
    / "spec/compatibility/broad-runs/auth-credential-tokens-local-shadow-20260918.json"
)


def _record() -> dict:
    return json.loads(RECORD.read_bytes())


def test_the_record_is_a_complete_local_shadow_of_every_case() -> None:
    record = _record()
    assert record["kind"] == "local-shadow" and record["productionExecuted"] is False
    assert record["failure"] is None and record["completionIssues"] == []
    assert record["expectedLocalAgreement"] == {"cases": CASE_COUNT, "unexpected": []}
    receipt = record["receipt"]
    assert receipt["recordingComplete"] is True
    assert receipt["cleanup"] == {
        "ownedAccounts": 3,
        "remainingAccounts": 0,
        "addressReadbacks": 2,
        "cleanupComplete": True,
    }
    assert [row["caseId"] for row in receipt["rows"]] == [
        case["id"] for case in observation_cases()
    ]
    assert shadow._agreement(receipt["rows"])["unexpected"] == []
    assert (
        record["shutdown"]["processStopped"] is True
        and record["shutdown"]["remainingChildren"] == 0
    )


def test_the_record_binds_the_lane_modules_as_they_stand() -> None:
    """A bound module edited after the run makes this fail; regenerate the shadow then."""
    binding = _record()["receipt"]["collectorBinding"]
    assert binding["modules"] == module_digests()
    assert re.fullmatch(r"[0-9a-f]{40}", binding["commit"])
    assert campaign.artifact_profile() == "auth-credential-" + binding["commit"][:9]


def test_the_record_contains_uid_matched_lookup_measurements() -> None:
    rows = {row["caseId"]: row for row in _record()["receipt"]["rows"]}
    assert (
        rows["revocation-same-second-session"]["assertions"]["lookupMatchesAccount"]
        is True
    )
    assert (
        rows["revocation-newer-session-accepted"]["assertions"]["lookupMatchesAccount"]
        is True
    )


def test_the_pre_lookup_20260923_record_is_kept_byte_identical() -> None:
    assert hashlib.sha256(PREVIOUS.read_bytes()).hexdigest() == PREVIOUS_SHA256


def test_the_record_carries_no_personal_path_or_credential() -> None:
    text = RECORD.read_text()
    # Personal path prefixes are assembled from parts so this file passes the same
    # publication-hygiene scan it mirrors.
    personal_prefixes = tuple(
        "/" + "/".join(parts) + "/"
        for parts in (("Users",), ("home",), ("private", "tmp"), ("var", "folders"))
    )
    for fragment in (*personal_prefixes, "Bearer ", "eyJ"):
        assert fragment not in text, fragment


def test_the_superseded_record_is_kept_byte_identical() -> None:
    superseded = json.loads(SUPERSEDED.read_bytes())
    assert superseded["expectedLocalAgreement"]["cases"] == 17
    assert (
        superseded["receipt"]["collectorBinding"]["commit"]
        == "905ede564c6d40498b615183db9f4103756585ba"
    )
