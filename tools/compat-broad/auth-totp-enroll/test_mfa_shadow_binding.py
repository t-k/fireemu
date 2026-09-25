"""The versioned local shadow must bind the modules at HEAD and at its own commit.

The historical `o2-mfa-local-shadow.json` keeps its bytes and its stale binding, and
`test_mfa_artifacts.py` pins it. The versioned record the O8 descriptor compares a
production run against has to be current: its provenance must equal what this tree
recomputes, and every bound path at its recorded commit must hash to the same bytes,
so a bound module changed after the record was taken fails here by name.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import mfa_descriptor as campaign
from mfa_cases import CASE_IDS, observation_cases, owned_accounts
from mfa_manifest import LIMITS, validate_campaign
from mfa_provenance import (
    BOUND_PATHS,
    compute_provenance,
    repository_root,
    verify_binding,
)

RECORD = campaign.SHADOW_RECORD
# Built from parts so this guard does not itself carry the strings it forbids.
_FORBIDDEN_PARTS = (("Users",), ("home",), ("private", "tmp"), ("var", "folders"))
FORBIDDEN_PATH_PREFIXES = tuple("/" + "/".join(parts) + "/" for parts in _FORBIDDEN_PARTS)


def load() -> dict:
    return json.loads((repository_root() / RECORD).read_text(encoding="utf-8"))


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repository_root()), *args])


def test_the_versioned_record_is_a_complete_local_shadow():
    record = load()
    assert record["campaignId"] == campaign.CAMPAIGN
    assert record["side"] == "local" and record["productionExecuted"] is False
    assert [row["id"] for row in record["rows"]] == list(CASE_IDS)
    assert record["recordingComplete"] is True
    assert record["disagreements"] == []
    assert validate_campaign(record["campaign"]) is True
    assert record["maxRequests"] == LIMITS["maxRequests"]
    assert len(CASE_IDS) < record["requestsCharged"] <= LIMITS["maxRequests"]
    recovery = record["recovery"]
    assert recovery["cleanupVerified"] is True
    assert recovery["remainingOwnedResources"] == 0
    assert recovery["ownedAccounts"] == len(owned_accounts())
    assert recovery["configurationMutated"] is False
    runtime = record["runtimeIdentity"]
    assert set(runtime) == {
        "artifactSha256",
        "executionCommit",
        "configurationDigest",
        "runId",
    }
    assert len(runtime["artifactSha256"]) == 64
    assert runtime["executionCommit"] == record["worktree"]["commit"]
    assert recovery["runId"]
    expectations = {item["id"]: item for item in record["expectations"]}
    for case in observation_cases():
        assert expectations[case["id"]]["expected"] == case["expectedLocal"], case["id"]
        assert expectations[case["id"]]["agrees"] is True, case["id"]


def test_the_versioned_record_binds_the_bound_modules_at_head():
    record = load()
    truth = compute_provenance(repository_root())
    stale = sorted(
        name
        for name in BOUND_PATHS
        if record["provenance"]["paths"].get(name) != truth["paths"][name]
    )
    assert stale == [], f"bound modules changed since the record was taken: {stale}"
    assert verify_binding(record["provenance"], repository_root()) is True


def test_the_recorded_commit_is_in_history_and_carries_the_same_bound_bytes():
    record = load()
    worktree = record["worktree"]
    assert worktree["resolved"] is True and worktree["clean"] is True
    commit = worktree["commit"]
    assert len(commit) == 40
    assert (
        subprocess.run(
            [
                "git",
                "-C",
                str(repository_root()),
                "merge-base",
                "--is-ancestor",
                commit,
                "HEAD",
            ],
            check=False,
        ).returncode
        == 0
    ), "the record's sourceCommit is not an ancestor of HEAD"
    stale = []
    for name in BOUND_PATHS:
        at_commit = hashlib.sha256(git("show", f"{commit}:{name}")).hexdigest()
        if at_commit != record["provenance"]["paths"][name]:
            stale.append(name)
    assert stale == [], f"the record's digests differ from its own commit: {stale}"


def test_the_versioned_record_carries_no_secret_or_personal_path():
    raw = (repository_root() / RECORD).read_text(encoding="utf-8")
    lowered = raw.lower()
    for material in (
        "sharedsecretkey",
        "idtoken",
        "refreshtoken",
        "mfapendingcredential",
        "sessioninfo",
    ):
        assert material not in lowered
    for prefix in FORBIDDEN_PATH_PREFIXES:
        assert prefix not in raw
    assert "\u0000" not in raw


def test_the_descriptor_reads_this_record_and_no_other():
    record = load()
    assert campaign.shadow_record() == record
    assert (
        campaign.artifact_profile()
        == "auth-totp-enroll-" + record["worktree"]["commit"][:9]
    )
