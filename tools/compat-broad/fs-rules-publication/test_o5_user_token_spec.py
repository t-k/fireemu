from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from o5_user_token_campaign import (
    OWNER_PRECONDITIONS,
    PERMISSION_ENVELOPE,
    admitted_manifest_digest,
    budget,
    source_digests,
)
from o5_user_token_case import CAMPAIGN, compile_case, digest
from o5_user_token_collector import (
    COLLECTOR_CONTRACT,
    ENVIRONMENT_LOCAL,
    LOOPBACK_HOSTS,
    ROLE_LOCAL_SHADOW,
    endpoint_host,
)
from o5_user_token_shadow import unredacted_identifiers

ROOT = Path(__file__).resolve().parents[3]
SPEC_DIRECTORY = ROOT / "spec" / "compatibility"
MATRIX = SPEC_DIRECTORY / "fs-rules-user-token-matrix.json"
SHADOW = SPEC_DIRECTORY / "fs-rules-user-token-local-shadow.json"

TEMPLATE_PROJECT = "template-project"
TEMPLATE_NONCE = "0" * 32


def matrix() -> dict:
    return json.loads(MATRIX.read_text())


def shadow() -> dict:
    return json.loads(SHADOW.read_text())


def test_the_checked_in_matrix_is_the_compiled_matrix() -> None:
    plan = compile_case(TEMPLATE_PROJECT, "(default)", TEMPLATE_NONCE)
    assert matrix()["observationCase"] == plan


def test_the_checked_in_budget_and_envelope_match_the_campaign_module() -> None:
    document = matrix()
    plan = compile_case(TEMPLATE_PROJECT, "(default)", TEMPLATE_NONCE)
    assert document["budget"] == budget(plan)
    assert document["permissionEnvelope"] == PERMISSION_ENVELOPE
    assert document["ownerPreconditions"] == list(OWNER_PRECONDITIONS)


def test_the_checked_in_matrix_claims_no_production_evidence() -> None:
    document = matrix()
    assert document["campaignId"] == CAMPAIGN
    assert document["status"] == "PREPARATION_ONLY"
    assert document["productionExecuted"] is False
    assert document["productionReady"] is False


def test_the_checked_in_identities_are_placeholders() -> None:
    case = matrix()["observationCase"]
    assert case["project"] == TEMPLATE_PROJECT
    assert case["nonce"] == TEMPLATE_NONCE
    assert case["tenantIsPlaceholder"] is True


def test_the_shadow_record_is_bound_to_this_matrix() -> None:
    """The record is a real execution. Changing the matrix invalidates it.

    If this fails after a case change, re-run the shadow with
    `o5_user_token_local_run.py --run <directory>` and replace the record.
    """
    record = shadow()
    plan = compile_case("fireemu-35fe6", "(default)", record["nonce"], record["tenant"])
    assert record["planDigest"] == plan["planDigest"]
    assert record["bundle"]["planDigest"] == plan["planDigest"]


def test_the_shadow_record_binds_its_artifact_and_source() -> None:
    record = shadow()
    artifact = record["artifact"]
    assert re.fullmatch(r"[0-9a-f]{64}", artifact["artifactSha256"])
    assert re.fullmatch(r"[0-9a-f]{40}", artifact["sourceCommit"])
    assert artifact["rustc"].startswith("rustc ")
    assert "/" not in artifact["worktree"]
    bound = record["bundle"]["acquisition"]["artifact"]
    assert bound == {
        "artifactSha256": artifact["artifactSha256"],
        "sourceCommit": artifact["sourceCommit"],
    }


def test_the_shadow_record_was_produced_by_the_lane_sources_on_disk() -> None:
    """The record binds the collector that produced it, by digest.

    A change to any manifest-bound lane module invalidates the record; re-run
    the shadow on the committed tree and replace it.
    """
    observer = shadow()["bundle"]["observer"]
    assert observer["sourceDigests"] == source_digests()
    assert observer["observerDigest"] == digest(source_digests())


def test_the_shadow_source_commit_is_head_or_a_recent_ancestor() -> None:
    """A length check accepted any 40 characters. The recorded commit has to
    exist here, be HEAD or an ancestor of it, and no runtime input or lane file may
    have changed since it, so a stale record is detected rather than carried."""
    commit = shadow()["artifact"]["sourceCommit"]

    def git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
        )

    if git("rev-parse", "--git-dir").returncode != 0:
        pytest.skip("not a git checkout, so the commit cannot be resolved")
    if git("rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        pytest.skip("shallow clone: earlier commits are absent by construction")
    kind = git("cat-file", "-t", commit)
    assert kind.returncode == 0 and kind.stdout.strip() == "commit", (
        f"the recorded source commit {commit} is not a commit in this repository"
    )
    assert git("merge-base", "--is-ancestor", commit, "HEAD").returncode == 0, (
        f"the recorded source commit {commit} is not HEAD or an ancestor of it"
    )
    # Staleness is decided by what changed, not by how many unrelated commits landed:
    # the record is stale when any runtime input of the fireemu artifact or any file of
    # this lane changed between the recorded commit and HEAD. Unrelated commits on a
    # busy integration branch must not invalidate a record whose inputs are unchanged.
    changed = git(
        "diff",
        "--name-only",
        f"{commit}..HEAD",
        "--",
        "crates",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo",
        "tools/compat-broad/fs-rules-publication",
        # Prose is not an input of the record; the modules and tests are.
        ":(exclude)tools/compat-broad/fs-rules-publication/README.md",
    )
    assert changed.returncode == 0
    assert changed.stdout.strip() == "", (
        "the shadow predates changes to its inputs; re-run it:\n" + changed.stdout
    )


def test_the_shadow_record_is_a_bound_local_acquisition() -> None:
    record = shadow()
    bundle = record["bundle"]
    assert bundle["contract"] == COLLECTOR_CONTRACT
    assert bundle["provenance"]["role"] == ROLE_LOCAL_SHADOW
    assert bundle["provenance"]["case"]["nonce"] == record["nonce"]
    assert bundle["provenance"]["case"]["tenant"] == record["tenant"]
    acquisition = bundle["acquisition"]
    assert acquisition["environment"] == {"kind": ENVIRONMENT_LOCAL}
    assert acquisition["nonceReservation"] is None
    assert acquisition["ownerPermission"] is None
    assert acquisition["campaignManifestDigest"] == admitted_manifest_digest(
        "fireemu-35fe6", "(default)", record["nonce"]
    )
    assert set(acquisition["principals"]) == {
        entry["ref"] for entry in matrix()["observationCase"]["ownedAccounts"]
    }
    transport = bundle["transport"]
    assert transport["endpoints"]
    assert all(endpoint_host(e) in LOOPBACK_HOSTS for e in transport["endpoints"])
    assert transport["sequenceMonotonic"] is True
    assert [r["label"] for r in transport["rulesetReleases"]] == ["A", "B"]
    assert all(row["endpoint"] is not None for row in bundle["rows"])
    assert bundle["productionExecuted"] is False
    assert bundle["productionReady"] is False


def test_the_shadow_record_is_a_complete_local_run() -> None:
    record = shadow()
    bundle = record["bundle"]
    assert record["status"] == "LOCAL_SHADOW_ONLY"
    assert record["productionExecuted"] is False
    assert record["productionReady"] is False
    assert record["exitCode"] == 0
    assert record["originsClosed"] is True
    assert record["tenantDeleted"] is True
    assert bundle["abort"] is None
    assert bundle["recordingComplete"] is True
    assert bundle["cleanup"]["cleanupComplete"] is True
    assert bundle["cleanup"]["outstandingResources"] == []
    assert bundle["cleanup"]["outstandingAccounts"] == []
    assert len(bundle["rows"]) == len(matrix()["observationCase"]["observation"])


def test_the_local_runtime_matched_every_expected_decision() -> None:
    assert shadow()["deviations"] == []


def test_the_published_record_carries_no_account_identifier() -> None:
    """A published record must speak principal labels, never uids.

    Locally the uids are throwaway. The same publication path would otherwise
    put a real campaign's account identifiers into the repository.
    """
    record = shadow()
    assert unredacted_identifiers(record) == []
    owners = [
        fields["ownerUid"]
        for row in record["bundle"]["rows"]
        if (fields := ((row.get("observed") or {}).get("fields") or {})).get("ownerUid")
    ]
    assert owners
    assert all(value.startswith("principal:") for value in owners)
    uids = [
        step["observed"]["uid"]
        for step in record["bundle"]["cleanup"]["accountSteps"]
        if (step.get("observed") or {}).get("uid")
    ]
    assert uids
    assert all(value.startswith("principal:") for value in uids)


def test_the_published_record_keeps_the_journal_out_of_a_temporary_path() -> None:
    assert "/" not in shadow()["bundle"]["journal"]


def test_the_shadow_record_carries_no_credential() -> None:
    raw = SHADOW.read_text().lower()
    for marker in ("idtoken", "refreshtoken", "password", "apikey", "authorization"):
        assert marker not in raw
    shape = re.compile(r"[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]*")

    def walk(value) -> None:
        if isinstance(value, dict):
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)
        elif isinstance(value, str):
            assert not shape.fullmatch(value), value[:40]

    walk(shadow())
    for row in shadow()["bundle"]["rows"]:
        assert len(row["credentialFingerprint"]) == 16
