"""The published local rehearsal record stays bound to the modules that produced it."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from fs_config_lifecycle import lifecycle_descriptor as campaign
from fs_config_lifecycle.cases import compile_cases
from fs_config_lifecycle.comparator import LOCAL_KIND
from fs_config_lifecycle.lifecycle_local import RECORD_KIND, bound_module_digests
from fs_config_lifecycle.surface_matrix import repo_root

RECORD = repo_root() / campaign.LOCAL_RECORD


def _record() -> dict:
    return json.loads(RECORD.read_text(encoding="utf-8"))


def test_the_record_is_a_completed_local_rehearsal_and_never_production_evidence() -> (
    None
):
    record = _record()
    assert record["kind"] == RECORD_KIND
    assert record["status"] == "completed"
    assert record["productionExecuted"] is False
    assert record["formalCompatibilityClaim"] is False
    assert record["executionKind"] == LOCAL_KIND
    assert record["runtime"]["transport"] == "loopback"
    assert record["ownedProcess"]["stopped"] is True
    assert record["ownedProcess"]["firestoreListenerClosed"] is True


def test_the_record_binds_the_lane_modules_and_a_committed_runtime_source() -> None:
    record = _record()
    assert record["sourceInputs"] == bound_module_digests(), (
        "lane modules changed since the rehearsal: rerun lifecycle_local.py on a "
        "committed tree and publish a new versioned record"
    )
    commit = record["runtime"]["sourceCommit"]
    assert len(commit) == 40
    subprocess.check_call(
        ["git", "-C", str(repo_root()), "merge-base", "--is-ancestor", commit, "HEAD"]
    )
    assert len(record["runtime"]["artifactSha256"]) == 64
    assert campaign.artifact_profile() == "fs-config-lifecycle-" + commit[:9]


def test_the_rehearsal_restored_the_ttl_field_and_recorded_the_exemption_deviation() -> (
    None
):
    record = _record()
    collection = record["collection"]
    assert collection["cleanupComplete"] is True
    assert collection["restoreVerified"] is True
    assert collection["unrecovered"] == []
    assert collection["steps"]["ttl"]["restore"] == "restored"
    assert (
        collection["steps"]["ttl"]["preDigest"]
        == collection["steps"]["ttl"]["verifyDigest"]
    )
    # FS-CONFIG-RT-004: the local runtime refuses the indexConfig patch, so OC-18 is
    # a recorded deviation and OC-19/OC-20 were never reached. Not hidden.
    assert collection["steps"]["exemption"]["restore"] == "apply-refused"
    assert collection["refusedApplies"] == ["OC-18"]
    assert collection["deviations"][0]["error"] == {
        "code": 501,
        "status": "UNIMPLEMENTED",
    }
    observed = set(collection["observedCases"])
    expected = {case["id"] for case in compile_cases(record["runtime"]["nonce"])}
    assert expected - observed == {"OC-19", "OC-20"}
    assert [item["case"] for item in record["expectedLocalDeviations"]] == [
        "OC-18",
        "OC-20",
    ]
    assert collection["chargedRequests"] == collection["rowCount"] == 17
    assert collection["chargedRequests"] <= 128


def test_the_local_projection_shape_equals_production_but_its_digest_differs() -> None:
    """RT-003 fields are present locally; uid, createTime and updateTime are local values."""
    baseline = _record()["baseline"]
    assert baseline["source"] == "local-preflight-read"
    assert baseline["equal"] is False
    assert baseline["localProjectionShape"] == baseline["productionProjectionShape"]
    assert {"uid", "createTime", "updateTime", "freeTier", "databaseEdition"} <= set(
        baseline["localProjectionShape"]
    )


def test_the_record_carries_no_secret_and_no_raw_body() -> None:
    """Personal absolute paths are refused by the publication-hygiene suite."""
    text = RECORD.read_text(encoding="utf-8")
    assert "Bearer" not in text
    record = _record()
    for row in record["collection"]["rows"]:
        assert "body" not in row
        assert "raw" not in row
    assert Path(record["runtime"]["artifactPath"]).parts[0] == "target"
