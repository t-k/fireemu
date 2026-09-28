from __future__ import annotations

import copy

import pytest
from transform_compiler import MAX_TRANSFORMS, compile_plan


def test_plan_is_deterministic_and_has_two_owned_documents() -> None:
    first = compile_plan("fireemu-35fe6", "(default)", "a" * 32)
    assert first == compile_plan("fireemu-35fe6", "(default)", "a" * 32)
    assert first["campaignId"] == "FS-DATA-WRITE-COMMIT-TRANSFORMS-03"
    assert set(first["documents"]) == {"exact-500", "over-501"}
    assert first["ownedScope"].endswith("/commit-limits-03")
    assert all(
        document["resource"].startswith(first["ownedScope"] + "/")
        for document in first["documents"].values()
    )
    assert first["documents"]["exact-500"]["transformCount"] == MAX_TRANSFORMS
    assert first["documents"]["over-501"]["transformCount"] == MAX_TRANSFORMS + 1


def test_plan_has_finite_11_observation_and_6_recovery_requests() -> None:
    plan = compile_plan("demo", "(default)", "b" * 32)
    assert len(plan["observation"]) == 11
    assert len(plan["recovery"]) == 6
    assert plan["budget"] == {
        "observationRequests": 11,
        "recoveryRequests": 6,
        "requestUpperBound": 17,
        "resourceUpperBound": 2,
        "concurrencyUpperBound": 1,
    }
    assert [row["kind"] for row in plan["observation"][:2]] == [
        "preflight-typed-absence",
        "preflight-typed-absence",
    ]
    commits = [row for row in plan["observation"] if row["kind"] == "commit-transform"]
    assert len(commits) == 2
    assert [
        len(write["transform"]["fieldTransforms"])
        for write in commits[0]["body"]["writes"]
    ] == [250, 250]
    assert [
        len(write["transform"]["fieldTransforms"])
        for write in commits[1]["body"]["writes"]
    ] == [250, 251]
    assert commits[0]["expect"] == {"outcome": "accepted", "status": 200}
    assert commits[1]["expect"] == {"outcome": "refused", "statusClass": "4xx"}


@pytest.mark.parametrize(
    "project,database,nonce",
    [
        ("", "(default)", "a" * 32),
        ("demo", "bad/name", "a" * 32),
        ("demo", "(default)", "A" * 32),
        ("demo", "(default)", "a" * 31),
    ],
)
def test_unsafe_target_is_rejected(project: str, database: str, nonce: str) -> None:
    with pytest.raises(ValueError):
        compile_plan(project, database, nonce)


def test_compiled_commit_targets_and_markers_are_owned_and_immutable() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    original = copy.deepcopy(plan)
    resources = {item["resource"] for item in plan["documents"].values()}
    for row in plan["observation"]:
        if row["kind"] == "create-only-patch":
            assert row["body"]["fields"]["_sharedOwner"] == {
                "referenceValue": row["body"]["name"]
            }
        if row["kind"] == "commit-transform":
            for write in row["body"]["writes"]:
                assert write["transform"]["document"] in resources
                assert all(
                    item["fieldPath"] != "_sharedOwner"
                    for item in write["transform"]["fieldTransforms"]
                )
    assert plan == original


def test_cleanup_is_version_bound_and_marker_checked() -> None:
    plan = compile_plan("demo", "(default)", "a" * 32)
    assert len(plan["recovery"]) == 6
    for start in (0, 3):
        read, delete, verify = plan["recovery"][start : start + 3]
        assert read["kind"] == "cleanup-ownership-read"
        assert delete["kind"] == "cleanup-conditional-delete"
        assert delete["versionFrom"] == start
        assert delete["expect"] == {"status": 200, "marker": "owned"}
        assert verify["expect"] == {"status": 404, "typed": "NOT_FOUND"}
