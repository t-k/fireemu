import copy
import json
import os
import subprocess
import sys
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest
import broad
import campaign_auth_list
import campaign_auth_list_shadow
from broad_contract import digest
from campaign_auth_list import (
    campaign_cases,
    campaign_manifest,
    compare_rows,
    proposal,
    validate_proposal,
)
from campaign_gate import validate as validate_typed_operation


def test_manifest_has_exact_five_cases_and_fixed_local_entry():
    accepted = [
        case
        for case in campaign_cases()
        if case.get("admission", "accepted") == "accepted"
    ]
    assert [case["id"] for case in accepted] == [
        "auth/refresh/changed-refresh@0",
        "auth/refresh/reference-refresh",
        "firestore/list-collection-ids/root",
        "firestore/list-collection-ids/missing-document-parent",
        "firestore/list-collection-ids/page-size-one",
    ]
    plan = campaign_manifest("a" * 32)
    assert plan["transport"] == "local-only"
    assert plan["maxConcurrency"] == 1
    assert plan["productionExecutable"] is False
    assert plan["costMicrousd"] < 100_000
    assert plan["observationRequests"] == 18
    assert len(plan["jobs"]["auth-list"]["recovery"]) == 19
    assert all(
        "parent" not in operation["body"]
        for operation in plan["jobs"]["auth-list"]["observation"]
        if operation["operationType"] == "firestore-list-collection-ids"
    )
    missing = next(
        operation
        for operation in plan["jobs"]["auth-list"]["observation"]
        if operation["operationType"] == "firestore-list-collection-ids"
        and operation["provenance"].get("case") == "missing-document-parent"
    )
    missing_segments = missing["resource"].split("/documents/", 1)[1].split("/")
    assert len(missing_segments) % 2 == 0
    assert missing_segments[-2:] == ["missing-parent-" + "a" * 32, "parent"]
    child = next(
        path
        for path in plan["jobs"]["auth-list"]["resources"]
        if "missing-parent-" in path
    )
    assert child.endswith("/parent/children/doc")


def test_facade_projects_legacy_auth_slots_to_canonical_account_resources(tmp_path):
    from campaign_gate import _project_auth_plan, create

    plan = campaign_manifest("a" * 32)
    create(tmp_path / "gate", plan)
    state = json.loads((tmp_path / "gate" / "state.json").read_bytes())
    auth_operations = [
        operation
        for operation in state["plan"]["jobs"]["auth-list"]["observation"]
        if operation["service"] == "auth"
    ]
    assert auth_operations
    assert all(operation["resource"].startswith("projects/demo-firestore-probe/auth/accounts/") for operation in auth_operations)
    assert all(operation["account"] for operation in auth_operations)
    assert all(
        operation["provenance"]["uid"] == "$binding:" + operation["account"] + "Uid"
        for operation in auth_operations
        if operation["operationType"] != "auth-sign-up"
    )
    canonical_path = tmp_path / "canonical-gate"
    create(canonical_path, _project_auth_plan(plan))
    canonical_state = json.loads((canonical_path / "state.json").read_bytes())
    assert canonical_state["plan"] == state["plan"]


@pytest.mark.parametrize("mutation", ["foreign-resource", "cross-uid-binding"])
def test_facade_rejects_auth_projection_tampering(tmp_path, mutation):
    from campaign_gate import create

    plan = campaign_manifest("b" * 32)
    operation = next(
        operation
        for operation in plan["jobs"]["auth-list"]["observation"]
        if operation["operationType"] == "auth-sign-in"
    )
    if mutation == "foreign-resource":
        operation["resource"] = "reference-" + "b" * 32
    else:
        operation["provenance"]["uid"] = "$binding:reference-" + "b" * 32 + "Uid"
    with pytest.raises(ValueError, match="closed local Auth-list contract drift"):
        create(tmp_path / mutation, plan)


def test_projected_auth_plan_digest_is_hash_seed_independent():
    script = (
        "import sys; sys.path[:0] = ['tools/compat-broad/auth-list', 'tools/compat-broad']; "
        "from broad_contract import digest; from campaign_auth_list import campaign_manifest; "
        "from campaign_gate import _project_auth_plan; "
        "print(digest(_project_auth_plan(campaign_manifest('c' * 32))))"
    )
    outputs = []
    for seed in ("1", "2"):
        environment = {**os.environ, "PYTHONHASHSEED": seed}
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        outputs.append(result.stdout.strip())
    assert outputs[0] == outputs[1]


def test_fresh_nonce_and_external_origin_fail_closed():
    with pytest.raises(ValueError, match="fresh hexadecimal"):
        campaign_manifest("old")
    value = proposal()
    drifted = copy.deepcopy(value)
    drifted["planTemplate"]["localOrigins"]["auth"] = (
        "https://identitytoolkit.googleapis.com"
    )
    with pytest.raises(ValueError):
        validate_proposal(drifted)


@pytest.mark.parametrize("kind", ["auth-refresh", "firestore-list-collection-ids"])
def test_typed_gate_requires_principal_resource_and_provenance(kind):
    operation = {
        "operationType": kind,
        "principal": "owner",
        "resource": "r",
        "provenance": {"source": "fixture"},
        "method": "POST",
        "path": "/v1/r:listCollectionIds",
        "body": {},
    }
    if kind == "auth-refresh":
        operation["provenance"]["token"] = "owned-refresh-token"
        operation["body"] = {"grant_type": "refresh_token", "refresh_token": "owned"}
    validate_typed_operation(operation)
    for field in ("principal", "resource", "provenance"):
        broken = copy.deepcopy(operation)
        broken.pop(field)
        with pytest.raises(ValueError):
            validate_typed_operation(broken)


def test_page_token_substitution_reuse_and_wrong_parent_are_rejected():
    plan = campaign_manifest("b" * 32)
    paged = [
        op
        for op in plan["jobs"]["auth-list"]["observation"]
        if op.get("operationType") == "firestore-list-collection-ids"
        and op["body"].get("pageToken")
    ]
    assert len(paged) == 1
    operation = paged[0]
    validate_typed_operation(operation)
    for mutation in ("wrong-parent", "substituted-token", "reused-token"):
        broken = copy.deepcopy(operation)
        if mutation == "wrong-parent":
            broken["path"] = broken["path"].replace("paged-", "wrong-paged-")
            broken["resource"] += "-wrong"
        else:
            broken["body"]["pageToken"] = "other-token"
            broken["provenance"]["pageToken"] = (
                "observed-continuation" if mutation == "reused-token" else "untrusted"
            )
            if mutation == "reused-token":
                broken["provenance"]["tokenValue"] = "other-token"
                broken["provenance"]["consumed"] = True
        with pytest.raises(ValueError):
            validate_typed_operation(broken)


@pytest.mark.parametrize(
    "flags",
    [
        {"recordingComplete": False},
        {"stateValidation": False},
        {"cleanupComplete": False},
    ],
)
def test_comparator_preserves_indeterminate_for_state_recording_cleanup_failures(flags):
    base = {
        "recordingComplete": True,
        "stateValidation": True,
        "cleanupComplete": True,
        "rows": [1],
    }
    other = dict(base)
    other.update(flags)
    assert compare_rows(base, other)["compatibility"] == "indeterminate"


def _write_shadow_worker(output, *, state_validation=True):
    """Provide the typed worker receipt; runtime flags stay independently asserted."""
    worker = output / "worker"
    worker.mkdir()
    (worker / "result.json").write_text(json.dumps({
        "schemaVersion": 1,
        "target": "owned-fireemu-artifact",
        "productionExecuted": False,
        "completed": state_validation is True,
        "recordingComplete": True,
        "stateValidation": state_validation,
        "cleanupComplete": True,
        "failure": None,
        "gate": {},
    }))


def test_shadow_public_result_keeps_state_validation_independent(tmp_path):
    report = {
        "status": "completed",
        "recordingComplete": True,
        "stateValidation": False,
        "ownedProcess": {"listenersClosed": True},
        "localObservations": [],
        "failure": None,
        "stopReason": "child-completed",
    }
    _write_shadow_worker(tmp_path, state_validation=False)
    with patch("broad.run", return_value=report):
        result = campaign_auth_list_shadow.run(tmp_path)
    assert result["recordingComplete"] is True
    assert result["stateValidation"] is False
    assert result["completed"] is False


@pytest.mark.parametrize("state_validation", [False, None])
def test_shadow_does_not_handoff_without_state_validation(tmp_path, state_validation):
    report = {
        "status": "completed",
        "recordingComplete": True,
        "stateValidation": state_validation,
        "ownedProcess": {"listenersClosed": True},
        "localObservations": [],
        "failure": None,
        "stopReason": "child-completed",
    }
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    _write_shadow_worker(shadow, state_validation=state_validation)
    with patch("broad.run", return_value=report):
        result = campaign_auth_list_shadow.run(shadow)
    assert result["recordingComplete"] is True
    assert result["stateValidation"] is False
    assert result["runtime"]["stateValidation"] is state_validation
    assert result["completed"] is False


def test_comparator_keeps_mismatch_and_same_wrong_operation_visible():
    left = {
        "recordingComplete": True,
        "stateValidation": True,
        "cleanupComplete": True,
        "rows": [{"operation": "wrong"}],
    }
    right = json.loads(json.dumps(left))
    assert compare_rows(left, right)["compatibility"] == "match"
    right["rows"][0]["status"] = "different"
    assert compare_rows(left, right)["compatibility"] == "mismatch"


def test_list_observation_validation_requires_expected_parent_and_pages():
    plan = campaign_manifest("a" * 32)
    operations = plan["jobs"]["auth-list"]["observation"]
    list_operations = [
        operation
        for operation in operations
        if operation["operationType"] == "firestore-list-collection-ids"
    ]
    root, missing, paged, continuation = list_operations
    rows = [
        {
            "operationType": "firestore-document-read",
            "resource": missing["resource"],
            "status": 404,
            "body": {"error": {"status": "NOT_FOUND"}},
        },
        {
            "operationType": "firestore-list-collection-ids",
            "resource": root["resource"],
            "status": 200,
            "body": {
                "collectionIds": [
                    "child-" + plan["nonce"],
                    "missing-parent-" + plan["nonce"],
                    "paged-parent-" + plan["nonce"],
                ]
            },
        },
        {
            "operationType": "firestore-list-collection-ids",
            "resource": missing["resource"],
            "status": 200,
            "body": {"collectionIds": ["children"]},
        },
        {
            "operationType": "firestore-list-collection-ids",
            "resource": paged["resource"],
            "status": 200,
            "body": {
                "collectionIds": ["alpha"],
                "nextPageToken": "opaque-fireemu-token",
            },
        },
        {
            "operationType": "firestore-list-collection-ids",
            "resource": continuation["resource"],
            "status": 200,
            "body": {"collectionIds": ["beta"]},
        },
    ]
    campaign_auth_list_shadow.validate_list_observations(rows, plan["nonce"])

    for mutation in ("bad-parent-status", "duplicate-page", "missing-page"):
        broken = copy.deepcopy(rows)
        if mutation == "bad-parent-status":
            broken[0]["status"] = 400
        elif mutation == "duplicate-page":
            broken[-1]["body"]["collectionIds"] = ["alpha"]
        else:
            broken[-1]["body"]["collectionIds"] = []
        with pytest.raises(ValueError):
            campaign_auth_list_shadow.validate_list_observations(
                broken, plan["nonce"]
            )


def test_auth_lookup_validation_rejects_structured_error_and_wrong_shape():
    validate = campaign_auth_list_shadow.validate_auth_lookup
    with pytest.raises(ValueError):
        validate({"error": {"status": "INVALID_ARGUMENT"}}, "uid-owned")
    with pytest.raises(ValueError):
        validate({"users": []}, "uid-owned")
    with pytest.raises(ValueError):
        validate({"users": [{"localId": "other"}]}, "uid-owned")
    validate(
        {"users": [{"localId": "uid-owned", "email": "owned@example.invalid"}]},
        "uid-owned",
    )


def test_deleted_lookup_validation_requires_explicit_empty_users():
    validate = campaign_auth_list_shadow.validate_deleted_lookup
    with pytest.raises(ValueError):
        validate(200, {"error": {"status": "INTERNAL"}})
    with pytest.raises(ValueError):
        validate(200, {})
    with pytest.raises(ValueError):
        validate(200, {"users": [{"localId": "still-present"}]})
    validate(200, {"users": []})
    validate(200, {"kind": "identitytoolkit#GetAccountInfoResponse"})
    validate(404, {"error": {"status": "USER_NOT_FOUND"}})


@pytest.mark.parametrize(
    "failure", ["auth-refusal", "timeout", "budget", "malformed", "non-json"]
)
def test_transport_and_refusal_failures_are_recorded_as_indeterminate(failure):
    left = {
        "recordingComplete": False,
        "stateValidation": True,
        "cleanupComplete": True,
        "failure": failure,
        "rows": [],
    }
    right = {**left, "recordingComplete": True, "failure": None}
    result = compare_rows(left, right)
    assert result["recording"] is False
    assert result["compatibility"] == "indeterminate"


def test_auth_refresh_source_mismatch_is_refused():
    operation = next(
        operation
        for operation in campaign_manifest("d" * 32)["jobs"]["auth-list"]["observation"]
        if operation["operationType"] == "auth-refresh"
    )
    operation["provenance"]["token"] = "wrong-source"
    with pytest.raises(
        ValueError, match="refresh token provenance|owned refresh token"
    ):
        validate_typed_operation(operation)


def test_checked_in_manifest_matches_proposal():
    path = (
        __import__("pathlib").Path(__file__).parents[3]
        / "spec/compatibility/broad-runs/prod-campaign-auth-list-01.json"
    )
    value = json.loads(path.read_bytes())
    current = proposal()
    assert value["kind"] == current["kind"]
    assert value["sourceCommit"] == current["planTemplate"]["sourceCommit"]
    assert value["cases"] == [
        case["id"]
        for case in campaign_cases()
        if case.get("admission", "accepted") == "accepted"
    ]
    assert value["transport"] == current["planTemplate"]["transport"]
    assert digest(
        {
            "kind": value["kind"],
            "cases": value["cases"],
            "transport": value["transport"],
        }
    )


def test_legacy_next_campaign_package_remains_immutable():
    import hashlib

    root = __import__("pathlib").Path(__file__).parents[3]
    package_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-v2.json"
    package = json.loads(package_path.read_bytes())
    assert hashlib.sha256(package_path.read_bytes()).hexdigest() == (
        "44471428cd147ac2b2104734e7d7f310b061a5650cdae6223ecfa4cb7979f45b"
    )
    legacy_fixture = root / package["localShadow"]["legacyFixture"]["path"]
    owned_artifact = root / package["localShadow"]["ownedArtifact"]["path"]
    assert hashlib.sha256(legacy_fixture.read_bytes()).hexdigest() == (
        "c49e1012c4fd49c540ab0854dbede12f15093f510a4e8f8ff06654fe388f9874"
    )
    assert hashlib.sha256(owned_artifact.read_bytes()).hexdigest() == (
        "91081dccb9718347847a76f9bb83340de3655fe09155487e1b392f8d2168b926"
    )
    assert package["status"] == "prepared-offline-blocked-owner"
    assert package["localShadow"]["legacyFixture"]["productionExecuted"] is False
    assert package["adapter"]["sourceCommit"] == "aad1a41de926fae244b42ac1bd2baa57bf2bcdde"
    assert package["adapter"]["shadowCommit"] == "f050e9bb84b4202146c8d4d0a741350c73aa0c50"
    assert package["adapter"]["sourceSha256"] == "aba4b0b9f306c021cd9b9786850a16d460adf336e993a4338155ecc807240427"
    assert package["adapter"]["shadowSha256"] == "28667c98521c7762e52aad0c5b57535e440df4972a3cea033ea78e1bde16c424"
    assert package["localShadow"]["ownedArtifact"]["executionCommit"] == "f050e9bb84b4202146c8d4d0a741350c73aa0c50"
    assert all(value is None for value in package["production"]["ownerInputs"].values())


def test_current_next_campaign_package_binds_current_artifact_result():
    import hashlib

    root = __import__("pathlib").Path(__file__).parents[3]
    package_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-v3.json"
    result_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-local-artifact-v3/result.json"
    package = json.loads(package_path.read_bytes())
    result = json.loads(result_path.read_bytes())
    assert hashlib.sha256(package_path.read_bytes()).hexdigest() == (
        "2aee67fe8d27d0e28ab623915eb7207b9f85f6948aad754fc7288e0b822d1c2b"
    )
    artifact = package["localShadow"]["ownedArtifact"]
    assert package["kind"] == "production-campaign-auth-list-next-v3"
    assert artifact["sha256"] == hashlib.sha256(result_path.read_bytes()).hexdigest()
    assert artifact["artifactSha256"] == result["artifactSha256"]
    assert artifact["executionCommit"] == result["executionCommit"]
    assert package["adapter"]["shadowSha256"] == "8c15512f1de689cc21e43819a98b5cc229e608e4dded691191434647ae6b6c28"
    assert package["adapter"]["sourceSha256"] == "88e4c79839b4aa9ba6e47a9f0b75ab9505461ae31fb04ff9dd2a842b4f916ed0"
    assert package["adapter"]["gateSha256"] == "7ac19bad00fc18df247105474cb51181a874b5f45a87a0fa196d454196381c1a"
    assert package["adapter"]["shadowCommit"] == result["executionCommit"]
    assert artifact["observerSha256"] == result["observerSha256"]
    assert result["productionExecuted"] is False
    assert artifact["observationRequests"] == 18
    assert artifact["recoveryRequests"] == 19
    assert artifact["totalRequests"] == 39
    assert all(value is None for value in package["production"]["ownerInputs"].values())


def test_v4_campaign_package_binds_integrated_artifact_result():
    import hashlib

    root = __import__("pathlib").Path(__file__).parents[3]
    package_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-v4.json"
    result_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-local-artifact-v4/result.json"
    package = json.loads(package_path.read_bytes())
    result = json.loads(result_path.read_bytes())
    artifact = package["localShadow"]["ownedArtifact"]
    assert hashlib.sha256(package_path.read_bytes()).hexdigest() == (
        "c5919b58a017b2a4bdc36bcfd2ea69bdae05197a640d74e1227695f245ed0a30"
    )
    assert package["kind"] == "production-campaign-auth-list-next-v4"
    assert artifact["sha256"] == hashlib.sha256(result_path.read_bytes()).hexdigest()
    assert artifact["artifactSha256"] == result["artifactSha256"]
    assert artifact["observerSha256"] == result["observerSha256"]
    assert artifact["parentManifestSha256"] == result["parentManifestSha256"]
    assert artifact["executionCommit"] == result["executionCommit"]
    assert package["adapter"]["shadowSha256"] == "cfafaf85be289ac6f16bb3b52a02494389a2c1b6a436f4ba23e0d2fbd9e35809"
    assert package["adapter"]["sourceSha256"] == "88e4c79839b4aa9ba6e47a9f0b75ab9505461ae31fb04ff9dd2a842b4f916ed0"
    assert package["adapter"]["gateSha256"] == "7ac19bad00fc18df247105474cb51181a874b5f45a87a0fa196d454196381c1a"
    assert package["adapter"]["shadowCommit"] == result["executionCommit"]
    assert result["productionExecuted"] is False
    assert result["recordingComplete"] is True
    assert result["stateValidation"] is True
    assert artifact["observationRequests"] == 18
    assert artifact["recoveryRequests"] == 19
    assert artifact["totalRequests"] == 39
    assert all(value is None for value in package["production"]["ownerInputs"].values())


def test_v5_campaign_package_binds_manifest_source_commit():
    import hashlib

    root = __import__("pathlib").Path(__file__).parents[3]
    package_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-v5.json"
    result_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-local-artifact-v5/result.json"
    package = json.loads(package_path.read_bytes())
    result = json.loads(result_path.read_bytes())
    artifact = package["localShadow"]["ownedArtifact"]
    assert hashlib.sha256(package_path.read_bytes()).hexdigest() == (
        "c78e9d9ffad56982ec660425487fc6ff7ce669e713348adfa273785d635778c9"
    )
    assert package["kind"] == "production-campaign-auth-list-next-v5"
    assert package["sourceCommit"] == campaign_auth_list.SOURCE_COMMIT
    assert package["adapter"]["sourceCommit"] == campaign_auth_list.SOURCE_COMMIT
    assert artifact["sha256"] == hashlib.sha256(result_path.read_bytes()).hexdigest()
    assert artifact["artifactSha256"] == result["artifactSha256"]
    assert artifact["observerSha256"] == result["observerSha256"]
    assert artifact["parentManifestSha256"] == result["parentManifestSha256"]
    assert artifact["executionCommit"] == result["executionCommit"]
    assert package["adapter"]["shadowSha256"] == "a62dbe7f7addfbb4dcc6d7b1fbf5f632034c31e521ce7f616ef0f1877785b74a"
    assert package["adapter"]["sourceSha256"] == "88e4c79839b4aa9ba6e47a9f0b75ab9505461ae31fb04ff9dd2a842b4f916ed0"
    assert package["adapter"]["gateSha256"] == "7ac19bad00fc18df247105474cb51181a874b5f45a87a0fa196d454196381c1a"
    assert package["adapter"]["shadowCommit"] == result["executionCommit"]
    assert artifact["observationRequests"] == 18
    assert artifact["recoveryRequests"] == 19
    assert artifact["totalRequests"] == 39
    assert result["productionExecuted"] is False
    assert result["recordingComplete"] is True
    assert result["stateValidation"] is True
    assert package["production"]["productionExecuted"] is False
    assert all(value is None for value in package["production"]["ownerInputs"].values())


def test_v6_campaign_package_preserves_historical_hashes():
    import hashlib

    root = __import__("pathlib").Path(__file__).parents[3]
    package_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-v6.json"
    result_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-local-artifact-v6/result.json"
    package = json.loads(package_path.read_bytes())
    result = json.loads(result_path.read_bytes())
    artifact = package["localShadow"]["ownedArtifact"]
    assert hashlib.sha256(package_path.read_bytes()).hexdigest() == (
        "576199d9e801569d0fd74687c9706f21fbd02f84619692353b4599653f1433bd"
    )
    assert package["kind"] == "production-campaign-auth-list-next-v6"
    assert package["sourceCommit"] == campaign_auth_list.SOURCE_COMMIT
    assert package["adapter"]["sourceCommit"] == campaign_auth_list.SOURCE_COMMIT
    assert artifact["sha256"] == hashlib.sha256(result_path.read_bytes()).hexdigest()
    assert artifact["artifactSha256"] == result["artifactSha256"]
    assert artifact["observerSha256"] == result["observerSha256"]
    assert artifact["parentManifestSha256"] == result["parentManifestSha256"]
    assert artifact["executionCommit"] == result["executionCommit"]
    assert package["adapter"]["shadowSha256"] == (
        "4010f1b16fb6d54a13d684374429aaa0f4e30b41b91f8e98aa73a4090872a73f"
    )
    assert package["adapter"]["sourceSha256"] == (
        "88e4c79839b4aa9ba6e47a9f0b75ab9505461ae31fb04ff9dd2a842b4f916ed0"
    )
    assert package["adapter"]["gateSha256"] == (
        "7ac19bad00fc18df247105474cb51181a874b5f45a87a0fa196d454196381c1a"
    )
    assert package["adapter"]["shadowCommit"] == result["executionCommit"]
    assert artifact["observationRequests"] == 18
    assert artifact["recoveryRequests"] == 19
    assert artifact["totalRequests"] == 39
    assert result["productionExecuted"] is False
    assert result["recordingComplete"] is True
    assert result["stateValidation"] is True
    assert package["production"]["productionExecuted"] is False
    assert all(value is None for value in package["production"]["ownerInputs"].values())


def test_v7_campaign_package_preserves_historical_shadow_and_result():
    import hashlib

    root = __import__("pathlib").Path(__file__).parents[3]
    package_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-v7.json"
    result_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-local-artifact-v7/result.json"
    package = json.loads(package_path.read_bytes())
    result = json.loads(result_path.read_bytes())
    artifact = package["localShadow"]["ownedArtifact"]
    assert hashlib.sha256(package_path.read_bytes()).hexdigest() == (
        "c7a57c8e930692223b0c8fba22d03c8957ad16ccaf53a46fa335246889db4457"
    )
    assert package["kind"] == "production-campaign-auth-list-next-v7"
    assert package["adapter"]["shadowCommit"] == (
        "34bcbdfbe1ca79305bd5cc5b591380b21f99458e"
    )
    assert package["adapter"]["shadowSha256"] == (
        "53d737a625f89c102299fc13c455a1f008f611362b6f5aef07c34427801dd70c"
    )
    assert artifact["sha256"] == hashlib.sha256(result_path.read_bytes()).hexdigest()
    assert artifact["artifactSha256"] == result["artifactSha256"]
    assert artifact["observerSha256"] == result["observerSha256"]
    assert artifact["parentManifestSha256"] == result["parentManifestSha256"]
    assert artifact["executionCommit"] == result["executionCommit"]
    assert result["productionExecuted"] is False
    assert result["recordingComplete"] is True
    assert result["stateValidation"] is True
    assert package["production"]["productionExecuted"] is False
    assert all(value is None for value in package["production"]["ownerInputs"].values())


def test_v8_campaign_package_preserves_historical_shadow_and_result():
    import hashlib

    root = __import__("pathlib").Path(__file__).parents[3]
    package_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-v8.json"
    result_path = root / "spec/compatibility/broad-runs/prod-campaign-auth-list-next-local-artifact-v8/result.json"
    package = json.loads(package_path.read_bytes())
    result = json.loads(result_path.read_bytes())
    artifact = package["localShadow"]["ownedArtifact"]
    assert hashlib.sha256(package_path.read_bytes()).hexdigest() == (
        "cff20c69f2dd0f9bfd7b0c08a15ec2749296155036934722d4570f6d51018146"
    )
    assert package["kind"] == "production-campaign-auth-list-next-v8"
    assert package["adapter"]["shadowCommit"] == (
        "43b5778c65b93c3468a80b1bdd3b0b850467c443"
    )
    assert package["adapter"]["shadowSha256"] == (
        "53d737a625f89c102299fc13c455a1f008f611362b6f5aef07c34427801dd70c"
    )
    assert package["adapter"]["sourceSha256"] == (
        "88e4c79839b4aa9ba6e47a9f0b75ab9505461ae31fb04ff9dd2a842b4f916ed0"
    )
    assert package["adapter"]["gateSha256"] == (
        "77c8bc791b6559fd002465f3ce6394d4a7e09a3f7e656922f3119ec982999e71"
    )
    assert artifact["sha256"] == hashlib.sha256(result_path.read_bytes()).hexdigest()
    assert artifact["artifactSha256"] == result["artifactSha256"]
    assert artifact["observerSha256"] == result["observerSha256"]
    assert artifact["parentManifestSha256"] == result["parentManifestSha256"]
    assert result["productionExecuted"] is False
    assert result["recordingComplete"] is True
    assert result["stateValidation"] is True
    assert package["production"]["productionExecuted"] is False
    assert all(value is None for value in package["production"]["ownerInputs"].values())


def test_actual_shadow_uses_fixed_fireemu_artifact_and_closes_transport(tmp_path):
    from campaign_auth_list_shadow import run

    result = run(tmp_path / "shadow")
    assert result["completed"] is True
    assert result["productionExecuted"] is False
    assert result["target"] == "owned-fireemu-artifact"
    assert result["artifactSha256"]
    assert result["runtime"]["ownedProcess"]["listenersClosed"] is True
    assert result["runtime"]["ownedProcess"]["stopped"] is True
    assert result["gate"]["observation"] == 18
    assert result["gate"]["recovery"] == 19
    assert result["gate"]["total"] == 39
    assert result["cleanupComplete"] is True
    assert result["stateValidation"] is True
    assert result["failure"] is None
    assert result["stopReason"] == "child-completed"


def test_legacy_shadow_fixture_rejects_invalid_auth_and_parent_shape():
    from http.server import ThreadingHTTPServer
    import threading

    from campaign_auth_list_shadow import ShadowHandler, wire

    server = ThreadingHTTPServer(("127.0.0.1", 0), ShadowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        status, _body, _content_type = wire(
            origin + "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
            "POST",
            {"email": "owned@example.invalid"},
            {"Content-Type": "application/json"},
            local=True,
        )
        assert status == 400
        status, body, _content_type = wire(
            origin
            + "/v1/projects/demo-firestore-probe/databases/(default)/documents/collection:listCollectionIds",
            "POST",
            {},
            {"Content-Type": "application/json"},
            local=True,
        )
        assert status == 400
        assert body["error"]["status"] == "INVALID_ARGUMENT"
        for invalid_parent in (
            "/collection//doc",
            "/collection/doc//sub",
            "/collection/doc/",
        ):
            status, body, _content_type = wire(
                origin
                + "/v1/projects/demo-firestore-probe/databases/(default)/documents"
                + invalid_parent
                + ":listCollectionIds",
                "POST",
                {},
                {"Content-Type": "application/json"},
                local=True,
            )
            assert status == 400
            assert body["error"]["status"] == "INVALID_ARGUMENT"
        for invalid_body in ([], "null"):
            status, body, _content_type = wire(
                origin
                + "/v1/projects/demo-firestore-probe/databases/(default)/documents:listCollectionIds",
                "POST",
                invalid_body,
                {"Content-Type": "application/json"},
                local=True,
            )
            assert status == 400
            assert body["error"]["status"] == "INVALID_ARGUMENT"
        status, _body, _content_type = wire(
            origin
            + "/v1/projects/demo-firestore-probe/databases/(default)/documents:listCollectionIds",
            "POST",
            {"parent": "projects/demo-firestore-probe/databases/(default)/documents"},
            {"Content-Type": "application/json"},
            local=True,
        )
        assert status == 400
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_gate_dispatch_rejects_typed_bypass_before_transport(tmp_path):
    from campaign_gate import CampaignGate, create

    plan = campaign_manifest("e" * 32)
    create(tmp_path / "gate", plan)
    gate = CampaignGate(tmp_path / "gate", "auth-list")
    gate.coordinator_call(0, lambda: (200, {}))
    gate.coordinator_call(1, lambda: (200, {}))
    gate.claim()
    operation = copy.deepcopy(plan["jobs"]["auth-list"]["observation"][0])
    operation["principal"] = "wrong-principal"
    called = False

    def send():
        nonlocal called
        called = True
        return 200, {}

    with pytest.raises(ValueError, match="request outside closed scenario"):
        gate.dispatch(operation, False, send)
    assert called is False


def test_gate_adapter_request_rejects_origin_bypass_before_transport(tmp_path):
    from campaign_gate import CampaignGate, create

    plan = campaign_manifest("f" * 32)
    create(tmp_path / "gate", plan)
    gate = CampaignGate(tmp_path / "gate", "auth-list")
    operation = plan["jobs"]["auth-list"]["observation"][0]
    adapter = SimpleNamespace(
        local={"auth": "https://external.invalid", "firestore": "https://external.invalid"},
        nonce=plan["nonce"],
        budget=SimpleNamespace(recovery=False),
    )
    with pytest.raises(ValueError, match="adapter origin/nonce/observer binding mismatch"):
        gate.adapter_request(adapter, operation, lambda: (200, {}))


def test_gate_finish_rejects_unclosed_recovery(tmp_path):
    from campaign_gate import CampaignGate, create

    plan = campaign_manifest("1" * 32)
    create(tmp_path / "gate", plan)
    gate = CampaignGate(tmp_path / "gate", "auth-list")
    gate.claim()
    with pytest.raises(ValueError, match="cleanup incomplete"):
        gate.finish()


def test_gate_rejects_lookup_only_plan_without_account_ownership(tmp_path):
    from campaign_gate import CampaignGate, create

    plan = campaign_manifest("2" * 32)
    operation = next(
        item
        for item in plan["jobs"]["auth-list"]["recovery"]
        if item["operationType"] == "auth-lookup"
    )
    plan["jobs"]["auth-list"]["recovery"] = [operation]
    # A single lookup cannot replace same-run creation, deletion and final
    # absence proofs for both accounts in the closed local recipe.
    with pytest.raises(ValueError, match="closed local Auth-list contract drift"):
        create(tmp_path / "gate", plan)
    assert not (tmp_path / "gate").exists()
    # The constructor must reject the same plan even if a generic Gate was
    # written directly, without this facade's create-time admission.
    from shared_gate import create as create_generic_gate
    from campaign_gate import _project_auth_plan
    create_generic_gate(tmp_path / "gate", _project_auth_plan(plan))
    with pytest.raises(ValueError, match="closed local Auth-list contract drift"):
        CampaignGate(tmp_path / "gate", "auth-list")
    state = json.loads((tmp_path / "gate/state.json").read_bytes())
    assert state["jobs"]["auth-list"]["absent"] == []


def test_shadow_cli_returns_nonzero_for_incomplete_result(tmp_path, monkeypatch):
    monkeypatch.setattr(
        campaign_auth_list_shadow,
        "run",
        lambda _output: {"completed": False, "failure": "cleanup incomplete"},
    )

    assert (
        campaign_auth_list_shadow.main(["--output", str(tmp_path / "shadow")])
        == 2
    )
