import sys

import pytest

sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
sys.path.insert(0, "tools/compat-broad")

from request_bytes_collector import (
    commit_versions,
    readback_matches,
    typed_not_found,
    validate_schedule,
)
from request_bytes_compiler import compile_request_bytes_plan


def plan():
    return compile_request_bytes_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )


def test_schedule_requires_observation_then_probe_cleanup():
    value = plan()
    validate_schedule(value)
    assert len(value["executionSchedule"]) == 258
    assert value["executionSchedule"][35]["phase"] == "recovery"
    assert value["executionSchedule"][86]["phase"] == "observation"


def test_commit_versions_requires_positional_complete_write_results():
    value = plan()
    resources = value["probes"][0]["resources"]
    receipt = {
        "complete": True,
        "failure": None,
        "status": 200,
        "body": {
            "writeResults": [
                {"updateTime": "2026-01-01T00:00:00.000000Z", "name": resource}
                for resource in resources
            ]
        },
    }
    assert len(commit_versions(receipt, resources)) == 17
    receipt["body"]["writeResults"][3]["name"] = resources[4]
    assert commit_versions(receipt, resources) is None


def test_over_refusal_is_typed_and_readback_never_accepts_foreign_document():
    refusal = {
        "complete": True,
        "failure": None,
        "status": 404,
        "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
    }
    assert typed_not_found(refusal)
    value = plan()
    document = value["documents"][value["probes"][0]["resources"][0]]
    foreign = {
        "complete": True,
        "failure": None,
        "status": 200,
        "body": {
            "name": value["probes"][0]["resources"][1],
            "fields": {},
            "updateTime": "2026-01-01T00:00:00.000000Z",
        },
    }
    assert not readback_matches(
        foreign,
        value["probes"][0]["resources"][0],
        document["fieldsSha256"],
        value["nonce"],
        None,
    )


def test_schedule_mutation_is_rejected():
    value = plan()
    value["executionSchedule"][35], value["executionSchedule"][36] = (
        value["executionSchedule"][36],
        value["executionSchedule"][35],
    )
    with pytest.raises(ValueError):
        validate_schedule(value)


def test_failed_preflight_never_sends_commit_or_next_probe(tmp_path):
    from request_bytes_collector import collect_local

    value = plan()
    dispatched = []

    def execute(operation):
        dispatched.append(operation)
        if operation["kind"] == "preflight-typed-absence" and len(dispatched) == 1:
            return {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {"name": operation["resource"]},
            }
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    result = collect_local(value, execute, tmp_path / "run")
    assert not result["completed"]
    assert not any(item["kind"] == "conditional-create-commit" for item in dispatched)
    assert not any(item["probe"] != "under" for item in dispatched)
    assert not any(item["method"] == "DELETE" for item in dispatched)


def test_lost_commit_response_holds_cleanup_responsibility(tmp_path):
    from request_bytes_collector import collect_local

    value = plan()
    dispatched = []

    def execute(operation):
        dispatched.append(operation)
        if operation["kind"] == "conditional-create-commit":
            return {"complete": False, "failure": "response-lost"}
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    result = collect_local(value, execute, tmp_path / "run")
    assert not result["completed"]
    assert not any(item["method"] == "DELETE" for item in dispatched)
    assert not any(item["probe"] != "under" for item in dispatched)
    assert result["resourceAbsence"] is False


def test_timestamp_accepts_firestore_precision_variants():
    from request_bytes_collector import commit_versions

    for timestamp in (
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00.1Z",
        "2026-01-01T00:00:00.123456789Z",
    ):
        assert commit_versions(
            {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {"writeResults": [{"updateTime": timestamp}]},
            },
            ["resource"],
        ) == [timestamp]
    assert (
        commit_versions(
            {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {"writeResults": [{"updateTime": "2026-99-99T99:99:99.1Z"}]},
            },
            ["resource"],
        )
        is None
    )


def test_three_probe_run_completes_with_typed_over_refusal(tmp_path):
    from request_bytes_collector import collect_local

    value = plan()
    documents = {
        write["update"]["name"]: write["update"]["fields"]
        for probe in value["probes"]
        for write in probe["body"]["writes"]
    }
    version = "2026-01-01T00:00:00.123456789Z"
    live = set()
    deletes = []

    def execute(operation):
        kind, resource = operation["kind"], operation.get("resource")
        if kind == "conditional-create-commit":
            if operation["probe"] == "over":
                return {
                    "complete": True,
                    "failure": None,
                    "status": 400,
                    "body": {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
                }
            resources = next(
                probe["resources"]
                for probe in value["probes"]
                if probe["label"] == operation["probe"]
            )
            live.update(resources)
            return {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {"writeResults": [{"updateTime": version} for _ in resources]},
            }
        if kind == "cleanup-version-bound-delete":
            assert resource in live
            assert operation["path"].endswith(
                "currentDocument.updateTime=" + version.replace(":", "%3A")
            )
            deletes.append(resource)
            live.remove(resource)
            return {"complete": True, "failure": None, "status": 200, "body": {}}
        if resource in live:
            return {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {
                    "name": resource,
                    "fields": documents[resource],
                    "updateTime": version,
                },
            }
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    result = collect_local(value, execute, tmp_path / "run")
    assert result["completed"] is True
    assert result["cleanupComplete"] is True
    assert result["resourceAbsence"] is True
    assert len(deletes) == 34
    assert not live
