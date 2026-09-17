import sys

import pytest

sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
sys.path.insert(0, "tools/compat-broad")

from request_bytes_collector import commit_versions, readback_matches, typed_not_found, validate_schedule
from request_bytes_compiler import compile_request_bytes_plan, logical_fields_digest


def plan():
    return compile_request_bytes_plan("local-project", "(default)", "0123456789abcdef0123456789abcdef")


def test_schedule_requires_observation_then_probe_cleanup():
    value = plan()
    validate_schedule(value)
    assert len(value["executionSchedule"]) == 258
    assert value["executionSchedule"][35]["phase"] == "recovery"
    assert value["executionSchedule"][86]["phase"] == "observation"


def test_commit_versions_requires_positional_complete_write_results():
    value = plan()
    resources = value["probes"][0]["resources"]
    receipt = {"complete": True, "failure": None, "status": 200, "body": {"writeResults": [{"updateTime": "2026-01-01T00:00:00.000000Z", "name": resource} for resource in resources]}}
    assert len(commit_versions(receipt, resources)) == 17
    receipt["body"]["writeResults"][3]["name"] = resources[4]
    assert commit_versions(receipt, resources) is None


def test_over_refusal_is_typed_and_readback_never_accepts_foreign_document():
    refusal = {"complete": True, "failure": None, "status": 404, "body": {"error": {"code": 404, "status": "NOT_FOUND"}}}
    assert typed_not_found(refusal)
    value = plan()
    document = value["documents"][value["probes"][0]["resources"][0]]
    foreign = {"complete": True, "failure": None, "status": 200, "body": {"name": value["probes"][0]["resources"][1], "fields": {}, "updateTime": "2026-01-01T00:00:00.000000Z"}}
    assert not readback_matches(foreign, value["probes"][0]["resources"][0], document["fieldsSha256"], value["nonce"], None)


def test_schedule_mutation_is_rejected():
    value = plan()
    value["executionSchedule"][35], value["executionSchedule"][36] = value["executionSchedule"][36], value["executionSchedule"][35]
    with pytest.raises(ValueError):
        validate_schedule(value)
