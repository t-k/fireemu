import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from commit_production import collect_commit
from gate_adapter import compiler_plan, create_commit_gate


def test_collector_charges_all_observation_and_recovery_operations(tmp_path):
    plan = compiler_plan("demo", "(default)", "a" * 32)
    gate = create_commit_gate(tmp_path / "gate", plan)
    gate.claim()
    stored = {}
    sent = []

    def transmit(operation):
        sent.append(copy.deepcopy(operation))
        resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
        if operation["method"] == "PATCH":
            body = {**operation["body"], "updateTime": "2026-01-01T00:00:00Z"}
            stored[resource] = body
            return {"complete": True, "failure": None, "status": 200, "body": body}
        if operation["method"] == "POST":
            if operation["expect"]["outcome"] == "refused":
                return {
                    "complete": True,
                    "failure": None,
                    "status": 400,
                    "body": {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
                }
            return {"complete": True, "failure": None, "status": 200, "body": {}}
        if operation["method"] == "DELETE":
            stored.pop(resource, None)
            return {"complete": True, "failure": None, "status": 200, "body": {}}
        if resource in stored:
            return {"complete": True, "failure": None, "status": 200, "body": stored[resource]}
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    result = collect_commit(gate, plan, tmp_path / "receipt", transmit=transmit)

    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is True
    assert len(result["rows"]) == 11
    assert len(result["cleanup"]) == 6
    assert len(sent) == 17
    assert gate.snapshot()["total"] == 17
    assert json.loads((tmp_path / "receipt" / "collection.json").read_text())["collectionComplete"] is True


def test_incomplete_wire_stops_observation_and_does_not_send_unsafe_delete(tmp_path):
    plan = compiler_plan("demo", "(default)", "b" * 32)
    gate = create_commit_gate(tmp_path / "gate", plan)
    gate.claim()
    sent = []

    def transmit(operation):
        sent.append(operation)
        if operation["kind"] == "commit-transform":
            return {"complete": False, "failure": "timeout"}
        if operation["method"] == "PATCH":
            return {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {
                    **operation["body"],
                    "updateTime": "2026-01-01T00:00:00Z",
                },
            }
        return {"complete": True, "failure": None, "status": 404, "body": {"error": {"code": 404, "status": "NOT_FOUND"}}}

    result = collect_commit(gate, plan, tmp_path / "receipt", transmit=transmit)

    assert result["recordingComplete"] is False
    assert not any(operation["method"] == "DELETE" for operation in sent)
