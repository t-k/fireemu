"""Real shared-Gate lifecycle tests for the Commit adapter."""

from __future__ import annotations

import copy
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from gate_adapter import compiler_plan, create_commit_gate
from shared_gate import Gate


def _run_observation(gate, plan, *, accepted_over=False):
    proofs = {}
    versions = {}
    for operation in plan["observation"]:
        kind = operation["kind"]
        resource = operation.get("resource")
        if kind == "commit-transform":
            resource = operation["resources"][0]
        if kind == "preflight-typed-absence":
            result = (404, {"error": {"code": 404, "status": "NOT_FOUND"}})
        elif kind == "create-only-patch":
            version = "2026-01-01T00:00:00Z"
            result = (
                200,
                {"name": resource, "fields": operation["body"]["fields"], "updateTime": version},
            )
            proofs[resource] = copy.deepcopy(result[1])
            versions[resource] = version
        elif kind == "commit-transform":
            if resource.endswith("over-501") and accepted_over:
                result = (200, {"writeResults": [], "commitTime": "2026-01-01T00:00:01Z"})
            else:
                result = (400, {"error": {"status": "INVALID_ARGUMENT"}})
        else:
            result = (
                200,
                {
                    "name": resource,
                    "fields": {"_sharedOwner": {"referenceValue": resource}},
                    "updateTime": versions[resource],
                },
            )
        gate.dispatch(operation, False, lambda result=result: result)
    return proofs, versions


def _run_recovery(gate, plan, versions, *, foreign=False):
    for operation in plan["recovery"]:
        kind = operation["kind"]
        resource = operation["resource"]
        if kind == "cleanup-ownership-read":
            marker = "foreign" if foreign else resource
            result = (
                200,
                {
                    "name": resource,
                    "fields": {"_sharedOwner": {"referenceValue": marker}},
                    "updateTime": versions[resource],
                },
            )
            gate.dispatch(operation, True, lambda result=result: result)
        elif kind == "cleanup-conditional-delete":
            resolved = dict(operation)
            resolved.pop("versionFrom")
            resolved["path"] += "?currentDocument.updateTime=" + versions[resource].replace(
                ":", "%3A"
            )
            gate.dispatch(resolved, True, lambda: (200, {}))
        else:
            gate.dispatch(
                operation,
                True,
                lambda: (404, {"error": {"code": 404, "status": "NOT_FOUND"}}),
            )


def test_commit_gate_cleans_unexpectedly_accepted_transform_and_preserves_creation_proof(tmp_path):
    plan = compiler_plan("demo", "(default)", "a" * 32)
    gate = create_commit_gate(tmp_path / "gate", plan)
    gate.claim()
    proofs, versions = _run_observation(gate, plan, accepted_over=True)
    state = gate.snapshot()
    original = copy.deepcopy(state["jobs"]["commit"]["creationProofs"])
    assert set(original) == set(proofs)
    _run_recovery(gate, plan, versions)
    gate.finish()
    assert gate.snapshot()["jobs"]["commit"]["creationProofs"] == original
    assert gate.snapshot()["total"] == 17


def test_commit_gate_rejects_foreign_marker_before_delete_callback(tmp_path):
    plan = compiler_plan("demo", "(default)", "b" * 32)
    gate = create_commit_gate(tmp_path / "gate", plan)
    gate.claim()
    _, versions = _run_observation(gate, plan)
    read = plan["recovery"][0]
    gate.dispatch(
        read,
        True,
        lambda: (
            200,
            {
                "name": read["resource"],
                "fields": {"_sharedOwner": {"referenceValue": "foreign"}},
                "updateTime": versions[read["resource"]],
            },
        ),
    )
    delete = dict(plan["recovery"][1])
    delete.pop("versionFrom")
    delete["path"] += "?currentDocument.updateTime=" + versions[read["resource"]].replace(
        ":", "%3A"
    )
    called = []
    with pytest.raises(ValueError, match="ownership marker"):
        gate.dispatch(delete, True, lambda: called.append(True))
    assert called == []


@pytest.mark.parametrize("marker", [["referenceValue"], {}, {"referenceValue": "x", "extra": "y"}])
def test_commit_gate_records_malformed_marker_as_invalid_proof(tmp_path, marker):
    plan = compiler_plan("demo", "(default)", "c" * 32)
    gate = create_commit_gate(tmp_path / "gate", plan)
    gate.claim()
    _, versions = _run_observation(gate, plan)
    read = plan["recovery"][0]
    gate.dispatch(
        read,
        True,
        lambda: (
            200,
            {
                "name": read["resource"],
                "fields": {"_sharedOwner": marker},
                "updateTime": versions[read["resource"]],
            },
        ),
    )
    capture = gate.snapshot()["jobs"]["commit"]["captures"]["0"]
    assert capture["ownerMarker"] is None
    delete = dict(plan["recovery"][1])
    delete.pop("versionFrom")
    delete["path"] += "?currentDocument.updateTime=" + versions[read["resource"]].replace(
        ":", "%3A"
    )
    with pytest.raises(ValueError, match="ownership marker"):
        gate.dispatch(delete, True, lambda: pytest.fail("unsafe delete callback"))


def test_commit_gate_rejects_noncanonical_ownership_timestamp(tmp_path):
    plan = compiler_plan("demo", "(default)", "d" * 32)
    gate = create_commit_gate(tmp_path / "gate", plan)
    gate.claim()
    _run_observation(gate, plan)
    read = plan["recovery"][0]
    invalid = "2026-01-01"
    gate.dispatch(
        read,
        True,
        lambda: (
            200,
            {
                "name": read["resource"],
                "fields": {"_sharedOwner": {"referenceValue": read["resource"]}},
                "updateTime": invalid,
            },
        ),
    )
    delete = dict(plan["recovery"][1])
    delete.pop("versionFrom")
    delete["path"] += "?currentDocument.updateTime=" + invalid
    with pytest.raises(ValueError, match="ownership marker"):
        gate.dispatch(delete, True, lambda: pytest.fail("unsafe delete callback"))


def test_default_gate_still_rejects_changed_creation_fields(tmp_path):
    gate = Gate.__new__(Gate)
    operation = {"method": "DELETE", "path": "/v1/a?currentDocument.updateTime=old"}
    job = {"creationProofs": {"a": {"fieldsDigest": "created", "updateTime": "old"}}, "captures": {"0": {"name": "a", "fieldsDigest": "changed"}}}
    with pytest.raises(ValueError):
        gate._validate_cleanup_ownership(operation, True, "a", 0, job)


@pytest.mark.parametrize(
    "foreign_name",
    [
        "remote_transport",
        "batch_adapter",
        "batch_contract",
        "batch_pair",
        "broad_cases",
        "broad_contract",
        "shared_cases",
        "shared_gate",
        "shared_production",
        "shared_production_pair",
    ],
)
def test_foreign_limits_module_is_rejected_before_adapter_import(tmp_path, foreign_name):
    script = """
import sys, types
from pathlib import Path
here = Path(sys.argv[1])
foreign_name = sys.argv[3]
foreign = types.ModuleType(foreign_name)
foreign.__file__ = str(Path(sys.argv[2]) / (foreign_name + '.py'))
sys.modules[foreign_name] = foreign
sys.path.insert(0, str(here.parent))
sys.path.insert(0, str(here))
try:
    import gate_adapter
except ImportError as error:
    if 'foreign module origin' not in str(error):
        raise
else:
    raise AssertionError('foreign module was accepted')
"""
    foreign_root = tmp_path / "foreign"
    foreign_root.mkdir()
    result = subprocess.run(
        [sys.executable, "-c", script, str(HERE), str(foreign_root), foreign_name],
        cwd=HERE.parent.parent.parent,
        env={**os.environ, "PYTHONPATH": str(HERE.parent)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
