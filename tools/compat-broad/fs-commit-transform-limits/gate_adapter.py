"""Shared-Gate adapter for the bounded Commit transform campaign."""

from __future__ import annotations

import copy
import importlib.util
import sys
import types
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from broad_contract import digest
from shared_gate import create

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_compiler = _load("_commit_gate_transform_compiler", HERE / "transform_compiler.py")
_commit_bridge = _load(
    "_commit_gate_production_bridge", HERE / "production_bridge.py"
)

# The existing LimitsGate supplies the one charged callback and consume_wire
# boundary. Load it by path because another campaign has a production_bridge.
_limits_dir = ROOT / "tools/compat-broad/fs-write-limits"
for _path in (str(_limits_dir),):
    if _path not in sys.path:
        sys.path.insert(0, _path)
# The bridge's transport module is intentionally not part of this adapter. A
# tiny import stub keeps loading the already-reviewed Gate subclass independent
# of the transport runtime (and its newer Python-only dependencies).
_transport_stub = types.ModuleType("remote_transport")
_transport_stub.prepare = lambda value: value
_transport_stub.request = lambda value: value
sys.modules.setdefault("remote_transport", _transport_stub)
_limits_bridge = _load(
    "_commit_gate_limits_bridge", _limits_dir / "production_bridge.py"
)
LimitsGate = _limits_bridge.LimitsGate


def compiler_plan(project: str, database: str, nonce: str) -> dict:
    return _compiler.compile_plan(project, database, nonce)


def gate_plan(plan: dict) -> dict:
    """Project the immutable compiler output into the shared Gate schema."""
    canonical = compiler_plan(plan["project"], plan["database"], plan["nonce"])
    if digest(plan) != digest(canonical):
        raise ValueError("compiler plan differs from canonical output")
    observation = [copy.deepcopy(item) for item in plan["observation"]]
    recovery = [copy.deepcopy(item) for item in plan["recovery"]]
    resources = copy.deepcopy(plan["ownedResources"])
    return {
        "contract": "shared-local-v2",
        "wallSeconds": 1200,
        "recoverySeconds": 120,
        "observationRequests": len(observation),
        "costMicrousd": 1700,
        "requestCostMicrousd": 100,
        "intervalSeconds": 0.25,
        "jobs": {
            "commit": {
                "resources": resources,
                "observation": observation,
                "recovery": recovery,
            }
        },
    }


class CommitGate(LimitsGate):
    """LimitsGate with mutation-aware, current-version cleanup authority."""

    def __init__(self, path, plan: dict):
        self.compiler = copy.deepcopy(plan)
        expected = compiler_plan(plan["project"], plan["database"], plan["nonce"])
        if digest(self.compiler) != digest(expected):
            raise ValueError("compiler plan differs from canonical output")
        super().__init__(path, "commit")
        if digest(self.snapshot()["plan"]) != digest(gate_plan(self.compiler)):
            raise ValueError("commit Gate plan binding differs")

    def dispatch(self, operation, recovery, send):
        if operation.get("kind") == "commit-transform":
            _commit_bridge.validate_commit_operation(self.compiler, operation)
            resource = operation["resources"][0]
            state = self.snapshot()
            if state["jobs"][self.job]["creationProofs"].get(resource) is None:
                raise ValueError("Commit requires immutable conditional-create proof")
        return super().dispatch(operation, recovery, send)

    def _recovery_capture(self, operation, status, body):
        capture = super()._recovery_capture(operation, status, body)
        marker = None
        fields = body.get("fields") if isinstance(body, dict) else None
        if isinstance(fields, dict) and fields.get("_sharedOwner") is not None:
            owner = fields["_sharedOwner"]
            if set(owner) == {"referenceValue"} and isinstance(
                owner["referenceValue"], str
            ):
                marker = {"referenceValue": owner["referenceValue"]}
        capture["ownerMarker"] = marker
        return capture

    def _validate_cleanup_ownership(self, operation, recovery, resource, source, job):
        if not recovery or operation.get("method") != "DELETE":
            raise ValueError("cleanup requires Commit recovery delete")
        if source not in (0, 3) or resource not in job["resources"]:
            raise ValueError("cleanup ownership read source differs")
        proof = job.get("creationProofs", {}).get(resource)
        capture = job["captures"].get(str(source))
        if proof is None or not isinstance(capture, dict):
            raise ValueError("cleanup requires immutable conditional-create proof")
        if (
            capture.get("status") != 200
            or capture.get("name") != resource
            or capture.get("ownerMarker") != {"referenceValue": resource}
            or not isinstance(capture.get("updateTime"), str)
        ):
            raise ValueError("current Commit ownership marker required")
        version = capture["updateTime"]
        try:
            datetime.fromisoformat(version.replace("Z", "+00:00"))
        except (TypeError, ValueError) as error:
            raise ValueError("invalid current ownership version") from error
        expected = copy.deepcopy(self.compiler["recovery"][source + 1])
        if expected.pop("versionFrom", None) != source:
            raise ValueError("Commit recovery source differs")
        expected["path"] += "?currentDocument.updateTime=" + quote(version, safe="")
        if digest(operation) != digest(expected):
            raise ValueError("cleanup operation differs from compiler target")


def create_commit_gate(path, plan: dict) -> CommitGate:
    """Create and bind the fixed Gate state for a compiler plan."""
    created = gate_plan(plan)
    create(path, created)
    return CommitGate(path, plan)
