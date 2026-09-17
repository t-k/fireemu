"""Shared-Gate adapter for the bounded Commit transform campaign."""

from __future__ import annotations

import copy
import importlib.util
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def _check_import_origins(expected: dict[str, Path]) -> None:
    """Reject preloaded campaign modules whose source is not canonical."""
    for name, path in expected.items():
        module = sys.modules.get(name)
        if module is None:
            continue
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str) or Path(origin).resolve() != path.resolve():
            raise ImportError(f"foreign module origin for {name}")


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_check_import_origins(
    {
        "broad_contract": ROOT / "tools/compat-broad/broad_contract.py",
        "shared_gate": ROOT / "tools/compat-broad/shared_gate.py",
    }
)
from broad_contract import digest  # noqa: E402
from shared_gate import create  # noqa: E402


_compiler_path = HERE / "transform_compiler.py"
_check_import_origins({"transform_compiler": _compiler_path})
if "transform_compiler" in sys.modules:
    _compiler = sys.modules["transform_compiler"]
else:
    _compiler = _load("transform_compiler", _compiler_path)
_commit_bridge = _load(
    "_commit_gate_production_bridge", HERE / "commit_production_bridge.py"
)

# The existing LimitsGate supplies the one charged callback and consume_wire
# boundary. Load it by path because another campaign has a production_bridge.
_limits_dir = ROOT / "tools/compat-broad/fs-write-limits"
_limits_origins = {
    name: _limits_dir / filename
    for name, filename in {
        "production_plan": "production_plan.py",
        "remote_transport": "remote_transport.py",
        "shadow": "shadow.py",
        "compiler": "compiler.py",
        "transport": "transport.py",
}.items()
}
_limits_origins["reservations"] = ROOT / "tools/compat-broad/production-admission/reservations.py"
_limits_origins.update(
    {
        name: ROOT / "tools/compat-broad" / f"{name}.py"
        for name in ("batch_adapter", "broad_contract", "shared_production")
    }
)
_check_import_origins(_limits_origins)
for _path in (str(_limits_dir),):
    if _path not in sys.path:
        sys.path.insert(0, _path)
_limits_bridge = _load(
    "_commit_gate_limits_bridge", _limits_dir / "production_bridge.py"
)
_check_import_origins(_limits_origins)
LimitsGate = _limits_bridge.LimitsGate
_TIMESTAMP = re.compile(
    r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$"
)


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
        resource = operation["path"].split("?", 1)[0].removeprefix("/v1/")
        if isinstance(fields, dict) and fields.get("_sharedOwner") is not None:
            owner = fields["_sharedOwner"]
            if (
                isinstance(owner, dict)
                and set(owner) == {"referenceValue"}
                and owner["referenceValue"] == resource
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
            or _TIMESTAMP.fullmatch(capture.get("updateTime", "")) is None
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
