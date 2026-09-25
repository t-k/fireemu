"""Shared-Gate adapter for the bounded Commit transform campaign."""

from __future__ import annotations

import copy
import fcntl
import hashlib
import importlib.util
import os
import re
import stat
import sys
import threading
import zipimport
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def _archive_origin() -> tuple[str, str] | None:
    """Bind zip imports to this module's inherited, read-only archive."""
    match = re.fullmatch(r"(/dev/fd/([0-9]+))/gate_adapter\.py", __file__)
    if match is None:
        return None
    archive, number = match.group(1), int(match.group(2))
    info = os.fstat(number)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 0
        or fcntl.fcntl(number, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
    ):
        raise ImportError("untrusted archive descriptor")
    identity = hashlib.sha256(os.pread(number, info.st_size, 0)).hexdigest()
    if archive not in sys.path:
        raise ImportError("archive import root differs")
    return archive, identity


_ARCHIVE = _archive_origin()


def _check_import_origins(expected: dict[str, Path]) -> None:
    """Reject preloaded campaign modules whose source is not canonical."""
    for name, path in expected.items():
        module = sys.modules.get(name)
        if module is None:
            continue
        origin = getattr(module, "__file__", None)
        if _ARCHIVE is not None:
            canonical = f"{_ARCHIVE[0]}/{name}.py"
            valid = (
                path.name == f"{name}.py"
                and origin == canonical
                and _archive_origin() == _ARCHIVE
            )
        else:
            valid = isinstance(origin, str) and Path(origin).resolve() == path.resolve()
        if not valid:
            raise ImportError(f"foreign module origin for {name}")


def _load(name: str, path: Path):
    if _ARCHIVE is not None:
        if _archive_origin() != _ARCHIVE:
            raise ImportError("archive digest changed")
        allowed = {
            ("transform_compiler", HERE / "transform_compiler.py"): "transform_compiler",
            ("_commit_gate_production_bridge", HERE / "commit_production_bridge.py"): "commit_production_bridge",
            ("_commit_gate_limits_bridge", HERE / "production_bridge.py"): "production_bridge",
            ("_commit_credential_preparation", ROOT / "tools/compat-broad/fs-write-txn/credential_prep.py"): "credential_prep",
        }
        member = allowed.get((name, path))
        if member is None:
            raise ImportError(f"unreviewed archive member for {name}")
        importer = zipimport.zipimporter(_ARCHIVE[0])
        code = importer.get_code(member)
        if code is None or code.co_filename != f"{_ARCHIVE[0]}/{member}.py":
            raise ImportError(f"cannot load {name} from archive")
        module = importer.load_module(member)
        if getattr(module, "__file__", None) != code.co_filename:
            raise ImportError(f"foreign module origin for {name}")
        sys.modules[name] = module
        if _archive_origin() != _ARCHIVE:
            raise ImportError("archive digest changed")
        return module
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
from broad_contract import digest
from shared_gate import create

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
_limits_dir = HERE if _ARCHIVE is not None else ROOT / "tools/compat-broad/fs-write-limits"
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
_limits_origins["reservations"] = (
    ROOT / "tools/compat-broad/production-admission/reservations.py"
)
_limits_origins.update(
    {
        name: ROOT / "tools/compat-broad" / f"{name}.py"
        for name in (
            "batch_adapter",
            "batch_contract",
            "batch_pair",
            "broad_cases",
            "broad_contract",
            "shared_cases",
            "shared_gate",
            "shared_production",
            "shared_production_pair",
        )
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
_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$")


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

    def __init__(self, path, plan: dict, *, production_binding=None):
        self.production_binding = copy.deepcopy(production_binding)
        self._commit_permit = None
        self.compiler = copy.deepcopy(plan)
        expected = compiler_plan(plan["project"], plan["database"], plan["nonce"])
        if digest(self.compiler) != digest(expected):
            raise ValueError("compiler plan differs from canonical output")
        super().__init__(path, "commit")
        expected_gate = (
            gate_plan(self.compiler)
            if production_binding is None
            else production_gate_plan(self.compiler, production_binding)
        )
        if digest(self.snapshot()["plan"]) != digest(expected_gate):
            raise ValueError("commit Gate plan binding differs")

    def consume_wire(self, operation, recovery):
        deadline = super().consume_wire(operation, recovery)
        if self.production_binding is not None:
            self._commit_permit = (
                threading.get_ident(),
                digest(operation),
                recovery,
                deadline,
            )
        return deadline

    def consume_commit_permit(self, operation):
        permit, self._commit_permit = self._commit_permit, None
        if permit is None or permit[:2] != (threading.get_ident(), digest(operation)):
            raise ValueError("Commit wire requires the charged collector callback")
        return permit[2:]

    def dispatch(self, operation, recovery, send):
        if self.production_binding is not None and digest(
            self.snapshot()["plan"]
        ) != digest(production_gate_plan(self.compiler, self.production_binding)):
            raise ValueError("reserved Commit plan changed")
        if operation.get("kind") == "commit-transform":
            _commit_bridge.validate_commit_operation(self.compiler, operation)
            resource = operation["resources"][0]
            state = self.snapshot()
            if state["jobs"][self.job]["creationProofs"].get(resource) is None:
                raise ValueError("Commit requires immutable conditional-create proof")
        try:
            return super().dispatch(operation, recovery, send)
        finally:
            self._commit_permit = None

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


def production_cost_model() -> dict:
    """Planning ceilings, not live SKU tariffs; independent owner confirmation required."""
    transfer = 17 * (2 * 1024 * 1024 * 2) + 10 * (16384 + 65536)
    storage = 64 * 1024 * 1024
    fixed = ((transfer + storage) * 1_000_000 + 2**30 - 1) // 2**30
    return {
        "dataCalls": 17,
        "dataRequestBytes": 2 * 1024 * 1024,
        "dataResponseBytes": 2 * 1024 * 1024,
        "managementSlots": 10,
        "managementRequestBytes": 16384,
        "managementResponseBytes": 65536,
        "transferBytesUpper": transfer,
        "storageBytesUpper": storage,
        "storageMonthsUpper": 1,
        "transferMicrousdPerGiB": 1_000_000,
        "storageMicrousdPerGiBMonth": 1_000_000,
        "requestMicrousd": 100,
        "fixedCostMicrousd": fixed,
        "totalCostMicrousd": fixed + 27 * 100,
        "basis": "bounded wire payloads; conservative 64 MiB document/index storage for one month; no free quota",
    }


def production_gate_plan(plan: dict, binding: dict) -> dict:
    """Versioned production allocation; the historical local plan stays unchanged.

    A fresh Coordinator charges two credential acquisition slots and eight
    metadata requests, in addition to the 17 data slots. The derived fixed
    allowance covers bounded storage and response egress; owner tariff
    confirmation remains a separate admission requirement.
    """
    if (
        not isinstance(binding, dict)
        or set(binding) != {"permissionDigest", "collectorSourceDigest"}
        or any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in binding.values()
        )
    ):
        raise ValueError("closed production binding required")
    from shared_production import management

    projected = gate_plan(plan)
    projected.update(
        transport="commit-reserved-production-v1",
        nonce=plan["nonce"],
        **copy.deepcopy(binding),
        observationRequests=17,
        recoverySeconds=180,
        fixedCostMicrousd=production_cost_model()["fixedCostMicrousd"],
        costMicrousd=production_cost_model()["totalCostMicrousd"],
        management={
            "observation": [
                {"id": "oauth-refresh", "duration": 12, "timeout": 13},
                {"id": "oauth-tokeninfo", "duration": 12, "timeout": 13},
            ]
            + management()[2:],
            "recovery": management()[2:],
        },
    )
    return projected


def create_production_commit_gate(path, plan: dict, binding: dict) -> CommitGate:
    projected = production_gate_plan(plan, binding)
    create(path, projected)
    return CommitGate(path, plan, production_binding=binding)
