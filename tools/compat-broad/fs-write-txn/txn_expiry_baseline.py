"""Pure baseline verification for the fixed transaction sandbox.

The project is source-bound. Its private number comes from the owner permission,
never from a route selector or an unverified response. No transport lives here.
"""

from pathlib import Path

from txn_expiry_plan import PROJECT
from txn_expiry_preflight import _load, preflight

_CORE = _load("_txn_baseline_core", Path(__file__).resolve().parent.parent / "fs-commit-transform-limits/commit_baseline.py")
_POLICY = _CORE.baseline_target(PROJECT)
ROUTES = _CORE.target_routes(_POLICY)
RECORD_KIND = _CORE.RECORD_KIND
PRODUCTION_LOG_ROOTS = _CORE.PRODUCTION_LOG_ROOTS
permission_baseline = _CORE.permission_baseline


def _target(project_number):
    return _CORE.baseline_target(PROJECT, preflight.validate_project_number(project_number))


def baseline_from_record(record_path, *, evidence_root, project_number, production_roots=PRODUCTION_LOG_ROOTS):
    return _CORE.baseline_from_record(record_path, evidence_root=evidence_root, production_roots=production_roots, target=_target(project_number))


def validate_provenance(value):
    return _CORE.validate_provenance(value, target=_POLICY)


def validate_identity(baseline, project_number):
    target = _target(project_number)
    _CORE._derive_target("projectIdentity", baseline.get("projectIdentity", {}), target)
    projection = baseline.get("databaseProjection", {})
    if projection.get("name") != f"projects/{PROJECT}/databases/(default)":
        raise ValueError("baseline database differs from the fixed target")


def validate_permission_baseline(permission, baseline):
    return _CORE.validate_permission_baseline(permission, baseline, target=_target(permission.get("projectNumber")))
