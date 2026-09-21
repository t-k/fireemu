"""Independent source and artifact provenance for the next MFA campaign.

The earlier review found that the preparation comparator accepted any 40-character
commit and any 64-character artifact digest a caller supplied, so the binding proved
nothing. This module removes the caller from the trust path: a receipt's binding is
accepted only when this process recomputes the same digests from the checked-out
worktree it is running in. A forged or stale binding therefore fails verification
instead of unlocking a semantic comparison.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

SCHEMA = "o2-mfa-provenance-v1"
_HEX = "0123456789abcdef"

_PACKAGE = "tools/compat-broad/auth-totp-enroll"

# The inputs whose bytes decide what a run means. This is every non-test module in the
# package, not a hand-picked subset: the case list decides what is intended, the recorder
# decides which requests are actually sent and what lands in a row, the collector sequences
# them, the comparator judges the result, and the lockfiles pin the environment. Binding
# the case list without the recorder would prove which observations were planned while
# leaving the program that made them free to differ.
BOUND_PATHS: tuple[str, ...] = (
    f"{_PACKAGE}/mfa_admission.py",
    f"{_PACKAGE}/mfa_cases.py",
    f"{_PACKAGE}/mfa_collector.py",
    f"{_PACKAGE}/mfa_comparator.py",
    f"{_PACKAGE}/mfa_config_lock.py",
    f"{_PACKAGE}/mfa_descriptor.py",
    f"{_PACKAGE}/mfa_gate.py",
    f"{_PACKAGE}/mfa_local_shadow.py",
    f"{_PACKAGE}/mfa_manifest.py",
    f"{_PACKAGE}/mfa_o8.py",
    f"{_PACKAGE}/mfa_production.py",
    f"{_PACKAGE}/mfa_production_transport.py",
    f"{_PACKAGE}/mfa_provenance.py",
    f"{_PACKAGE}/mfa_timing.py",
    f"{_PACKAGE}/mfa_totp.py",
    f"{_PACKAGE}/mfa_walk.py",
    f"{_PACKAGE}/mfa_wire.py",
    f"{_PACKAGE}/mfa_persistence.py",
    f"{_PACKAGE}/mfa_request_budget.py",
    "tools/compat-broad/batch_wire.py",
    # The production session spawns the shared wire worker through this adapter and
    # verifies the bearer through this credential module; both decide which bytes
    # reach the service, so both are bound.
    "tools/compat-broad/batch_adapter.py",
    "tools/compat-broad/fs-write-txn/credential_prep.py",
    "tools/compat-inventory/pyproject.toml",
    "tools/compat-inventory/uv.lock",
)


def unbound_package_modules(root: Path) -> list[str]:
    """Return package modules that issue or shape observations but are not bound."""
    package = Path(root) / _PACKAGE
    if not package.is_dir():
        return []
    return sorted(
        f"{_PACKAGE}/{path.name}"
        for path in package.glob("*.py")
        if not path.name.startswith(("test_", "conftest", "totp_"))
        and f"{_PACKAGE}/{path.name}" not in BOUND_PATHS
    )


class ProvenanceError(RuntimeError):
    """Raised when the bound inputs cannot be read from the worktree."""


def repository_root() -> Path:
    """Return the repository root that contains this file."""
    return Path(__file__).resolve().parents[3]


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def file_digest(path: Path) -> str:
    """Return the SHA-256 of one file's bytes."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compute_provenance(root: Path) -> dict[str, Any]:
    """Recompute the bound-input digests from `root`, refusing an incomplete tree."""
    root = Path(root)
    paths: dict[str, str] = {}
    missing: list[str] = []
    for relative in BOUND_PATHS:
        candidate = root / relative
        if not candidate.is_file():
            missing.append(relative)
            continue
        paths[relative] = file_digest(candidate)
    if missing:
        raise ProvenanceError(f"missing bound inputs: {', '.join(sorted(missing))}")
    return {
        "schema": SCHEMA,
        "evidence": "recomputed-from-worktree",
        "paths": paths,
        "digest": hashlib.sha256(_canonical(paths)).hexdigest(),
    }


def verify_binding(record: Any, root: Path) -> bool:
    """Return True only when `record` equals the provenance recomputed from `root`."""
    if not isinstance(record, dict):
        return False
    try:
        truth = compute_provenance(root)
    except ProvenanceError:
        return False
    if record.get("schema") != SCHEMA or record.get("evidence") != truth["evidence"]:
        return False
    paths = record.get("paths")
    if not isinstance(paths, dict) or paths != truth["paths"]:
        return False
    digest = record.get("digest")
    return isinstance(digest, str) and digest == truth["digest"]


def _git(root: Path) -> Callable[[list[str]], str]:
    def runner(arguments: list[str]) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            text=True,
            capture_output=True,
            timeout=30,
        )
        return completed.stdout

    return runner


def describe_worktree(
    root: Path, runner: Callable[[list[str]], str] | None = None
) -> dict[str, Any]:
    """Report the commit the bound inputs were read at and whether the tree was clean."""
    execute = runner if runner is not None else _git(Path(root))
    try:
        commit = execute(["rev-parse", "HEAD"]).strip()
        status = execute(["status", "--porcelain"])
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "clean": False, "resolved": False}
    if len(commit) != 40 or any(character not in _HEX for character in commit):
        return {"commit": None, "clean": False, "resolved": False}
    return {"commit": commit, "clean": status.strip() == "", "resolved": True}
