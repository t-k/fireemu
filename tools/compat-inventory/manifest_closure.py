"""Test-only helper: the transitive top-level in-repo import closure of some entry
modules. Test infrastructure, imported by publication tests, never by a recorder or
publisher, so it is not itself an execution dependency of any receipt."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# The tool directories the recorders and owned runners put on sys.path.
SEARCH_DIRS = [
    ROOT / "tools/auth-mfa-start-disabled",
    ROOT / "tools/auth-pending-lifetime",
    ROOT / "tools/auth-pending-lifetime-boundary",
    ROOT / "tools/auth-pending-triggers",
    ROOT / "tools/auth-pending-revocation",
    ROOT / "tools/auth-password-maximum",
    ROOT / "tools/compat-inventory",
]


def _module_file(name: str) -> Path | None:
    for directory in SEARCH_DIRS:
        candidate = directory / (name + ".py")
        if candidate.is_file():
            return candidate
    return None


def _top_level_imported_modules(path: Path) -> set[str]:
    """First-segment module names imported at MODULE LEVEL. Imports nested inside a
    function are lazy and not loaded when the module is imported, so they are not part of
    the import-time execution closure; a lazily-imported module reached only through a
    function the observed path never calls is correctly excluded."""
    names: set[str] = set()
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def in_repo_closure(entry_paths: list[Path]) -> set[str]:
    """Repo-relative paths of every in-repo module reachable through module-level
    imports from the entry modules (the entry modules themselves included)."""
    seen: set[Path] = set()
    stack = [p.resolve() for p in entry_paths]
    while stack:
        path = stack.pop()
        if path in seen:
            continue
        seen.add(path)
        for name in _top_level_imported_modules(path):
            found = _module_file(name)
            if found and found.resolve() not in seen:
                stack.append(found.resolve())
    return {str(p.relative_to(ROOT)) for p in seen}
