"""Candidate input collector; callers must supply fresh, complete compiler dep-info."""

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

_TEST_TREES = {"tests", "benches", "examples", "proptest-regressions"}


def _make_dependencies(text):
    if not isinstance(text, str) or not text.strip() or "\0" in text:
        raise ValueError("dep-info is empty or malformed")
    logical_lines = re.sub(r"\\\r?\n", " ", text).splitlines()
    dependencies = []
    for line in logical_lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        escaped = False
        colon = None
        for index, char in enumerate(line):
            if char == ":" and not escaped:
                colon = index
                break
            if char == "\\" and not escaped:
                escaped = True
            else:
                escaped = False
        if colon is None or not line[:colon].strip():
            raise ValueError("dep-info contains a malformed rule")
        token, escaped = [], False
        for char in line[colon + 1:]:
            if char.isspace() and not escaped:
                if token:
                    dependencies.append("".join(token))
                    token.clear()
            elif char == "\\" and not escaped:
                escaped = True
            else:
                token.append(char)
                escaped = False
        if escaped:
            raise ValueError("dep-info ends with an escape")
        if token:
            dependencies.append("".join(token))
    if not dependencies:
        raise ValueError("dep-info has no dependencies")
    return dependencies


def _is_registry(path):
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
    return path.is_relative_to(cargo_home / "registry")


def _is_test_tree(path):
    return bool(path.parts and path.parts[0] in _TEST_TREES)


def txn_binary_inputs(root, dep_info):
    """Return candidate SHA256 inputs; fresh complete clean-build dep-info cannot be proven here or accepted by the current artifact.

    Cargo metadata does not resolve selected features or target predicates, so every declared local normal/build edge is included, even when optional or target-inactive; packages with build scripts or proc macros bind their full inventoried package contents.
    """
    root = Path(root).resolve(strict=True)
    for required in (root / "Cargo.toml", root / "Cargo.lock"):
        if not required.is_file() or required.is_symlink():
            raise ValueError(f"required Cargo input is missing or unsafe: {required.name}")
    try:
        metadata = json.loads(subprocess.run(
            ["cargo", "metadata", "--no-deps", "--offline", "--locked", "--format-version", "1", "--manifest-path", str(root / "Cargo.toml")],
            cwd=root, check=True, capture_output=True, text=True,
        ).stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        raise ValueError("Cargo metadata is unavailable") from error
    if Path(metadata.get("workspace_root", "")).resolve() != root:
        raise ValueError("Cargo metadata workspace root differs")
    packages = {package["id"]: package for package in metadata.get("packages", [])}
    workspace = set(metadata.get("workspace_members", []))
    by_name = {}
    for package_id in workspace:
        package = packages.get(package_id)
        if package:
            by_name.setdefault(package["name"], []).append(package_id)
    roots = [package_id for package_id in workspace if packages.get(package_id, {}).get("name") == "fireemu"]
    if len(roots) != 1:
        raise ValueError("workspace must contain one fireemu package")
    reachable, pending = set(), roots[:]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        package = packages.get(package_id)
        if package is None:
            raise ValueError("reachable package metadata is missing")
        reachable.add(package_id)
        for dependency in package.get("dependencies", []):
            if dependency.get("kind") == "dev":
                continue
            if dependency.get("path"):
                path = Path(dependency["path"]).resolve()
                if not path.is_relative_to(root):
                    raise ValueError("local path dependency is outside the workspace")
                matches = [candidate for candidate in by_name.get(dependency["name"], [])
                           if Path(packages[candidate]["manifest_path"]).resolve().parent == path]
                if len(matches) != 1:
                    raise ValueError("local path dependency is missing or ambiguous in workspace metadata")
                pending.extend(matches)
    package_roots = {}
    build_sensitive = set()
    for package_id in reachable:
        package = packages[package_id]
        package_root = Path(package["manifest_path"]).resolve().parent
        if not package_root.is_relative_to(root):
            raise ValueError("reachable package is outside the workspace")
        package_roots[package_root] = package
        if package.get("targets") and any(target.get("kind") == ["proc-macro"] for target in package["targets"]):
            build_sensitive.add(package_root)
        if package.get("targets") and any(target.get("kind") == ["custom-build"] for target in package["targets"]):
            build_sensitive.add(package_root)
    # Cargo's package inventory avoids binding ignored caches, local credentials, and target output.
    try:
        files = subprocess.check_output(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root
        ).decode().split("\0")
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("workspace file inventory is unavailable") from error
    files = [name for name in files if name]
    names = set()
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml"):
        if (root / name).is_file():
            names.add(name)
    cargo_dir = root / ".cargo"
    if cargo_dir.is_dir():
        names.update(name for name in files if name.startswith(".cargo/"))
    for package_root, package in package_roots.items():
        names.add((package_root / "Cargo.toml").relative_to(root).as_posix())
        prefix = package_root.relative_to(root).as_posix() + "/"
        for name in files:
            if not name.startswith(prefix):
                continue
            path = root / name
            if path.is_symlink():
                raise ValueError("symlink package input is unsupported")
            relative = Path(name).relative_to(package_root.relative_to(root))
            if package_root not in build_sensitive and _is_test_tree(relative):
                continue
            if path.is_file() and (path.suffix != ".rs" or package_root in build_sensitive):
                names.add(name)
    binary_targets = [target for target in packages[roots[0]].get("targets", [])
                      if target.get("name") == "fireemu" and "bin" in target.get("kind", [])]
    if len(binary_targets) != 1:
        raise ValueError("fireemu binary target metadata is missing or ambiguous")
    main = Path(binary_targets[0]["src_path"]).resolve()
    if not main.is_relative_to(root) or main.is_symlink() or not main.is_file():
        raise ValueError("fireemu binary main is missing or unsafe")
    dependency_names = set()
    target_directory = Path(metadata.get("target_directory", root / "target")).resolve()
    for raw in _make_dependencies(dep_info):
        path = Path(raw)
        path = (root / path).resolve() if not path.is_absolute() else path.resolve()
        if path.is_relative_to(target_directory):
            continue
        if not path.is_relative_to(root):
            if _is_registry(path):
                continue
            raise ValueError("dep-info path is outside the workspace")
        if not path.is_file():
            raise ValueError("dep-info input is missing")
        relative_name = path.relative_to(root).as_posix()
        dependency_names.add(relative_name)
        names.add(relative_name)
    if main.relative_to(root).as_posix() not in dependency_names:
        raise ValueError("dep-info does not include fireemu binary main")
    for name in names:
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("candidate input is unsafe or outside the workspace")
    if not names:
        raise ValueError("candidate input set is empty")
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(names)}
