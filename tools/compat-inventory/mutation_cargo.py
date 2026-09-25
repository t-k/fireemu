"""Admit Cargo mutation builds only into marked, disjoint output directories."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from owned_runner import MUTATION_OUTPUT_MARKER as MARKER
from owned_runner import reject_mutation_artifact


def metadata(workspace: Path, env: dict) -> set[Path]:
    result = subprocess.run(
        ["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1"],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    data = json.loads(result.stdout)
    # An older Cargo without build-directory introspection is not admitted.
    return {Path(data[k]).resolve() for k in ("target_directory", "build_directory")}


def overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def admit(normal: Path, mutant: Path, output: Path, args: list[str]) -> dict:
    if not args or args[0] not in {"check", "build", "test", "nextest", "clippy"}:
        raise ValueError(
            "explicit Cargo verification command required; aliases forbidden"
        )
    if any(
        a.startswith(
            ("--config", "--target-dir", "--build-dir", "--manifest-path", "-C", "-Z")
        )
        for a in args
    ):
        raise ValueError("output/configuration overrides are forbidden")
    normal, mutant, output = normal.resolve(), mutant.resolve(), output.resolve()
    if normal == mutant:
        raise ValueError("separate mutation worktree required")
    environment = dict(os.environ)
    # Protect both shell-driven and sanitized owned-runner normal builds.
    clean = {
        k: v
        for k, v in environment.items()
        if k in {"PATH", "HOME", "TMPDIR", "SYSTEMROOT", "LANG", "LC_ALL"}
    }
    protected = metadata(normal, environment) | metadata(normal, clean)
    for directory in protected:
        reject_mutation_artifact(directory)
        if overlaps(output, directory):
            raise ValueError("mutation and normal output directories overlap")
    target, build = output / "target", output / "build"
    environment.update(
        CARGO_TARGET_DIR=str(target),
        CARGO_BUILD_TARGET_DIR=str(target),
        CARGO_BUILD_BUILD_DIR=str(build),
    )
    effective = metadata(mutant, environment)
    if effective != {target, build}:
        raise ValueError("Cargo did not honor both isolated output directories")
    if any(
        overlaps(path, normal_path) for path in effective for normal_path in protected
    ):
        raise ValueError("effective outputs overlap")
    identity = {
        "normalWorkspace": str(normal),
        "mutationWorkspace": str(mutant),
        "outputs": sorted(map(str, effective)),
    }
    marker = output / MARKER
    if (
        output.exists()
        and any(output.iterdir())
        and (not marker.is_file() or json.loads(marker.read_text()) != identity)
    ):
        raise ValueError("nonempty output is not owned by this mutation scope")
    output.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(identity, sort_keys=True) + "\n")
    return environment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normal-workspace", type=Path, required=True)
    parser.add_argument("--mutation-workspace", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("cargo_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.cargo_args[1:] if args.cargo_args[:1] == ["--"] else args.cargo_args
    env = admit(
        args.normal_workspace, args.mutation_workspace, args.output_root, command
    )
    return subprocess.run(
        ["cargo", *command], cwd=args.mutation_workspace, env=env, check=False
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
