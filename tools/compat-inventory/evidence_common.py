"""Small deterministic identities and bounded filesystem access for evidence tools."""

import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# This is the frozen source closure for the published aggregation-v1 receipts.
# Keep additions to the tool directory out of historical evidence identities unless
# they are part of this execution path and a new evidence class is reviewed.
AGGREGATION_PROBE_FILES_V1 = (
    "aggregation_corpus.py",
    "aggregation_evidence.py",
    "aggregation_index.py",
    "aggregation_package.py",
    "aggregation_probe.py",
    "aggregation_response.py",
    "auth_probe.py",
    "capture.py",
    "evidence_common.py",
    "owned_runner.py",
    "probe.py",
    "protobuf_inventory.py",
    "publish.py",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def fingerprint(value: object) -> str:
    return sha(canonical(value))


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def read(root: Path, relative: str) -> bytes:
    path = (root / relative).resolve()
    require(
        not Path(relative).is_absolute() and path.is_relative_to(root.resolve()),
        "artifact path escapes evidence root",
    )
    require(path.stat().st_size <= 8 * 1024 * 1024, "artifact exceeds size budget")
    return path.read_bytes()


def save(path: Path, value: dict) -> None:
    data = json.dumps(value, indent=2, allow_nan=False) + "\n"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def runtime_inputs(root: Path) -> dict:
    names = (
        subprocess.check_output(
            [
                "git",
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "Cargo.toml",
                "Cargo.lock",
                "rust-toolchain.toml",
                ".cargo",
                "crates",
            ],
            cwd=root,
        )
        .decode()
        .split("\0")
    )
    result = {name: sha((root / name).read_bytes()) for name in sorted(names) if name}
    require(bool(result), "runtime input set is empty")
    return result


def runtime_inputs_at_commit(commit: str, root: Path = ROOT) -> dict:
    require(
        re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
        "invalid runtime source commit",
    )
    try:
        names = (
            subprocess.check_output(
                [
                    "git",
                    "ls-tree",
                    "-r",
                    "-z",
                    "--name-only",
                    commit,
                    "--",
                    "Cargo.toml",
                    "Cargo.lock",
                    "rust-toolchain.toml",
                    ".cargo",
                    "crates",
                ],
                cwd=root,
            )
            .decode()
            .split("\0")
        )
    except subprocess.CalledProcessError as error:
        raise ValueError("runtime source commit is unavailable") from error
    names = [name for name in names if name]
    require(bool(names), "runtime source commit is empty")
    result = {}
    for name in sorted(names):
        try:
            content = subprocess.check_output(
                ["git", "show", f"{commit}:{name}"],
                cwd=root,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as error:
            raise ValueError("runtime source commit is incomplete") from error
        result[name] = sha(content)
    return result


#: The definition of `binary_inputs`, recorded beside a digest of them so a reader knows which set it describes.
BINARY_INPUTS_SCHEME = "binary-v1"

#: Directories directly under a crate that no build of the crate's library or binary reads: integration tests (and their
#: fixtures), benchmarks, examples and proptest regression files.
_TEST_ONLY_TREES = ("tests", "benches", "examples", "proptest-regressions")
_TEST_ONLY_PATH = re.compile(r"^crates/[^/]+/(?:" + "|".join(_TEST_ONLY_TREES) + r")/")
_INCLUDING = re.compile(
    r"include_str!|include_bytes!|include!|#\[\s*path\s*=|#\[\s*cfg_attr\([^\]]*path\s*="
)


def _binary_input(name: str) -> bool:
    return _TEST_ONLY_PATH.match(name) is None


def binary_inputs(root: Path) -> dict:
    """What a debug build of `fireemu` is made from: the runtime inputs without the test-only trees of the crates (see
    `_TEST_ONLY_TREES`). A change to an integration test cannot change the binary, so it must not move this set; any other
    change to the crates, the manifests, the lock, the toolchain or `.cargo` does. `source_files_including_test_only_trees`
    proves that no source file reaches into the excluded trees."""
    return {name: value for name, value in runtime_inputs(root).items() if _binary_input(name)}


def binary_inputs_at_commit(commit: str, root: Path = ROOT) -> dict:
    return {name: value for name, value in runtime_inputs_at_commit(commit, root).items() if _binary_input(name)}


def source_files_including_test_only_trees(root: Path) -> list:
    """The source files and build scripts of the crates that name a test-only tree in an include macro or a module path: the
    only ways a file of an excluded tree could enter a build. A module path under a `cfg(...)` attribute that names `test`
    is a test build's own and is not reported."""
    found = []
    for name in sorted(runtime_inputs(root)):
        if not _binary_input(name) or not name.endswith(".rs"):
            continue
        lines = (root / name).read_text(errors="replace").splitlines()
        for index, line in enumerate(lines):
            if not _INCLUDING.search(line) or not any(re.search(rf"(?:^|[/\"]){tree}[/\"]", line) for tree in _TEST_ONLY_TREES):
                continue
            gate = [other.strip() for other in lines[max(0, index - 3):index] if other.strip().startswith("#[cfg(")]
            if line.lstrip().startswith("#[") and gate and re.search(r"\btest\b", gate[-1]):
                continue
            found.append(name)
            break
    return found


def _current_commit(root: Path) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()


def runtime_inputs_for_receipt(commit: str, root: Path = ROOT) -> dict:
    if commit == _current_commit(root):
        return runtime_inputs(root)
    return runtime_inputs_at_commit(commit, root)


def _probe_paths(evidence_class: str | None, directory: Path) -> list[Path]:
    if evidence_class is None:
        paths = sorted(directory.glob("*.py"))
        return [path for path in paths if not path.name.startswith("test_")]
    if evidence_class == "aggregation-v1":
        return [directory / name for name in AGGREGATION_PROBE_FILES_V1]
    raise ValueError(f"unknown evidence class: {evidence_class}")


def probe_inputs(
    evidence_class: str | None = None, directory: Path | None = None
) -> dict:
    directory = Path(__file__).parent if directory is None else directory
    paths = _probe_paths(evidence_class, directory)
    require(all(path.is_file() for path in paths), "probe source file is missing")
    return {path.name: sha(path.read_bytes()) for path in paths}


def probe_inputs_at_commit(evidence_class: str, commit: str, root: Path = ROOT) -> dict:
    require(
        re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
        "invalid probe source commit",
    )
    names = [path.name for path in _probe_paths(evidence_class, Path(__file__).parent)]
    result = {}
    for name in names:
        try:
            content = subprocess.check_output(
                ["git", "show", f"{commit}:tools/compat-inventory/{name}"],
                cwd=root,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as error:
            raise ValueError(
                "probe source commit does not contain its closure"
            ) from error
        result[name] = sha(content)
    return result


def probe_inputs_for_receipt(
    evidence_class: str, commit: str, root: Path = ROOT
) -> dict:
    if commit == _current_commit(root):
        return probe_inputs(evidence_class)
    return probe_inputs_at_commit(evidence_class, commit, root)
