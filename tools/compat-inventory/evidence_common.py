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


_TREE_WORDS = "|".join(re.escape(tree) for tree in _TEST_ONLY_TREES)
#: A path or a string that names one of the excluded trees as a path segment (also inside `concat!(env!(...), "/tests/x.rs")` or `"$CARGO_MANIFEST_DIR/tests"`).
_NAMES_TREE = re.compile(rf"(?:^|[/\"'\s])(?:{_TREE_WORDS})(?:[/\"'\s]|$)")
#: An invocation that reads a file or a directory into a build.
_EMBEDDING = re.compile(r"\b(?:include_str|include_bytes|include|include_dir|include_flate|embed_dir|embed_file|embed_str)\s*!\s*[(\[{]")
_PAIRS = {"(": ")", "[": "]", "{": "}"}


def _masked(text: str) -> str:
    """The source with comments and the contents of string and character literals blanked (same length), so brackets can be matched."""
    out, index, size = [], 0, len(text)
    while index < size:
        two = text[index:index + 2]
        if two == "//":
            end = text.find("\n", index)
            end = size if end < 0 else end
            out.append(" " * (end - index))
            index = end
        elif two == "/*":
            end = text.find("*/", index + 2)
            end = size if end < 0 else end + 2
            out.append(re.sub(r"[^\n]", " ", text[index:end]))
            index = end
        elif (raw := re.compile(r'r(#*)"').match(text, index)) and (index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_")):
            close = '"' + raw.group(1)
            end = text.find(close, raw.end())
            end = size if end < 0 else end + len(close)
            out.append(re.sub(r"[^\n]", " ", text[index:end]))
            index = end
        elif text[index] == '"':
            end = index + 1
            while end < size and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            end = min(size, end + 1)
            out.append(re.sub(r"[^\n]", " ", text[index:end]))
            index = end
        elif text[index] == "'" and (char := re.compile(r"'(?:\\.[^']*|[^'\\])'").match(text, index)):
            out.append(" " * (char.end() - index))
            index = char.end()
        else:
            out.append(text[index])
            index += 1
    return "".join(out)


def _closing(masked: str, start: int) -> int:
    """The index just past the bracket that closes the one at `start`, or the end of the text."""
    opener = masked[start]
    depth = 0
    for index in range(start, len(masked)):
        if masked[index] == opener:
            depth += 1
        elif masked[index] == _PAIRS[opener]:
            depth -= 1
            if depth == 0:
                return index + 1
    return len(masked)


def _positive_test_gate(expression: str) -> bool:
    """Whether a `cfg(...)` expression holds only in a test build: `test`, or an `all(...)` with such a term. `not(...)`, `any(...)` and anything else do not."""
    expression = expression.strip()
    if expression == "test":
        return True
    match = re.fullmatch(r"all\s*\((.*)\)", expression, re.S)
    if not match:
        return False
    terms, depth, current = [], 0, ""
    for char in match.group(1):
        if char == "," and depth == 0:
            terms.append(current)
            current = ""
            continue
        depth += (char == "(") - (char == ")")
        current += char
    terms.append(current)
    return any(_positive_test_gate(term) for term in terms)


def _attributes(masked: str) -> list:
    """Every outer attribute as (start, end, text of the cfg expression or None)."""
    found = []
    for match in re.finditer(r"#\s*\[", masked):
        end = _closing(masked, match.end() - 1)
        cfg = re.fullmatch(r"\s*cfg\s*\((.*)\)\s*", masked[match.end():end - 1], re.S)
        found.append((match.start(), end, cfg.group(1) if cfg else None))
    return found


def _test_gated_after(masked: str, attributes: list, position: int) -> bool:
    """Whether the item that starts at `position` is preceded, attribute after attribute with only blanks between, by a positive test gate."""
    cursor = position
    for start, end, cfg in reversed([a for a in attributes if a[1] <= position]):
        if masked[end:cursor].strip():
            break
        if cfg is not None and _positive_test_gate(cfg):
            return True
        cursor = start
    return False


def _test_regions(masked: str, attributes: list) -> list:
    """The spans of the modules (`mod name { ... }`) that a positive test gate precedes."""
    regions = []
    for match in re.finditer(r"\bmod\s+\w+\s*\{", masked):
        if _test_gated_after(masked, attributes, match.start()):
            regions.append((match.start(), _closing(masked, match.end() - 1)))
    return regions


def _reaches_test_tree(text: str) -> bool:
    masked = _masked(text)
    attributes = _attributes(masked)
    regions = _test_regions(masked, attributes)
    spans = []
    for match in _EMBEDDING.finditer(masked):
        spans.append((match.start(), _closing(masked, match.end() - 1)))
    for start, end, _cfg in attributes:
        if re.search(r"\b(?:path|folder)\s*=", masked[start:end]):
            spans.append((start, end))
    for start, end in spans:
        if not _NAMES_TREE.search(text[start:end]):
            continue
        if any(low <= start < high for low, high in regions):
            continue
        if text[start:start + 2] == "#[" or masked[start] == "#":
            # a module path: excused by the positive test gate on the module it names (the attributes just before it, or this attribute's own cfg_attr is not a gate)
            if _test_gated_after(masked, attributes, start) or any(a[0] != start and a[1] <= start and not masked[a[1]:start].strip() and a[2] is not None and _positive_test_gate(a[2]) for a in attributes):
                continue
        return True
    return False


def _manifest_reaches_test_tree(text: str, crate: str) -> bool:
    """Whether a crate manifest points its library, a binary or its build script into an excluded tree (the test, bench and example targets are those trees)."""
    import posixpath
    import tomllib

    try:
        manifest = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return True
    paths = [manifest.get("package", {}).get("build"), manifest.get("lib", {}).get("path")]
    paths += [entry.get("path") for entry in manifest.get("bin", []) if isinstance(entry, dict)]
    for value in paths:
        if isinstance(value, str) and _TEST_ONLY_PATH.match(posixpath.normpath(posixpath.join(crate, value))):
            return True
    return False


def source_files_including_test_only_trees(root: Path) -> list:
    """The bound files that could pull a file of an excluded tree into a build, sorted:
    - sources and build scripts with an include or embedding macro (read across lines) or a module path whose text names an excluded tree, unless a positive test
      gate (`cfg(test)`, `cfg(all(.., test, ..))`; never `not` or `any`) excuses it, on the attribute or on the enclosing module;
    - build scripts that name an excluded tree anywhere (they read files with plain `std::fs`);
    - crate manifests whose library, binary or build-script path lies in an excluded tree."""
    found = []
    for name in sorted(runtime_inputs(root)):
        if not _binary_input(name):
            continue
        text = (root / name).read_text(errors="replace")
        if name.endswith("/build.rs"):
            if _NAMES_TREE.search(text):
                found.append(name)
        elif name.endswith(".rs"):
            if _reaches_test_tree(text):
                found.append(name)
        elif name.endswith("/Cargo.toml") and name.startswith("crates/"):
            if _manifest_reaches_test_tree(text, name.rsplit("/", 1)[0]):
                found.append(name)
    return found


def dependency_info_paths(info: str, root: Path) -> list:
    """The files under `root` that a cargo dependency-info file (`target/debug/fireemu.d`) lists, relative and normalized, sorted: what a build actually read."""
    import posixpath

    listed = info.split(": ", 1)[-1]
    prefix = str(root).rstrip("/") + "/"
    found = set()
    for token in re.split(r"(?<!\\)\s+", listed.strip()):
        token = token.replace("\\ ", " ")
        if token.startswith(prefix):
            found.add(posixpath.normpath(token[len(prefix):]))
    return sorted(found)


def dependency_info_in_test_only_trees(info: str, root: Path) -> list:
    """The listed files that lie in an excluded tree of a crate: a build that read one must not be pinned under `binary_inputs`."""
    return [path for path in dependency_info_paths(info, root) if _TEST_ONLY_PATH.match(path)]


def ui_bundled(root: Path) -> bool:
    """Whether a build in `root` would embed the user interface: `crates/fireemu-adapter-ui/build.rs` bundles `ui/dist` when its entry page exists. The directory is
    git-ignored build output that neither input definition binds, so a build that is to be pinned must be made without it."""
    return (root / "ui" / "dist" / "index.html").is_file()


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
