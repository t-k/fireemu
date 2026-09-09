"""Small deterministic identities and bounded filesystem access for evidence tools."""

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


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


def probe_inputs() -> dict:
    directory = Path(__file__).parent
    return {
        p.name: sha(p.read_bytes())
        for p in sorted(directory.glob("*.py"))
        if not p.name.startswith("test_")
    }
