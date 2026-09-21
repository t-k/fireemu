"""Process-level plumbing: the single-inference lock, the result cache and
atomic creation of new output files."""

from __future__ import annotations

import fcntl
import json
import os
import re
from pathlib import Path

CACHE_KEY = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_STATE_DIR = Path.home() / ".cache" / "fireemu-local-assist"


class OutputError(ValueError):
    """The output path cannot be used; nothing was written."""


class InferenceLock:
    """A non-blocking flock; the second holder is told to report busy."""

    def __init__(self, state_dir: Path):
        self.path = state_dir / "inference.lock"
        self._handle = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.path, "a+")  # noqa: SIM115 - held until release()
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False
        self._handle = handle
        return True

    def release(self) -> None:
        if self._handle is None:
            return
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None


def cache_path(state_dir: Path, key: str) -> Path:
    if not CACHE_KEY.match(key):
        raise ValueError("cache key must be a sha256 hex digest")
    return state_dir / "cache" / f"{key}.json"


def cache_get(state_dir: Path, key: str) -> dict | None:
    path = cache_path(state_dir, key)
    try:
        with open(path, "rb") as handle:
            entry = json.loads(handle.read().decode("utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return None
    if not isinstance(entry, dict) or entry.get("cacheKey") != key:
        return None
    return entry


def cache_put(state_dir: Path, key: str, entry: dict) -> None:
    path = cache_path(state_dir, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {**entry, "cacheKey": key}, ensure_ascii=False, indent=2
    ).encode("utf-8")
    temp = path.with_name(path.name + f".tmp-{os.getpid()}")
    with open(temp, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def check_new_output_path(output: str) -> Path:
    path = Path(output)
    if not path.is_absolute():
        raise OutputError("output must be an absolute path")
    if "\x00" in output:
        raise OutputError("output path contains a NUL byte")
    if path.exists() or path.is_symlink():
        raise OutputError(f"output {output} already exists; refusing to overwrite")
    if not path.parent.is_dir():
        raise OutputError(f"output directory {path.parent} does not exist")
    return path


def write_new_file(path: Path, payload: bytes) -> None:
    """Create `path` atomically; fail if anything appears there first."""
    temp = path.with_name(path.name + f".tmp-{os.getpid()}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp, path)
        except FileExistsError:
            raise OutputError(f"output {path} already exists; refusing to overwrite")
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass
