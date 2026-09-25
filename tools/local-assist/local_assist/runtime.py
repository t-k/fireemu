"""Process-level plumbing: the single-inference lock with its persistent
in-flight marker, the result cache and atomic creation of new output files.

The flock only lives as long as the process. The marker file outlives it:
it is written before a request is sent and removed only once the server has
fully answered. A run that times out (or loses the connection mid-reply)
leaves it in place, so later runs refuse with `server-state-unknown` until
an operator has confirmed the server is idle and cleared it explicitly.
"""

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


class LockBusy(RuntimeError):
    """Another local-assist process holds the inference lock right now."""


class InferenceLock:
    """A non-blocking flock; the second holder is told to report busy."""

    def __init__(self, state_dir: Path):
        self.path = state_dir / "inference.lock"
        self.marker = state_dir / "inflight.json"
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

    def inflight(self) -> dict | None:
        """The record of an unfinished request, or None when the slot is clean.

        Any marker counts, even one that cannot be parsed: an unreadable
        marker is still evidence that a request was sent and never settled.
        """
        try:
            raw = self.marker.read_bytes()
        except FileNotFoundError:
            return None
        except OSError:
            return {"unreadable": True}
        try:
            record = json.loads(raw.decode("utf-8"))
        except ValueError:
            return {"unreadable": True}
        return record if isinstance(record, dict) else {"unreadable": True}

    def mark_inflight(self, record: dict) -> None:
        """Persist `record` before the request goes out. Caller holds the flock."""
        payload = json.dumps(record, ensure_ascii=False, indent=2).encode("utf-8")
        temp = self.marker.with_name(self.marker.name + f".tmp-{os.getpid()}")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.marker)

    def clear_inflight(self) -> None:
        """The server answered completely; the slot is known to be free again."""
        try:
            os.unlink(self.marker)
        except FileNotFoundError:
            pass


def reset_lock(state_dir: Path) -> dict | None:
    """Remove the in-flight marker on the operator's say-so.

    Refuses while a run holds the flock. Returns the removed record (None when
    there was nothing to remove). Never contacts the server: the operator has
    to have confirmed it is idle (`/health`, `/slots`) before calling this.
    """
    lock = InferenceLock(state_dir)
    if not lock.acquire():
        raise LockBusy("a local-assist run holds the inference lock; not resetting")
    try:
        record = lock.inflight()
        lock.clear_inflight()
        return record
    finally:
        lock.release()


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
