"""Helpers for checking source digests at immutable campaign commits."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path, PurePosixPath


def historical_sha256(root: Path, commit: str, relative_path: str) -> str:
    """Hash a checked-in blob from the campaign's declared source commit."""
    path = PurePosixPath(relative_path)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("relative historical source path required")
    blob = subprocess.check_output(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(root),
            "cat-file",
            "blob",
            f"{commit}:{path.as_posix()}",
        ],
        stderr=subprocess.PIPE,
    )
    return hashlib.sha256(blob).hexdigest()
