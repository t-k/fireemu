"""Serialize and validate public JSON using the canonical conformance policy."""

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "conformance/src/public-evidence-cli.mjs"


def public_json(value, **json_options):
    """Return the caller's JSON serialization only after canonical Node validation."""
    serialized = json.dumps(value, **json_options) + "\n"
    public_json_bytes(serialized.encode("utf-8"))
    return serialized


def public_json_bytes(data):
    """Return the exact JSON bytes only after canonical Node validation."""
    if not isinstance(data, bytes):
        raise TypeError("public evidence bytes must be bytes")
    try:
        result = subprocess.run(
            ["node", str(VALIDATOR)],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise ValueError("public evidence validation unavailable") from None
    if result.returncode != 0:
        raise ValueError("public evidence path validation failed") from None
    return data
