"""Bounded local replay of the saved Firestore reads/read-time program."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from broad import bounded_firestore_program, digest, run

SAVED_PROGRAM_SHA256 = "613376ceac1ae5126803efe55f32f01ae8fcf27b20f8ded3d5cbbf23d102add9"
PROGRAM_DIGEST = "adf956497d20db3a8bb48f036886b169b033a3883b4d2e3371152accf111100a"


def load_saved_program(path: Path) -> dict:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SAVED_PROGRAM_SHA256:
        raise ValueError("saved read-time record hash mismatch")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("saved read-time record must be an object")
    if value.get("selectedProgramDigests", {}).get("reads/read-time") != PROGRAM_DIGEST:
        raise ValueError("saved read-time program digest is not bound")
    return value


def replay(saved_path: Path, output: Path) -> dict:
    saved = load_saved_program(saved_path)
    program = bounded_firestore_program("reads/read-time")[0]
    if digest(program) != PROGRAM_DIGEST:
        raise ValueError("current reads/read-time program changed")
    result = run(output, firestore_program="reads/read-time")
    replay_metadata = {
        "savedRecordSha256": SAVED_PROGRAM_SHA256,
        "savedProgramDigest": PROGRAM_DIGEST,
        "programId": "reads/read-time",
        "productionExecuted": False,
        "savedRecordStatus": saved.get("status"),
    }
    (output / "replay.json").write_text(json.dumps(replay_metadata, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--saved", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = replay(args.saved, args.output)
    print(json.dumps({"status": result["status"], "output": str(args.output)}))
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
