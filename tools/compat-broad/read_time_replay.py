"""Bounded local replay of the saved Firestore reads/read-time program."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))

from broad import (
    PROJECT,
    bounded_firestore_program,
    digest,
    local_origin,
    run,
)
from broad import (
    child as broad_child,
)

SAVED_PROGRAM_SHA256 = (
    "613376ceac1ae5126803efe55f32f01ae8fcf27b20f8ded3d5cbbf23d102add9"
)
PROGRAM_DIGEST = "adf956497d20db3a8bb48f036886b169b033a3883b4d2e3371152accf111100a"
POSTSTATE_DOCUMENT = f"projects/{PROJECT}/databases/(default)/documents/rt/a"


def load_saved_program(path: Path) -> dict:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SAVED_PROGRAM_SHA256:
        raise ValueError("saved read-time record hash mismatch")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("saved read-time record must be an object")  # noqa: TRY004 -- Keep saved-record validation errors as one refusal type.
    if value.get("selectedProgramDigests", {}).get("reads/read-time") != PROGRAM_DIGEST:
        raise ValueError("saved read-time program digest is not bound")
    return value


def replay(saved_path: Path, output: Path) -> dict:
    saved = load_saved_program(saved_path)
    program = bounded_firestore_program("reads/read-time")[0]
    if digest(program) != PROGRAM_DIGEST:
        raise ValueError("current reads/read-time program changed")
    result = run(
        output,
        child_script=Path(__file__).resolve(),
        firestore_program="reads/read-time",
    )
    replay_metadata = {
        "savedRecordSha256": SAVED_PROGRAM_SHA256,
        "savedProgramDigest": PROGRAM_DIGEST,
        "programId": "reads/read-time",
        "productionExecuted": False,
        "savedRecordStatus": saved.get("status"),
    }
    (output / "replay.json").write_text(json.dumps(replay_metadata, indent=2) + "\n")
    return result


def read_poststate(firestore_origin: str) -> dict:
    """Read the fixed document once and retain only non-sensitive validation facts."""
    status = None
    payload = None
    try:
        origin = local_origin(firestore_origin)
        request = Request(
            f"{origin}/v1/{POSTSTATE_DOCUMENT}",
            headers={"Authorization": "Bearer owner"},
            method="GET",
        )
        with urlopen(request, timeout=5) as response:
            status = response.status
            if status == 200:
                payload = json.loads(response.read())
    except HTTPError as error:
        status = error.code
    except (URLError, TimeoutError, OSError, ValueError):
        pass

    name_matches = (
        isinstance(payload, dict) and payload.get("name") == POSTSTATE_DOCUMENT
    )
    fields = payload.get("fields") if isinstance(payload, dict) else None
    version = fields.get("v") if isinstance(fields, dict) else None
    integer_value = version.get("integerValue") if isinstance(version, dict) else None
    value_matches = type(integer_value) is str and integer_value == "2"
    return {
        "status": status,
        "documentNameMatches": name_matches,
        "integerValueIsTwo": value_matches,
    }


def run_child(
    output: Path, nonce: str, firestore_program: str, *, delegate=None
) -> int:
    """Run the bounded program, then validate its final state before child exit."""
    if firestore_program != "reads/read-time":
        raise ValueError("bounded replay only permits reads/read-time")
    (delegate or broad_child)(output.resolve(), nonce, firestore_program)
    cases_path = output / "cases.json"
    cases = json.loads(cases_path.read_bytes())
    if not isinstance(cases, dict):
        raise ValueError("bounded replay child report must be an object")  # noqa: TRY004 -- Keep malformed child reports as one refusal type.
    try:
        instance = json.loads((output / "instance.json").read_bytes())
        if (
            instance["pid"] != os.getpid()
            or instance["parentPid"] != os.getppid()
            or instance["nonce"] != nonce
        ):
            raise ValueError("unexpected bounded replay child ownership")
        firestore_origin = instance["firestoreOrigin"]
        poststate = read_poststate(firestore_origin)
    except (OSError, KeyError, TypeError, ValueError):
        poststate = {
            "status": None,
            "documentNameMatches": False,
            "integerValueIsTwo": False,
        }
    state_validation = (
        poststate["status"] == 200
        and poststate["documentNameMatches"] is True
        and poststate["integerValueIsTwo"] is True
    )
    cases["postStateReadback"] = poststate
    cases["stateValidation"] = state_validation
    cases_path.write_text(json.dumps(cases, indent=2) + "\n")
    return 0 if state_validation else 2


def main(argv=None, *, child_runner=run_child) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--saved", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--firestore-program")
    args = parser.parse_args(argv)
    if args.child is not None:
        if args.nonce is None or args.firestore_program is None:
            parser.error("--child requires --nonce and --firestore-program")
        return child_runner(args.child, args.nonce, args.firestore_program)
    if args.saved is None or args.output is None:
        parser.error("replay mode requires --saved and --output")
    result = replay(args.saved, args.output)
    print(json.dumps({"status": result["status"], "output": str(args.output)}))
    return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
