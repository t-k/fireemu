"""Bounded O8 entrypoint for one already approved Commit campaign.

This boundary consumes an independently frozen O7 permission and private
credential handoff. It has no preparation, metadata-only, ADC, or injected
transport mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import select
import stat
import sys
import time
import time
from pathlib import Path

import commit_acquisition as acquisition
from broad_contract import digest
from commit_remote_transport import request as remote_request
from commit_reserved_adapter import validate_handoff

MAX_HANDOFF_BYTES = 16 * 1024
APPROVAL_KIND = "commit-o8-approval-v1"
MANIFEST_KIND = "commit-o8-manifest-v1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute one frozen, O7-approved Commit campaign."
    )
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--permission", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    handoff = parser.add_mutually_exclusive_group(required=True)
    handoff.add_argument("--credential-fd", type=int)
    handoff.add_argument("--credential-file", type=Path)
    return parser


def _read_json(
    path: Path, *, limit: int = 8 * 1024 * 1024, private: bool = False
) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("bounded regular input file required")
    info = path.stat()
    if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("private approval file required")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("bounded JSON object required")
    return value, raw


def _read_private_fd(fd: int) -> dict:
    if type(fd) is not int or fd < 0:
        raise ValueError("private credential descriptor required")
    info = os.fstat(fd)
    if stat.S_ISREG(info.st_mode) and (
        info.st_uid != os.getuid() or info.st_mode & 0o077
    ):
        raise ValueError("private credential descriptor required")
    raw = bytearray()
    deadline = time.monotonic() + 5
    while len(raw) <= MAX_HANDOFF_BYTES:
        if not stat.S_ISREG(info.st_mode):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise ValueError("private credential handoff deadline")
        chunk = os.read(fd, MAX_HANDOFF_BYTES + 1 - len(raw))
        if not chunk:
            break
        raw.extend(chunk)
    if len(raw) > MAX_HANDOFF_BYTES:
        raise ValueError("bounded private credential handoff required")
    value = json.loads(bytes(raw))
    if not isinstance(value, dict):
        raise ValueError("private credential handoff required")
    return value


def _read_private_file(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("private credential file required")
    with path.open("rb") as stream:
        return _read_private_fd(stream.fileno())


def _read_handoff(args: argparse.Namespace) -> dict:
    if args.credential_fd is not None:
        return _read_private_fd(args.credential_fd)
    return _read_private_file(args.credential_file)


def _validate_frozen(inputs: dict) -> None:
    if inputs.get("kind") != "commit-frozen-inputs-v2":
        raise ValueError("O7 frozen approval binding required")
    required = {
        "permission",
        "permissionDigest",
        "plan",
        "planDigest",
        "sourceCommit",
        "sourceInputs",
        "artifactSha256",
        "inputsDigest",
    }
    if not required.issubset(inputs) or inputs["permission"].get(
        "kind"
    ) != "commit-owner-execution-permission-v1":
        raise ValueError("O7 frozen approval binding required")
    if (
        inputs["inputsDigest"]
        != digest({key: value for key, value in inputs.items() if key != "inputsDigest"})
        or inputs["permissionDigest"] != digest(inputs["permission"])
        or inputs["planDigest"] != digest(inputs["plan"])
        or not isinstance(inputs["sourceInputs"], dict)
        or not isinstance(inputs["sourceCommit"], str)
        or not isinstance(inputs["artifactSha256"], str)
    ):
        raise ValueError("O7 frozen approval binding differs")


def _validate_approval(
    approval: dict,
    manifest_bytes: bytes,
    manifest: dict,
    inputs: dict,
    permission: dict,
    *,
    ledger: Path,
) -> None:
    expected = {
        "kind",
        "status",
        "manifestSha256",
        "inputsDigest",
        "permissionDigest",
        "sourceCommit",
        "sourceInputsDigest",
        "artifactSha256",
        "planDigest",
        "nonceDigest",
        "ledgerRoot",
        "launcherSha256",
        "windowStartsAt",
        "windowExpiresAt",
    }
    if set(approval) != expected or approval["kind"] != APPROVAL_KIND:
        raise ValueError("O7 approval artifact required")
    if manifest.get("kind") != MANIFEST_KIND:
        raise ValueError("O7 manifest artifact required")
    if approval["status"] != "approved":
        raise ValueError("O7 approval is not approved")
    if hashlib.sha256(manifest_bytes).hexdigest() != approval["manifestSha256"]:
        raise ValueError("O7 manifest digest differs")
    bindings = {
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(inputs["plan"]["nonce"]),
        "ledgerRoot": str(ledger.absolute()),
        "launcherSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    if any(approval[key] != value for key, value in bindings.items()):
        raise ValueError("O7 approval binding differs")
    if manifest.get("inputsDigest") != inputs["inputsDigest"]:
        raise ValueError("O7 manifest binding differs")
    for key in ("windowStartsAt", "windowExpiresAt"):
        if (
            type(approval[key]) not in (int, float)
            or isinstance(approval[key], bool)
            or not math.isfinite(approval[key])
        ):
            raise ValueError("O7 execution window invalid")
    now = time.time()
    if not approval["windowStartsAt"] <= now <= approval["windowExpiresAt"]:
        raise ValueError("O7 execution window expired")


def execute(args: argparse.Namespace) -> dict:
    inputs, _ = _read_json(args.inputs)
    _validate_frozen(inputs)
    manifest, manifest_bytes = _read_json(args.manifest, private=True)
    approval, _ = _read_json(args.approval, private=True)
    permission, _ = _read_json(args.permission)
    _validate_approval(
        approval,
        manifest_bytes,
        manifest,
        inputs,
        permission,
        ledger=args.ledger,
    )
    handoff = _read_handoff(args)
    api_key = handoff.get("apiKey")
    if not isinstance(api_key, str):
        raise ValueError("private credential handoff required")
    # Validate before reservation or any possible wire operation.
    if digest(permission) != inputs["permissionDigest"]:
        raise ValueError("stale O7 permission binding")
    validate_handoff(handoff, permission, api_key)
    result = acquisition.run_acquisition(
        args.output,
        inputs,
        permission_path=args.permission,
        source_root=args.source,
        artifact_path=args.artifact,
        ledger_root=args.ledger,
        api_key=api_key,
        credential_handoff=handoff,
        transmit=remote_request,
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute(args)
        complete = (
            result.get("failure") is None
            and result.get("releaseEligible") is True
            and result.get("reservationReleased") is True
        )
        return 0 if complete else 1
    except Exception as error:  # noqa: BLE001 -- public output must be secret-free.
        print(f"Commit O8 refused ({type(error).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
