"""Bounded O8 entrypoint for one already approved Commit campaign.

This boundary consumes an independently frozen O7 permission and private
credential handoff. It has no preparation, metadata-only, ADC, or injected
transport mode.
"""

# ruff: noqa: TRY004 -- Public boundary collapses malformed private input to one refusal class.

from __future__ import annotations

import argparse
import json
import os
import select
import stat
import sys
import time
from pathlib import Path

import commit_acquisition as acquisition
import o8_bundle
from broad_contract import (
    digest as digest,  # noqa: PLC0414 -- re-exported for callers of this boundary
)
from commit_reserved_adapter import validate_handoff

MAX_HANDOFF_BYTES = 16 * 1024
CAMPAIGN_SECONDS = 1200
RECOVERY_SECONDS = 180
APPROVAL_KIND = "commit-o8-approval-v1"
MANIFEST_KIND = "commit-o8-manifest-v1"
REVIEWED_ARTIFACT_PROFILE = "repaired-567565bdd"


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
    """Delegate to the single shared definition of the frozen O7 binding."""
    acquisition.validate_frozen_inputs(inputs)


def _validate_approval(
    approval: dict,
    manifest_bytes: bytes,
    manifest: dict,
    inputs: dict,
    permission: dict,
    *,
    ledger: Path,
    manifest_path: Path,
    artifact_path: Path,
    launcher_path: Path,
) -> dict:
    """Delegate to the single shared definition of the complete O7 check set."""
    return acquisition.validate_o7_admission(
        inputs=inputs,
        approval=approval,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_path=manifest_path,
        permission=permission,
        ledger_root=ledger,
        artifact_path=artifact_path,
        launcher_path=launcher_path,
    )


def execute(args: argparse.Namespace) -> dict:
    inputs, _ = _read_json(args.inputs)
    manifest, manifest_bytes = _read_json(args.manifest, private=True)
    approval, _ = _read_json(args.approval, private=True)
    permission, _ = _read_json(args.permission)
    # One shared check set: approval, manifest, window, Ledger root, launcher
    # digest, artifact profile, retained artifact and permission binding.
    _validate_approval(
        approval,
        manifest_bytes,
        manifest,
        inputs,
        permission,
        ledger=args.ledger,
        manifest_path=args.manifest,
        artifact_path=args.artifact,
        launcher_path=Path(__file__),
    )
    # Build and own the worker archive before any credential is read. The
    # writable construction handle is closed and the file unlinked before the
    # descriptor is admitted, so no writable alias to these bytes survives.
    archive, archive_sha256 = o8_bundle.build_worker_archive_from_source(
        args.source, inputs["sourceInputs"]
    )
    with o8_bundle.unlinked_archive_fd(archive, archive_sha256) as archive_fd:
        capability = acquisition.issue_production_capability(
            inputs=inputs,
            approval=approval,
            manifest=manifest,
            manifest_bytes=manifest_bytes,
            manifest_path=args.manifest,
            permission=permission,
            ledger_root=args.ledger,
            artifact_path=args.artifact,
            launcher_path=Path(__file__),
            binding=archive_fd,
            binding_digest=archive_sha256,
        )
        try:
            handoff = _read_handoff(args)
            api_key = handoff.get("apiKey")
            if not isinstance(api_key, str):
                raise ValueError("private credential handoff required")
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
                capability=capability,
            )
            acquisition.revoke_production_capability(capability)
            return result
        except BaseException:
            # An admission that will not be executed must not stay issued.
            acquisition.revoke_production_capability(capability)
            raise


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
