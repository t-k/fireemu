"""Bounded O8 entrypoint for one already approved FS-WRITE-LIMITS-03 campaign.

This boundary consumes an independently frozen O7 permission and an owner
approval. It has no preparation mode, no injected transport mode and no
credential discovery: the bearer token arrives only on a private descriptor.

The launcher validates the retained source and O7 approval before consuming the
capability. The acquisition reserves the shared Ledger and claims the Gate job
before it reads the private handoff; the management preflight then reads the
token attestation, the project, database, index-exemption and Auth baselines
before the first data request, and the campaign refuses to start unless the
exempt collection group's field configuration matches the declared after state.
Exit 0 requires verified cleanup and Ledger release; exit 1 retains possible
writes, and exit 2 proves no create was dispatched or refuses admission before
execution.
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

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import limits_03_admission as admission
import limits_03_descriptor as campaign
from broad_contract import digest

MAX_HANDOFF_BYTES = 16 * 1024
HANDOFF_KIND = "limits-03-bearer-token-v1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute one frozen, O7-approved FS-WRITE-LIMITS-03 campaign."
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


def _read_handoff(args: argparse.Namespace) -> dict:
    if args.credential_fd is not None:
        return _read_private_fd(args.credential_fd)
    path = args.credential_file
    if path.is_symlink() or not path.is_file():
        raise ValueError("private credential file required")
    with path.open("rb") as stream:
        return _read_private_fd(stream.fileno())


def validate_handoff(handoff: dict, permission: dict) -> str:
    """Validate an explicitly supplied bearer token against the permission."""
    if (
        not isinstance(handoff, dict)
        or set(handoff) != {"kind", "permissionDigest", "token"}
        or handoff["kind"] != HANDOFF_KIND
    ):
        raise ValueError("bound limits-03 credential handoff required")
    token = handoff["token"]
    if (
        handoff["permissionDigest"] != digest(permission)
        or not isinstance(token, str)
        or not token
        or len(token) > 8192
    ):
        raise ValueError("bound limits-03 credential handoff required")
    return token


def execute(args: argparse.Namespace) -> dict:
    args.execution_may_have_started = False
    inputs, _ = _read_json(args.inputs)
    manifest, manifest_bytes = _read_json(args.manifest, private=True)
    approval, _ = _read_json(args.approval, private=True)
    permission, _ = _read_json(args.permission)
    # One shared check set: approval, manifest, window, Ledger root, launcher
    # digest, artifact profile, retained artifact and permission binding.
    admission.validate_o7_admission(
        inputs=inputs,
        approval=approval,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_path=args.manifest,
        permission=permission,
        ledger_root=args.ledger,
        artifact_path=args.artifact,
        launcher_path=Path(__file__),
    )
    admission._provenance(args.source, inputs["sourceCommit"], inputs["sourceInputs"])
    # The Gate plan is compiled before the capability exists, so a campaign
    # whose reservations do not fit is refused without one. The index
    # precondition is re-checked against the permission for the same reason.
    admission.gate_plan_for(inputs, permission)
    admission._validate_index_precondition(permission)
    binding, binding_digest = campaign.worker_binding()
    capability = admission.issue_production_capability(
        inputs=inputs,
        approval=approval,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_path=args.manifest,
        permission=permission,
        ledger_root=args.ledger,
        artifact_path=args.artifact,
        launcher_path=Path(__file__),
        binding=binding,
        binding_digest=binding_digest,
    )
    try:
        # Advisory: the atomic Ledger reservation and Gate admission inside
        # execute_production still precede the credential reader.
        admission.validate_fresh_admission(args.ledger, inputs["plan"], permission)
        from limits_03_production import execute as execute_production

        def read_credential():
            token = validate_handoff(_read_handoff(args), permission)
            # If evidence publication later fails, absence is not established.
            args.execution_may_have_started = True
            return token

        return execute_production(
            capability=capability,
            inputs=inputs,
            permission=permission,
            credential_reader=read_credential,
            ledger_root=args.ledger,
            output=args.output,
        )
    finally:
        # An admission that will not be executed must not stay issued.
        admission.revoke_production_capability(capability)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute(args)
    except Exception as error:  # noqa: BLE001 -- public output must be secret-free.
        uncertain = getattr(args, "execution_may_have_started", False)
        state = "interrupted; reservation may remain held" if uncertain else "refused"
        print(f"Limits-03 O8 {state} ({type(error).__name__}).", file=sys.stderr)
        return 1 if uncertain else 2
    if result.get("reservationReleased") and result.get("failure") is None:
        return 0
    return 1 if result.get("mayHaveCreated") else 2


if __name__ == "__main__":
    raise SystemExit(main())
