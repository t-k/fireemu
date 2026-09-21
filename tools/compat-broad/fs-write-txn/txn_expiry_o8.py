"""Bounded O8 entrypoint for one already approved transaction expiry campaign.

This boundary consumes an independently frozen O7 permission and an owner
approval. It has no preparation mode, no injected transport mode, no rehearsal
switch and no credential discovery: the bearer token arrives only on a private
descriptor, and it is read only after the shared Ledger reservation exists and
the Gate is claimed.

Exit codes carry the request-byte meaning. 0: the run completed, every owned
document was proven absent and the reservation was released. 1: a reservation
was taken and is still held; `<output>/receipt.json` names the stop point and
the retirement path (`abort_no_data`, `close_after_abandon` or owner
escalation). 2: admission refused before any reservation existed; nothing was
sent and nothing was created.
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

import txn_expiry_admission as admission
import txn_expiry_descriptor as campaign
from broad_contract import digest

MAX_HANDOFF_BYTES = 16 * 1024
HANDOFF_KIND = campaign.HANDOFF_KIND


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute one frozen, O7-approved transaction expiry campaign."
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
        raise ValueError("bound transaction expiry credential handoff required")
    token = handoff["token"]
    if (
        handoff["permissionDigest"] != digest(permission)
        or not isinstance(token, str)
        or not token
        or len(token) > 8192
        or any(not 33 <= ord(c) <= 126 for c in token)
    ):
        raise ValueError("bound transaction expiry credential handoff required")
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
    # whose reservations do not fit is refused without one.
    admission.gate_plan_for(inputs, permission)
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
        # Advisory: the atomic Ledger reservation inside execute still precedes
        # the credential reader.
        admission.validate_fresh_admission(args.ledger, inputs["plan"], permission)
        from txn_expiry_production import execute as execute_production

        def read_credential():
            token = validate_handoff(_read_handoff(args), permission)
            # From here a reservation exists; a failure is exit 1, not 2.
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
        admission.revoke_production_capability(capability)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute(args)
    except Exception as error:  # noqa: BLE001 -- public output must be secret-free.
        uncertain = getattr(args, "execution_may_have_started", False)
        state = "interrupted; reservation may remain held" if uncertain else "refused"
        print(
            f"Transaction expiry O8 {state} ({type(error).__name__}).", file=sys.stderr
        )
        return 1 if uncertain else 2
    if result.get("reservationReleased") and result.get("failure") is None:
        return 0
    # A receipt exists and a reservation is held: exit 1 whether the stop is a
    # retirable no-data stop or an uncertain one; the receipt says which.
    retirement = result.get("retirement") or {}
    print(
        f"Transaction expiry O8 stopped at {result.get('stopPoint')}; reservation "
        f"held; retirement path {retirement.get('disposition')}.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
