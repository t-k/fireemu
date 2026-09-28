"""Bounded O8 entrypoint for one already approved AUTH-MFA-AGE-TOTP-01 run.

This boundary consumes an independently frozen O7 permission and an owner approval.
It has no preparation mode, no injected transport mode and no credential discovery:
the bearer token and the Web API key arrive together on a private descriptor, and
only after admission, the hosting check, the Ledger reservation and the run
directory exist.

Exit 0 requires every case resolved, every owned account proven absent, the
configuration restore verified and the Ledger reservation released. Exit 1 means the
run started and did not complete: the reservation is still held, a receipt was
written, and `--resume` or `--abandon` is the next step. Exit 2 means admission or
the hosting check refused before anything was reserved or read.

`--resume` is admitted only while the original reservation still holds the critical
path that is left plus the recovery reserve. `--abandon` is recovery only: it does
not consult the reservation deadline or the hosting check, restores the
configuration and deletes the owned accounts, and needs an approval whose window is
still open (the owner re-mints one for a recovery after the original expired).

    mfa_o8.py --inputs ... --approval ... --manifest ... --permission ...
              --source <frozen checkout> --artifact <retained fireemu>
              --ledger <shared root> --output <fresh private dir>
              --credential-fd 3  3< <private handoff>
    mfa_o8.py ... --output <same dir> --resume  --credential-fd 3  3< <handoff>
    mfa_o8.py ... --output <same dir> --abandon --credential-fd 3  3< <handoff>
"""

# ruff: noqa: TRY004 -- Public boundary collapses malformed private input to one refusal class.

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import stat
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from broad_contract import digest

import mfa_admission as admission
import mfa_descriptor as campaign
from mfa_timing import WallClockSleeper

MAX_HANDOFF_BYTES = 16 * 1024
HANDOFF_KIND = "mfa-credential-handoff-v1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute, resume or abandon one frozen, O7-approved MFA campaign."
    )
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--permission", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--resume", action="store_true")
    mode.add_argument("--abandon", action="store_true")
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


def validate_handoff(handoff: dict, permission: dict) -> dict:
    """The bearer token and Web API key, bound to this permission's digest."""
    if (
        not isinstance(handoff, dict)
        or set(handoff) != {"kind", "permissionDigest", "token", "apiKey"}
        or handoff["kind"] != HANDOFF_KIND
        or handoff["permissionDigest"] != digest(permission)
    ):
        raise ValueError("bound MFA credential handoff required")
    for key, limit in (("token", 8192), ("apiKey", 512)):
        if not campaign.transport.private_string(handoff[key], limit):
            raise ValueError("bound MFA credential handoff required")
    return {"token": handoff["token"], "apiKey": handoff["apiKey"]}


def execute(args: argparse.Namespace) -> dict:
    args.execution_may_have_started = False
    inputs, _ = _read_json(args.inputs)
    manifest, manifest_bytes = _read_json(args.manifest, private=True)
    approval, _ = _read_json(args.approval, private=True)
    permission, _ = _read_json(args.permission)
    sleeper = WallClockSleeper()
    admission.require_production_timing(inputs)
    descriptor = admission.descriptor_for_plan(inputs["plan"], sleeper)
    admission.validate_o7_admission(
        descriptor,
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
    # The claim and the Gate projection are compiled before the capability exists,
    # and the shared modules are asked whether they host this campaign at all; a
    # refusal here names its reason and nothing has been reserved or read.
    gate_plan = admission.gate_plan_for(inputs, permission, descriptor)
    claim = admission.reservation_claim(
        inputs,
        gate_path=args.output / "gate",
        gate_plan=gate_plan,
        descriptor_=descriptor,
    )
    if not args.abandon:
        admission.require_hosted(claim, gate_plan)
    # An abandon reserves nothing and hosts nothing new: it restores the project
    # configuration and deletes what the run owns under the recovery reserve, so the
    # hosting check and the reservation deadline are not consulted. What it still
    # needs is this approval's window, which the owner re-mints for a late recovery.
    binding, binding_digest = campaign.worker_binding()
    capability = admission.issue_production_capability(
        descriptor,
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
    stop = {"requested": False}

    def request_stop(_signum, _frame):
        stop["requested"] = True

    try:
        if not (args.resume or args.abandon):
            admission.validate_fresh_admission(args.ledger, inputs["plan"], permission)
        from mfa_production import execute as execute_production

        def read_credential():
            credentials = validate_handoff(_read_handoff(args), permission)
            args.execution_may_have_started = True
            return credentials

        previous = signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        try:
            return execute_production(
                capability=capability,
                inputs=inputs,
                permission=permission,
                credential_reader=read_credential,
                ledger_root=args.ledger,
                output=args.output,
                sleeper=sleeper,
                descriptor_=descriptor,
                source_root=args.source,
                resume=args.resume,
                abandon=args.abandon,
                stop_requested=lambda: stop["requested"],
            )
        finally:
            signal.signal(signal.SIGINT, previous)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
    finally:
        admission.revoke_production_capability(capability)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute(args)
    except Exception as error:  # noqa: BLE001 -- public output must be secret-free.
        uncertain = getattr(args, "execution_may_have_started", False)
        state = "interrupted; reservation may remain held" if uncertain else "refused"
        print(f"MFA O8 {state} ({type(error).__name__}).", file=sys.stderr)
        return 1 if uncertain else 2
    if result.get("reservationReleased") and result.get("failure") is None:
        return 0
    if result.get("executionStarted"):
        print(
            "MFA O8 did not complete; reservation held"
            + (", resumable" if result.get("resumable") else "")
            + f" (stop point {result.get('stopPoint')})."
            + (
                " The project Auth configuration is STILL CHANGED under the held "
                "lock: resume or abandon this run."
                if result.get("configurationStillApplied")
                else ""
            )
            + (
                f" Untracked signups: {result['untrackedIntents']}; the owner must "
                "find and delete them."
                if result.get("untrackedIntents")
                else ""
            ),
            file=sys.stderr,
        )
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
