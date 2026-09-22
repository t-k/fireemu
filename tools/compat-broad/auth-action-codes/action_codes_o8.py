"""Private-FD O8 entrypoint for the bounded AUTH-ACTION production adapter.

This entrypoint performs admission and source/artifact checks before consuming an
O8 capability. Credentials are read from a private descriptor and passed only to
the existing Action transport; they are never command-line arguments or receipt
fields. A loopback origin is deliberately unavailable in production mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import select
import stat
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import action_codes_admission as admission
import action_codes_plan as plan_module
import action_codes_production as production
import action_codes_remote_transport as remote

MAX_HANDOFF_BYTES = 16 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Execute one approved AUTH-ACTION O8 campaign.")
    for name in ("inputs", "approval", "manifest", "permission", "source", "artifact", "ledger", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--credential-fd", type=int, required=True)
    return parser


def _read_json(path: Path, *, private: bool = False) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("bounded regular input file required")
    info = path.stat()
    if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("private approval file required")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("bounded JSON object required")
    return value, raw


def read_private_fd(fd: int) -> dict:
    if type(fd) is not int or fd < 0:
        raise ValueError("private credential descriptor required")
    info = os.fstat(fd)
    if stat.S_ISREG(info.st_mode) and (info.st_uid != os.getuid() or info.st_mode & 0o077):
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


def _names(value: Any) -> set[str]:
    if isinstance(value, str) and value.startswith("$binding:"):
        return {value.removeprefix("$binding:")}
    if isinstance(value, dict):
        result: set[str] = set()
        for item in value.values():
            result.update(_names(item))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result.update(_names(item))
        return result
    return set()


def bindings_for(plan: dict) -> dict[str, dict[str, str]]:
    """Create private in-memory values for every frozen placeholder."""
    result: dict[str, dict[str, str]] = {}
    nonce = plan["nonce"]

    def stable(name: str) -> str:
        return hashlib.sha256(f"AUTH-ACTION:{nonce}:{name}".encode()).hexdigest()

    for stage in (*plan["stages"], *plan["recovery"]):
        values: dict[str, str] = {}
        for name in _names(stage["body"]):
            if name == "unknownEmail" or name.endswith(".email"):
                suffix = name.split(".", 1)[0][-1].lower() if name != "unknownEmail" else "absent"
                values[name] = f"o1-oob-{nonce}-{suffix}@example.invalid"
            elif name.endswith(".localId"):
                values[name] = "pending-" + stable(name)[:24]
            elif name == "weakPassword":
                values[name] = "Aa9!" + stable(name)[:20]
            elif name == "wrongCode":
                values[name] = "wrong-" + stable(name)[:24]
            else:
                values[name] = "private-" + stable(name)[:24]
        result[stage["id"]] = values
    return result


def execute(args: argparse.Namespace) -> dict:
    if Path(args.source).resolve() != ROOT.resolve():
        raise ValueError("frozen Action source root required")
    inputs, _ = _read_json(args.inputs)
    manifest, manifest_bytes = _read_json(args.manifest, private=True)
    approval, _ = _read_json(args.approval, private=True)
    permission, _ = _read_json(args.permission)
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
    admission._validate_artifact_binding(inputs, args.artifact)
    handoff = read_private_fd(args.credential_fd)
    plan = plan_module.campaign_manifest(inputs["plan"]["nonce"], project=remote.AUTHORIZED_PROJECT)
    remote._validate_handoff(handoff, permission)
    worker, worker_digest = remote.credential_remote.worker_binding()
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
        binding=worker,
        binding_digest=worker_digest,
    )
    try:
        return production.execute(
            capability=capability,
            inputs=inputs,
            permission=permission,
            ledger_root=args.ledger,
            output=args.output,
            bindings=bindings_for(plan),
            credential_handoff=handoff,
            verify_handoff=remote._validate_handoff,
            fixture_origin=None,
            production=True,
            permission_expires_at=approval["windowExpiresAt"],
        )
    finally:
        import o8_admission

        o8_admission.revoke_production_capability(capability)


def main(argv: list[str] | None = None) -> int:
    try:
        execute(build_parser().parse_args(argv))
    except Exception as error:  # noqa: BLE001 - public boundary must not expose handoff data
        print(f"AUTH-ACTION O8 refused ({type(error).__name__}).", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
