"""Fail-closed O8 entrypoint for the prepared FS-LISTEN-SDK campaign."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import listen_descriptor as campaign
from o8_admission import validate_o7_admission


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Execute one approved Listen campaign.")
    for name in ("inputs", "approval", "manifest", "permission", "artifact", "ledger", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    handoff = parser.add_mutually_exclusive_group(required=True)
    handoff.add_argument("--credential-fd", type=int)
    handoff.add_argument("--credential-file", type=Path)
    return parser


def _read_json(path: Path, *, private: bool = False) -> tuple[dict, bytes]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("bounded regular input file required")
    if private and path.stat().st_mode & 0o077:
        raise ValueError("private approval file required")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("bounded JSON object required")
    return value, raw


def execute(args: argparse.Namespace) -> dict:
    descriptor = campaign.descriptor()
    inputs, _ = _read_json(args.inputs)
    manifest, manifest_bytes = _read_json(args.manifest, private=True)
    approval, _ = _read_json(args.approval, private=True)
    permission, _ = _read_json(args.permission)
    validate_o7_admission(
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
    # The shared reservation registry intentionally does not yet admit this
    # campaign. Even a complete O7 shape cannot enable production here.
    raise ValueError("FS-LISTEN-SDK production transport disabled")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)
    try:
        execute(args)
    except Exception as error:  # noqa: BLE001 - public refusal is secret-free.
        print(f"FS-LISTEN-SDK refused ({type(error).__name__}).")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
