"""Prepare a secret-free Auth packet05 recovery bundle.

This is an offline operator boundary. It reads a held parent and the shared
Ledger, compiles a fresh lookup child, and writes detached authority documents.
It never calls a transport, begins a child reservation, or closes a parent.
The resulting files are inputs for a separately authorized execution process.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import secrets
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(HERE))

import credential_recovery as recovery
import reservations
from broad_contract import digest

PACKET_KIND = "auth-packet05-recovery-preparation-v1"
ARTIFACT_NAMES = (
    "packet.json",
    "plan.json",
    "permission.json",
    "o7.json",
    "o8.json",
    "parent-evidence.json",
)
SECRET_KEYS = frozenset(
    {
        "accessToken",
        "apiKey",
        "idToken",
        "password",
        "privateKey",
        "refreshToken",
        "serviceAccount",
    }
)
MAX_INPUT_BYTES = 8 * 1024 * 1024


def _refuse(reason: str) -> None:
    raise recovery.RecoveryRefusal(reason)


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        _refuse("bounded regular JSON input required")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError):
        _refuse("bounded JSON input required")
    if not isinstance(value, dict):
        _refuse("bounded JSON object required")
    return value


def _parent_claim_matches_ledger(parent: Mapping[str, Any], ledger: Any) -> None:
    ticket = parent.get("ticket")
    if not isinstance(ticket, Mapping):
        _refuse("parent Ledger ticket required")
    bound_claim_method = getattr(ledger, "bound_claim", None)
    if not callable(bound_claim_method):
        _refuse("production-admission Ledger claim API required")
    try:
        bound_claim = bound_claim_method(copy.deepcopy(dict(ticket)))
    except Exception as error:  # noqa: BLE001 -- never expose Ledger details at this boundary.
        raise recovery.RecoveryRefusal(
            f"parent Ledger claim refused: {type(error).__name__}"
        ) from None
    if (
        not isinstance(bound_claim, Mapping)
        or bound_claim.get("campaignId") != recovery.CAMPAIGN
    ):
        _refuse("canonical Auth parent claim required")
    ticket_digest = ticket.get("claimDigest")
    if ticket_digest is not None and ticket_digest != digest(bound_claim):
        _refuse("parent Ledger claim binding changed")
    supplied_claim = parent.get("claim")
    if not isinstance(supplied_claim, Mapping):
        _refuse("parent claim evidence required")
    supplied_digest = supplied_claim.get("claimDigest")
    claim_without_digest = {
        key: value for key, value in supplied_claim.items() if key != "claimDigest"
    }
    if supplied_digest not in (None, digest(bound_claim), digest(claim_without_digest)):
        _refuse("parent claim evidence differs from Ledger")


def _assert_fresh_nonce(ledger: Any, parent: Mapping[str, Any], nonce: str) -> None:
    snapshot_method = getattr(ledger, "snapshot", None)
    if not callable(snapshot_method):
        _refuse("production-admission Ledger snapshot API required")
    try:
        state = snapshot_method()
    except Exception as error:  # noqa: BLE001 -- never expose Ledger details at this boundary.
        raise recovery.RecoveryRefusal(
            f"parent Ledger snapshot refused: {type(error).__name__}"
        ) from None
    target = digest(nonce)
    if not isinstance(state, Mapping):
        _refuse("canonical Ledger snapshot required")
    for row in (state.get("reservations", {}) or {}).values():
        if not isinstance(row, Mapping):
            continue
        claim = row.get("claim")
        if isinstance(claim, Mapping) and claim.get("nonceDigest") == target:
            _refuse("recovery nonce already reserved")
        for child in row.get("recoveryChildren", []) or []:
            child_claim = child.get("claim") if isinstance(child, Mapping) else None
            if (
                isinstance(child_claim, Mapping)
                and child_claim.get("nonceDigest") == target
            ):
                _refuse("recovery nonce already reserved")


def _authority_documents(
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    expires_at = plan["deadlineAt"]
    permission = {
        "kind": recovery.PERMISSION_KIND,
        "campaignId": recovery.CAMPAIGN,
        "parentClaimDigest": plan["parent"]["claimDigest"],
        "planDigest": plan["planDigest"],
        "nonceDigest": plan["recoveryNonceDigest"],
        "sourceInputsDigest": plan["provenance"]["sourceInputsDigest"],
        "budget": copy.deepcopy(recovery.CHILD_BUDGET),
        "issuedAt": plan["issuedAt"],
        "expiresAt": expires_at,
    }
    permission_digest = digest(permission)
    o7 = {
        "kind": recovery.O7_KIND,
        "status": "approved",
        "campaignId": recovery.CAMPAIGN,
        "planDigest": plan["planDigest"],
        "permissionDigest": permission_digest,
        "nonceDigest": plan["recoveryNonceDigest"],
        "sourceInputsDigest": plan["provenance"]["sourceInputsDigest"],
        "issuedAt": plan["issuedAt"],
        "expiresAt": expires_at,
    }
    o8 = {
        "kind": recovery.O8_KIND,
        "status": "issued",
        "campaignId": recovery.CAMPAIGN,
        "planDigest": plan["planDigest"],
        "permissionDigest": permission_digest,
        "nonceDigest": plan["recoveryNonceDigest"],
        "sourceInputsDigest": plan["provenance"]["sourceInputsDigest"],
        "oneShot": True,
        "consumed": False,
        "issuedAt": plan["issuedAt"],
        "expiresAt": expires_at,
    }
    recovery.validate_authority_bundle(
        plan, permission=permission, o7=o7, o8=o8, now=plan["issuedAt"]
    )
    return permission, o7, o8


def _reject_secret_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        if SECRET_KEYS.intersection(value):
            _refuse("secret-bearing recovery artifact refused")
        for child in value.values():
            _reject_secret_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_keys(child)


def prepare_packet(
    parent: Mapping[str, Any],
    *,
    ledger: Any,
    provenance: Mapping[str, Any],
    recovery_nonce: str | None = None,
    now: float | None = None,
    deadline_seconds: int = recovery.MAX_DEADLINE_SECONDS,
) -> dict[str, Any]:
    """Compile detached recovery authorities without changing the Ledger."""
    try:
        _parent_claim_matches_ledger(parent, ledger)
        nonce = secrets.token_hex(16) if recovery_nonce is None else recovery_nonce
        recovery._nonce(nonce, "recovery")
        _assert_fresh_nonce(ledger, parent, nonce)
        plan = recovery.compile_recovery_plan(
            parent,
            recovery_nonce=nonce,
            provenance=provenance,
            now=now,
            deadline_seconds=deadline_seconds,
        )
        permission, o7, o8 = _authority_documents(plan)
        snapshot = recovery._parent_snapshot(parent)
    except recovery.RecoveryRefusal:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as error:
        raise recovery.RecoveryRefusal(
            f"malformed Auth packet05 parent ({type(error).__name__})"
        ) from None
    bundle = {
        "kind": PACKET_KIND,
        "campaignId": recovery.CAMPAIGN,
        "productionExecuted": False,
        "productionAllowed": False,
        "ledgerMutated": False,
        "immutableParent": copy.deepcopy(dict(parent["immutableParent"])),
        "parentEvidence": copy.deepcopy(snapshot["evidence"]),
        "plan": plan,
        "permission": permission,
        "o7": o7,
        "o8": o8,
    }
    _reject_secret_keys(bundle)
    return bundle


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(
            value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False
        ).encode()
        + b"\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def write_packet(bundle: Mapping[str, Any], output: Path) -> Path:
    """Write a new private preparation directory and no parent/ledger state."""
    if not isinstance(bundle, Mapping) or bundle.get("kind") != PACKET_KIND:
        _refuse("Auth packet05 preparation bundle required")
    _reject_secret_keys(bundle)
    destination = output.resolve()
    if destination.exists():
        _refuse("new recovery output directory required")
    destination.mkdir(mode=0o700, parents=False)
    files = {
        "packet.json": dict(bundle),
        "plan.json": bundle["plan"],
        "permission.json": bundle["permission"],
        "o7.json": bundle["o7"],
        "o8.json": bundle["o8"],
        "parent-evidence.json": {
            "immutableParent": bundle["immutableParent"],
            "parentEvidence": bundle["parentEvidence"],
        },
    }
    try:
        for name in ARTIFACT_NAMES:
            _write_json(destination / name, files[name])
    except Exception:
        for path in destination.iterdir():
            path.unlink()
        destination.rmdir()
        raise
    return destination


def _assert_output_detached(output: Path, ledger: Any) -> None:
    ledger_path = getattr(ledger, "path", None)
    if not isinstance(ledger_path, Path):
        _refuse("canonical Ledger path required")
    destination = output.resolve()
    canonical = ledger_path.resolve()
    if destination == canonical or canonical in destination.parents:
        _refuse("recovery output must be outside canonical Ledger")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare an offline, secret-free Auth packet05 recovery bundle."
    )
    parser.add_argument(
        "--parent", type=Path, required=True, help="held packet05 parent evidence JSON"
    )
    parser.add_argument(
        "--provenance",
        type=Path,
        required=True,
        help="source-bound recovery provenance JSON",
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        required=True,
        help="canonical shared Ledger root (read-only)",
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="new private preparation directory"
    )
    parser.add_argument(
        "--recovery-nonce",
        help="fresh 32-hex nonce; omitted generates one from the OS CSPRNG",
    )
    parser.add_argument(
        "--deadline-seconds", type=int, default=recovery.MAX_DEADLINE_SECONDS
    )
    parser.add_argument(
        "--now", type=float, help="issue time for deterministic offline rehearsal"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        ledger = reservations.Ledger(args.ledger)
        _assert_output_detached(args.output, ledger)
        bundle = prepare_packet(
            _read_json(args.parent),
            ledger=ledger,
            provenance=_read_json(args.provenance),
            recovery_nonce=args.recovery_nonce,
            now=args.now,
            deadline_seconds=args.deadline_seconds,
        )
        output = write_packet(bundle, args.output)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 -- public output must remain secret-free.
        print(
            f"AUTH-CREDENTIAL packet05 recovery refused ({type(error).__name__}).",
            file=sys.stderr,
        )
        return 2
    print(
        f"AUTH-CREDENTIAL packet05 recovery prepared offline at {output} (no production request sent)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["PACKET_KIND", "build_parser", "main", "prepare_packet", "write_packet"]
