"""Run the packet05 recovery handoff boundary without network or Ledger writes.

This command is the bounded commander-facing executor for the preparation
artifact. It rechecks the canonical parent, fixed-source closure, nonce and
detached review evidence, then emits a redacted handoff for a separately
authorized production executor. It deliberately has no transport callback and
never calls the Ledger allocation or settlement APIs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(HERE))

import credential_recovery as recovery
import credential_recovery_prepare as prepare
import reservations
from broad_contract import digest


def _same(left: Any, right: Any, reason: str) -> None:
    if left != right:
        raise recovery.RecoveryRefusal(reason)


def prepare_execution_request(
    packet: dict[str, Any],
    *,
    parent: dict[str, Any],
    ledger: Any,
    source_root: Path,
    now: float,
) -> dict[str, Any]:
    """Revalidate a prepared packet and return a non-authorizing handoff."""
    if not isinstance(packet, dict) or packet.get("kind") != prepare.PACKET_KIND:
        raise recovery.RecoveryRefusal("Auth packet05 preparation bundle required")
    if packet.get("productionExecuted") is not False or packet.get("productionAllowed") is not False or packet.get("ledgerMutated") is not False:
        raise recovery.RecoveryRefusal("production execution flags differ")
    canonical_parent, state = prepare._reconstruct_parent(parent, ledger)
    parent_snapshot = recovery._parent_snapshot(canonical_parent)
    _same(packet.get("immutableParent"), canonical_parent.get("immutableParent"), "immutable parent changed")
    _same(packet.get("parentEvidence"), parent_snapshot["evidence"], "parent evidence changed")
    plan = packet.get("plan")
    if not isinstance(plan, dict):
        raise recovery.RecoveryRefusal("recovery plan required")
    recovery.validate_plan(plan, canonical_parent)
    prepare._verify_fixed_source(
        plan["provenance"],
        source_root,
        parent_snapshot["sourceCommit"],
        parent_snapshot["generation"],
    )
    prepare._assert_fresh_nonce(ledger, plan["recoveryNonce"], state)
    permission, o7, o8, reviews = prepare._validate_reviewed_authorities(
        plan,
        packet.get("permission"),
        packet.get("o7"),
        packet.get("o8"),
        packet.get("permissionReview"),
        packet.get("o7Review"),
        packet.get("o8Review"),
        now=now,
    )
    _same(packet["permission"], permission, "permission review evidence changed")
    _same(packet["o7"], o7, "O7 review evidence changed")
    _same(packet["o8"], o8, "O8 review evidence changed")
    review_digests = [digest(review) for review in reviews]
    return {
        "kind": "auth-packet05-recovery-execution-handoff-v1",
        "campaignId": recovery.CAMPAIGN,
        "planDigest": plan["planDigest"],
        "parentEvidenceDigest": parent_snapshot["evidence"]["evidenceDigest"],
        "sourceCommit": plan["provenance"]["sourceCommit"],
        "recoveryNonceDigest": plan["recoveryNonceDigest"],
        "reviewEvidenceDigests": review_digests,
        "networkAllowed": False,
        "ledgerMutationAllowed": False,
        "productionExecuted": False,
        "requiresSeparateExecutor": True,
        "operationCount": 1,
    }


def _write_request(request: dict[str, Any], output: Path) -> Path:
    destination = output.resolve()
    if destination.exists() or destination.is_symlink():
        raise recovery.RecoveryRefusal("new recovery handoff directory required")
    destination.mkdir(mode=0o700, parents=False)
    try:
        path = destination / "execution-handoff.json"
        with path.open("x", encoding="utf-8") as stream:
            json.dump(request, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
        path.chmod(0o600)
    except Exception:
        for path in destination.iterdir():
            path.unlink()
        destination.rmdir()
        raise
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and hand off Auth packet05 recovery without production execution."
    )
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--now", type=float, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        ledger = reservations.Ledger(args.ledger)
        prepare._assert_output_detached(args.output, ledger)
        packet = prepare._read_json(args.packet)
        request = prepare_execution_request(
            packet,
            parent=prepare._read_json(args.parent),
            ledger=ledger,
            source_root=args.source,
            now=args.now,
        )
        output = _write_request(request, args.output)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 -- keep commander output secret-free.
        print(f"AUTH-CREDENTIAL packet05 handoff refused ({type(error).__name__}).", file=sys.stderr)
        return 2
    print(f"AUTH-CREDENTIAL packet05 handoff validated offline at {output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_parser", "main", "prepare_execution_request"]
