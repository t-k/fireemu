"""Prepare and verify the index-configuration precondition of FS-WRITE-LIMITS-03.

The campaign observes the document-name boundary only under one single-field
exemption on the exempt collection group. This tool writes the after state of
`conformance/firestore.indexes.json` for the commander to deploy, and verifies
that the file on disk is the before or the after state the package declares.
It deploys nothing and holds no credential: `firebase deploy` is the
commander's own step, and the launcher's preflight is what proves the
deployed configuration matches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))

import limits_03_descriptor as campaign
import limits_03_preflight as preflight
from broad_contract import digest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--write-after",
        type=Path,
        help="write the index configuration with the declared exemption appended",
    )
    mode.add_argument(
        "--verify",
        choices=("before", "after"),
        help="check that the file matches the declared before or after digest",
    )
    mode.add_argument(
        "--precondition",
        action="store_true",
        help="print the declared precondition, digests and commands",
    )
    mode.add_argument(
        "--verify-deployed",
        type=Path,
        metavar="READBACK",
        help="check a saved field readback against the declared exemption",
    )
    mode.add_argument(
        "--verify-restored",
        type=Path,
        metavar="READBACK",
        help="check a saved field readback against the restored default and "
        "write the restore record; requires --receipt",
    )
    parser.add_argument("--file", type=Path, default=ROOT / campaign.INDEXES_FILE)
    parser.add_argument(
        "--record",
        type=Path,
        default=ROOT / campaign.RESTORE_RECORD,
        help="where --verify-restored writes the restore record",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        metavar="RECEIPT",
        help="the production receipt.json of the run --verify-restored restores",
    )
    return parser


MAX_READBACK_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 4 * 1024 * 1024


def _readback(path: Path) -> tuple[dict, bytes]:
    """One saved JSON body of the field resource, bounded and regular."""
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > MAX_READBACK_BYTES
    ):
        raise SystemExit("bounded regular readback file required")
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise SystemExit("JSON object readback required")
    return value, raw


def _load_receipt(path: Path) -> dict:
    """One saved production receipt.json, bounded and regular."""
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_size > MAX_RECEIPT_BYTES
    ):
        raise SystemExit("bounded regular receipt file required")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise SystemExit("JSON object receipt required")
    return value


def restore_record(
    readback: dict, raw: bytes, *, indexes_path: Path, receipt: dict
) -> dict:
    """The evidence that the exempt group inherits the default again.

    Judged on the readback alone: the deploy's exit status proves nothing about
    the field. The record also binds the index file on disk, which must be the
    committed before state, so a restore run against an edited file is
    refused, and binds the production receipt of the run it restores -- a
    record cannot be produced before any production run, or from a run whose
    postflight never confirmed the exemption was in force.
    """
    verified = preflight.verify_index_restored(readback)
    file_digest = hashlib.sha256(indexes_path.read_bytes()).hexdigest()
    if file_digest != campaign.INDEXES_SHA256_BEFORE:
        raise ValueError("index configuration file is not the declared before state")
    if receipt.get("postflightComplete") is not True:
        raise ValueError("production receipt does not confirm postflight completed")
    exemption = receipt.get("indexExemption")
    if (
        not isinstance(exemption, dict)
        or exemption.get("verifiedAtPostflight") is not True
    ):
        raise ValueError(
            "production receipt does not confirm the exemption was verified "
            "at postflight"
        )
    ticket = receipt.get("ticket")
    reservation = ticket.get("reservation") if isinstance(ticket, dict) else None
    if not isinstance(reservation, str) or not reservation:
        raise ValueError("production receipt does not carry a reservation ticket")
    gate_digest = receipt.get("gateDigest")
    if not isinstance(gate_digest, str) or len(gate_digest) != 64:
        raise ValueError("production receipt does not carry a Gate digest")
    return {
        "kind": campaign.RESTORE_RECORD_KIND,
        "campaignId": campaign.CAMPAIGN,
        "field": preflight.INDEX_FIELD,
        "readbackSha256": hashlib.sha256(raw).hexdigest(),
        "bodyDigest": verified["bodyDigest"],
        "projection": verified["projection"],
        "projectionDigest": verified["projectionDigest"],
        "inheritedIndexes": verified["inheritedIndexes"],
        "conformanceIndexesSha256": file_digest,
        "receiptDigest": digest(receipt),
        "reservationTicket": reservation,
        "gateDigest": gate_digest,
        "verified": True,
    }


def validate_restore_record(record: dict) -> None:
    """A restore record must be this campaign's, judged on the restored state,
    and bound to the production receipt of the run it restores."""
    if (
        not isinstance(record, dict)
        or record.get("kind") != campaign.RESTORE_RECORD_KIND
        or record.get("campaignId") != campaign.CAMPAIGN
        or record.get("field") != preflight.INDEX_FIELD
        or record.get("verified") is not True
        or record.get("projection") != preflight.EXPECTED_INDEX_RESTORED_PROJECTION
        or record.get("projectionDigest") != preflight.expected_index_restored_digest()
        or record.get("conformanceIndexesSha256") != campaign.INDEXES_SHA256_BEFORE
        or not isinstance(record.get("inheritedIndexes"), list)
        or not isinstance(record.get("reservationTicket"), str)
        or not record.get("reservationTicket")
        or any(
            not isinstance(record.get(key), str) or len(record[key]) != 64
            for key in ("readbackSha256", "bodyDigest", "receiptDigest", "gateDigest")
        )
    ):
        raise ValueError(
            "restore record does not prove the restored default bound to a "
            "production receipt"
        )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    precondition = campaign.index_exemption_precondition()
    if args.precondition:
        print(json.dumps(precondition, indent=2, sort_keys=True))
        return 0
    if args.verify_deployed is not None:
        readback, _raw = _readback(args.verify_deployed)
        try:
            preflight.verify_index_exemption(
                readback,
                {
                    "indexExemptionProjectionDigest": precondition["readback"][
                        "projectionDigest"
                    ]
                },
            )
        except ValueError as error:
            print(f"deployed: refused ({error})", file=sys.stderr)
            return 2
        print("deployed: exemption in force; the default ancestor is named")
        return 0
    if args.verify_restored is not None:
        if args.receipt is None:
            print(
                "restored: --receipt is required with --verify-restored",
                file=sys.stderr,
            )
            return 2
        readback, raw = _readback(args.verify_restored)
        receipt = _load_receipt(args.receipt)
        try:
            record = restore_record(
                readback, raw, indexes_path=args.file, receipt=receipt
            )
        except ValueError as error:
            print(f"restored: refused ({error})", file=sys.stderr)
            return 2
        if args.record.exists() or args.record.is_symlink():
            print(
                "restored: a restore record already exists; not replaced",
                file=sys.stderr,
            )
            return 2
        args.record.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        print(f"restored: {record['projectionDigest']}  {args.record}")
        return 0
    if args.write_after is not None:
        target = args.write_after
        if target.is_symlink():
            raise SystemExit("refusing to write through a symlink")
        current = hashlib.sha256(target.read_bytes()).hexdigest()
        if current != precondition["conformanceIndexesSha256Before"]:
            print(
                "the index configuration is not in the declared before state; "
                "refusing to append the exemption",
                file=sys.stderr,
            )
            return 2
        content = campaign.indexes_after_bytes()
        if (
            hashlib.sha256(content).hexdigest()
            != precondition["conformanceIndexesSha256After"]
        ):
            raise SystemExit("computed after state differs from the declaration")
        target.write_bytes(content)
        print(precondition["conformanceIndexesSha256After"])
        return 0
    expected = precondition[
        "conformanceIndexesSha256Before"
        if args.verify == "before"
        else "conformanceIndexesSha256After"
    ]
    observed = hashlib.sha256(args.file.read_bytes()).hexdigest()
    print(f"{args.verify}: expected {expected} observed {observed}")
    return 0 if observed == expected else 2


if __name__ == "__main__":
    raise SystemExit(main())
