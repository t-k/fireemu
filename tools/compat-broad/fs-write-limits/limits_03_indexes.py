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
sys.path.insert(0, str(HERE))

import limits_03_descriptor as campaign


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
    parser.add_argument("--file", type=Path, default=ROOT / campaign.INDEXES_FILE)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    precondition = campaign.index_exemption_precondition()
    if args.precondition:
        print(json.dumps(precondition, indent=2, sort_keys=True))
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
