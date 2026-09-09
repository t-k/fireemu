"""Package reviewed inputs and complete candidates without synthesizing approval."""

import argparse
import gzip
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from aggregation_corpus import SCOPE, corpus
from aggregation_evidence import DIRECTORY, LOCATORS, OBLIGATIONS, URL, validate_bundle
from capture import extract_page
from evidence_common import probe_inputs, require, save, sha


def package(source: Path, local: Path, production: Path) -> None:
    require(not DIRECTORY.exists(), "bundle already exists")
    DIRECTORY.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        dir=DIRECTORY.parent, prefix=".aggregation-stage-"
    ) as temporary:
        staged = Path(temporary) / "bundle"
        stage(source, local, production, staged)
        validate_bundle(staged)
        staged.rename(DIRECTORY)


def stage(source: Path, local: Path, production: Path, directory: Path) -> None:
    raw = source.read_bytes()
    require(
        sha(raw) == "989ff51cba98e3baf92b239fa68986980f122ebef56511d1c98a40335d34a559",
        "not the reviewed source capsule",
    )
    extracted = extract_page(raw.decode())
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "source.html.gz").write_bytes(gzip.compress(raw, mtime=0))
    save(
        directory / "source-review.json",
        {
            "url": URL,
            "rawSha256": sha(raw),
            "bodySha256": sha(extracted["text"].encode()),
            "extractor": extracted["extractor"],
            "extractorSha256": probe_inputs()["capture.py"],
            "fetchedAt": "2026-09-09T14:21:24.817821+00:00",
            "reviewedAt": datetime.now(UTC).date().isoformat(),
            "reviewer": "Codex (agent-authored interpretation, not execution approval)",
            "extent": "selected-sections-only",
            "locators": LOCATORS,
            "obligations": OBLIGATIONS,
            "parentRequirement": "REQ-FS-PARITY-01",
        },
    )
    save(directory / "corpus.json", corpus())
    for name, path in [("local.json", local), ("production.json", production)]:
        save(directory / name, json.loads(path.read_bytes()))
    save(
        directory / "index.json",
        {
            "schemaVersion": 1,
            "scope": SCOPE,
            "approvals": [],
            "files": {p.name: sha(p.read_bytes()) for p in sorted(directory.iterdir())},
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--local", type=Path, required=True)
    parser.add_argument("--production", type=Path, required=True)
    args = parser.parse_args()
    package(args.source, args.local, args.production)
