"""Emit the frozen FS-LISTEN-SDK inputs that the Node collector reads.

The checked-in JSON under `spec/compatibility/` is generated from this package,
never edited by hand. `test_o6_listen_sdk_spec.py` fails if the two drift, so
the Node side and the Python side always agree on the same catalog and budget.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import cases
from .campaign import BUDGET

CASES_SPEC = "spec/compatibility/fs-listen-sdk-cases.json"
BUDGET_SPEC = "spec/compatibility/fs-listen-sdk-budget.json"


def cases_document() -> dict[str, Any]:
    document = cases.catalog()
    document["catalogDigest"] = cases.catalog_digest()
    return document


def budget_document() -> dict[str, Any]:
    return {
        "schema": "o6-listen-sdk-budget-v1",
        "note": "Local shadow runs use these same bounds; production adds a permission.",
        "budget": dict(BUDGET),
    }


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write_all(repo_root: str | Path) -> list[Path]:
    root = Path(repo_root)
    written = []
    for relative, document in (
        (CASES_SPEC, cases_document()),
        (BUDGET_SPEC, budget_document()),
    ):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render(document), encoding="utf-8")
        written.append(target)
    return written


if __name__ == "__main__":  # pragma: no cover - manual regeneration entrypoint
    import sys

    for written_path in write_all(sys.argv[1] if len(sys.argv) > 1 else "."):
        print(written_path)
