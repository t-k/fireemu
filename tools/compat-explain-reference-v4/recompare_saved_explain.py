"""Recompare a frozen Explain receipt with a current local shadow.

The saved production receipt and its original local shadow are validated from
the historical collector checkout. The current local shadow is validated from
this checkout. No production request is made and neither input is modified.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))

from batch_contract import PROJECT
from batch_pair import normalize
from broad_contract import digest
from campaign_explain import normalize_response, validate_envelope


def _read_object(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"regular JSON file required: {path}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def _validate_historical_commit_binding(
    *,
    checkout_commit: str,
    production_execution_commit: str,
    original_local_execution_commit: str,
) -> None:
    """Require both frozen receipts to identify the selected checkout."""
    for label, execution_commit in (
        ("production", production_execution_commit),
        ("original local", original_local_execution_commit),
    ):
        if execution_commit != checkout_commit:
            raise ValueError(
                f"historical {label} executionCommit does not match checkout "
                f"{checkout_commit}"
            )


def _validate_historical_receipts(
    production_path: Path, original_local_path: Path, historical_commit: str
) -> dict:
    """Validate both frozen operands with the exact historical collector."""
    with tempfile.TemporaryDirectory(prefix="fireemu-explain-history-") as directory:
        checkout = Path(directory) / "checkout"
        subprocess.run(
            ["git", "clone", "--quiet", "--no-hardlinks", str(ROOT), str(checkout)],
            check=True,
            cwd=ROOT,
        )
        subprocess.run(
            ["git", "checkout", "--quiet", historical_commit],
            check=True,
            cwd=checkout,
        )
        checkout_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=checkout, text=True
        ).strip()
        helper = r'''
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "tools/compat-broad"))
import campaign_explain as historical

production_path = Path(sys.argv[1])
local_path = Path(sys.argv[2])
production = json.loads(production_path.read_bytes())
local = json.loads(local_path.read_bytes())
historical.validate_envelope(
    local, local=True, directory=local_path.parent
)
historical.validate_envelope(production, local=False)
if production["localRecordSha256"] != historical.digest(local):
    raise ValueError("historical production/local binding differs")
print(json.dumps({
    "production": {
        "executionCommit": production["executionCommit"],
        "manifestDigest": production["manifestDigest"],
        "observerSha256": production["observerSha256"],
        "comparisonContractDigest": production["comparisonContractDigest"],
        "recordedCompatibility": production.get("compatibility"),
        "localRecordSha256": production["localRecordSha256"],
    },
    "originalLocal": {
        "executionCommit": local["executionCommit"],
        "manifestDigest": local["manifestDigest"],
        "observerSha256": local["observerSha256"],
        "comparisonContractDigest": local["comparisonContractDigest"],
        "recordSha256": historical.digest(local),
    },
}))
'''
        completed = subprocess.run(
            [sys.executable, "-c", helper, str(production_path), str(original_local_path)],
            cwd=checkout,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise ValueError(
                "historical receipt validation failed: "
                + (completed.stderr.strip() or completed.stdout.strip())
            )
        historical = json.loads(completed.stdout)
        _validate_historical_commit_binding(
            checkout_commit=checkout_commit,
            production_execution_commit=historical["production"]["executionCommit"],
            original_local_execution_commit=historical["originalLocal"][
                "executionCommit"
            ],
        )
        historical["historicalCollectorCommit"] = checkout_commit
        return historical


def _normalization_names(nonce: str) -> dict:
    return {
        "firestoreParents": {
            "campaign": f"projects/{PROJECT}/databases/(default)/documents/campaign/{nonce}"
        }
    }


def _canonicalize_nonce(value, nonce: str):
    if isinstance(value, str):
        return value.replace(nonce, "<campaign-nonce>")
    if isinstance(value, list):
        return [_canonicalize_nonce(item, nonce) for item in value]
    if isinstance(value, dict):
        return {
            key: _canonicalize_nonce(item, nonce) for key, item in value.items()
        }
    return value


def _normalized_body(nonce: str, row: dict) -> object:
    return normalize_response(
        row["body"],
        nonce,
        operation=row["request"],
        status=row["status"],
    )


def _write_output_exclusively(output: Path, result: dict, input_paths: tuple[Path, ...]) -> None:
    output_resolved = output.resolve(strict=False)
    if any(output_resolved == input_path.resolve() for input_path in input_paths):
        raise ValueError(f"output must be a new regular file: {output}")
    if os.path.lexists(output):
        raise ValueError(f"output must be a new regular file: {output}")

    output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result, indent=2) + "\n"
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ValueError(f"output must be a new regular file: {output}") from error
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _absolute_without_resolving(path: Path) -> Path:
    """Normalize CLI paths for subprocesses while retaining symlink identity."""
    return Path(os.path.abspath(os.fspath(path)))


def recompare(
    production_path: Path,
    original_local_path: Path,
    current_local_path: Path,
    historical_commit: str,
) -> dict:
    production = _read_object(production_path)
    _read_object(original_local_path)
    current_local = _read_object(current_local_path)
    historical = _validate_historical_receipts(
        production_path, original_local_path, historical_commit
    )
    validate_envelope(current_local, local=True, directory=current_local_path.parent)

    production_rows = production["receipt"]["rows"]
    local_rows = current_local["receipt"]["rows"]
    if len(production_rows) != len(local_rows):
        raise ValueError("observation row count differs")

    rows = []
    for production_row, local_row in zip(production_rows, local_rows, strict=True):
        if production_row.get("id") != local_row.get("id"):
            raise ValueError("observation row identity differs")
        if _canonicalize_nonce(
            production_row["request"], production["nonce"]
        ) != _canonicalize_nonce(local_row["request"], current_local["nonce"]):
            raise ValueError("observation operation differs")
        production_body = _normalized_body(production["nonce"], production_row)
        local_body = _normalized_body(current_local["nonce"], local_row)
        # The current normalizer projects only the explicitly documented duration.
        # Re-run the shared normalizer without that projection to classify the reason.
        raw_production = normalize(
            production_row["body"],
            _normalization_names(production["nonce"]),
            service="firestore",
        )
        raw_local = normalize(
            local_row["body"],
            _normalization_names(current_local["nonce"]),
            service="firestore",
        )
        projected_equal = digest([production_row["status"], production_body]) == digest(
            [local_row["status"], local_body]
        )
        raw_equal = digest([production_row["status"], raw_production]) == digest(
            [local_row["status"], raw_local]
        )
        if projected_equal:
            verdict = "match"
            classification = (
                "expected-nondeterminism" if not raw_equal else "exact"
            )
        else:
            verdict = "mismatch"
            classification = "semantic-difference"
        rows.append(
            {
                "id": production_row["id"],
                "productionStatus": production_row["status"],
                "localStatus": local_row["status"],
                "productionBodyDigest": digest(production_row["body"]),
                "localBodyDigest": digest(local_row["body"]),
                "normalizedProductionDigest": digest(production_body),
                "normalizedLocalDigest": digest(local_body),
                "verdict": verdict,
                "classification": classification,
            }
        )

    return {
        "kind": "query-explain-saved-production-recomparison-v1",
        "productionExecuted": False,
        "historicalValidation": historical,
        "currentLocal": {
            "executionCommit": current_local["executionCommit"],
            "manifestDigest": current_local["manifestDigest"],
            "observerSha256": current_local["observerSha256"],
            "comparisonContractDigest": current_local["comparisonContractDigest"],
            "configurationDigest": current_local["configurationDigest"],
            "recordSha256": digest(current_local),
            "artifactSha256": current_local["runtime"]["artifactSha256"],
        },
        "originalProductionCompatibility": production.get("compatibility"),
        "recordingComplete": production["recordingComplete"]
        and current_local["recordingComplete"],
        "stateVerified": production["stateVerified"] and current_local["stateVerified"],
        "cleanupComplete": production["cleanupComplete"]
        and current_local["cleanupComplete"],
        "rows": rows,
        "compatibility": "match"
        if all(row["verdict"] == "match" for row in rows)
        else "mismatch",
        "expectedNondeterminismRows": [
            row["id"]
            for row in rows
            if row["classification"] == "expected-nondeterminism"
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", type=Path, required=True)
    parser.add_argument("--original-local", type=Path, required=True)
    parser.add_argument("--current-local", type=Path, required=True)
    parser.add_argument("--historical-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    production = _absolute_without_resolving(args.production)
    original_local = _absolute_without_resolving(args.original_local)
    current_local = _absolute_without_resolving(args.current_local)
    output = _absolute_without_resolving(args.output)
    result = recompare(
        production,
        original_local,
        current_local,
        args.historical_commit,
    )
    _write_output_exclusively(
        output,
        result,
        (production, original_local, current_local),
    )
    print(
        json.dumps(
            {"compatibility": result["compatibility"], "rows": len(result["rows"])}
        )
    )
    return 0 if result["compatibility"] in {"match", "mismatch"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
