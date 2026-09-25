"""Strict saved-production comparison for one Firestore REST error condition."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
CASE_ID = "firestore:errors/rest-shapes#write-bad-base64"
PROGRAM_ID = "errors/rest-shapes"
STEP_ID = "write-bad-base64"
HISTORICAL_COMMIT = "2526c61eda5fc53ac91250307786127ae3c601be"
HISTORICAL_MATRIX_DIGEST = (
    "308f0d12a445f4db78a9010d2d3f4f5810e3cf66fe811eab35d9817afc6c042f"
)
EXPECTED_PROGRAM_DIGEST = (
    "c4b201decb3adaf50ac1f9173b927bf6729bd7e2ee8785aacae2664adcbe69db"
)
EXPECTED_STEP_DIGEST = (
    "a1154c823058e82acc258c1c0049dd9491dde96da2dbda16689ff5cebe8c8282"
)
HTTP_CONTRACT = "bounded-http-v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _indeterminate(reason: str) -> dict[str, Any]:
    return {
        "id": CASE_ID,
        "status": "indeterminate",
        "reason": reason,
        "productionExecuted": False,
    }


def _historical_program() -> dict[str, Any]:
    output = subprocess.check_output(
        [
            "node",
            "--input-type=module",
        ],
        input=(
            subprocess.check_output(
                [
                    "git",
                    "show",
                    f"{HISTORICAL_COMMIT}:conformance/src/firestore-probe/programs.mjs",
                ],
                cwd=ROOT,
            )
            + b"\nconsole.log(JSON.stringify(PROGRAMS));\n"
        ),
        cwd=ROOT,
    )
    programs = json.loads(output)
    matches = [program for program in programs if program.get("id") == PROGRAM_ID]
    if len(matches) != 1:
        raise ValueError("historical program identity is not unique")
    return matches[0]


def _valid_hash_map(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and bool(value)
        and all(
            isinstance(path, str)
            and path
            and isinstance(digest, str)
            and SHA256.fullmatch(digest) is not None
            for path, digest in value.items()
        )
    )


def _valid_parent_seal(manifest: dict[str, Any]) -> bool:
    seal = manifest.get("parentManifestSha256")
    unsigned = {
        key: value for key, value in manifest.items() if key != "parentManifestSha256"
    }
    return (
        isinstance(seal, str)
        and SHA256.fullmatch(seal) is not None
        and seal == _digest(unsigned)
    )


def _valid_http_receipt(actual: Any) -> bool:
    if not isinstance(actual, dict) or not isinstance(actual.get("http"), dict):
        return False
    wire = actual["http"]
    return (
        type(actual.get("status")) is int
        and 100 <= actual["status"] <= 599
        and wire.get("contract") == HTTP_CONTRACT
        and type(wire.get("status")) is int
        and wire["status"] == actual["status"]
        and wire.get("complete") is True
        and wire.get("failure") is None
        and wire.get("truncated") is False
        and wire.get("digestScope") == "full"
        and wire.get("bodyKind") == "json"
        and isinstance(wire.get("contentType"), str)
        and wire.get("contentTypeTruncated") is False
        and type(wire.get("receivedBytes")) is int
        and wire["receivedBytes"] > 0
        and type(wire.get("retainedBytes")) is int
        and wire["retainedBytes"] == wire["receivedBytes"]
        and isinstance(wire.get("bodySha256"), str)
        and SHA256.fullmatch(wire["bodySha256"]) is not None
        and isinstance(actual.get("code"), str)
        and bool(actual["code"])
        and (
            200 <= actual["status"] < 300
            or (isinstance(actual.get("message"), str) and bool(actual["message"]))
        )
    )


def _case_row(rows: Any) -> dict[str, Any] | None:
    if not isinstance(rows, list):
        return None
    matches = [
        row for row in rows if isinstance(row, dict) and row.get("id") == CASE_ID
    ]
    return matches[0] if len(matches) == 1 else None


def compare_evidence(
    manifest: Any,
    cases: Any,
    historical_matrix: Any,
    *,
    expected_source_commit: str,
    current_cases_sha256: str | None = None,
) -> dict[str, Any]:
    """Compare complete current HTTP data against one pinned production row.

    Invalid, missing, stale, or inapplicable evidence always returns indeterminate.
    A mismatch is emitted only after every evidence and provenance check succeeds.
    """
    try:
        if not isinstance(manifest, dict) or not isinstance(cases, dict):
            return _indeterminate("malformed-current-artifact")
        if not isinstance(historical_matrix, dict):
            return _indeterminate("malformed-historical-matrix")
        if _digest(historical_matrix) != HISTORICAL_MATRIX_DIGEST:
            return _indeterminate("historical-matrix-digest-drift")
        if not isinstance(expected_source_commit, str) or not GIT_SHA.fullmatch(
            expected_source_commit
        ):
            return _indeterminate("invalid-expected-source-commit")
        if (
            manifest.get("status") not in {"completed", "incomplete"}
            or manifest.get("stopReason") != "child-completed"
            or manifest.get("exitCode") != 0
            or manifest.get("recordingComplete") is not True
            or manifest.get("productionExecuted") is not False
            or manifest.get("executionCommit") != expected_source_commit
            or GIT_SHA.fullmatch(str(manifest.get("executionCommit", ""))) is None
            or SHA256.fullmatch(str(manifest.get("artifactSha256", ""))) is None
            or not isinstance(manifest.get("build"), dict)
            or manifest["build"].get("artifactSha256") != manifest.get("artifactSha256")
            or manifest["build"].get("inputs") != manifest.get("runtimeInputs")
            or not _valid_hash_map(manifest.get("runtimeInputs"))
            or not _valid_hash_map(manifest.get("executionInputs"))
            or SHA256.fullmatch(str(manifest.get("configurationDigest", ""))) is None
            or not isinstance(manifest.get("ownedProcess"), dict)
            or manifest["ownedProcess"].get("stopped") is not True
            or manifest["ownedProcess"].get("listenersClosed") is not True
            or not _valid_parent_seal(manifest)
            or any(
                manifest.get(key)
                for key in (
                    "cleanupFailure",
                    "parentCleanupFailure",
                    "terminationVerificationFailure",
                    "partialResultFailure",
                    "failureType",
                )
            )
        ):
            return _indeterminate("current-source-artifact-provenance-incomplete")
        if (
            cases.get("kind") != "second-broad-local-http-v1"
            or cases.get("recordingComplete") is not True
            or cases.get("productionExecuted") is not False
            or not isinstance(current_cases_sha256, str)
            or SHA256.fullmatch(current_cases_sha256) is None
            or manifest.get("partialResultSha256") != current_cases_sha256
        ):
            return _indeterminate("current-cases-artifact-unbound-or-incomplete")
        case_row = _case_row(cases.get("cases"))
        parent_row = _case_row(manifest.get("cases"))
        if (
            case_row is None
            or parent_row is None
            or case_row != parent_row
            or case_row.get("collectionComplete") is not True
        ):
            return _indeterminate("missing-or-conflicting-current-condition-row")
        actual = case_row.get("actual")
        if not _valid_http_receipt(actual):
            return _indeterminate("current-http-receipt-incomplete")

        matrix_rows = [
            row
            for row in historical_matrix.get("programs", [])
            if isinstance(row, dict) and row.get("id") == PROGRAM_ID
        ]
        if len(matrix_rows) != 1:
            return _indeterminate("historical-program-missing-or-ambiguous")
        expected = matrix_rows[0].get("steps", {}).get(STEP_ID, {}).get("production")
        if not isinstance(expected, dict):
            return _indeterminate("historical-production-observation-missing")
        program = _historical_program()
        step_rows = [
            step
            for step in program.get("steps", [])
            if isinstance(step, dict) and step.get("id") == STEP_ID
        ]
        if (
            _digest(program) != EXPECTED_PROGRAM_DIGEST
            or len(step_rows) != 1
            or _digest(step_rows[0]) != EXPECTED_STEP_DIGEST
            or expected
            != {
                "status": 400,
                "code": "INVALID_ARGUMENT",
                "message": "Invalid value at 'writes[0].update.fields[0].value.bytes_value' (TYPE_BYTES), Base64 decoding failed for \"!!!\"",
            }
        ):
            return _indeterminate("historical-program-or-step-inapplicable")
        selected = cases.get("selectedPrograms")
        if not isinstance(selected, list):
            return _indeterminate("current-program-unbound")
        current_programs = [
            item
            for item in selected
            if isinstance(item, dict) and item.get("id") == PROGRAM_ID
        ]
        if (
            len(current_programs) != 1
            or _digest(current_programs[0]) != EXPECTED_PROGRAM_DIGEST
        ):
            return _indeterminate("current-program-or-step-inapplicable")
        got = {key: actual.get(key) for key in ("status", "code", "message")}
        difference = next(
            (
                f"$.{key}"
                for key in ("status", "code", "message")
                if got[key] != expected[key]
            ),
            None,
        )
        return {
            "id": CASE_ID,
            "status": "mismatch" if difference else "match",
            "reason": None,
            "firstDifference": difference,
            "expected": expected,
            "actual": got,
            "historicalProgramDigest": EXPECTED_PROGRAM_DIGEST,
            "historicalStepDigest": EXPECTED_STEP_DIGEST,
            "sourceCommit": manifest["executionCommit"],
            "artifactSha256": manifest["artifactSha256"],
            "currentCasesSha256": current_cases_sha256,
            "productionExecuted": False,
        }
    except (
        KeyError,
        TypeError,
        ValueError,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ):
        return _indeterminate("evidence-validation-failed")


def _read_json(path: Path) -> tuple[Any, str]:
    data = path.read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument(
        "--matrix",
        type=Path,
        default=ROOT / "conformance/firestore-production-matrix.json",
    )
    args = parser.parse_args()
    try:
        manifest, _ = _read_json(args.manifest)
        cases, cases_sha256 = _read_json(args.cases)
        matrix, _ = _read_json(args.matrix)
    except (OSError, json.JSONDecodeError):
        result = _indeterminate("evidence-file-missing-or-malformed")
    else:
        result = compare_evidence(
            manifest,
            cases,
            matrix,
            expected_source_commit=args.expected_source_commit,
            current_cases_sha256=cases_sha256,
        )
    print(json.dumps(result, sort_keys=True))
    return {"match": 0, "mismatch": 1, "indeterminate": 2}[result["status"]]


if __name__ == "__main__":
    sys.exit(main())
