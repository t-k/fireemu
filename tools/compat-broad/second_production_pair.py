"""Compare independently admitted mapped receipts without inventing oracle results."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from broad_contract import digest
from second_admission import equal
from second_mapping import comparable, validate_rows, validate_trace


def observed_value(row, bindings):
    value = comparable(row, bindings)
    http = row["observation"]["http"]
    # Scope equivalence to JSON and its conventional UTF-8 spelling only.
    # Unknown parameters and other media types keep their full header value.
    if re.fullmatch(
        r'[ \t]*application/json[ \t]*(?:;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8")[ \t]*)?',
        http["contentType"],
        flags=re.IGNORECASE | re.ASCII,
    ):
        value["observation"]["wire"]["contentType"] = "application/json"
    if http["bodyKind"] != "json":
        value["observation"]["rawBody"] = {
            k: http[k] for k in ("bodySha256", "receivedBytes")
        }
    return value


def compare(production, local):
    from second_production_contract import (
        binding,
        manifest,
        observer_digest,
        validate_receipt_environment,
    )

    errors = []
    safety = []
    for target, result in (("production", production), ("local", local)):
        try:
            if result.get("target") != target or result.get("mode") != "mapped":
                raise ValueError("distinct production/local mapped targets required")
            if (
                result.get("manifestDigest") != digest(manifest())
                or result.get("comparisonContractDigest") != digest(binding())
                or result.get("observerDigest") != observer_digest()
            ):
                raise ValueError("manifest, comparison contract, or observer not bound")
            if not validate_receipt_environment(result):
                raise ValueError("environment evidence incomplete")
            validate_rows(result, observed_outcomes=True)
            safety.append(validate_trace(result, observed_outcomes=True))
        except (ValueError, KeyError, TypeError, StopIteration) as error:
            errors.append({"side": target, "reason": str(error)})
    identity = local.get("runtimeIdentity")
    if (
        not isinstance(identity, dict)
        or set(identity) != {"artifactSha256", "executionCommit", "configurationDigest"}
        or not all(isinstance(v, str) and v for v in identity.values())
    ):
        errors.append({"side": "local", "reason": "fixed runtime identity unavailable"})
    complete = all(r.get("recordingComplete") is True for r in (production, local))
    cleanup = all(r.get("cleanupComplete") is True for r in (production, local))
    rows = []
    if not errors:
        for left, right in zip(production["rows"], local["rows"], strict=True):
            rows.append(
                {
                    "id": left["id"],
                    "compatibility": "match"
                    if equal(
                        observed_value(left, production["bindings"]),
                        observed_value(right, local["bindings"]),
                    )
                    else "mismatch",
                }
            )
    return {
        "kind": "second45-production-local-comparison-v2",
        "comparisonContractDigest": digest(binding()),
        "inputDigests": [digest(r) for r in (production, local)],
        "recordingComplete": complete,
        "cleanupComplete": cleanup,
        "stateValidation": False
        if False in safety or any(r.get("safety") is False for r in (production, local))
        else (True if len(safety) == 2 and all(safety) else None),
        "compatibility": "indeterminate"
        if errors or not complete or not cleanup
        else (
            "match" if all(r["compatibility"] == "match" for r in rows) else "mismatch"
        ),
        "rows": rows,
        "errors": errors,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--production", type=Path, required=True)
    parser.add_argument("--local", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = compare(
        json.loads(args.production.read_text()), json.loads(args.local.read_text())
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    return (
        1
        if not result["recordingComplete"]
        or not result["cleanupComplete"]
        or result["compatibility"] == "indeterminate"
        or (args.check and result["compatibility"] != "match")
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
