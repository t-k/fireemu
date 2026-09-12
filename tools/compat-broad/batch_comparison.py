"""Compare mapped local responses with the same current abstract sequence, never old-ID joins."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from batch_contract import candidate
from broad_cases import check_generated, generated_programs
from broad_contract import ROOT, decision, digest, first_difference


def normalize(value, parent):
    # The closed candidate contains no seeded timestamps >= 2026. Match the inherited
    # session's documented server-time placeholder, without erasing IDs/types/order.
    if isinstance(value, str):
        if (
            re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", value)
            and int(value[:4]) >= 2026
        ):
            return "<now>"
        if value == parent or value.startswith(parent + "/"):
            return (
                "projects/demo-firestore-probe/databases/(default)/documents"
                + value[len(parent) :]
            )
        return value
    if isinstance(value, list):
        return [normalize(item, parent) for item in value]
    if isinstance(value, dict):
        return {k: normalize(v, parent) for k, v in value.items()}
    return value


def compare(batch, baseline):
    manifest = candidate()
    if (
        batch["manifestDigest"] != digest(manifest)
        or batch["productionExecuted"] is not False
    ):
        raise ValueError("only this candidate's local mapping validation is supported")
    normalizer = "conformance/src/firestore-probe/session.mjs"
    if (
        baseline["executionInputs"][normalizer]
        != hashlib.sha256((ROOT / normalizer).read_bytes()).hexdigest()
    ):
        raise ValueError("baseline normalizer changed")
    selected = {p["id"]: p for p in baseline["selectedPrograms"]["firestore"]}
    if any(
        digest(p) != digest(selected.get(p["id"]))
        for p in manifest["firestorePrograms"]
    ):
        raise ValueError("abstract operation sequence differs")
    compared, generated = [], {}
    seen = set()
    for row in batch["rows"]:
        if row["id"] in seen:
            raise ValueError("duplicate result")
        seen.add(row["id"])
        if row["id"].startswith("auth:"):
            compared.append(
                {
                    "id": row["id"],
                    "basis": "local-invariant",
                    "passed": row["status"] == "pass",
                }
            )
            continue
        body = row["body"]
        error = (
            next((item["error"] for item in body if "error" in item), None)
            if isinstance(body, list)
            else body.get("error")
        )
        got = {
            "status": row["status"],
            "code": error.get("status", str(error.get("code", ""))) if error else "OK",
        }
        if not error:
            got["body"] = normalize(body, row["mappedParent"])
        name, step = row["id"].removeprefix("firestore:").split("#")
        if name.startswith("broad/"):
            generated[step] = got
        else:
            expected = baseline["localObservations"]["firestore"][name]["steps"][step]
            difference = first_difference(decision(got), decision(expected))
            compared.append(
                {
                    "id": row["id"],
                    "basis": "same-current-sequence-local-mapping-comparison",
                    "passed": difference is None,
                    "firstDifference": difference,
                }
            )
    compared.extend(
        {"id": row["id"], "basis": row["basis"], "passed": row["status"] == "pass"}
        for row in check_generated(generated_programs()[0], {"steps": generated})
    )
    expected_ids = {
        row["id"] for row in baseline["cases"] if row["id"].startswith("auth:broad/")
    }
    expected_ids.update(
        "firestore:" + p["id"] + "#" + step["id"]
        for p in manifest["firestorePrograms"]
        for step in p["steps"]
    )
    if seen != expected_ids:
        raise ValueError("missing or unexpected diagnostic rows")
    return {
        "productionComparison": False,
        "rows": compared,
        "passed": sum(row["passed"] for row in compared),
        "total": len(compared),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = compare(
        json.loads(args.batch.read_bytes()), json.loads(args.baseline.read_bytes())
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": result["passed"], "total": result["total"]}))
