"""Fresh full-response observations for the reviewed aggregation slice.

This module never approves evidence. Production mutations use the original exact
UUID fixture ownership/journal/cleanup rules, never a database enumeration.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from aggregation_corpus import SCOPE, corpus, query_body
from aggregation_index import cleanup_index, prepare_index
from evidence_common import ROOT, fingerprint, probe_inputs, require, save
from probe import (
    DATABASE,
    NUMBER,
    PROJECT,
    cleanup_resources,
    endpoint,
    owned_name,
    request,
    require_status,
    summarize_aggregation,
)


def observe(
    target: str, output: Path, origin: str | None = None, collection: str | None = None
) -> dict:
    output.touch(exist_ok=False)
    base = endpoint(target, origin)
    template = corpus()
    report = {
        "schemaVersion": 2,
        "acceptance": "candidate",
        "target": target,
        "connection": "production"
        if target == "production"
        else "external-daemon-unverified",
        "scope": SCOPE,
        "recordedAt": datetime.now(UTC).isoformat(),
        "probeSource": {
            "commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "files": probe_inputs(),
        },
        "corpusSha256": fingerprint(template),
        "project": PROJECT,
        "cases": [],
        "cleanup": [],
        "status": "inconclusive",
    }
    attempted, confirmed = [], []
    marker = uuid.uuid4().hex
    collection = collection or f"compat_{uuid.uuid4().hex}"
    owned_name(collection, "A")
    report["collection"] = collection
    index_receipt = {}
    report["index"] = index_receipt
    token = "owner"
    try:
        if target == "production":
            token = subprocess.check_output(
                ["gcloud", "auth", "application-default", "print-access-token"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
            status, project = request(
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}",
                token,
            )
            require_status(status, 200)
            require(
                isinstance(project, dict)
                and project.get("projectId") == PROJECT
                and str(project.get("projectNumber")) == NUMBER,
                "production project mismatch",
            )
            report["verifiedProjectNumber"] = NUMBER
            status, db = request(f"{base}/v1/{DATABASE}", token)
            require_status(status, 200)
            if not isinstance(db, dict):
                raise ValueError("invalid database readback")
            require(
                db.get("type") == "FIRESTORE_NATIVE"
                and db.get("databaseEdition") == "STANDARD",
                "requires Standard/Native",
            )
            report["database"] = {
                key: db.get(key)
                for key in [
                    "name",
                    "type",
                    "databaseEdition",
                    "concurrencyMode",
                    "locationId",
                ]
            }
        if target == "production":
            prepare_index(
                token, collection, index_receipt, lambda: save(output, report)
            )
        report["ownershipMarker"] = marker
        document_base = f"{base}/v1/{DATABASE}/documents"
        for key, fields in template["fixtures"].items():
            name = owned_name(collection, key)
            fields["__fireemuOracleOwner"] = {"stringValue": marker}
            attempted.append(name)
            report["attemptedResources"] = list(attempted)
            save(output, report)
            status, _ = request(
                f"{document_base}:commit",
                token,
                {
                    "writes": [
                        {
                            "update": {"name": name, "fields": fields},
                            "currentDocument": {"exists": False},
                        }
                    ]
                },
            )
            require_status(status, 200)
            confirmed.append(name)
            report["ownedResources"] = list(confirmed)
        before = {}
        for name in confirmed:
            status, document = request(f"{base}/v1/{name}", token)
            require_status(status, 200)
            before[name] = document
        report["stateBefore"] = before
        for case in template["queries"]:
            body = query_body(case, collection)
            status, raw = request(f"{document_base}:runAggregationQuery", token, body)
            result = {
                "id": case["id"],
                "request": body,
                "httpStatus": status,
                "rawResponse": raw,
                "passed": False,
            }
            report["cases"].append(result)
            save(output, report)
            require_status(status, 200)
            result["passed"] = summarize_aggregation(raw) == case["expected"]
        writes = {
            "writes": [
                {
                    "update": {
                        "name": owned_name(collection, "A"),
                        "fields": {"x": {"integerValue": "99"}},
                    }
                },
                {
                    "update": {"name": owned_name(collection, "D"), "fields": {}},
                    "currentDocument": {"exists": False},
                },
            ]
        }
        status, raw = request(f"{document_base}:commit", token, writes)
        report["cases"].append(
            {
                "id": "refused-commit",
                "request": writes,
                "httpStatus": status,
                "rawResponse": raw,
                "passed": status == 409
                and isinstance(raw, dict)
                and raw.get("error", {}).get("status") == "ALREADY_EXISTS",
            }
        )
        after = {}
        for name in confirmed:
            status, document = request(f"{base}/v1/{name}", token)
            require_status(status, 200)
            after[name] = document
        report["stateAfter"] = after
        report["cases"].append({"id": "unchanged-state", "passed": before == after})
        report["status"] = (
            "passed" if all(row["passed"] for row in report["cases"]) else "failed"
        )
    except Exception as error:  # noqa: BLE001 -- sanitize credential-bearing transport errors.
        report["failure"] = type(error).__name__
    finally:
        report["cleanup"] = cleanup_resources(base, token, attempted, confirmed, marker)
        if target == "production":
            cleanup_index(
                token, collection, index_receipt, lambda: save(output, report)
            )
            if index_receipt.get("createAttempted") and not index_receipt.get(
                "confirmedMissing"
            ):
                report["status"] = "cleanup-incomplete"
        if len(report["cleanup"]) != 4 or not all(
            row["confirmedMissing"] for row in report["cleanup"]
        ):
            report["status"] = "cleanup-incomplete"
        save(output, report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["production", "local"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--origin")
    args = parser.parse_args()
    origin = args.origin
    if args.target == "local" and origin is None:
        origin = f"http://{os.environ['FIRESTORE_EMULATOR_HOST']}"
    result = observe(args.target, args.output, origin)
    if result["status"] != "passed":
        raise SystemExit("Aggregation observation incomplete; inspect candidate")
    print(
        f"{args.target}: {len(result['cases'])} cases; exact fixture cleanup complete"
    )


if __name__ == "__main__":
    main()
