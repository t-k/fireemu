"""Bounded ordering diagnostics, not compatibility approvals or learned expectations."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat-inventory"))

from aggregation_corpus import corpus
from aggregation_evidence import validate_aggregate_fields
from evidence_common import ROOT, fingerprint, require, save, sha
from owned_runner import control_get, local_addresses
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


def cases(collection: str) -> list[dict]:
    rows = []
    for label, field in [
        ("omitted", None),
        ("name-asc", "__name__"),
        ("x-asc", "x"),
        ("x-asc-offset", "x"),
        ("x-desc", "x"),
    ]:
        query = {"from": [{"collectionId": collection}], "limit": 2}
        if field is not None:
            query["orderBy"] = [
                {
                    "field": {"fieldPath": field},
                    "direction": "DESCENDING" if label == "x-desc" else "ASCENDING",
                }
            ]
        if label == "x-asc-offset":
            query.update(offset=2, limit=1)
        for kind in ["count-sum", "sum", "documents"]:
            aggregations = [{"alias": "sum", "sum": {"field": {"fieldPath": "x"}}}]
            if kind == "count-sum":
                aggregations.insert(0, {"alias": "count", "count": {}})
            body = (
                {"structuredQuery": query}
                if kind == "documents"
                else {
                    "structuredAggregationQuery": {
                        "structuredQuery": query,
                        "aggregations": aggregations,
                    }
                }
            )
            rows.append(
                {
                    "id": f"{label}-{kind}",
                    "method": "runQuery"
                    if kind == "documents"
                    else "runAggregationQuery",
                    "body": deepcopy(body),
                }
            )
    return rows


def validate_timestamp(value: object) -> None:
    require(
        isinstance(value, str)
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
            value,
        )
        is not None,
        "invalid timestamp",
    )
    if not isinstance(value, str):
        raise ValueError("invalid timestamp type")  # noqa: TRY004 -- protocol validation error
    require(datetime.fromisoformat(value).utcoffset() is not None, "naive timestamp")


def document_ids(raw: object, prefix: str) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("invalid document stream")
    result = []
    for row in raw:
        require(
            isinstance(row, dict)
            and bool(row)
            and not set(row) - {"document", "readTime", "skippedResults"},
            "invalid document stream element",
        )
        if "skippedResults" in row:
            require(
                type(row["skippedResults"]) is int
                and 0 <= row["skippedResults"] <= 2147483647
                and "readTime" in row,
                "invalid skippedResults",
            )
        if "readTime" in row:
            validate_timestamp(row["readTime"])
        if "document" not in row:
            continue
        document = row["document"]
        require(
            isinstance(document, dict)
            and set(document) == {"name", "fields", "createTime", "updateTime"}
            and isinstance(document.get("fields"), dict),
            "invalid document",
        )
        names = {prefix + "/" + key: key for key in corpus()["fixtures"]}
        require(document.get("name") in names, "foreign document in diagnostic")
        for key in ["createTime", "updateTime"]:
            validate_timestamp(document[key])
        fields = document["fields"]
        owner = fields.get("__fireemuOracleOwner")
        require(
            isinstance(owner, dict)
            and set(owner) == {"stringValue"}
            and isinstance(owner["stringValue"], str)
            and re.fullmatch(r"[a-f0-9]{32}", owner["stringValue"]) is not None,
            "invalid fixture owner",
        )
        require(
            fingerprint(fields)
            == fingerprint(
                {
                    **corpus()["fixtures"][names[document["name"]]],
                    "__fireemuOracleOwner": owner,
                }
            ),
            "invalid fixture fields",
        )
        result.append(names[document["name"]])
    require(len(result) == len(set(result)), "duplicate document")
    return result


def observe(target: str, output: Path) -> dict:
    output.touch(exist_ok=False)
    origin = (
        None
        if target == "production"
        else "http://" + os.environ["FIRESTORE_EMULATOR_HOST"]
    )
    base = endpoint(target, origin)
    collection, marker = "compat_" + uuid.uuid4().hex, uuid.uuid4().hex
    report = {
        "schemaVersion": 1,
        "kind": "ordering-diagnostic",
        "acceptance": "unapproved-observation",
        "target": target,
        "project": PROJECT,
        "collection": collection,
        "recordedAt": datetime.now(UTC).isoformat(),
        "toolSha256": sha(Path(__file__).read_bytes()),
        "caseSha256": fingerprint(cases("COLLECTION")),
        "sourceCommit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "cases": [],
        "status": "inconclusive",
        "ownershipMarker": marker,
    }
    token = "owner"
    attempted, confirmed = [], []
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
                "project identity mismatch",
            )
            status, database = request(base + "/v1/" + DATABASE, token)
            require_status(status, 200)
            require(
                isinstance(database, dict)
                and database.get("name") == DATABASE
                and database.get("databaseEdition") == "STANDARD"
                and database.get("type") == "FIRESTORE_NATIVE",
                "database identity mismatch",
            )
            report["database"] = database
            report["verifiedProjectNumber"] = NUMBER
        else:
            firestore, control = local_addresses(
                os.environ["FIRESTORE_EMULATOR_HOST"], os.environ["FIREEMU_CONTROL_URL"]
            )
            control_token = os.environ["FIREEMU_CONTROL_TOKEN"]
            status, caps = control_get(control, "/v1/capabilities", control_token)
            good, resources = control_get(
                control, "/v1/sessions/default/resources", control_token
            )
            bad, _ = control_get(
                control, "/v1/sessions/default/resources", control_token + "-wrong"
            )
            require(
                status == good == 200
                and bad == 403
                and caps.get("profile") == "strict"
                and resources.get("project") == PROJECT,
                "local instance mismatch",
            )
            report["instance"] = {
                "parentPid": os.getppid(),
                "pid": os.getpid(),
                "profile": caps["profile"],
                "version": caps["version"],
                "origin": firestore,
            }
        for key, fields in corpus()["fixtures"].items():
            name = owned_name(collection, key)
            fields["__fireemuOracleOwner"] = {"stringValue": marker}
            attempted.append(name)
            report["attemptedResources"] = list(attempted)
            save(output, report)
            status, _ = request(
                f"{base}/v1/{DATABASE}/documents:commit",
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
        before: dict[str, dict] = {}
        for name in confirmed:
            status, document = request(f"{base}/v1/{name}", token)
            require_status(status, 200)
            if not isinstance(document, dict):
                raise ValueError("invalid fixture snapshot")  # noqa: TRY004 -- protocol validation error
            before[name] = document
        document_ids(
            [{"document": doc} for doc in before.values()],
            f"{DATABASE}/documents/{collection}",
        )
        require(
            all(
                doc["fields"]["__fireemuOracleOwner"] == {"stringValue": marker}
                for doc in before.values()
            ),
            "fixture owner mismatch",
        )
        report["before"] = before
        for case in cases(collection):
            status, raw = request(
                f"{base}/v1/{DATABASE}/documents:{case['method']}", token, case["body"]
            )
            row = {**case, "httpStatus": status, "rawResponse": raw}
            report["cases"].append(row)
            save(output, report)
            if status != 200:
                continue
            if case["method"] == "runQuery":
                row["documentIds"] = document_ids(
                    raw, f"{DATABASE}/documents/{collection}"
                )
                require(
                    all(
                        item["document"] == before[item["document"]["name"]]
                        for item in raw
                        if "document" in item
                    ),
                    "query document differs from fixture snapshot",
                )
            else:
                fields = summarize_aggregation(raw)
                aliases = {
                    a["alias"]: {}
                    for a in case["body"]["structuredAggregationQuery"]["aggregations"]
                }
                validate_aggregate_fields(fields, {"expected": aliases})
                row["aggregateFields"] = fields
        after = {}
        for name in confirmed:
            status, document = request(f"{base}/v1/{name}", token)
            require_status(status, 200)
            after[name] = document
        report["after"] = after
        require(before == after, "read-only diagnostics changed fixtures")
        if all(row["httpStatus"] == 200 for row in report["cases"]):
            report["status"] = "observed"
    except Exception as error:  # noqa: BLE001 -- never print credential-bearing transport errors.
        report["failure"] = type(error).__name__
    finally:
        report["cleanup"] = cleanup_resources(base, token, attempted, confirmed, marker)
        if (
            len(confirmed) != 4
            or len(report["cleanup"]) != 4
            or not all(row["confirmedMissing"] for row in report["cleanup"])
        ):
            report["status"] = "cleanup-incomplete"
        save(output, report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["production", "local"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = observe(args.target, args.output)
    print(
        json.dumps(
            {
                "status": result["status"],
                "cases": len(result["cases"]),
                "cleanup": len(result["cleanup"]),
            }
        )
    )
    raise SystemExit(0 if result["status"] == "observed" else 1)
