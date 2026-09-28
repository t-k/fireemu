"""Bounded Firestore aggregation/atomicity observation; never enumerates existing data.

Records a candidate receipt, not an accepted expectation. Credentials remain in memory.
Only four exclusively created documents in a UUID root collection can be deleted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

PROJECT = "fireemu-35fe6"
NUMBER = "592603257417"
DATABASE = f"projects/{PROJECT}/databases/(default)"


def endpoint(target: str, origin: str | None) -> str:
    if target == "production" and origin is None:
        return "https://firestore.googleapis.com"
    url = urllib.parse.urlsplit(origin or "")
    if (
        target != "local"
        or url.scheme != "http"
        or url.hostname not in {"localhost", "127.0.0.1", "::1"}
        or url.username
        or url.password
        or url.path
        or url.query
        or url.fragment
    ):
        raise ValueError(
            "use the fixed production endpoint or a bare loopback HTTP origin"
        )
    return str(origin)


def owned_name(collection: str, document: str) -> str:
    if re.fullmatch(r"compat_[a-f0-9]{32}", collection) is None or document not in {
        "A",
        "B",
        "C",
        "D",
    }:
        raise ValueError("resource outside the exact owned fixture namespace")
    return f"{DATABASE}/documents/{collection}/{document}"


def summarize_aggregation(body: object) -> dict:
    if not isinstance(body, list):
        raise TypeError("expected a complete REST response array")
    results = [
        row["result"]["aggregateFields"]
        for row in body
        if isinstance(row, dict)
        and "result" in row
        and "aggregateFields" in row["result"]
    ]
    if len(results) != 1:
        raise ValueError("expected exactly one completed aggregation result")
    return results[0]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("credential-bearing requests never follow redirects")


def request(
    url: str, token: str | None, body: dict | None = None, method: str | None = None
) -> tuple[int, dict | list]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        url, data=data, method=method or ("POST" if data else "GET"), headers=headers
    )
    try:
        response = urllib.request.build_opener(NoRedirect()).open(req, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("probe response exceeds budget")
        status = response.status
        value = json.loads(raw) if raw else {}
        if not isinstance(status, int) or not isinstance(value, (dict, list)):
            raise TypeError("unexpected HTTP/JSON response shape")
        return status, value


def require_status(actual: int, expected: int) -> None:
    if actual != expected:
        raise ValueError(f"unexpected HTTP status {actual}; expected {expected}")


def has_ownership_marker(document: object, marker: str) -> bool:
    return isinstance(document, dict) and document.get("fields", {}).get(
        "__fireemuOracleOwner"
    ) == {"stringValue": marker}


def cleanup_resources(
    origin: str, token: str, attempted: list[str], confirmed: list[str], marker: str
) -> list[dict]:
    results = []
    for name in attempted:
        try:
            recovered = False
            if name not in confirmed:
                status, document = request(f"{origin}/v1/{name}", token)
                if status == 404:
                    results.append(
                        {"name": name, "deleted": False, "confirmedMissing": True}
                    )
                    continue
                require_status(status, 200)
                if not has_ownership_marker(document, marker):
                    raise ValueError(
                        "uncertain create is not demonstrably owned; leave it untouched"
                    )
                recovered = True
            status, _ = request(f"{origin}/v1/{name}", token, method="DELETE")
            require_status(status, 200)
            status, _ = request(f"{origin}/v1/{name}", token)
            require_status(status, 404)
            results.append(
                {
                    "name": name,
                    "deleted": True,
                    "confirmedMissing": True,
                    "recoveredOwnership": recovered,
                }
            )
        except Exception as error:  # noqa: BLE001 -- cleanup must continue after any client failure.
            # A failed request, decoder or transport must not skip remaining cleanup work.
            results.append(
                {
                    "name": name,
                    "deleted": False,
                    "confirmedMissing": False,
                    "error": type(error).__name__,
                }
            )
    return results


def run(target: str, origin: str | None, output: Path, binary: Path) -> None:
    base_origin = endpoint(target, origin)
    # Reserve the candidate output before any production operation; never overwrite evidence.
    with output.open("x") as destination:
        receipt = {
            "schemaVersion": 1,
            "kind": "live-production" if target == "production" else "live-fireemu",
            "acceptance": "candidate",
            "recordedAt": datetime.now(UTC).isoformat(),
            "project": PROJECT,
            "expectedProjectNumber": NUMBER,
            "sourceCommit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True
            ).strip(),
            "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "probeSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "profile": "strict" if target == "local" else "production",
            "sdk": "none (REST via Python stdlib)",
            "cases": [],
            "cleanup": [],
            "status": "inconclusive",
        }
        owned: list[str] = []
        attempted: list[str] = []
        marker = uuid.uuid4().hex
        token = "owner"

        def persist() -> None:
            destination.seek(0)
            destination.write(json.dumps(receipt, indent=2) + "\n")
            destination.truncate()
            destination.flush()
            os.fsync(destination.fileno())

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
                if not isinstance(project, dict):
                    raise ValueError("project response is not an object")
                if (
                    project.get("projectId") != PROJECT
                    or str(project.get("projectNumber")) != NUMBER
                ):
                    raise ValueError("production project identity mismatch")
                receipt["projectNumberVerified"] = True
                status, database = request(f"{base_origin}/v1/{DATABASE}", token)
                require_status(status, 200)
                if not isinstance(database, dict):
                    raise ValueError("database response is not an object")
                receipt["database"] = {
                    key: database.get(key)
                    for key in [
                        "name",
                        "type",
                        "databaseEdition",
                        "concurrencyMode",
                        "locationId",
                    ]
                }
                if (
                    database.get("type") != "FIRESTORE_NATIVE"
                    or database.get("databaseEdition") != "STANDARD"
                ):
                    raise ValueError("this corpus requires Standard / Native")
            collection = f"compat_{uuid.uuid4().hex}"
            base = f"{base_origin}/v1/{DATABASE}/documents"
            fixture = {
                "A": {"x": {"integerValue": "10"}},
                "B": {},
                "C": {"x": {"stringValue": "not-a-number"}},
                "D": {"x": {"integerValue": "20"}},
            }
            for doc, fields in fixture.items():
                name = owned_name(collection, doc)
                fields["__fireemuOracleOwner"] = {"stringValue": marker}
                attempted.append(name)
                receipt["attemptedResources"] = list(attempted)
                receipt["ownershipMarker"] = marker
                persist()
                status, _ = request(
                    f"{base}:commit",
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
                owned.append(name)
                receipt["ownedResources"] = list(owned)
            before = {}
            for name in owned:
                status, value = request(f"{base_origin}/v1/{name}", token)
                require_status(status, 200)
                before[name] = value
            count = {"alias": "count", "count": {}}
            total = {"alias": "sum", "sum": {"field": {"fieldPath": "x"}}}
            average = {"alias": "avg", "avg": {"field": {"fieldPath": "x"}}}
            cases = [
                (
                    "count-alone-includes-missing",
                    [count],
                    {"count": {"integerValue": "4"}},
                ),
                (
                    "count-with-sum-excludes-missing",
                    [count, total],
                    {"count": {"integerValue": "3"}, "sum": {"integerValue": "30"}},
                ),
                (
                    "count-with-avg-excludes-missing",
                    [count, average],
                    {"count": {"integerValue": "3"}, "avg": {"doubleValue": 15}},
                ),
                (
                    "sum-and-avg-ignore-nonnumeric",
                    [total, average],
                    {"sum": {"integerValue": "30"}, "avg": {"doubleValue": 15}},
                ),
            ]
            for case, aggregations, expected in cases:
                status, value = request(
                    f"{base}:runAggregationQuery",
                    token,
                    {
                        "structuredAggregationQuery": {
                            "structuredQuery": {"from": [{"collectionId": collection}]},
                            "aggregations": aggregations,
                        }
                    },
                )
                require_status(status, 200)
                actual = summarize_aggregation(value)
                receipt["cases"].append(
                    {
                        "id": case,
                        "httpStatus": status,
                        "actual": actual,
                        "expected": expected,
                        "passed": actual == expected,
                    }
                )
            status, error = request(
                f"{base}:commit",
                token,
                {
                    "writes": [
                        {
                            "update": {
                                "name": owned_name(collection, "A"),
                                "fields": {"x": {"integerValue": "99"}},
                            }
                        },
                        {
                            "update": {
                                "name": owned_name(collection, "D"),
                                "fields": {},
                            },
                            "currentDocument": {"exists": False},
                        },
                    ]
                },
            )
            code = (
                error.get("error", {}).get("status")
                if isinstance(error, dict)
                else None
            )
            receipt["cases"].append(
                {
                    "id": "commit-refuses-existing-document",
                    "httpStatus": status,
                    "code": code,
                    "passed": status == 409 and code == "ALREADY_EXISTS",
                }
            )
            unchanged = True
            after = {}
            for name in owned:
                status, value = request(f"{base_origin}/v1/{name}", token)
                require_status(status, 200)
                after[name] = value
                unchanged = unchanged and value == before[name]
            receipt["stateBefore"] = before
            receipt["stateAfter"] = after
            receipt["cases"].append(
                {
                    "id": "queries-and-refused-commit-preserve-fields-and-times",
                    "passed": unchanged,
                }
            )
            receipt["status"] = (
                "passed"
                if all(case["passed"] for case in receipt["cases"])
                else "failed"
            )
        except Exception as error:  # noqa: BLE001 -- record a sanitized candidate and always clean up.
            # No raw response, request, OAuth token or subprocess stdout is persisted.
            receipt["failure"] = type(error).__name__
        finally:
            receipt["cleanup"] = cleanup_resources(
                base_origin, token, attempted, owned, marker
            )
            if any(not row["confirmedMissing"] for row in receipt["cleanup"]):
                receipt["status"] = "cleanup-failed"
            receipt["executedCases"] = len(receipt["cases"])
            persist()
        if (
            receipt["status"] != "passed"
            or receipt["executedCases"] != 6
            or len(owned) != 4
        ):
            raise SystemExit("Probe did not pass; inspect sanitized candidate receipt")
        print(
            f"{target}: 6 cases passed; 4 owned documents deleted and confirmed missing"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["local", "production"], required=True)
    parser.add_argument("--origin")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/fireemu"))
    args = parser.parse_args()
    if (
        args.target == "local"
        and args.origin is None
        and os.environ.get("FIRESTORE_EMULATOR_HOST")
    ):
        args.origin = f"http://{os.environ['FIRESTORE_EMULATOR_HOST']}"
    run(args.target, args.origin, args.output, args.binary)


if __name__ == "__main__":
    main()
