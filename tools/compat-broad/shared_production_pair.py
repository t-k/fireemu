"""Compare acquired shared scenarios without converting local invariants into an oracle."""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import quote

from batch_adapter import observer_digest
from batch_pair import normalize as batch_normalize
from broad_contract import digest, local_origin
from shared_cases import campaign_manifest, manifest

G0_PRODUCTION_RESULT_SHA256 = (
    "47672f4e3162b4a0ddfb7baaab622007602aeed6c1fa3d6e5e84034bcbb87772"
)
G0_ORIGINAL_COMPARISON_CONTRACT_DIGEST = (
    "e20a4f5d2325a3c88306ca30407a3d5b8f224ce9d95f77490f9d0908ec22eb6c"
)
G0_ORIGINAL_MANIFEST_DIGEST = (
    "13e97e0146c483ad6ab93f1dc8ecc4a8ea2615eaf481878047aec94f42fcecd1"
)
G0_NORMALIZATION_VERSION = "shared-g0-batchwrite-status-resource-v1"


def g0_contract():
    from shared_production import binding

    return {
        "version": "shared-g0-runtime-recomparison-v1",
        "baseAdmissionContractDigest": digest(binding()),
        "normalizationVersion": G0_NORMALIZATION_VERSION,
        "normalizerImplementationDigest": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "scope": "Firestore status/*/message exact owned resource tokens only",
    }


def _normalize_status_message(value, names):
    resources = names.get("firestoreResources", {})
    candidates = []
    for role, parent in names.get("firestoreParents", {}).items():
        for resource in resources.get(role, []):
            if not isinstance(resource, str) or not resource.startswith(parent + "/"):
                continue
            candidates.append((resource, "documents/" + role + resource[len(parent) :]))
    candidates.sort(key=lambda item: len(item[0]), reverse=True)
    boundary = frozenset(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-"
    )
    output = []
    cursor = 0
    while cursor < len(value):
        match = None
        for token, replacement in candidates:
            start = value.find(token, cursor)
            if start < 0:
                continue
            end = start + len(token)
            if (
                (start == 0 or value[start - 1] not in boundary)
                and (end == len(value) or value[end] not in boundary)
                and (match is None or start < match[0])
            ):
                match = (start, end, replacement)
        if match is None:
            output.append(value[cursor:])
            break
        start, end, replacement = match
        output.extend((value[cursor:start], replacement))
        cursor = end
    return "".join(output)


def normalize_g0(value, names, *, service, path=()):
    """Apply the versioned G0 status-message normalization before shared normalization."""
    if (
        service == "firestore"
        and isinstance(value, str)
        and len(path) == 3
        and path[0] == "status"
        and path[2] == "message"
    ):
        return _normalize_status_message(value, names)
    if isinstance(value, list):
        return [
            normalize_g0(item, names, service=service, path=(*path, str(i)))
            for i, item in enumerate(value)
        ]
    if isinstance(value, dict):
        return {
            key: normalize_g0(item, names, service=service, path=(*path, key))
            for key, item in value.items()
        }
    return batch_normalize(value, names, service=service, path=path)


def validate_record(record, *, local=False, historical_observer=False):
    batch = record.get("batch", record)
    plan = batch["gate"]["plan"]
    expected = manifest(plan["nonce"])
    expected_observer = (
        batch.get("observerDigest") if historical_observer else observer_digest()
    )
    if plan["observerSha256"] != expected_observer:
        raise ValueError("observer mismatch")
    if digest(plan["jobs"]) != digest(expected["jobs"]):
        raise ValueError("closed scenario mismatch")
    if set(batch["jobs"]) != set(expected["jobs"]):
        raise ValueError("scenario missing or added")
    for key, job in batch["jobs"].items():
        operations = expected["jobs"][key]["observation"]
        rows = job["rows"]
        if len(rows) != len(operations):
            raise ValueError("operation missing or added")
        for index, (row, operation) in enumerate(zip(rows, operations, strict=True)):
            if digest([row["index"], row["request"]]) != digest([index, operation]):
                raise ValueError("independent typed operation mismatch")
            if type(row.get("status")) is not int or "body" not in row:
                raise ValueError("response unavailable")
        if (
            job.get("recordingComplete") is not True
            or job.get("cleanupComplete") is not True
            or (
                local
                and (
                    job.get("safety") is not True
                    or job.get("stateVerified") is not True
                )
            )
        ):
            raise ValueError("incomplete scenario")
    if batch.get("completed") is not True:
        raise ValueError("incomplete execution")
    events = batch["gate"]["events"]
    for key, job in batch["jobs"].items():
        observed = [
            e for e in events if e["job"] == key and e["phase"] == "observation"
        ]
        if len(observed) != len(job["rows"]):
            raise ValueError("observation receipt count mismatch")
        for row, event in zip(job["rows"], observed, strict=True):
            if (
                event.get("completed") is not True
                or event["index"] != row["index"]
                or event["requestDigest"] != digest(row["request"])
                or event["responseDigest"] != digest(row["body"])
                or type(event["status"]) is not int
                or event["status"] != row["status"]
            ):
                raise ValueError("observation receipt mismatch")
        state = batch["gate"]["jobs"][key]
        if (
            state.get("complete") is not True
            or state.get("inflight") is not False
            or sorted(state["absent"]) != sorted(expected["jobs"][key]["resources"])
        ):
            raise ValueError("cleanup evidence incomplete")
        declared_cleanup = expected["jobs"][key]["recovery"]
        if len(job["cleanup"]) != len(declared_cleanup):
            raise ValueError("cleanup sequence incomplete")
        for index, (row, declared) in enumerate(
            zip(job["cleanup"], declared_cleanup, strict=True)
        ):
            operation = dict(declared)
            source = operation.pop("versionFrom", None)
            if source is not None:
                original = job["cleanup"][source]
                version = original.get("body", {}).get("updateTime")
                if (
                    original.get("status") == 200
                    and isinstance(version, str)
                    and version
                ):
                    operation["path"] += "?currentDocument.updateTime=" + quote(
                        version, safe=""
                    )
                elif row.get("status") is not None:
                    raise ValueError("DELETE without captured version")
            if digest([row.get("index"), row.get("request")]) != digest(
                [index, operation]
            ):
                raise ValueError("cleanup recipe/version relation differs")
        for resource in expected["jobs"][key]["resources"]:
            last = [
                r
                for r in job["cleanup"]
                if r.get("request", {}).get("path") == "/v1/" + resource
                and r["request"]["method"] == "GET"
            ]
            if not last or last[-1].get("status") != 404:
                raise ValueError("final absence receipt missing")
        recovery = [e for e in events if e["job"] == key and e["phase"] == "recovery"]
        for row in job["cleanup"]:
            if row.get("status") is None:
                continue
            matching = [e for e in recovery if e["index"] == row["index"]]
            if (
                len(matching) != 1
                or matching[0].get("requestDigest") != digest(row["request"])
                or matching[0].get("responseDigest") != digest(row["body"])
                or matching[0].get("status") != row["status"]
            ):
                raise ValueError("recovery receipt mismatch")
    state = batch["gate"]
    management = state.get("managementEvents", [])
    if (
        state["total"] != len(events) + len(management) + plan["coordinatorRequests"]
        or state["total"] > (26 if local else 36)
        or state["observation"] > plan["observationRequests"]
        or state["costMicrousd"] > plan["costMicrousd"]
    ):
        raise ValueError("shared allocation evidence mismatch")
    if local and plan["transport"] != "local-only":
        raise ValueError("production record is not a local execution")
    if local and (
        batch.get("productionExecuted") is not False
        or batch.get("wireHistoryMatchesReservations") is not True
        or batch.get("sharedConstraints") is not True
    ):
        raise ValueError("local evidence unavailable")
    return batch


def _compare(production, local, *, g0_recompare=False):
    from shared_production import binding
    from shared_production import manifest as production_manifest

    result = {
        "contract": binding(),
        "productionDigest": digest(production),
        "localDigest": digest(local),
        "rows": [],
        "compatibility": "indeterminate",
    }
    try:
        left = validate_record(production, historical_observer=g0_recompare)
        right = validate_record(local, local=True)
        production_contract = (
            G0_ORIGINAL_COMPARISON_CONTRACT_DIGEST
            if g0_recompare
            else digest(binding())
        )
        if (
            left.get("productionExecuted") is not True
            or left.get("configurationUnchanged") is not True
            or left.get("stateVerified") is not True
            or left.get("cleanupComplete") is not True
            or any(
                job.get("safety") is not True
                or job.get("stateVerified") is not True
                or job.get("cleanupComplete") is not True
                for job in left["jobs"].values()
            )
            or (not g0_recompare and left.get("localRecordSha256") != digest(local))
            or len(left["gate"].get("managementEvents", [])) not in (10, 12)
            or left.get("manifestDigest")
            != (
                G0_ORIGINAL_MANIFEST_DIGEST
                if g0_recompare
                else digest(production_manifest())
            )
            or left.get("comparisonContractDigest") != production_contract
        ):
            raise ValueError("production contract incomplete")
    except (KeyError, TypeError, ValueError) as error:
        result["reason"] = str(error)
        return result
    try:
        permission = left["permission"]
        if (
            digest(permission) != left["permissionDigest"]
            or digest(permission) != left["gate"]["plan"]["permissionDigest"]
            or (not g0_recompare and permission["localRecordSha256"] != digest(local))
            or (
                g0_recompare
                and permission["localRecordSha256"] != left["localRecordSha256"]
            )
        ):
            raise ValueError("permission binding differs")
        ids = [e["id"] for e in left["gate"]["managementEvents"]]
        required_ids = [
            phase + ":" + key
            for phase in ("observation", "recovery")
            for key in ("project", "database", "auth", "key")
        ]
        credentials = ["observation:access-command", "observation:tokeninfo"]
        if sorted(ids) not in (
            sorted(required_ids + credentials),
            sorted(
                required_ids
                + credentials
                + ["recovery:access-command", "recovery:tokeninfo"]
            ),
        ):
            raise ValueError("management operation identities differ")
        metadata = left["metadataEvidence"]
        if sorted(e["id"] for e in metadata) != sorted(required_ids):
            raise ValueError("metadata receipts missing or duplicated")
        for entry in metadata:
            value, action = entry["value"], entry["id"].split(":")[1]
            if type(entry["status"]) is not int or entry["status"] != 200:
                raise ValueError("metadata response unsuccessful")
            if action == "project" and digest(value) != digest(
                {
                    "projectId": permission["project"],
                    "projectNumber": permission["projectNumber"],
                }
            ):
                raise ValueError("project baseline differs")
            if action == "database" and (
                value["projectionDigest"] != permission["databaseProjectionDigest"]
                or digest(value["projection"]) != permission["databaseProjectionDigest"]
            ):
                raise ValueError("database baseline differs")
            if (
                action == "auth"
                and entry["responseDigest"] != permission["authConfigDigest"]
            ):
                raise ValueError("auth baseline differs")
            parent = "projects/" + permission["projectNumber"] + "/locations/global"
            if action == "key" and (
                value["parent"] != parent
                or not value["name"].startswith(parent + "/keys/")
            ):
                raise ValueError("key membership differs")
    except (KeyError, TypeError, ValueError) as error:
        result["reason"] = str(error)
        return result
    for key in left["jobs"]:
        names = [
            {
                "firestoreParents": {
                    key: b["gate"]["plan"]["jobs"][key]["resources"][0].rsplit("/", 1)[
                        0
                    ]
                },
                "firestoreResources": {
                    key: b["gate"]["plan"]["jobs"][key]["resources"]
                },
            }
            for b in (left, right)
        ]
        for a, b in zip(
            left["jobs"][key]["rows"], right["jobs"][key]["rows"], strict=True
        ):
            values = [
                {
                    "status": r["status"],
                    "body": (
                        normalize_g0(r["body"], n, service="firestore")
                        if g0_recompare
                        else batch_normalize(r["body"], n, service="firestore")
                    ),
                }
                for r, n in zip((a, b), names, strict=True)
            ]
            result["rows"].append(
                {
                    "job": key,
                    "index": a["index"],
                    "production": values[0],
                    "local": values[1],
                    "verdict": "match"
                    if digest(values[0]) == digest(values[1])
                    else "mismatch",
                }
            )
    result["compatibility"] = (
        "match" if all(r["verdict"] == "match" for r in result["rows"]) else "mismatch"
    )
    return result


def compare(production, local):
    return _compare(production, local)


def compare_campaign_rows(production, local, expected_ids, expected_preflight=None):
    """Compare a closed shared-adapter receipt while retaining lifecycle status.

    This is the same typed response boundary as the shared comparator, restricted
    to a campaign's concrete row IDs. A complete semantic mismatch is evidence,
    whereas missing state or cleanup is indeterminate.
    """
    result = {
        "recordingComplete": production.get("recordingComplete") is True
        and local.get("recordingComplete") is True,
        "collectionComplete": production.get("collectionComplete") is True
        and local.get("collectionComplete") is True,
        "stateValidation": production.get("stateValidation") is True
        and local.get("stateValidation") is True,
        "cleanupComplete": production.get("cleanupComplete") is True
        and local.get("cleanupComplete") is True,
        "preflightDrift": False,
        "rows": [],
        "compatibility": "indeterminate",
    }
    if expected_preflight is not None and (
        production.get("preflight") != expected_preflight
        or local.get("preflight") != expected_preflight
    ):
        result["preflightDrift"] = True
        return result
    if not (result["collectionComplete"] and result["cleanupComplete"]):
        return result
    evidences = []
    for receipt in (production, local):
        evidence = receipt.get("principalEvidence")
        if not _campaign_receipt_matches_manifest(receipt, evidence):
            return result
        evidences.append(evidence)
    if _campaign_evidence_binding(evidences[0]) != _campaign_evidence_binding(
        evidences[1]
    ):
        return result
    left, right = production.get("rows", []), local.get("rows", [])
    if [row.get("id") for row in left] != list(expected_ids) or [
        row.get("id") for row in right
    ] != list(expected_ids):
        return result
    for a, b in zip(left, right, strict=True):
        result["rows"].append(
            {
                "id": a["id"],
                "production": {"status": a.get("status"), "body": a.get("body")},
                "local": {"status": b.get("status"), "body": b.get("body")},
                "verdict": "match"
                if digest([a.get("status"), a.get("body")])
                == digest([b.get("status"), b.get("body")])
                else "mismatch",
            }
        )
    result["compatibility"] = (
        "match"
        if all(row["verdict"] == "match" for row in result["rows"])
        else "mismatch"
    )
    return result


def _campaign_receipt_matches_manifest(receipt, evidence, *, expected_plan=None):
    if not isinstance(evidence, dict):
        return False
    if evidence.get("job") != "query-explain" or not isinstance(
        evidence.get("nonce"), str
    ):
        return False
    try:
        expected = (
            campaign_manifest(evidence["nonce"])
            if expected_plan is None
            else dict(expected_plan)
        )
    except ValueError:
        return False
    origins = evidence.get("localOrigins")
    production = expected_plan is not None and "permissionDigest" in expected_plan
    if production:
        if origins != {} or expected["nonce"] != evidence["nonce"]:
            return False
    elif not isinstance(origins, dict) or set(origins) != {"auth", "firestore"}:
        return False
    try:
        if not production:
            local_origin(origins["auth"])
            local_origin(origins["firestore"])
    except (TypeError, ValueError):
        return False
    if not production:
        expected["localOrigins"] = origins
    if evidence.get("planDigest") != digest(expected):
        return False
    job = expected["jobs"]["query-explain"]
    if expected_plan is not None:
        if expected["nonce"] != evidence["nonce"]:
            return False
        for phase, rows in (
            ("observation", receipt.get("rows")),
            ("recovery", receipt.get("cleanup")),
        ):
            events = evidence.get("dispatch", {}).get(phase)
            if not isinstance(rows, list) or not isinstance(events, list):
                return False
            if any(
                not isinstance(row, dict)
                or type(row.get("index")) is not int
                or row["index"] != index
                or type(row.get("status")) is not int
                or not 100 <= row["status"] <= 599
                for index, row in enumerate(rows)
            ):
                return False
            if any(
                not isinstance(event, dict)
                or type(event.get("index")) is not int
                or type(event.get("status")) is not int
                for event in events
            ):
                return False
        if digest([row.get("request") for row in receipt["rows"]]) != digest(
            job["observation"]
        ):
            return False
        if [row["status"] for row in receipt["cleanup"]] != [
            200,
            200,
            404,
            200,
            200,
            404,
        ]:
            return False
    rows = receipt.get("rows", [])
    if [row.get("id") for row in rows] != job["stepIds"]:
        return False
    if [row.get("request") for row in rows] != job["observation"]:
        return False
    dispatch = evidence.get("dispatch")
    if not isinstance(dispatch, dict):
        return False
    observation_events = dispatch.get("observation", [])
    if len(observation_events) != len(rows):
        return False
    for index, (event, row, operation) in enumerate(
        zip(observation_events, rows, job["observation"], strict=True)
    ):
        if (
            event.get("index") != index
            or event.get("requestDigest") != digest(operation)
            or event.get("requestDigest") != digest(row.get("request"))
            or event.get("completed") is not True
            or event.get("status") != row.get("status")
            or event.get("responseDigest") != digest(row.get("body"))
        ):
            return False
    cleanup = receipt.get("cleanup", [])
    declared_cleanup = job["recovery"]
    if len(cleanup) != len(declared_cleanup):
        return False
    recovery_events = dispatch.get("recovery", [])
    verified_events = 0
    for index, (row, declared) in enumerate(
        zip(cleanup, declared_cleanup, strict=True)
    ):
        operation = dict(declared)
        source = operation.pop("versionFrom", None)
        valid_version = False
        if source is not None:
            prior = cleanup[source]
            if prior.get("status") == 200 and isinstance(prior.get("body"), dict):
                version = prior["body"].get("updateTime")
                if isinstance(version, str) and version:
                    valid_version = True
                    operation["path"] += "?currentDocument.updateTime=" + quote(
                        version, safe=""
                    )
        if row.get("index") != index or row.get("request") != operation:
            return False
        matching = [event for event in recovery_events if event.get("index") == index]
        if source is not None and not valid_version:
            skipped = {
                "index": index,
                "request": operation,
                "status": None,
                "body": {"skipped": "absent-or-unavailable-cleanup-read"},
            }
            if (
                operation.get("method") != "DELETE"
                or digest(row) != digest(skipped)
                or matching
            ):
                return False
            continue
        if row.get("status") is None or len(matching) != 1:
            return False
        event = matching[0]
        if (
            event.get("index") != index
            or event.get("requestDigest") != digest(operation)
            or event.get("completed") is not True
            or event.get("status") != row.get("status")
            or event.get("responseDigest") != digest(row.get("body"))
        ):
            return False
        verified_events += 1
    if len(recovery_events) != verified_events:
        return False
    for resource in job["resources"]:
        reads = [
            row
            for row in cleanup
            if row["request"]["method"] == "GET"
            and row["request"]["path"] == "/v1/" + resource
        ]
        if not reads or reads[-1].get("status") != 404:
            return False
    return True


def _campaign_evidence_binding(evidence):
    return {
        "planDigest": evidence["planDigest"],
        "job": evidence["job"],
        "nonce": evidence["nonce"],
        "localOrigins": evidence["localOrigins"],
        "dispatchRequestDigests": {
            phase: [
                (event.get("index"), event.get("requestDigest"))
                for event in evidence["dispatch"][phase]
            ]
            for phase in ("observation", "recovery")
        },
    }


def compare_g0_runtime_recompare(production_path, local):
    """Recompare a pinned G0 production receipt against a new local runtime receipt."""
    production_path = Path(production_path)
    raw = production_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != G0_PRODUCTION_RESULT_SHA256:
        raise ValueError("G0 production result hash mismatch")
    production = json.loads(raw)
    result = _compare(production, local, g0_recompare=True)
    result["mode"] = "g0-runtime-recomparison"
    contract = g0_contract()
    result["contract"] = contract
    result["comparisonContractDigest"] = digest(contract)
    result["source"] = {
        "productionResultSha256": G0_PRODUCTION_RESULT_SHA256,
        "originalComparisonContractDigest": G0_ORIGINAL_COMPARISON_CONTRACT_DIGEST,
        "originalManifestDigest": G0_ORIGINAL_MANIFEST_DIGEST,
        "newComparisonContractDigest": digest(contract),
        "baseAdmissionContractDigest": contract["baseAdmissionContractDigest"],
        "oldLocalRecordSha256": production["localRecordSha256"],
        "limitation": (
            "The immutable production receipt's old localRecordSha256 is retained "
            "as provenance and is not used to approve this new runtime receipt."
        ),
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--production", type=Path)
    source.add_argument("--g0-runtime-recompare-production", type=Path)
    parser.add_argument("--local", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    local = json.loads(args.local.read_bytes())
    if args.g0_runtime_recompare_production:
        result = compare_g0_runtime_recompare(
            args.g0_runtime_recompare_production, local
        )
    else:
        result = compare(json.loads(args.production.read_bytes()), local)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    return (
        2
        if result["compatibility"] == "indeterminate"
        or args.check
        and result["compatibility"] != "match"
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
