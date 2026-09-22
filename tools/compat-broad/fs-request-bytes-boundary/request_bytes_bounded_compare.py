"""Compare the retained request-byte rows without promoting broad compatibility."""

from __future__ import annotations

import argparse
import hashlib
import json
from urllib.parse import parse_qs, urlsplit
from pathlib import Path
from typing import Any

PROBES = ("under", "exact", "over")
EXPECTED_STATUS = {"under": 200, "exact": 200, "over": 200}
EXPECTED_BODY_BYTES = {"under": 10_485_759, "exact": 10_485_760, "over": 10_485_761}
EXPECTED_BODY_SHA256 = {
    "under": "30d370c82a20cf41281b77205c1d358edb70ac67f465003edd7075a8df64face",
    "exact": "d99d2569ee0c3225aca13d9dc330472a96a6b15ea5f7c2b040f3afb613a85768",
    "over": "8a410d0e04ea9bae39fb85daffdc469e2c3f2aa822372b13d998ce4fc8d10a9c",
}
IMMUTABLE_EXPECTED_SHA256 = "8f39ba06084a2b8342d5abe91f80e57eb78af7ee09a108c8ece3ba58271e7571"
IMMUTABLE_EXPECTED_DIGEST = "f5e6b9a2782dd9dff1d1e8fb16bb36542203341c4fd00f41c71a0a3d68ad30eb"
ARTIFACT_SHA256 = "903728746e512d158363c092196e015f79805ab513757a5924d319c8dac0996d"
HARNESS_COMMIT = "48392f5e3ea1f69307c227ec97a04a93166da4ed"
RUNTIME_SOURCE_COMMIT = "ba4a026363d6ec05267cf646439c10d729ab805f"
RUNTIME_SOURCE_MAP_SHA256 = "9bba0af9ad134dca0df655a42aa771dd88faeb658679712eb72b0db6160301a1"
PRODUCTION_INPUTS_SHA256 = "b7b423ea1c28b1bc610eae9281f0c89f04e467d7504d32f13318564fba79651f"
PRODUCTION_RECEIPT_SHA256 = "10ff0f711c6b10e740d3620021f028d9ffd6891e4e5aa55dc620dbad960895cd"
PRODUCTION_RESULT_SHA256 = "cb8ef1af7a630362b8d6b161d69dbe0b7bf2688b3fcc5ebdb0d9138cd6290450"
PRODUCTION_GATE_STATE_SHA256 = "dda8f96ac2f8db4417dc3c56f5032467244952ef8656f627398d56e2d226afea"
LOCAL_MANIFEST_SHA256 = "7afacb213758873229d3005d86791a503a468601fcc2dc1cc9f8a305fe5ee87e"
LOCAL_PROJECTION_SHA256 = "1ab02dd1560c381b6f9987782d92b6d9850344ff1d7f805cf6d3ba282e945b19"
RUNTIME_ARTIFACT = Path("/Users/tk/work/firebase-emulator/docs.local/runs/requestbytes-native-ba4-20260922/fireemu")
RUNTIME_SOURCE_MAP = Path("/Users/tk/work/firebase-emulator/docs.local/runs/requestbytes-native-ba4-20260922/source-runtime-input-map.txt")
PRODUCTION_RUN = "requestbytes-production-2a1-fresh02"
RESULT_KIND = "requestbytes-bounded-response-sideeffect-comparison-v1"


class ComparisonError(ValueError):
    """A retained-evidence binding or post-state predicate failed."""


def _json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ComparisonError(f"regular file required: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _regular_child(root: Path, relative: str) -> Path:
    raw = root / relative
    path = raw.resolve()
    if raw.is_symlink() or root.resolve() not in path.parents or not path.is_file():
        raise ComparisonError("response file must be a regular child")
    return path


def _response(collection: Path, row: dict[str, Any]) -> Any:
    name = row.get("responseBodyFile")
    if not isinstance(name, str) or Path(name).name != name:
        raise ComparisonError("response path traversal")
    path = _regular_child(collection, name)
    data = path.read_bytes()
    if row.get("responseSha256") != hashlib.sha256(data).hexdigest() or row.get("responseBytes") != len(data):
        raise ComparisonError("response file digest binding")
    receipt = row.get("receipt")
    if isinstance(receipt, dict) and receipt.get("bodyBytes") != len(data):
        raise ComparisonError("response receipt byte binding")
    return json.loads(data)


def _same_json(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same_json(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_json(a, b) for a, b in zip(left, right))
    return left == right


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _rows(run: Path) -> tuple[Path, dict[str, Any]]:
    collection = run / "collection"
    if not collection.is_dir():
        raise ComparisonError("collection directory missing")
    rows = {}
    for path in sorted(collection.glob("row-*.json")):
        row = _json(path)
        if not isinstance(row, dict) or path.name in rows:
            raise ComparisonError("duplicate or malformed row")
        rows[path.name] = row
    if len(rows) != 258:
        raise ComparisonError("the 258-row primary collection is incomplete")
    return collection, rows


def _status(row: dict[str, Any]) -> int:
    receipt = row.get("receipt")
    if not isinstance(receipt, dict) or type(receipt.get("status")) is not int:
        raise ComparisonError("receipt status missing")
    return receipt["status"]


def _probe_result(run: Path, probe: str) -> dict[str, Any]:
    collection, rows = _rows(run)
    request_body = _regular_child(collection, f"request-{probe}.body")
    body_bytes = request_body.read_bytes()
    request_json = json.loads(body_bytes)
    writes = request_json.get("writes")
    if not isinstance(writes, list) or len(writes) != 17:
        raise ComparisonError(f"{probe}: request write count")
    expected: dict[str, Any] = {}
    for write in writes:
        if set(write) != {"update", "currentDocument"} or write["currentDocument"] != {"exists": False}:
            raise ComparisonError(f"{probe}: ownership precondition")
        update = write.get("update")
        if not isinstance(update, dict) or set(update) != {"name", "fields"}:
            raise ComparisonError(f"{probe}: malformed update")
        name = update["name"]
        if name in expected:
            raise ComparisonError(f"{probe}: duplicate resource")
        expected[name] = update["fields"]
    commit_rows = [r for r in rows.values() if r.get("probe") == probe and r.get("kind") == "conditional-create-commit"]
    if len(commit_rows) != 1:
        raise ComparisonError(f"{probe}: commit row count")
    commit = commit_rows[0]
    if commit.get("requestBytes") != len(body_bytes) or commit.get("requestSha256") != hashlib.sha256(body_bytes).hexdigest():
        raise ComparisonError(f"{probe}: request body row binding")
    response = _response(collection, commit)
    results = response.get("writeResults")
    if _status(commit) != 200 or not isinstance(results, list) or len(results) != 17:
        raise ComparisonError(f"{probe}: commit response")
    if any(not isinstance(item, dict) or not item.get("updateTime") for item in results):
        raise ComparisonError(f"{probe}: versioned write results")

    readbacks = [r for r in rows.values() if r.get("probe") == probe and r.get("kind") == "probe-readback"]
    if len(readbacks) != 17 or {_row_resource(r) for r in readbacks} != set(expected):
        raise ComparisonError(f"{probe}: readback resource set")
    fields_equal = True
    readback_digests = []
    for row in readbacks:
        body = _response(collection, row)
        if _status(row) != 200 or body.get("name") != row.get("resource"):
            fields_equal = False
            continue
        fields_equal = fields_equal and _same_json(body.get("fields"), expected[row["resource"]])
        readback_digests.append(_digest({"name": body.get("name"), "fields": body.get("fields")}))

    ownership_reads = [r for r in rows.values() if r.get("probe") == probe and r.get("kind") == "cleanup-ownership-read"]
    deletes = [r for r in rows.values() if r.get("probe") == probe and r.get("kind") == "cleanup-version-bound-delete"]
    absence = [r for r in rows.values() if r.get("probe") == probe and r.get("kind") == "cleanup-verify-absence"]
    if len(ownership_reads) != 17 or len(deletes) != 17 or len(absence) != 17:
        raise ComparisonError(f"{probe}: versioned cleanup counts")
    expected_names = set(expected)
    if any(_row_resource(row) not in expected_names for row in ownership_reads + deletes + absence):
        raise ComparisonError(f"{probe}: cleanup resource set")
    if any(_status(row) not in (200, 404) for row in ownership_reads):
        raise ComparisonError(f"{probe}: ownership read status")
    update_times = {}
    for row in readbacks:
        body = _response(collection, row)
        update_time = body.get("updateTime")
        if not isinstance(update_time, str) or not update_time:
            raise ComparisonError(f"{probe}: readback version")
        update_times[row["resource"]] = update_time
    if any(_status(row) != 200 for row in deletes):
        raise ComparisonError(f"{probe}: version-bound delete status")
    for row in deletes:
        query = parse_qs(urlsplit(row.get("path", "")).query)
        if query.get("currentDocument.updateTime") != [update_times[row["resource"]]]:
            raise ComparisonError(f"{probe}: delete version linkage")
    final_absence = all(_status(row) == 404 and _typed_not_found(collection, row) for row in absence)
    if not fields_equal or not all(_status(row) == 200 for row in readbacks):
        raise ComparisonError(f"{probe}: readback fields or status")
    if not final_absence:
        raise ComparisonError(f"{probe}: final typed absence")
    return {
        "commitStatus": _status(commit),
        "writeResultCount": len(results),
        "readbackCount": len(readbacks),
        "resourceSetDigest": _digest(sorted(expected)),
        "fieldsDigest": _digest(expected),
        "readbackDigest": _digest(sorted(readback_digests)),
        "allReadback200": all(_status(row) == 200 for row in readbacks),
        "fieldsEqual": fields_equal,
        "versionBoundDeleteCount": len(deletes),
        "finalAbsenceCount": len(absence),
        "allFinalAbsence404": final_absence,
        "requestBytes": len(body_bytes),
        "requestSha256": hashlib.sha256(body_bytes).hexdigest(),
    }


def _row_resource(row: dict[str, Any]) -> str:
    resource = row.get("resource")
    if not isinstance(resource, str) or not resource:
        raise ComparisonError("resource missing")
    return resource


def _typed_not_found(collection: Path, row: dict[str, Any]) -> bool:
    body = _response(collection, row)
    error = body.get("error")
    return isinstance(error, dict) and error.get("status") == "NOT_FOUND" and error.get("code") == 404


def _validate_local_bindings(run: Path, immutable: Path) -> dict[str, Any]:
    projection = _json(run / "v2-projection.json")
    manifest = _json(run / "manifest.json")
    if projection.get("immutableExpectedDigest") != _digest(_json(immutable)):
        raise ComparisonError("immutable expected digest binding")
    if manifest.get("artifactSha256") != ARTIFACT_SHA256 or manifest.get("sourceCheckoutCommit") != HARNESS_COMMIT:
        raise ComparisonError("runtime artifact/source binding")
    if manifest.get("productionExecuted") is not False or manifest.get("productionEndpointUsed") is not False:
        raise ComparisonError("local replay production binding")
    if projection.get("productionExecuted") is not False or projection.get("productionEndpointUsed") is not False:
        raise ComparisonError("projection production binding")
    if projection.get("actualStatusByProbe") != EXPECTED_STATUS:
        raise ComparisonError("local status binding")
    if projection.get("typedFinalAbsence51") is not True:
        raise ComparisonError("aggregate absence binding")
    if projection.get("legacyCollectorFailure") != ["over:unexpected-success"]:
        raise ComparisonError("legacy failure was altered")
    if projection.get("collectorCompleted") is not False or projection.get("cleanupComplete") is not False:
        raise ComparisonError("legacy incomplete state was altered")
    if manifest.get("formalCompatibilityClaim") is not False:
        raise ComparisonError("formal compatibility claim")
    if _sha256(run / "manifest.json") != LOCAL_MANIFEST_SHA256 or _sha256(run / "v2-projection.json") != LOCAL_PROJECTION_SHA256:
        raise ComparisonError("local frozen file binding")
    return projection


def _validate_runtime_anchor(production_run: Path) -> None:
    anchors = {
        "inputs.json": PRODUCTION_INPUTS_SHA256,
        "receipt.json": PRODUCTION_RECEIPT_SHA256,
        "collection/result.json": PRODUCTION_RESULT_SHA256,
        "gate/state.json": PRODUCTION_GATE_STATE_SHA256,
    }
    for relative, expected in anchors.items():
        if _sha256(production_run / relative) != expected:
            raise ComparisonError(f"production anchor changed: {relative}")
    if RUNTIME_ARTIFACT.is_symlink() or not RUNTIME_ARTIFACT.is_file() or _sha256(RUNTIME_ARTIFACT) != ARTIFACT_SHA256:
        raise ComparisonError("runtime artifact binding")
    if RUNTIME_SOURCE_MAP.is_symlink() or not RUNTIME_SOURCE_MAP.is_file() or _sha256(RUNTIME_SOURCE_MAP) != RUNTIME_SOURCE_MAP_SHA256:
        raise ComparisonError("runtime source map binding")
    fields = {}
    for line in RUNTIME_SOURCE_MAP.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    if fields.get("sourceCommit") != RUNTIME_SOURCE_COMMIT or fields.get("artifactSha256") != ARTIFACT_SHA256:
        raise ComparisonError("runtime source/artifact map binding")


def compare_runs(production_run: Path, local_run: Path, output: Path) -> dict[str, Any]:
    immutable = local_run / "immutable-expected.json"
    expected = _json(immutable)
    if _sha256(immutable) != IMMUTABLE_EXPECTED_SHA256 or expected.get("statusByProbe") != EXPECTED_STATUS:
        raise ComparisonError("immutable production status binding")
    if expected.get("bodyBindings") != {
        probe: {"bytes": EXPECTED_BODY_BYTES[probe], "sha256": EXPECTED_BODY_SHA256[probe]}
        for probe in PROBES
    }:
        raise ComparisonError("immutable body binding")
    if expected.get("savedRun", "").endswith(PRODUCTION_RUN) is False:
        raise ComparisonError("saved production run binding")
    _validate_runtime_anchor(production_run)
    production = {probe: _probe_result(production_run, probe) for probe in PROBES}
    local = {probe: _probe_result(local_run, probe) for probe in PROBES}
    _validate_local_bindings(local_run, immutable)
    for probe in PROBES:
        for result in (production[probe], local[probe]):
            if result["requestBytes"] != EXPECTED_BODY_BYTES[probe] or result["requestSha256"] != EXPECTED_BODY_SHA256[probe]:
                raise ComparisonError(f"{probe}: immutable body binding")
    parity = {
        probe: {
            "productionStatus": production[probe]["commitStatus"],
            "localStatus": local[probe]["commitStatus"],
            "statusEqual": production[probe]["commitStatus"] == local[probe]["commitStatus"] == EXPECTED_STATUS[probe],
            "production": {k: v for k, v in production[probe].items() if k not in ("requestBytes", "requestSha256")},
            "local": {k: v for k, v in local[probe].items() if k not in ("requestBytes", "requestSha256")},
            "sideEffectEqual": all(production[probe][key] == local[probe][key] for key in ("writeResultCount", "readbackCount", "resourceSetDigest", "fieldsDigest", "readbackDigest", "allReadback200", "fieldsEqual", "versionBoundDeleteCount", "finalAbsenceCount", "allFinalAbsence404")),
        }
        for probe in PROBES
    }
    result = {
        "kind": RESULT_KIND,
        "cases": list(PROBES),
        "boundedObservedParity": all(item["statusEqual"] and item["sideEffectEqual"] for item in parity.values()),
        "statusByProbe": {probe: item["localStatus"] for probe, item in parity.items()},
        "sideEffectByProbe": parity,
        "typedFinalAbsence": all(item["local"]["allFinalAbsence404"] and item["production"]["allFinalAbsence404"] for item in parity.values()),
        "parentConditionAccepted": False,
        "formalCompatibilityClaim": False,
        "legacyCollectorFailure": ["over:unexpected-success"],
        "productionRun": str(production_run),
        "localRun": str(local_run),
        "immutableExpectedSha256": IMMUTABLE_EXPECTED_SHA256,
        "artifactSha256": ARTIFACT_SHA256,
        "sourceCheckoutCommit": HARNESS_COMMIT,
        "bodyBindings": {
            probe: {"bytes": EXPECTED_BODY_BYTES[probe], "sha256": EXPECTED_BODY_SHA256[probe]}
            for probe in PROBES
        },
        "productionEvidence": {
            "runId": PRODUCTION_RUN,
            "inputsSha256": _sha256(production_run / "inputs.json"),
            "receiptSha256": _sha256(production_run / "receipt.json"),
            "collectionResultSha256": _sha256(production_run / "collection/result.json"),
            "gateSnapshotSha256": _sha256(production_run / "gate-snapshot.json"),
        },
        "localEvidence": {
            "manifestSha256": _sha256(local_run / "manifest.json"),
            "projectionSha256": _sha256(local_run / "v2-projection.json"),
        },
    }
    if output.exists() or output.is_symlink():
        raise ComparisonError("refusing to overwrite existing output")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production-run", type=Path, required=True)
    parser.add_argument("--local-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = compare_runs(args.production_run, args.local_run, args.output)
    except (ComparisonError, OSError, json.JSONDecodeError) as error:
        print(f"bounded comparison refused: {error}")
        return 2
    print(json.dumps({"kind": result["kind"], "boundedObservedParity": result["boundedObservedParity"], "typedFinalAbsence": result["typedFinalAbsence"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
