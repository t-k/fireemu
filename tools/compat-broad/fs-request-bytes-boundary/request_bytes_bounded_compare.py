"""Compare the retained request-byte rows without promoting broad compatibility."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
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
PRODUCTION_ROW_DIGEST = "0f44b5daf53e7474d1dd14865fee7404603f83dc23a1bcd2ff8740f19a105fb7"
FREEZE_MANIFEST_SHA256 = "9ea3479f2449244cd05ab9b62be33daf0259b357a0d837edf8357993edd3ed5b"
PRODUCTION_RUN = "requestbytes-production-2a1-fresh02"
RESULT_KIND = "requestbytes-bounded-response-sideeffect-comparison-v1"
CONDITION_IDS = [
    "FS-LIMIT-API-REQUEST-BYTES-UNDER",
    "FS-LIMIT-API-REQUEST-BYTES-EXACT",
    "FS-LIMIT-API-REQUEST-BYTES-OVER",
]
_COMMIT = re.compile(r"^[0-9a-f]{40}$")


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


def _row_digest(collection: Path) -> str:
    hashes = []
    for path in sorted(collection.glob("row-*.json")):
        hashes.append(f"{path.name}:{_sha256(path)}")
    return hashlib.sha256("\n".join(hashes).encode()).hexdigest()


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
    def phase(kind: str) -> list[dict[str, Any]]:
        return [r for r in rows.values() if r.get("probe") == probe and r.get("kind") == kind]

    preflight = phase("preflight-typed-absence")
    if len(preflight) != 17 or len({_row_resource(row) for row in preflight}) != 17 or {_row_resource(row) for row in preflight} != set(expected):
        raise ComparisonError(f"{probe}: preflight resource set")
    for row in preflight:
        if row.get("method") != "GET" or row.get("path") != "/v1/" + row["resource"] or _status(row) != 404 or not _typed_not_found(collection, row):
            raise ComparisonError(f"{probe}: preflight typed absence")

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
    if any(type(item.get("updateTime")) is not str or not item["updateTime"] for item in results):
        raise ComparisonError(f"{probe}: versioned write results")

    readbacks = [r for r in rows.values() if r.get("probe") == probe and r.get("kind") == "probe-readback"]
    if len(readbacks) != 17 or len({_row_resource(r) for r in readbacks}) != 17 or {_row_resource(r) for r in readbacks} != set(expected):
        raise ComparisonError(f"{probe}: readback resource set")
    if any(row.get("method") != "GET" or row.get("path") != "/v1/" + row["resource"] for row in readbacks):
        raise ComparisonError(f"{probe}: readback canonical path")
    fields_equal = True
    readback_digests = []
    readback_versions = {}
    for row in readbacks:
        body = _response(collection, row)
        if _status(row) != 200 or body.get("name") != row.get("resource"):
            fields_equal = False
            continue
        fields_equal = fields_equal and _same_json(body.get("fields"), expected[row["resource"]])
        if type(body.get("updateTime")) is not str or not body["updateTime"]:
            raise ComparisonError(f"{probe}: readback version")
        readback_versions[row["resource"]] = body["updateTime"]
        readback_digests.append(_digest({"name": body.get("name"), "fields": body.get("fields")}))
    if list(readback_versions.get(name) for name in expected) != [item["updateTime"] for item in results]:
        raise ComparisonError(f"{probe}: commit/readback version linkage")

    ownership_reads = [r for r in rows.values() if r.get("probe") == probe and r.get("kind") == "cleanup-ownership-read"]
    deletes = [r for r in rows.values() if r.get("probe") == probe and r.get("kind") == "cleanup-version-bound-delete"]
    absence = [r for r in rows.values() if r.get("probe") == probe and r.get("kind") == "cleanup-verify-absence"]
    if len(ownership_reads) != 17 or len(deletes) != 17 or len(absence) != 17:
        raise ComparisonError(f"{probe}: versioned cleanup counts")
    expected_names = set(expected)
    for phase_rows in (ownership_reads, deletes, absence):
        names = [_row_resource(row) for row in phase_rows]
        if len(set(names)) != 17 or set(names) != expected_names:
            raise ComparisonError(f"{probe}: cleanup resource set")
    if any(_row_resource(row) not in expected_names for row in ownership_reads + deletes + absence):
        raise ComparisonError(f"{probe}: cleanup resource set")
    if any(row.get("method") != "GET" or row.get("path") != "/v1/" + row["resource"] or _status(row) != 200 for row in ownership_reads):
        raise ComparisonError(f"{probe}: ownership read status")
    update_times = readback_versions
    for row in ownership_reads:
        body = _response(collection, row)
        if (
            body.get("name") != row["resource"]
            or not _same_json(body.get("fields"), expected[row["resource"]])
            or body.get("updateTime") != update_times[row["resource"]]
        ):
            raise ComparisonError(f"{probe}: ownership version linkage")
    if any(_status(row) != 200 for row in deletes):
        raise ComparisonError(f"{probe}: version-bound delete status")
    if any(row.get("method") != "DELETE" for row in deletes):
        raise ComparisonError(f"{probe}: delete method")
    for row in deletes:
        query = parse_qs(urlsplit(row.get("path", "")).query)
        if urlsplit(row.get("path", "")).path != "/v1/" + row["resource"] or query.get("currentDocument.updateTime") != [update_times[row["resource"]]]:
            raise ComparisonError(f"{probe}: delete version linkage")
    if any(row.get("method") != "GET" or row.get("path") != "/v1/" + row["resource"] for row in absence):
        raise ComparisonError(f"{probe}: absence canonical path")
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
    projection = _json(run / "v3-projection.json")
    manifest = _json(run / "manifest.json")
    if projection.get("immutableExpectedDigest") != _digest(_json(immutable)):
        raise ComparisonError("immutable expected digest binding")
    source_commit = manifest.get("sourceCheckoutCommit")
    modules = manifest.get("sourceModuleDigests")
    if (
        manifest.get("artifactSha256") != ARTIFACT_SHA256
        or not isinstance(source_commit, str)
        or _COMMIT.fullmatch(source_commit) is None
        or source_commit == HARNESS_COMMIT
        or not isinstance(modules, dict)
        or set(modules) != {
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_collector.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_bounded_compare.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_compiler.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_local_transport.py",
        }
        or any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in modules.values()
        )
    ):
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
    if projection.get("captureComplete") is not True or projection.get("cleanupSafetyComplete") is not True:
        raise ComparisonError("local cleanup safety binding")
    if projection.get("sourceCheckoutCommit") != source_commit:
        raise ComparisonError("projection/source commit binding")
    if manifest.get("formalCompatibilityClaim") is not False:
        raise ComparisonError("formal compatibility claim")
    return projection


def _journal_digest(entries: list[dict[str, Any]]) -> str:
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_journal_files(run: Path, journal: dict[str, Any], expected: dict[str, Any]) -> None:
    collection = run / "collection"
    rows = journal.get("rowEntries")
    sidecars = journal.get("sidecarEntries")
    if (
        not isinstance(rows, list)
        or not isinstance(sidecars, list)
        or len(rows) != 258
        or len(sidecars) != 258
        or [item.get("sequence") for item in rows] != list(range(258))
    ):
        raise ComparisonError("V3 journal sequence/count")
    names = [item.get("name") for item in rows + sidecars]
    if any(not isinstance(name, str) or Path(name).name != name for name in names) or len(set(names)) != len(names):
        raise ComparisonError("V3 journal filename coverage")
    for entry in rows + sidecars:
        if type(entry.get("bytes")) is not int or not isinstance(entry.get("sha256"), str):
            raise ComparisonError("V3 journal entry shape")
        path = _regular_child(collection, entry["name"])
        data = path.read_bytes()
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ComparisonError(f"V3 journal byte binding: {entry['name']}")
    sidecar_names = {entry["name"] for entry in sidecars}
    referenced = set()
    for entry in rows:
        row = _json(collection / entry["name"])
        sidecar = row.get("responseBodyFile")
        if not isinstance(sidecar, str) or sidecar not in sidecar_names:
            raise ComparisonError("V3 row/sidecar coverage")
        referenced.add(sidecar)
    if referenced != sidecar_names:
        raise ComparisonError("V3 sidecar reference coverage")
    if journal.get("entryDigest") != _journal_digest(rows + sidecars):
        raise ComparisonError("V3 journal digest")
    bindings = journal.get("requestBindings")
    if bindings != expected.get("bodyBindings"):
        raise ComparisonError("V3 request binding")


def _validate_v3_capture(run: Path, freeze: Path, freeze_sha256: str) -> dict[str, Any]:
    if freeze.is_symlink() or not freeze.is_file() or _sha256(freeze) != freeze_sha256:
        raise ComparisonError("V3 freeze binding")
    frozen = _json(freeze)
    if frozen.get("kind") != "requestbytes-exact-replay-private-freeze-v3":
        raise ComparisonError("V3 freeze kind")
    files = frozen.get("files")
    required_files = {
        "manifest.json",
        "cases.json",
        "v3-projection.json",
        "immutable-expected.json",
        "collection/result.json",
        "local-journal-anchor.json",
    }
    if not isinstance(files, dict) or set(files) != required_files:
        raise ComparisonError("V3 freeze files")
    for relative, expected in files.items():
        path = _regular_child(run, relative)
        if _sha256(path) != expected:
            raise ComparisonError(f"V3 frozen file changed: {relative}")
    journal_path = _regular_child(run, frozen.get("localJournalFile", ""))
    anchor = _json(journal_path)
    journal = anchor.get("producerJournal")
    if not isinstance(journal, dict):
        raise ComparisonError("V3 producer journal missing")
    result_path = _regular_child(run, "collection/result.json")
    result = _json(result_path)
    if result.get("localJournal") != journal:
        raise ComparisonError("V3 journal/result binding")
    if journal.get("captureComplete") is not True or journal.get("rowCount") != 258 or journal.get("sidecarCount") != 258:
        raise ComparisonError("V3 incomplete local journal")
    cases = _json(_regular_child(run, "cases.json"))
    manifest = _json(_regular_child(run, "manifest.json"))
    if _sha256(_regular_child(run, "cases.json")) != manifest.get("partialResultSha256"):
        raise ComparisonError("V3 supervisor/cases binding")
    if cases.get("collectionResultSha256") != _sha256(result_path) or cases.get("localJournalDigest") != journal.get("entryDigest"):
        raise ComparisonError("V3 cases/journal binding")
    if cases.get("captureComplete") is not True or cases.get("conditionIds") != CONDITION_IDS:
        raise ComparisonError("V3 cases contract")
    if (
        manifest.get("productionExecuted") is not False
        or manifest.get("productionEndpointUsed") is not False
        or manifest.get("ownedProcess", {}).get("stopped") is not True
        or manifest.get("ownedProcess", {}).get("listenersClosed") is not True
    ):
        raise ComparisonError("V3 process/production closure")
    if result.get("productionExecuted") is not False or result.get("localOnly") is not True:
        raise ComparisonError("V3 result production binding")
    expected = _json(_regular_child(run, "immutable-expected.json"))
    _validate_journal_files(run, journal, expected)
    if result.get("cleanupSafetyComplete") is not True or result.get("resourceAbsence") is not True:
        raise ComparisonError("V3 cleanup safety")
    if cases.get("recordingComplete") is not True:
        raise ComparisonError("V3 supervisor recording binding")
    return journal


def _validate_runtime_anchor(production_run: Path, runtime_artifact: Path, runtime_source_map: Path, freeze_manifest: Path) -> None:
    anchors = {
        "inputs.json": PRODUCTION_INPUTS_SHA256,
        "receipt.json": PRODUCTION_RECEIPT_SHA256,
        "collection/result.json": PRODUCTION_RESULT_SHA256,
        "gate/state.json": PRODUCTION_GATE_STATE_SHA256,
    }
    for relative, expected in anchors.items():
        if _sha256(production_run / relative) != expected:
            raise ComparisonError(f"production anchor changed: {relative}")
    if runtime_artifact.is_symlink() or not runtime_artifact.is_file() or _sha256(runtime_artifact) != ARTIFACT_SHA256:
        raise ComparisonError("runtime artifact binding")
    if runtime_source_map.is_symlink() or not runtime_source_map.is_file() or _sha256(runtime_source_map) != RUNTIME_SOURCE_MAP_SHA256:
        raise ComparisonError("runtime source map binding")
    fields = {}
    for line in runtime_source_map.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    if fields.get("sourceCommit") != RUNTIME_SOURCE_COMMIT or fields.get("artifactSha256") != ARTIFACT_SHA256:
        raise ComparisonError("runtime source/artifact map binding")
    if freeze_manifest.is_symlink() or not freeze_manifest.is_file() or _sha256(freeze_manifest) != FREEZE_MANIFEST_SHA256:
        raise ComparisonError("private freeze manifest binding")
    frozen = _json(freeze_manifest)
    if frozen.get("bindings", {}).get("runtimeArtifactSha256") != ARTIFACT_SHA256 or frozen.get("bindings", {}).get("harnessSourceCommit") != HARNESS_COMMIT:
        raise ComparisonError("private freeze bindings")


def compare_runs(
    production_run: Path,
    local_run: Path,
    output: Path,
    *,
    runtime_artifact: Path | None = None,
    runtime_source_map: Path | None = None,
    freeze_manifest: Path | None = None,
    v3_freeze: Path | None = None,
    v3_freeze_sha256: str | None = None,
) -> dict[str, Any]:
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
    if production_run.name != PRODUCTION_RUN:
        raise ComparisonError("saved production path binding")
    if v3_freeze is None or v3_freeze_sha256 is None:
        raise ComparisonError("missing V3 local journal anchor")
    if runtime_artifact is None or runtime_source_map is None or freeze_manifest is None:
        evidence_root = Path(expected["savedRun"]).resolve().parents[2]
        runtime_artifact = evidence_root / "docs.local/runs/requestbytes-native-ba4-20260922/fireemu"
        runtime_source_map = evidence_root / "docs.local/runs/requestbytes-native-ba4-20260922/source-runtime-input-map.txt"
        freeze_manifest = evidence_root / "docs.local/runs/requestbytes-exact-replay-20260922-v2/freeze-manifest.json"
    _validate_runtime_anchor(production_run, runtime_artifact, runtime_source_map, freeze_manifest)
    _validate_v3_capture(local_run, v3_freeze, v3_freeze_sha256)
    production_collection, production_rows = _rows(production_run)
    if _row_digest(production_collection) != expected.get("rowDigest") or _row_digest(production_collection) != PRODUCTION_ROW_DIGEST:
        raise ComparisonError("anchored production row journal changed")
    production = {probe: _probe_result(production_run, probe) for probe in PROBES}
    local = {probe: _probe_result(local_run, probe) for probe in PROBES}
    local_projection = _validate_local_bindings(local_run, immutable)
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
        "sourceCheckoutCommit": local_projection["sourceCheckoutCommit"],
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
            "projectionSha256": _sha256(local_run / "v3-projection.json"),
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as error:
        raise ComparisonError("refusing to overwrite existing output") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production-run", type=Path, required=True)
    parser.add_argument("--local-run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime-artifact", type=Path, required=True)
    parser.add_argument("--runtime-source-map", type=Path, required=True)
    parser.add_argument("--freeze-manifest", type=Path, required=True)
    parser.add_argument("--v3-freeze", type=Path, required=True)
    parser.add_argument("--v3-freeze-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = compare_runs(args.production_run, args.local_run, args.output, runtime_artifact=args.runtime_artifact, runtime_source_map=args.runtime_source_map, freeze_manifest=args.freeze_manifest, v3_freeze=args.v3_freeze, v3_freeze_sha256=args.v3_freeze_sha256)
    except (ComparisonError, OSError, json.JSONDecodeError) as error:
        print(f"bounded comparison refused: {error}")
        return 2
    print(json.dumps({"kind": result["kind"], "boundedObservedParity": result["boundedObservedParity"], "typedFinalAbsence": result["typedFinalAbsence"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
