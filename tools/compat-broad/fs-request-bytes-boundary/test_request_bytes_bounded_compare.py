import json
import hashlib
import shutil
from pathlib import Path

import pytest

import request_bytes_bounded_compare as comparator
from request_bytes_bounded_compare import ComparisonError, compare_runs


ROOT = Path(__file__).resolve().parents[5]
PRODUCTION = ROOT / "docs.local/runs/requestbytes-production-2a1-fresh02"
LOCAL = ROOT / "docs.local/runs/requestbytes-exact-replay-20260922-v2/ba4-483-rerun"
RUNTIME_ARTIFACT = ROOT / "docs.local/runs/requestbytes-native-ba4-20260922/fireemu"
RUNTIME_SOURCE_MAP = ROOT / "docs.local/runs/requestbytes-native-ba4-20260922/source-runtime-input-map.txt"
FREEZE_MANIFEST = ROOT / "docs.local/runs/requestbytes-exact-replay-20260922-v2/freeze-manifest.json"


@pytest.fixture(scope="module")
def local_copy(tmp_path_factory: pytest.TempPathFactory) -> Path:
    target = tmp_path_factory.mktemp("bounded") / "local"
    shutil.copytree(LOCAL, target)
    return target


def _run(local: Path, output: Path) -> dict:
    return compare_runs(
        PRODUCTION,
        local,
        output,
        runtime_artifact=RUNTIME_ARTIFACT,
        runtime_source_map=RUNTIME_SOURCE_MAP,
        freeze_manifest=FREEZE_MANIFEST,
    )


def _v3_fixture(tmp_path: Path, *, unsafe_cleanup: bool = False) -> Path:
    from request_bytes_run_fixture import run_collector

    run = tmp_path / "v3"
    run.mkdir()
    result = run_collector(run / "collection", over=None)
    result_path = run / "collection/result.json"
    if unsafe_cleanup:
        result["resourceAbsence"] = False
        result["cleanupSafetyComplete"] = False
        result["failures"] = ["cleanup:final-absence:incomplete"]
        result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    source_root = Path(__file__).resolve().parents[3]
    source_paths = {
        relative: hashlib.sha256((source_root / relative).read_bytes()).hexdigest()
        for relative in (
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_collector.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_bounded_compare.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_compiler.py",
            "tools/compat-broad/fs-request-bytes-boundary/request_bytes_local_transport.py",
        )
    }
    expected = {
        "kind": "requestbytes-immutable-saved-status-binding-v1",
        "savedRun": "/private/immutable/requestbytes-production-2a1-fresh02",
        "bodyBindings": result["localJournal"]["requestBindings"],
        "statusByProbe": comparator.EXPECTED_STATUS,
    }
    (run / "immutable-expected.json").write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
    journal = result["localJournal"]
    cases = {
        "captureComplete": journal["captureComplete"],
        "recordingComplete": not unsafe_cleanup,
        "conditionIds": comparator.CONDITION_IDS,
        "collectionResultSha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
        "localJournalDigest": journal["entryDigest"],
    }
    (run / "cases.json").write_text(json.dumps(cases, indent=2, sort_keys=True) + "\n")
    manifest = {
        "partialResultSha256": hashlib.sha256((run / "cases.json").read_bytes()).hexdigest(),
        "productionExecuted": False,
        "productionEndpointUsed": False,
        "formalCompatibilityClaim": False,
        "artifactSha256": comparator.ARTIFACT_SHA256,
        "sourceCheckoutCommit": "a" * 40,
        "sourceModuleDigests": source_paths,
        "ownedProcess": {"stopped": True, "listenersClosed": True},
    }
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    projection = {
        "productionExecuted": False,
        "productionEndpointUsed": False,
        "immutableExpectedDigest": hashlib.sha256(
            json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "actualStatusByProbe": comparator.EXPECTED_STATUS,
        "typedFinalAbsence51": result["resourceAbsence"],
        "legacyCollectorFailure": ["over:unexpected-success"],
        "collectorCompleted": False,
        "cleanupComplete": False,
        "captureComplete": journal["captureComplete"],
        "cleanupSafetyComplete": result["cleanupSafetyComplete"],
        "sourceCheckoutCommit": "a" * 40,
    }
    (run / "v3-projection.json").write_text(json.dumps(projection, indent=2, sort_keys=True) + "\n")
    anchor = {
        "kind": "requestbytes-v3-local-journal-anchor-v1",
        "producerJournal": journal,
        "journalDigest": journal["entryDigest"],
    }
    (run / "local-journal-anchor.json").write_text(json.dumps(anchor, indent=2, sort_keys=True) + "\n")
    freeze = {
        "kind": "requestbytes-exact-replay-private-freeze-v3",
        "localJournalFile": "local-journal-anchor.json",
        "files": {
            name: hashlib.sha256((run / name).read_bytes()).hexdigest()
            for name in (
                "manifest.json",
                "cases.json",
                "v3-projection.json",
                "immutable-expected.json",
                "collection/result.json",
                "local-journal-anchor.json",
            )
        },
    }
    freeze_path = run / "freeze.json"
    freeze_path.write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n")
    return run


def test_actual_saved_rows_produce_bounded_result(local_copy: Path, tmp_path: Path) -> None:
    with pytest.raises(ComparisonError, match="V3 local journal"):
        _run(local_copy, tmp_path / "result.json")


def test_real_collector_journal_chain_is_accepted(tmp_path: Path) -> None:
    run = _v3_fixture(tmp_path)
    journal = comparator._validate_v3_capture(
        run, run / "freeze.json", hashlib.sha256((run / "freeze.json").read_bytes()).hexdigest()
    )
    projection = comparator._validate_local_bindings(run, run / "immutable-expected.json")
    assert journal["captureComplete"] is True
    assert journal["entryDigest"]
    assert projection["cleanupSafetyComplete"] is True


def test_capture_without_cleanup_safety_is_refused(tmp_path: Path) -> None:
    run = _v3_fixture(tmp_path, unsafe_cleanup=True)
    with pytest.raises(ComparisonError, match="cleanup safety"):
        comparator._validate_v3_capture(
            run, run / "freeze.json", hashlib.sha256((run / "freeze.json").read_bytes()).hexdigest()
        )


@pytest.mark.parametrize(
    "relative,mutate",
    [
        ("collection/row-017.json", lambda d: d["receipt"].update(status=400)),
        ("collection/row-017.json", lambda d: d.update(probe="exact")),
        ("collection/row-018.json", lambda d: d.update(resource="foreign/resource")),
        ("manifest.json", lambda d: d.update(artifactSha256="0" * 64)),
        ("v2-projection.json", lambda d: d.update(legacyCollectorFailure=[])),
    ],
)
def test_row_and_binding_tampering_is_refused(
    local_copy: Path, tmp_path: Path, relative: str, mutate
) -> None:
    path = local_copy / relative
    original = path.read_bytes()
    value = json.loads(original)
    mutate(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    try:
        with pytest.raises(ComparisonError):
            _run(local_copy, tmp_path / "rejected.json")
    finally:
        path.write_bytes(original)


def test_response_field_tampering_is_refused(local_copy: Path, tmp_path: Path) -> None:
    path = local_copy / "collection/response-018.body"
    original = path.read_bytes()
    value = json.loads(original)
    value["fields"]["blob"]["stringValue"] += "x"
    path.write_text(json.dumps(value), encoding="utf-8")
    try:
        with pytest.raises(ComparisonError):
            _run(local_copy, tmp_path / "rejected.json")
    finally:
        path.write_bytes(original)


def test_boolean_and_string_fields_are_not_equal(local_copy: Path, tmp_path: Path) -> None:
    path = local_copy / "collection/response-018.body"
    original = path.read_bytes()
    value = json.loads(original)
    value["fields"]["blob"]["stringValue"] = False
    path.write_text(json.dumps(value), encoding="utf-8")
    try:
        with pytest.raises(ComparisonError):
            _run(local_copy, tmp_path / "rejected.json")
    finally:
        path.write_bytes(original)


def test_write_version_tampering_is_refused(local_copy: Path, tmp_path: Path) -> None:
    path = local_copy / "collection/response-017.body"
    original = path.read_bytes()
    value = json.loads(original)
    value["writeResults"][0].pop("updateTime")
    path.write_text(json.dumps(value), encoding="utf-8")
    try:
        with pytest.raises(ComparisonError):
            _run(local_copy, tmp_path / "rejected.json")
    finally:
        path.write_bytes(original)


def test_final_absence_tampering_is_refused(local_copy: Path, tmp_path: Path) -> None:
    path = local_copy / "collection/response-037.body"
    original = path.read_bytes()
    value = json.loads(original)
    value["error"]["status"] = "OK"
    path.write_text(json.dumps(value), encoding="utf-8")
    try:
        with pytest.raises(ComparisonError):
            _run(local_copy, tmp_path / "rejected.json")
    finally:
        path.write_bytes(original)


def test_final_absence_resource_tampering_is_refused(local_copy: Path, tmp_path: Path) -> None:
    path = local_copy / "collection/row-037.json"
    original = path.read_bytes()
    value = json.loads(original)
    value["resource"] = "foreign/resource"
    path.write_text(json.dumps(value), encoding="utf-8")
    try:
        with pytest.raises(ComparisonError):
            _run(local_copy, tmp_path / "rejected.json")
    finally:
        path.write_bytes(original)


def test_body_tampering_is_refused(local_copy: Path, tmp_path: Path) -> None:
    path = local_copy / "collection/request-under.body"
    original = path.read_bytes()
    path.write_bytes(original + b" ")
    try:
        with pytest.raises(ComparisonError):
            _run(local_copy, tmp_path / "rejected.json")
    finally:
        path.write_bytes(original)


def test_existing_output_is_never_overwritten(local_copy: Path, tmp_path: Path) -> None:
    output = tmp_path / "existing.json"
    output.write_text("retain", encoding="utf-8")
    with pytest.raises(ComparisonError, match="V3 local journal"):
        _run(local_copy, output)
    assert output.read_text(encoding="utf-8") == "retain"
