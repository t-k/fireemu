import json
import shutil
from pathlib import Path

import pytest

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


def test_actual_saved_rows_produce_bounded_result(local_copy: Path, tmp_path: Path) -> None:
    with pytest.raises(ComparisonError, match="V3 local journal"):
        _run(local_copy, tmp_path / "result.json")


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
