from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SIBLING = HERE.parent / "fs-write-limits"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SIBLING))

from comparator import compare_rows as compare_v1
from compiler import compile_limits_plan
from v2_kernel import compare_rows


def journal(nonce: str, project: str):
    plan = compile_limits_plan(project, "(default)", nonce * 32)
    rows = []
    for index, request in enumerate(
        plan["localGatePlan"]["jobs"]["limits"]["observation"]
    ):
        rows.append(
            {
                "index": index,
                "request": copy.deepcopy(request),
                "complete": True,
                "status": 400,
                "body": {"error": {"status": "INVALID_ARGUMENT", "code": 400}},
                "failure": None,
            }
        )
    return plan, rows


def resource(plan, row):
    return row["request"]["path"].split("?", 1)[0].removeprefix("/v1/")


def error_rows(plan, rows):
    for index, row in enumerate(rows):
        if index >= 8:
            continue
        current = resource(plan, row)
        if index % 2:
            message = f"Document '{current}' cannot be written because its size (123) exceeds 1048576."
        else:
            message = f'Document "{current}" not found.'
        row["body"] = {
            "error": {"status": "INVALID_ARGUMENT", "code": 400, "message": message}
        }


def test_v2_turns_current_resource_only_into_expected_nondeterminism():
    production_plan, production_rows = journal("a", "demo-production")
    local_plan, local_rows = journal("b", "demo-local")
    error_rows(production_plan, production_rows)
    error_rows(local_plan, local_rows)

    assert (
        compare_v1(production_plan, production_rows, local_plan, local_rows)[
            "classification"
        ]
        == "SEMANTIC_MISMATCH"
    )
    compared = compare_rows(production_plan, production_rows, local_plan, local_rows)
    assert compared["classification"] == "EXPECTED_NONDETERMINISM"
    assert compared["kind"] == "fs-write-limits-semantic-kernel-v2"
    assert len(compared["rows"]) == 16
    assert (
        sum(
            row["classification"] == "EXPECTED_NONDETERMINISM"
            for row in compared["rows"]
        )
        == 8
    )


@pytest.mark.parametrize(
    "rewrite",
    [
        lambda resource: f'Document "{resource.upper()}" not found.',
        lambda resource: f'Document "unknown/{resource}" not found.',
        lambda resource: f'Document "{resource}/longer" not found.',
        lambda resource: f'Document "prefix-{resource}-suffix" not found.',
        lambda resource: f'Document "{resource}" not found. ({resource})',
        lambda resource: (
            f"Document '{resource}' cannot be written because its size (123) exceeds 1048576!"
        ),
    ],
)
def test_v2_preserves_non_exact_or_non_message_resource_text(rewrite):
    production_plan, production_rows = journal("a", "demo-production")
    local_plan, local_rows = journal("b", "demo-local")
    error_rows(production_plan, production_rows)
    error_rows(local_plan, local_rows)
    current = resource(local_plan, local_rows[0])
    local_rows[0]["body"]["error"]["message"] = rewrite(current)

    result = compare_rows(production_plan, production_rows, local_plan, local_rows)
    assert result["classification"] == "SEMANTIC_MISMATCH"
    assert result["rows"][0]["classification"] == "SEMANTIC_MISMATCH"


def test_v2_does_not_replace_resource_tokens_outside_error_message():
    production_plan, production_rows = journal("a", "demo-production")
    local_plan, local_rows = journal("b", "demo-local")
    error_rows(production_plan, production_rows)
    error_rows(local_plan, local_rows)
    current = resource(local_plan, local_rows[0])
    local_rows[0]["body"]["details"] = {"literal": current}
    production_rows[0]["body"]["details"] = {
        "literal": resource(production_plan, production_rows[0])
    }

    result = compare_rows(production_plan, production_rows, local_plan, local_rows)
    assert result["classification"] == "SEMANTIC_MISMATCH"


def test_v2_source_hash_is_stable_and_v1_files_are_untouched():
    from v2_kernel import V1_COMPARATOR, V1_PRODUCTION, V2_SOURCE_SHA256

    assert (
        V2_SOURCE_SHA256
        == hashlib.sha256(
            Path(__file__).with_name("v2_kernel.py").read_bytes()
        ).hexdigest()
    )
    assert V1_COMPARATOR.name == "comparator.py"
    assert V1_PRODUCTION.name == "production.py"


def test_output_directory_creation_refuses_existing_symlink(tmp_path):
    from recompare import create_output_directory

    output = tmp_path / "result"
    created = create_output_directory(output)
    assert created == output
    with pytest.raises(FileExistsError):
        create_output_directory(output)

    symlink = tmp_path / "symlink"
    symlink.symlink_to(output, target_is_directory=True)
    with pytest.raises(FileExistsError):
        create_output_directory(symlink)


def test_json_output_refuses_existing_symlink_and_hardlink(tmp_path):
    from recompare import save_json

    source = tmp_path / "source.json"
    source.write_text("{}\n")
    hardlink = tmp_path / "hardlink.json"
    hardlink.hardlink_to(source)
    with pytest.raises(FileExistsError):
        save_json(hardlink, {"changed": True})

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(source)
    with pytest.raises(FileExistsError):
        save_json(symlink, {"changed": True})


def test_hashed_json_parses_the_same_bytes_it_reports(tmp_path):
    from recompare import read_json_hashed

    path = tmp_path / "evidence.json"
    path.write_bytes(b'{"value": 1}\n')
    value, digest = read_json_hashed(path)
    assert value == {"value": 1}
    assert digest == hashlib.sha256(b'{"value": 1}\n').hexdigest()


def test_local_bundle_snapshot_uses_captured_bytes(tmp_path):
    from recompare import capture_local_bundle

    source = tmp_path / "local"
    source.mkdir()
    names = ("manifest.json", "cases.json", "result.json", "shadow-binding.json")
    for name in names:
        (source / name).write_bytes(name.encode())
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"artifact")
    private = tmp_path / "private"
    private.mkdir()
    snapshot, artifact_snapshot, hashes, artifact_hash = capture_local_bundle(
        source, artifact, private
    )
    (source / "result.json").write_bytes(b"mutated")
    artifact.write_bytes(b"mutated-artifact")
    assert (snapshot / "result.json").read_bytes() == b"result.json"
    assert artifact_snapshot.read_bytes() == b"artifact"
    assert hashes["result.json"] == hashlib.sha256(b"result.json").hexdigest()
    assert artifact_hash == hashlib.sha256(b"artifact").hexdigest()


def test_v2_binding_declares_both_source_files_and_aggregate():
    from recompare import V2_ENTRY_SOURCE_SHA256, V2_SOURCE_SHA256
    from v2_kernel import V2_SOURCE_SHA256 as kernel_hash

    assert V2_ENTRY_SOURCE_SHA256 != kernel_hash
    assert len(V2_SOURCE_SHA256) == 64


def test_recompare_preserves_indeterminate_for_invalid_v1_acquisition(tmp_path):
    from recompare import recompare

    production = tmp_path / "production"
    local = tmp_path / "local"
    production.mkdir()
    local.mkdir()
    artifact = tmp_path / "missing-artifact"
    output = tmp_path / "output"

    result = recompare(production, local, artifact, output)
    v1 = json.loads((output / "v1-result.json").read_bytes())
    v2 = json.loads((output / "v2-result.json").read_bytes())
    binding = json.loads((output / "binding.json").read_bytes())

    assert result["classification"] == "INDETERMINATE"
    assert v1["classification"] == "INDETERMINATE"
    assert v2["classification"] == "INDETERMINATE"
    assert binding["acquisitionValidated"] is False
    assert binding["promotionReady"] is False
    assert (
        binding["v2ResultSha256"]
        == hashlib.sha256((output / "v2-result.json").read_bytes()).hexdigest()
    )


def test_recompare_retained_repaired_artifact_against_immutable_production(tmp_path):
    """Optional private-evidence integration; no credentials or production dispatch."""
    import subprocess

    from recompare import recompare

    common = Path(
        subprocess.check_output(
            ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=HERE,
            text=True,
        ).strip()
    )
    retained = common.parent / "docs.local/logs/2026-09-17"
    production = retained / "limits-production-40dfc0da3"
    local = retained / "limits-repair-shadow-8b33aac4d"
    if not production.is_dir() or not local.is_dir():
        pytest.skip("private immutable evidence not retained in this checkout")
    expected = {
        "receipt.json": "ca418bcf1eed6d906baebc7d22090161752071c7d845ab19a10bd3b6ddc429a7",
        "inputs.json": "27f62136d95e85ae514ffd4ec7ae885d806d09540bfbf8a4281f837c06323499",
    }
    for name, checksum in expected.items():
        assert hashlib.sha256((production / name).read_bytes()).hexdigest() == checksum
    result = recompare(production, local, local / "fireemu", tmp_path / "derived")
    binding = json.loads((tmp_path / "derived/binding.json").read_bytes())
    assert binding["acquisitionValidated"] is True
    assert result["classification"] == "EXPECTED_NONDETERMINISM"
    assert binding["productionReceiptSha256"] == expected["receipt.json"]
    assert binding["frozenInputsSha256"] == expected["inputs.json"]
    assert (
        binding["artifactSha256"]
        == "76f855367910ad237de6ffd491091f20bcdccdb2e5eb8ee417e80b94bf6ac397"
    )
    for name, checksum in expected.items():
        assert hashlib.sha256((production / name).read_bytes()).hexdigest() == checksum
