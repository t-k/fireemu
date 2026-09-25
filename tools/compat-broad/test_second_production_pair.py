"""Observed outcomes do not relax independent operation and version admission."""

import copy
import hashlib
import json
import subprocess
import sys

import pytest
from broad_contract import digest
from second_admission import FS_IDS, manifest
from second_mapping import validate_rows, validate_trace
from test_second_mapping import receipt
from test_second_production import boundary  # noqa: F401


def deleted_receipt():
    value = receipt("mapped")
    value["admissionDigest"] = digest(manifest())
    program = FS_IDS[1]
    document = value["documents"][program]
    diagnostic = next(r for r in value["rows"] if r["id"] == program + "/diagnostic")
    after = next(r for r in value["rows"] if r["id"] == program + "/after")
    for row, status in ((diagnostic, 200), (after, 404)):
        old = copy.deepcopy(row["observation"])
        row["observation"]["httpStatus"] = status
        row["observation"]["http"]["status"] = status
        row["observation"]["body"] = {}
        entry = next(
            t
            for t in value["trace"]
            if t["phase"] == row["id"].rsplit("/", 1)[1]
            and t["observation"] == old
            and t["sent"] == row["sent"]
        )
        entry["observation"] = copy.deepcopy(row["observation"])
    after["versions"].pop("after")
    cleanup = [
        t
        for t in value["trace"]
        if t["phase"] == "recovery" and t["sent"]["path"] == "/v1/" + document
    ]
    cleanup[0]["observation"] = copy.deepcopy(after["observation"])
    value["trace"].remove(cleanup[1])
    for ordinal, entry in enumerate(value["trace"]):
        entry["ordinal"] = ordinal
    return value


def test_deleted_document_is_an_observed_outcome_with_absence_cleanup():
    value = deleted_receipt()
    validate_rows(value, observed_outcomes=True)
    assert validate_trace(value, observed_outcomes=True)
    with pytest.raises(ValueError):
        validate_rows(value)


@pytest.mark.parametrize(
    "mutation", ["phase", "ordinal", "recovery", "latest-version", "duplicate-mask"]
)
def test_new_contract_still_rejects_detached_or_changed_operations(mutation):
    value = deleted_receipt()
    if mutation in {"phase", "ordinal", "recovery"}:
        value["trace"][0][mutation] = {
            "phase": "after",
            "ordinal": 9,
            "recovery": True,
        }[mutation]
    else:
        row = next(
            r
            for r in value["rows"]
            if r["id"]
            == FS_IDS[1 if mutation == "latest-version" else 0] + "/diagnostic"
        )
        entry = next(t for t in value["trace"] if t["sent"] == row["sent"])
        if mutation == "latest-version":
            row["sent"]["query"][0][1] = row["versions"]["before"]
        else:
            row["sent"]["query"].pop()
        entry["sent"] = copy.deepcopy(row["sent"])
    with pytest.raises(ValueError):
        validate_trace(value, observed_outcomes=True)


def current_local(source):
    from second_production_contract import binding, observer_digest
    from second_production_contract import manifest as production_manifest

    value = copy.deepcopy(source)
    value.update(
        kind="second45-local-run-v1",
        target="local",
        productionExecuted=False,
        admissionDigest=digest(manifest()),
        manifestDigest=digest(manifest()),
        comparisonManifestDigest=digest(production_manifest()),
        comparisonContractDigest=digest(binding()),
        observerDigest=observer_digest(),
    )
    return value


@pytest.fixture
def production_inputs(request):
    # The imported fixture substitutes every external boundary before construction.
    return request.getfixturevalue("boundary")


def test_production_pair_preserves_match_mismatch_missing_and_cleanup(
    production_inputs, tmp_path
):
    from second_mapped import execute_45
    from second_production import Production45Adapter
    from second_production_contract import manifest as production_manifest
    from second_production_pair import compare

    permission, backend = production_inputs
    adapter = Production45Adapter(
        production_manifest(), permission, permission["nonce"], tmp_path / "pair"
    )
    remote = execute_45(adapter, adapter.output, {"executionCommit": "c" * 40})
    local = current_local(backend.source)
    parent_local = copy.deepcopy(local)
    result = compare(remote, local)
    assert result["compatibility"] == "match", result["errors"]
    changed = copy.deepcopy(local)
    row = changed["rows"][0]
    row["observation"]["body"] = {"error": {"code": 499}}
    next(t for t in changed["trace"] if t["phase"] == "diagnostic")["observation"] = (
        copy.deepcopy(row["observation"])
    )
    assert compare(remote, changed)["compatibility"] == "mismatch"
    changed = copy.deepcopy(local)
    changed["rows"].pop()
    assert compare(remote, changed)["compatibility"] == "indeterminate"
    changed = copy.deepcopy(local)
    changed["cleanupComplete"] = False
    result = compare(remote, changed)
    assert result["recordingComplete"] and not result["cleanupComplete"]
    assert result["compatibility"] != "match"


@pytest.mark.parametrize(
    "mutation", ["query", "phase", "observer", "metadata", "non-json"]
)
def test_symmetric_or_detached_results_never_become_production_match(
    production_inputs, tmp_path, mutation
):
    from second_mapped import execute_45
    from second_production import Production45Adapter
    from second_production_contract import manifest as production_manifest
    from second_production_pair import compare

    permission, backend = production_inputs
    adapter = Production45Adapter(
        production_manifest(), permission, permission["nonce"], tmp_path / "pair"
    )
    remote = execute_45(adapter, adapter.output, {"executionCommit": "c" * 40})
    local = current_local(backend.source)
    for side in (remote, local):
        if mutation == "query":
            row = next(r for r in side["rows"] if r["id"] == FS_IDS[0] + "/diagnostic")
            entry = next(t for t in side["trace"] if t["sent"] == row["sent"])
            row["sent"]["query"].pop()
            entry["sent"] = copy.deepcopy(row["sent"])
        elif mutation == "phase":
            side["trace"][0]["phase"] = "after"
        elif mutation == "observer":
            side["observerDigest"] = "f" * 64
        elif mutation == "non-json":
            row = side["rows"][0]
            row["observation"]["body"] = None
            row["observation"]["http"]["bodyKind"] = "non-json"
            row["observation"]["http"]["bodySha256"] = (
                "a" if side is remote else "b"
            ) * 64
            next(t for t in side["trace"] if t["phase"] == "diagnostic")[
                "observation"
            ] = copy.deepcopy(row["observation"])
    if mutation == "metadata":
        remote["metadataTrace"].pop()
    result = compare(remote, local)
    assert result["compatibility"] == (
        "mismatch" if mutation == "non-json" else "indeterminate"
    ), result


def test_successful_remote_delete_is_complete_but_different(
    production_inputs, tmp_path
):
    from second_mapped import execute_45
    from second_production import Production45Adapter
    from second_production_contract import manifest as production_manifest
    from second_production_pair import compare

    permission, backend = production_inputs
    adapter = Production45Adapter(
        production_manifest(), permission, permission["nonce"], tmp_path / "pair"
    )
    remote = execute_45(adapter, adapter.output, {"executionCommit": "c" * 40})
    changed = deleted_receipt()
    remote.update(rows=changed["rows"], trace=changed["trace"])
    result = compare(remote, current_local(backend.source))
    assert result["recordingComplete"] and result["cleanupComplete"]
    assert result["stateValidation"] is True
    assert result["compatibility"] == "mismatch", result["errors"]
    assert [r["id"] for r in result["rows"] if r["compatibility"] == "mismatch"] == [
        FS_IDS[1] + "/diagnostic",
        FS_IDS[1] + "/after",
    ]


def test_json_content_type_equivalence_through_production_compare(
    production_inputs, tmp_path
):
    from second_mapped import execute_45
    from second_mapping import comparable
    from second_production import Production45Adapter
    from second_production_contract import manifest as production_manifest
    from second_production_pair import compare

    permission, backend = production_inputs
    adapter = Production45Adapter(
        production_manifest(), permission, permission["nonce"], tmp_path / "headers"
    )
    remote = execute_45(adapter, adapter.output, {"executionCommit": "c" * 40})
    local = current_local(backend.source)
    original = copy.deepcopy(local)
    for header in [
        "application/json; charset=utf-8",
        "Application/JSON",
        ' APPLICATION/JSON ; CHARSET = "UTF-8" \t',
        "application/json ; charset=UtF-8",
    ]:
        altered = copy.deepcopy(remote)
        row = altered["rows"][0]
        row["observation"]["http"]["contentType"] = header
        row["observation"]["mediaType"] = header.split(";", 1)[0].strip().lower()
        next(t for t in altered["trace"] if t["phase"] == "diagnostic")[
            "observation"
        ] = copy.deepcopy(row["observation"])
        snapshot = copy.deepcopy(altered)
        result = compare(altered, local)
        assert result["compatibility"] == "match", (header, result["errors"])
        assert altered == snapshot and local == original
        assert row["observation"]["http"]["contentType"] == header
        assert comparable(row, altered["bindings"]) != comparable(
            local["rows"][0], local["bindings"]
        )


def test_material_response_differences_remain_through_production_compare(
    production_inputs, tmp_path
):
    from second_mapped import execute_45
    from second_production import Production45Adapter
    from second_production_contract import manifest as production_manifest
    from second_production_pair import compare

    permission, backend = production_inputs
    adapter = Production45Adapter(
        production_manifest(), permission, permission["nonce"], tmp_path / "differences"
    )
    remote = execute_45(adapter, adapter.output, {"executionCommit": "c" * 40})
    local = current_local(backend.source)
    cases = [
        ("body", {"error": {"code": 401}}),
        ("body", {"error": {"code": "400"}}),
        ("body", {"error": {}}),
        ("body", {"error": {"code": 400, "extra": None}}),
    ]
    cases += [
        ("header", v)
        for v in [
            "text/plain",
            "",
            "application/json;",
            "application/json; charset=iso-8859-1",
            "application/json; profile=one",
        ]
    ]
    for kind, value in cases:
        altered = copy.deepcopy(remote)
        row = altered["rows"][0]
        if kind == "body":
            row["observation"]["body"] = value
        else:
            row["observation"]["http"]["contentType"] = value
            row["observation"]["mediaType"] = value.split(";", 1)[0].strip().lower()
        next(t for t in altered["trace"] if t["phase"] == "diagnostic")[
            "observation"
        ] = copy.deepcopy(row["observation"])
        result = compare(altered, local)
        assert result["compatibility"] == "mismatch", (kind, value, result)


@pytest.mark.parametrize(
    "left,right",
    [
        ("text/plain; charset=utf-8", "text/plain; charset=iso-8859-1"),
        ("application/json; profile=one", "application/json; profile=two"),
        ("application/json; charset=utf-8; charset=utf-8", "application/json"),
        ("application/json\r\n", "application/json"),
        ("", "not-a-media-type"),
    ],
)
def test_other_parameters_and_invalid_headers_are_not_erased(left, right):
    from second_production_pair import observed_value

    source = receipt("mapped")
    a, b = [copy.deepcopy(source["rows"][0]) for _ in range(2)]
    for row, header in ((a, left), (b, right)):
        row["observation"]["http"]["contentType"] = header
        row["observation"]["mediaType"] = header.split(";", 1)[0].strip().lower()
    assert observed_value(a, source["bindings"]) != observed_value(
        b, source["bindings"]
    )


def test_saved_comparator_uses_current_runtime_anchor_path():
    from broad_contract import ROOT
    from second_production_pair import PARENT_RUNTIME_ANCHOR

    assert PARENT_RUNTIME_ANCHOR == (
        "spec/compatibility/broad-runs/second45-parent-runtime-anchor-v4.json"
    )
    legacy_anchor = ROOT / "spec/compatibility/broad-runs/second45-parent-runtime-anchor-v3.json"
    assert hashlib.sha256(legacy_anchor.read_bytes()).hexdigest() == (
        "a05e5e564c20c1be9f354b5862f61746ed1f1b257516edfea75477a23b250d9d"
    )


def test_synthetic_runtime_fixture_passes_lower_level_validation():
    local = current_local(receipt("mapped"))

    validate_rows(local, observed_outcomes=True)
    assert validate_trace(local, observed_outcomes=True) is True


def test_saved_mode_rejects_missing_retained_runtime_fixture(tmp_path):
    from second_production_pair import load_parent_manifest

    with pytest.raises(FileNotFoundError):
        load_parent_manifest(tmp_path / "missing-parent-manifest.json")


def test_saved_candidate_rejects_self_hashed_fabricated_parent(
    production_inputs, tmp_path
):
    from broad_contract import ROOT
    from second_production_pair import compare_saved

    permission, backend = production_inputs
    local = current_local(backend.source)
    candidate_path = ROOT / "spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json"
    parent_path = tmp_path / "parent.json"
    parent_path.write_text(
        json.dumps(
            {
                "status": "completed",
                "productionExecuted": False,
                "artifactSha256": local["runtimeIdentity"]["artifactSha256"],
                "executionCommit": local["runtimeIdentity"]["executionCommit"],
                "configurationDigest": local["runtimeIdentity"]["configurationDigest"],
                "mappedReceiptFileSha256": digest(local),
                "mappedReceiptKind": local["kind"],
                "mappedReceiptRuntimeIdentity": local["runtimeIdentity"],
                "mappedReceiptRecordingComplete": True,
                "mappedReceiptCleanupComplete": True,
                "localObservations": {"mapped": local},
            }
        )
    )
    parent = json.loads(parent_path.read_text())
    parent["parentManifestSha256"] = digest(parent)
    parent_path.write_text(json.dumps(parent))
    result = compare_saved(
        candidate_path, local, parent_path, local_source_sha256=digest(local)
    )
    assert result["compatibility"] != "match"
    assert result["mode"] == "saved-production-versus-local"
    assert result["historicalObserverDigest"]
    assert result["currentObserverDigest"] == local["observerDigest"]
    assert len(result["productionCandidateSourceSha256"]) == 64
    assert result["currentLocalSourceSha256"] == digest(local)


def test_saved_cli_rejects_reauthored_parent_with_recomputed_self_hash(
    production_inputs, tmp_path
):
    from broad_contract import ROOT

    _, backend = production_inputs
    local = current_local(backend.source)
    local["runtimeIdentity"] = {
        "artifactSha256": "a" * 64,
        "executionCommit": "b" * 40,
        "configurationDigest": "c" * 64,
    }
    local_path = tmp_path / "local.json"
    local_path.write_text(json.dumps(local))
    parent = {
        "status": "completed",
        "productionExecuted": False,
        "artifactSha256": local["runtimeIdentity"]["artifactSha256"],
        "executionCommit": local["runtimeIdentity"]["executionCommit"],
        "configurationDigest": local["runtimeIdentity"]["configurationDigest"],
        "mappedReceiptFileSha256": hashlib.sha256(local_path.read_bytes()).hexdigest(),
        "mappedReceiptKind": local["kind"],
        "mappedReceiptRuntimeIdentity": local["runtimeIdentity"],
        "mappedReceiptRecordingComplete": True,
        "mappedReceiptCleanupComplete": True,
    }
    parent["parentManifestSha256"] = digest(parent)
    parent_path = tmp_path / "manifest.json"
    parent_path.write_text(json.dumps(parent))
    output_path = tmp_path / "comparison.json"
    script = ROOT / "tools/compat-broad/second_production_pair.py"
    process = subprocess.Popen(
        [
            sys.executable,
            str(script),
            "--mode",
            "saved",
            "--saved-production-candidate",
            str(ROOT / "spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json"),
            "--local",
            str(local_path),
            "--parent-manifest",
            str(parent_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "tools/compat-broad")},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    process.communicate()
    assert process.returncode != 0
    assert json.loads(output_path.read_text())["compatibility"] == "indeterminate"


@pytest.mark.parametrize("field", ["kind", "manifestDigest", "admissionDigest", "comparisonManifestDigest"])
def test_saved_mode_rejects_exact_local_receipt_manifest_mutations(
    production_inputs, tmp_path, field
):
    from broad_contract import ROOT
    from second_production_pair import compare_saved

    _, backend = production_inputs
    local = current_local(backend.source)
    original = copy.deepcopy(local)
    parent = {
        "status": "completed",
        "productionExecuted": False,
        "artifactSha256": local["runtimeIdentity"]["artifactSha256"],
        "executionCommit": local["runtimeIdentity"]["executionCommit"],
        "configurationDigest": local["runtimeIdentity"]["configurationDigest"],
        "mappedReceiptFileSha256": digest(original),
        "mappedReceiptKind": original["kind"],
        "mappedReceiptRuntimeIdentity": original["runtimeIdentity"],
        "mappedReceiptRecordingComplete": True,
        "mappedReceiptCleanupComplete": True,
        "localObservations": {"mapped": original},
    }
    parent["parentManifestSha256"] = digest(parent)
    parent_path = tmp_path / "parent.json"
    parent_path.write_text(json.dumps(parent))
    if field == "kind":
        local[field] = "second45-local-run-v0"
    else:
        local[field] = "0" * 64
    result = compare_saved(
        ROOT / "spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json",
        local,
        parent_path,
        local_source_sha256=digest(local),
    )
    assert result["compatibility"] == "indeterminate"


@pytest.mark.parametrize(
    "mutation",
    [
        "relabeled",
        "artifact-identity",
        "commit-identity",
        "configuration-identity",
        "parent-status",
        "parent-production-true",
        "parent-production-missing",
        "recording",
        "cleanup",
    ],
)
def test_saved_cli_rejects_unbound_or_incomplete_current_receipt(
    production_inputs, tmp_path, mutation
):
    from broad_contract import ROOT

    _, backend = production_inputs
    local = current_local(backend.source)
    parent_local = copy.deepcopy(local)
    if mutation == "relabeled":
        local["target"] = "production"
    elif mutation == "artifact-identity":
        local["runtimeIdentity"]["artifactSha256"] = "a" * 64
    elif mutation == "commit-identity":
        local["runtimeIdentity"]["executionCommit"] = "a" * 40
    elif mutation == "configuration-identity":
        local["runtimeIdentity"]["configurationDigest"] = "a" * 64
    elif mutation == "recording":
        local["recordingComplete"] = False
    elif mutation == "cleanup":
        local["cleanupComplete"] = False
    candidate_path = ROOT / "spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json"
    local_path = tmp_path / "local.json"
    output_path = tmp_path / "comparison.json"
    local_path.write_text(json.dumps(local))
    parent_path = tmp_path / "parent.json"
    parent_status = "incomplete" if mutation == "parent-status" else "completed"
    parent = {
        "status": parent_status,
        "productionExecuted": mutation == "parent-production-true",
        "artifactSha256": parent_local["runtimeIdentity"]["artifactSha256"],
        "executionCommit": parent_local["runtimeIdentity"]["executionCommit"],
        "configurationDigest": parent_local["runtimeIdentity"]["configurationDigest"],
        "localObservations": {"mapped": parent_local},
    }
    if mutation == "parent-production-missing":
        del parent["productionExecuted"]
    parent_path.write_text(json.dumps(parent))
    script = ROOT / "tools/compat-broad/second_production_pair.py"
    process = subprocess.Popen(
        [
            sys.executable,
            str(script),
            "--mode",
            "saved",
            "--saved-production-candidate",
            str(candidate_path),
            "--local",
            str(local_path),
            "--parent-manifest",
            str(parent_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "tools/compat-broad")},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = process.communicate()
    assert process.returncode != 0, (stdout, stderr)
    saved = json.loads(output_path.read_text())
    assert saved["compatibility"] == "indeterminate"


def test_saved_cli_rejects_tampered_candidate_file(production_inputs, tmp_path):
    from broad_contract import ROOT

    _, backend = production_inputs
    candidate_path = tmp_path / "candidate.json"
    candidate_path.write_bytes(
        (ROOT / "spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json").read_bytes()
        + b" "
    )
    local_path = tmp_path / "local.json"
    local_path.write_text(json.dumps(current_local(backend.source)))
    parent_path = tmp_path / "parent.json"
    parent_path.write_text(json.dumps({"status": "completed"}))
    output_path = tmp_path / "comparison.json"
    script = ROOT / "tools/compat-broad/second_production_pair.py"
    process = subprocess.Popen(
        [
            sys.executable,
            str(script),
            "--mode",
            "saved",
            "--saved-production-candidate",
            str(candidate_path),
            "--local",
            str(local_path),
            "--parent-manifest",
            str(parent_path),
            "--output",
            str(output_path),
        ],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "tools/compat-broad")},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = process.communicate()
    assert process.returncode != 0, (stdout, stderr)
    assert not output_path.exists()
