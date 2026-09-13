"""Observed outcomes do not relax independent operation and version admission."""

import copy

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
        target="local",
        productionExecuted=False,
        admissionDigest=digest(manifest()),
        manifestDigest=digest(production_manifest()),
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
    assert result["compatibility"] == "indeterminate"


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
