"""Observed outcomes do not relax independent operation and version admission."""

import copy

import pytest
from broad_contract import digest
from second_admission import FS_IDS, manifest
from second_mapping import validate_rows, validate_trace
from test_second_mapping import receipt


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
