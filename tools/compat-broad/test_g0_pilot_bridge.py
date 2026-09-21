"""Coverage for the G0 pilot bridge; private paths are supplied only by the operator."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path

import pytest

from shared_production_pair import compare_g0_runtime_recompare


def _private_inputs() -> tuple[Path, Path]:
    production = os.environ.get("G0_PRIVATE_PRODUCTION_RESULT")
    local = os.environ.get("G0_PRIVATE_LOCAL_RECORD")
    if not production or not local:
        pytest.skip("private G0 inputs not supplied")
    return Path(production), Path(local)


def _compare(production: Path, local: dict):
    return compare_g0_runtime_recompare(production, local)


def test_private_g0_reference_has_twelve_matching_rows():
    production, local_path = _private_inputs()
    result = _compare(production, json.loads(local_path.read_bytes()))
    assert result["compatibility"] == "match"
    assert len(result["rows"]) == 12


@pytest.mark.parametrize("mutation", range(12))
def test_each_g0_row_value_or_type_mutation_is_rejected(mutation):
    production, local_path = _private_inputs()
    local = json.loads(local_path.read_bytes())
    row = local["batch"]["jobs"]["partial"]["rows"] + local["batch"]["jobs"]["transaction-field"]["rows"]
    target = row[mutation]
    if mutation % 2:
        target["status"] = str(target["status"])
    else:
        target["body"] = {"pilotMutation": True}
    assert _compare(production, local)["compatibility"] != "match"


def test_missing_and_extra_g0_rows_are_rejected():
    production, local_path = _private_inputs()
    local = json.loads(local_path.read_bytes())
    rows = local["batch"]["jobs"]["partial"]["rows"]
    rows.pop()
    assert _compare(production, local)["compatibility"] == "indeterminate"
    local = json.loads(local_path.read_bytes())
    local["batch"]["jobs"]["partial"]["rows"].append(copy.deepcopy(rows[-1]))
    assert _compare(production, local)["compatibility"] == "indeterminate"
