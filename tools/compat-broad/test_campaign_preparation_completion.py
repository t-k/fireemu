"""Current offline preparation never rewrites or inherits a historical permission."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from broad_contract import digest
from campaign_explain import binding, manifest, validate_manifest

ROOT = Path(__file__).resolve().parents[2]
HISTORICAL = {
    "prod-campaign-explain-01-v7.json": "9f044c7ec8eaa3f2faae3cf3f0337d8f58b5069f07b5ae0127f101492699b319",
    "prod-campaign-explain-01-v7-binding.json": "9eea809ec95581c3d2696136511345b7423299b0fa75276142e51f3d3b4817a1",
    "prod-campaign-explain-01-v8.json": "a31b2db0892cc4825609eb80c59bfb08a94fccb2c6a7b4830d01d6ac0cb42fd8",
    "prod-campaign-explain-01-v8-binding.json": "6f6758381121fa1c88ff1fde108607eeac01f2572c998c15d4f883307bd3fa21",
}


@pytest.mark.parametrize("name,expected", HISTORICAL.items())
def test_historical_explain_preparations_remain_byte_identical(name, expected):
    path = ROOT / "spec/compatibility/broad-runs" / name
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("version", [7, 8])
def test_old_preparation_is_not_an_accepted_current_manifest(version):
    path = ROOT / "spec/compatibility/broad-runs" / f"prod-campaign-explain-01-v{version}.json"
    previous = json.loads(path.read_bytes())
    assert previous["kind"] != manifest()["kind"]
    assert digest(previous) != binding()["manifestDigest"]
    with pytest.raises(ValueError, match="drift"):
        validate_manifest(previous)


def test_new_generation_is_preparation_not_observation_or_permission():
    current = manifest()
    assert current["kind"] == "production-campaign-explain-01-v9"
    assert current["preparation"] == {
        "authorizesProduction": False,
        "requiresFreshPermissionBinding": True,
        "productionExecuted": False,
    }
    assert current["status"] == "prepared-offline"
    assert current["networkCalls"] == 0
    assert current["template"]["nonce"] == "{freshNonce}"
    assert binding()["manifestDigest"] == digest(current)
    assert binding()["observerSha256"] == current["environment"]["observerSha256"]


@pytest.mark.parametrize("field", ["authorizesProduction", "productionExecuted", "requiresFreshPermissionBinding"])
def test_preparation_authority_fields_cannot_be_changed(field):
    current = copy.deepcopy(manifest())
    current["preparation"][field] = not current["preparation"][field]
    with pytest.raises(ValueError, match="manifest drift"):
        validate_manifest(current)
