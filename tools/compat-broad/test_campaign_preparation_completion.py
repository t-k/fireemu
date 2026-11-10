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
    "prod-campaign-explain-01-v7.json": "f4d96c4783b6d8895fbd3de1f4c2e4a4562f1904ab89b3943fc86ecad92af151",
    "prod-campaign-explain-01-v7-binding.json": "5ec3c303f5170df2f4a1e29606a695939d9da40a9376ea3f5f2ef511e4e94c14",
    "prod-campaign-explain-01-v8.json": "a62e87f34a49324a5c8af0f149850687b4cf6f3f09f3b2d597aba899bd8d811b",
    "prod-campaign-explain-01-v8-binding.json": "87307e902b2d272adc8fdde93b4fee9a6bb8e1571b635718f8bdc39b8596e528",
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
