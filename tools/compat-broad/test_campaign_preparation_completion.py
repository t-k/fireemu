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
    "prod-campaign-explain-01-v7.json": "b540c9dae2a8998604e17f5163bb6ecb9add8e4e42ffde3b01cda5c74114f871",
    "prod-campaign-explain-01-v7-binding.json": "8617178de84e19a2e3d958dce40507182fa3bc2e5bb26f1ae4dab853dadd46da",
    "prod-campaign-explain-01-v8.json": "9c7355d031dc692c80ed068ea1cedfbaf7906e894adcc5baf38d518bf839a18b",
    "prod-campaign-explain-01-v8-binding.json": "924a84b6616845c749cd2a5a25d8a2f4bac89b8a459d19f64ea06febdfa68566",
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
