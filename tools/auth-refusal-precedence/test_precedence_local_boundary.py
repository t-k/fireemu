"""The local v1 safety gate must not change historical publication contracts."""

import hashlib
import importlib
import json
import sys
from pathlib import Path

import precedence_contract as historical
import pytest
from test_precedence_safety import run, world

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))


def test_historical_contract_keeps_the_published_sha256():
    assert hashlib.sha256(Path(historical.__file__).read_bytes()).hexdigest() == (
        "f147c3ffa94fb7bffa8e385dd3fb1bc17ad73f9648ccb74d62f5c309d753e3cd"
    )


def test_saved_production_and_historical_local_publications_remain_valid():
    publisher = importlib.import_module("publish-auth-refusal-precedence")
    comparison = importlib.import_module("publish-auth-refusal-precedence-comparison")
    publisher.validate(json.loads(publisher.BUNDLE.read_bytes()))
    saved = json.loads(comparison.BUNDLE.read_bytes())
    assert "localValidActiveToken" not in saved["local"]
    comparison.validate(saved)
    # A private local extension is not part of the historical published schema.
    with pytest.raises(ValueError):
        comparison.validate_local({**saved["local"], "localValidActiveToken": {}})


def test_local_v1_gate_rejects_production_and_historical_local_reports():
    from precedence_local_contract_v1 import complete_local_v1

    publisher = importlib.import_module("publish-auth-refusal-precedence")
    comparison = importlib.import_module("publish-auth-refusal-precedence-comparison")
    production = json.loads(publisher.BUNDLE.read_bytes())["production"]
    local = json.loads(comparison.BUNDLE.read_bytes())["local"]
    for report in (production, local):
        observed = {
            **report,
            "status": "observed",
            "configRestored": True,
            "configDigestMatches": True,
        }
        assert historical.complete(observed)
        assert not complete_local_v1(observed)


@pytest.mark.parametrize("account", ["a", "b"])
@pytest.mark.parametrize("field", ["disableUser:null", "emailVerified"])
def test_owned_completion_rejects_unapplied_display_name(
    tmp_path, monkeypatch, account, field
):
    from precedence_owned import owned_complete

    _, saved = run(tmp_path, monkeypatch, world(tmp_path, local=True))
    assert owned_complete(saved)
    assert not owned_complete({**saved, "childCleanupFailure": "ValueError"})
    assert not owned_complete({**saved, "target": "production"})
    for row in saved["localValidActiveToken"]["fields"]:
        if row["account"] == account and row["field"] == field:
            row["displayNameApplied"] = False
    assert historical.complete(saved)
    assert not owned_complete(saved)


def test_production_publisher_rejects_local_v1_report(tmp_path, monkeypatch):
    from precedence_local_contract_v1 import complete_local_v1

    publisher = importlib.import_module("publish-auth-refusal-precedence")
    _, saved = run(tmp_path, monkeypatch, world(tmp_path, local=True))
    assert complete_local_v1(saved)
    with pytest.raises(ValueError):
        publisher.project(saved, "0" * 40)
