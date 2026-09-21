"""Coverage ledger for the fail-closed FS-LISTEN-SDK O8 entrypoint."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from listen_descriptor import descriptor
from listen_o8 import execute, main

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "production-admission"))


def test_descriptor_binds_the_existing_listen_catalog_and_windows():
    value = descriptor()

    assert value.campaign_id == "FS-LISTEN-SDK"
    assert value.campaign_seconds == 600
    assert value.recovery_seconds == 180
    assert "tools/compat-broad/fs-listen-resume/listen_collector.mjs" in value.required_source_entries
    assert "tools/compat-broad/fs-listen-resume/listen_sdk_adapter.mjs" in value.required_source_entries
    assert "tools/compat-broad/fs-listen-resume/listen_browser_adapter.mjs" in value.source_map()


def test_unknown_shared_registry_campaign_stays_fail_closed():
    from reservations import CATALOGUED_CAMPAIGN_IDS

    assert descriptor().campaign_id not in CATALOGUED_CAMPAIGN_IDS


def test_entrypoint_rejects_malformed_frozen_inputs_before_credential_read(tmp_path):
    paths = {}
    for name in ("inputs", "approval", "manifest", "permission"):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps({"malformed": True}), encoding="utf-8")
        if name in {"approval", "manifest"}:
            path.chmod(0o600)
        paths[name] = path
    args = SimpleNamespace(
        inputs=paths["inputs"], approval=paths["approval"],
        manifest=paths["manifest"], permission=paths["permission"],
        artifact=tmp_path / "artifact", ledger=tmp_path / "ledger",
        credential_file=tmp_path / "must-not-be-read", credential_fd=None,
        output=tmp_path / "output",
    )

    with pytest.raises(ValueError, match="O7 frozen approval binding required"):
        execute(args)


def test_cli_fails_closed_without_production_inputs(capsys):
    result = main([])

    assert result == 2
    assert "required" in capsys.readouterr().err
