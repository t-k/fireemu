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


def test_descriptor_compiles_positive_plan_and_permission_shape():
    value = descriptor()
    plan = value.plan_compiler("0123456789abcdef0123456789abcdef")
    source_inputs = value.source_map()
    permission = value.permission_bindings(plan, "a" * 40, "b" * 64, source_inputs)

    assert plan["campaignId"] == "FS-LISTEN-SDK"
    assert plan["project"] == "fireemu-35fe6"
    assert plan["database"] == "(default)"
    assert permission["sdk"]["firebase"] == "12.18.0"
    assert permission["budget"] == value.budget
    assert value.cost_model()["hardCostCeilingUsd"] == 0.5


@pytest.mark.parametrize("bad_nonce", ["", "z" * 32, "0" * 31])
def test_descriptor_rejects_invalid_nonce(bad_nonce):
    with pytest.raises(ValueError):
        descriptor().plan_compiler(bad_nonce)


def test_descriptor_rejects_source_binding_drift():
    value = descriptor()
    with pytest.raises(ValueError, match="source digest"):
        value.binding_verifier(b"adapter", "a" * 64, {value.required_source_entries[1]: "b" * 64})


def test_descriptor_rejects_artifact_profile_and_missing_artifact(tmp_path):
    artifact = tmp_path / "artifact"
    manifest = tmp_path / "manifest"
    artifact.write_bytes(b"artifact")
    manifest.write_bytes(b"manifest")
    with pytest.raises(ValueError, match="profile"):
        descriptor().retained_artifact_validator(artifact, manifest, "wrong")


def test_descriptor_rejects_project_change_at_campaign_compiler():
    from o6_listen_o8 import campaign as listen_campaign

    with pytest.raises(ValueError, match="project/database"):
        listen_campaign.compile_campaign("0" * 32, project="other")


def test_unknown_shared_registry_campaign_stays_fail_closed():
    from reservations import CATALOGUED_CAMPAIGN_IDS

    assert descriptor().campaign_id not in CATALOGUED_CAMPAIGN_IDS


def test_entrypoint_rejects_unregistered_campaign_before_credential_read(tmp_path):
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

    with pytest.raises(ValueError, match="shared Ledger registry"):
        execute(args)


def test_cli_fails_closed_without_production_inputs(capsys):
    result = main([])

    assert result == 2
    assert "required" in capsys.readouterr().err
