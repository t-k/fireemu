"""Offline contract tests for the bounded Commit O8 entrypoint."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import commit_o8


def test_cli_rejects_missing_o7_approval_before_acquisition(tmp_path, monkeypatch):
    called = False

    def unexpected(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(commit_o8.acquisition, "run_acquisition", unexpected)
    inputs = tmp_path / "inputs.json"
    inputs.write_text(
        json.dumps(
            {
                "kind": "commit-frozen-inputs-v2",
                "permissionDigest": commit_o8.digest({}),
            }
        )
    )
    handoff = tmp_path / "handoff.json"
    handoff.write_text("{}")

    result = commit_o8.main(
        [
            "--inputs",
            str(inputs),
            "--approval",
            str(tmp_path / "approval.json"),
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--permission",
            str(tmp_path / "permission.json"),
            "--source",
            str(tmp_path),
            "--artifact",
            str(handoff),
            "--ledger",
            str(tmp_path / "ledger"),
            "--output",
            str(tmp_path / "output"),
            "--credential-file",
            str(handoff),
        ]
    )

    assert result == 2
    assert called is False


def test_cli_does_not_discover_credentials_or_accept_api_key_argument(tmp_path):
    parser = commit_o8.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--api-key", "secret"])
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in commit_o8.__dict__


def test_frozen_input_digest_is_required_for_o7_binding():
    value = {
        "kind": "commit-frozen-inputs-v2",
        "permission": {"kind": "commit-owner-execution-permission-v1"},
        "permissionDigest": commit_o8.digest({"kind": "other"}),
        "plan": {},
        "planDigest": commit_o8.digest({}),
        "sourceCommit": "frozen",
        "sourceInputs": {},
        "artifactSha256": "artifact",
        "inputsDigest": "wrong",
    }
    with pytest.raises(ValueError, match="O7 frozen approval binding"):
        commit_o8._validate_frozen(value)


def test_complete_released_acquisition_is_success_even_when_comparison_flag_is_false(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(commit_o8, "execute", lambda args: {
        "failure": None,
        "releaseEligible": True,
        "reservationReleased": True,
        "acquisitionValidated": False,
    })
    result = commit_o8.main(
        [
            "--inputs", str(tmp_path / "inputs"),
            "--approval", str(tmp_path / "approval"),
            "--manifest", str(tmp_path / "manifest"),
            "--permission", str(tmp_path / "permission"),
            "--source", str(tmp_path / "source"),
            "--artifact", str(tmp_path / "artifact"),
            "--ledger", str(tmp_path / "ledger"),
            "--output", str(tmp_path / "output"),
            "--credential-file", str(tmp_path / "credential"),
        ]
    )
    assert result == 0


def test_cli_binds_exact_fixed_transport_and_handoff_without_public_secret(
    tmp_path, monkeypatch, capsys
):
    calls = {}
    monkeypatch.setattr(
        commit_o8.acquisition,
        "run_acquisition",
        lambda output, inputs, **kwargs: calls.update(kwargs)
        or {
            "failure": None,
            "releaseEligible": True,
            "reservationReleased": True,
            "acquisitionValidated": False,
        },
    )
    monkeypatch.setattr(commit_o8, "_validate_frozen", lambda inputs: None)
    monkeypatch.setattr(commit_o8, "_validate_approval", lambda *args, **kwargs: None)
    monkeypatch.setattr(commit_o8, "validate_handoff", lambda *args: None)
    inputs = tmp_path / "inputs.json"
    inputs.write_text(
        json.dumps(
            {
                "kind": "commit-frozen-inputs-v2",
                "permissionDigest": commit_o8.digest({}),
            }
        )
    )
    permission = tmp_path / "permission.json"
    permission.write_text("{}")
    approval = tmp_path / "approval.json"
    approval.write_text("{}")
    approval.chmod(0o600)
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}")
    manifest.chmod(0o600)
    source = tmp_path / "source"
    source.mkdir()
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"artifact")
    secret = "secret-api-key-value"
    handoff = tmp_path / "handoff.json"
    handoff.write_text(json.dumps({"apiKey": secret, "adc": {"private": "value"}}))
    handoff.chmod(0o600)

    result = commit_o8.main(
        [
            "--inputs",
            str(inputs),
            "--approval",
            str(approval),
            "--manifest",
            str(manifest),
            "--permission",
            str(permission),
            "--source",
            str(source),
            "--artifact",
            str(artifact),
            "--ledger",
            str(tmp_path / "ledger"),
            "--output",
            str(tmp_path / "output"),
            "--credential-file",
            str(handoff),
        ]
    )

    assert result == 0
    assert calls["transmit"] is commit_o8.remote_request
    assert calls["api_key"] == secret
    assert calls["credential_handoff"]["apiKey"] == secret
    public = capsys.readouterr()
    assert secret not in public.out + public.err
