"""Offline contract tests for the bounded Commit O8 entrypoint."""

import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "production-admission"))
sys.path.insert(0, str(HERE))

import commit_o8

_SPEC = importlib.util.spec_from_file_location("o8_bundle", HERE / "o8_bundle.py")
assert _SPEC is not None and _SPEC.loader is not None
o8_bundle = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(o8_bundle)


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
                "artifactSha256": "artifact",
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
    monkeypatch.setattr(
        commit_o8,
        "execute",
        lambda args: {
            "failure": None,
            "releaseEligible": True,
            "reservationReleased": True,
            "acquisitionValidated": False,
        },
    )
    result = commit_o8.main(
        [
            "--inputs",
            str(tmp_path / "inputs"),
            "--approval",
            str(tmp_path / "approval"),
            "--manifest",
            str(tmp_path / "manifest"),
            "--permission",
            str(tmp_path / "permission"),
            "--source",
            str(tmp_path / "source"),
            "--artifact",
            str(tmp_path / "artifact"),
            "--ledger",
            str(tmp_path / "ledger"),
            "--output",
            str(tmp_path / "output"),
            "--credential-file",
            str(tmp_path / "credential"),
        ]
    )
    assert result == 0


def _frozen_inputs(tmp_path):
    """Build a complete, internally consistent frozen O7 input record."""
    permission = {
        "kind": "commit-owner-execution-permission-v1",
        "wallSeconds": commit_o8.CAMPAIGN_SECONDS,
        "recoverySeconds": commit_o8.RECOVERY_SECONDS,
    }
    plan = {"campaignId": "FS-DATA-WRITE-COMMIT-TRANSFORMS-03", "nonce": "a" * 32}
    source_inputs = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in (
            *o8_bundle.WORKER_SOURCES,
            *commit_o8.acquisition.COMMIT.required_source_entries,
        )
    }
    inputs = {
        "kind": "commit-frozen-inputs-v2",
        "permission": permission,
        "permissionDigest": commit_o8.digest(permission),
        "plan": plan,
        "planDigest": commit_o8.digest(plan),
        "sourceCommit": "0" * 40,
        "sourceInputs": source_inputs,
        "artifactSha256": "b" * 64,
    }
    inputs["inputsDigest"] = commit_o8.digest(inputs)
    return inputs, permission


def _approval(inputs, manifest_bytes, ledger):
    now = time.time()
    return {
        "kind": commit_o8.APPROVAL_KIND,
        "status": "approved",
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": commit_o8.digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": commit_o8.digest(inputs["plan"]["nonce"]),
        "ledgerRoot": str(ledger.resolve(strict=False)),
        "launcherSha256": hashlib.sha256(
            (HERE / "commit_o8.py").read_bytes()
        ).hexdigest(),
        "artifactProfile": commit_o8.REVIEWED_ARTIFACT_PROFILE,
        "windowStartsAt": now - 1,
        "windowExpiresAt": now + 4 * commit_o8.CAMPAIGN_SECONDS,
        "executionHost": commit_o8.acquisition.execution_host(),
    }


def _cli_fixture(tmp_path, monkeypatch, calls, *, approval_overrides=None):
    inputs, permission = _frozen_inputs(tmp_path)
    ledger = tmp_path / "ledger"
    manifest_value = {
        "kind": commit_o8.MANIFEST_KIND,
        "inputsDigest": inputs["inputsDigest"],
    }
    manifest_bytes = json.dumps(manifest_value).encode()
    approval_value = {
        **_approval(inputs, manifest_bytes, ledger),
        **(approval_overrides or {}),
    }
    paths = {}
    for name, data in (
        ("inputs.json", json.dumps(inputs).encode()),
        ("permission.json", json.dumps(permission).encode()),
        ("approval.json", json.dumps(approval_value).encode()),
        ("manifest.json", manifest_bytes),
    ):
        path = tmp_path / name
        path.write_bytes(data)
        path.chmod(0o600)
        paths[name] = path
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"artifact")
    secret = "secret-api-key-value"
    handoff = tmp_path / "handoff.json"
    handoff.write_text(json.dumps({"apiKey": secret, "adc": {"private": "value"}}))
    handoff.chmod(0o600)
    def fake_acquisition(output, frozen, **kwargs):
        calls.update(kwargs)
        capability = kwargs.get("capability")
        if capability is not None:
            calls["capabilitySnapshot"] = {
                "binding_digest": capability.binding_digest,
                "campaign_id": capability.campaign_id,
                "inputs_digest": capability.inputs_digest,
                "ledger_root": capability.ledger_root,
                "window_starts_at": capability.window_starts_at,
                "window_expires_at": capability.window_expires_at,
            }
        return {
            "failure": None,
            "releaseEligible": True,
            "reservationReleased": True,
            "acquisitionValidated": False,
        }

    monkeypatch.setattr(commit_o8.acquisition, "run_acquisition", fake_acquisition)
    monkeypatch.setattr(
        commit_o8.acquisition,
        "validate_retained_artifact",
        lambda *args, **kwargs: {
            "artifactSha256": inputs["artifactSha256"],
            "retainedManifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
    )
    monkeypatch.setattr(commit_o8, "validate_handoff", lambda *args: None)
    argv = [
        "--inputs",
        str(paths["inputs.json"]),
        "--approval",
        str(paths["approval.json"]),
        "--manifest",
        str(paths["manifest.json"]),
        "--permission",
        str(paths["permission.json"]),
        "--source",
        str(ROOT),
        "--artifact",
        str(artifact),
        "--ledger",
        str(ledger),
        "--output",
        str(tmp_path / "output"),
        "--credential-file",
        str(handoff),
    ]
    return inputs, argv, secret


def test_cli_issues_an_archive_bound_capability_without_a_public_secret(
    tmp_path, monkeypatch, capsys
):
    calls = {}
    inputs, argv, secret = _cli_fixture(tmp_path, monkeypatch, calls)
    _, expected_sha = o8_bundle.build_worker_archive_from_source(
        ROOT, inputs["sourceInputs"]
    )

    assert commit_o8.main(argv) == 0
    assert "transmit" not in calls
    assert "injected_transport" not in calls
    capability = calls["capability"]
    assert isinstance(capability, commit_o8.acquisition.ProductionWireCapability)
    snapshot = calls["capabilitySnapshot"]
    assert snapshot["binding_digest"] == expected_sha
    assert snapshot["campaign_id"] == inputs["plan"]["campaignId"]
    assert snapshot["inputs_digest"] == inputs["inputsDigest"]
    assert calls["api_key"] == secret
    assert calls["credential_handoff"]["apiKey"] == secret
    public = capsys.readouterr()
    assert secret not in public.out + public.err
    assert expected_sha not in public.out


@pytest.mark.parametrize(
    "override",
    [
        {"status": "pending"},
        {"inputsDigest": "0" * 64},
        {"manifestSha256": "0" * 64},
        {"artifactSha256": "0" * 64},
        {"planDigest": "0" * 64},
        {"sourceInputsDigest": "0" * 64},
    ],
    ids=[
        "not-approved",
        "changed-inputs",
        "changed-manifest",
        "changed-artifact",
        "changed-plan",
        "changed-source-map",
    ],
)
def test_cli_refuses_a_broken_o7_binding_without_any_wire_call(
    tmp_path, monkeypatch, override
):
    calls = {}
    _, argv, _secret = _cli_fixture(
        tmp_path, monkeypatch, calls, approval_overrides=override
    )
    assert commit_o8.main(argv) == 2
    assert calls == {}


def test_cli_refuses_a_source_checkout_that_no_longer_matches_the_frozen_map(
    tmp_path, monkeypatch
):
    """A replaced worker source cannot be turned into a production capability."""
    calls = {}
    _inputs, argv, _secret = _cli_fixture(tmp_path, monkeypatch, calls)
    checkout = tmp_path / "checkout"
    for name in o8_bundle.WORKER_SOURCES:
        target = checkout / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    (checkout / next(iter(o8_bundle.WORKER_SOURCES))).write_text("# replaced\n")
    argv[argv.index("--source") + 1] = str(checkout)
    assert commit_o8.main(argv) == 2
    assert calls == {}


def test_cli_refuses_a_stale_permission_before_any_wire_call(tmp_path, monkeypatch):
    calls = {}
    _inputs, argv, _secret = _cli_fixture(tmp_path, monkeypatch, calls)
    permission_path = Path(argv[argv.index("--permission") + 1])
    permission_path.write_text(json.dumps({"kind": "rebound"}))
    assert commit_o8.main(argv) == 2
    assert calls == {}


def test_cli_refuses_a_rejected_handoff_before_any_wire_call(tmp_path, monkeypatch):
    calls = {}
    _inputs, argv, _secret = _cli_fixture(tmp_path, monkeypatch, calls)

    def refuse(*_args):
        raise ValueError("bound Commit credential handoff required")

    monkeypatch.setattr(commit_o8, "validate_handoff", refuse)
    assert commit_o8.main(argv) == 2
    assert calls == {}


def test_a_failed_handoff_revokes_the_issued_capability(tmp_path, monkeypatch):
    """An admission that will not be executed must not stay issued."""
    calls = {}
    _inputs, argv, _secret = _cli_fixture(tmp_path, monkeypatch, calls)

    def refuse(*_args):
        raise ValueError("bound Commit credential handoff required")

    monkeypatch.setattr(commit_o8, "validate_handoff", refuse)
    before = set(commit_o8.acquisition._ISSUED)
    assert commit_o8.main(argv) == 2
    assert calls == {}
    assert set(commit_o8.acquisition._ISSUED) == before


def test_the_cli_binds_the_capability_to_its_ledger_root_and_window(
    tmp_path, monkeypatch
):
    calls = {}
    _inputs, argv, _secret = _cli_fixture(tmp_path, monkeypatch, calls)
    ledger = Path(argv[argv.index("--ledger") + 1])
    assert commit_o8.main(argv) == 0
    snapshot = calls["capabilitySnapshot"]
    assert snapshot["ledger_root"] == str(ledger.resolve(strict=False))
    assert snapshot["window_starts_at"] <= time.time()
    assert snapshot["window_expires_at"] > time.time() + commit_o8.CAMPAIGN_SECONDS
