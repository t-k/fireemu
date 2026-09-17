import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "auth_account_linking_owned",
    Path(__file__).with_name("auth-account-linking-owned.py"),
)
_module = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_module)
validate_manifest = _module.validate_manifest
run = _module.run


def test_manifest_binds_completed_local_artifact(tmp_path: Path):
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"owned-artifact")
    digest = hashlib.sha256(b"owned-artifact").hexdigest()
    source, actual = validate_manifest(
        {
            "status": "completed",
            "productionExecuted": False,
            "executionCommit": "8b33aac4d" * 4 + "8b33aac4d"[:4],
            "artifactSha256": digest,
        },
        artifact,
    )
    assert source == "8b33aac4d" * 4 + "8b33aac4d"[:4]
    assert actual == digest


def test_manifest_rejects_production_or_artifact_drift(tmp_path: Path):
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"owned-artifact")
    digest = hashlib.sha256(b"other-artifact").hexdigest()
    with pytest.raises(ValueError, match="production"):
        validate_manifest(
            {
                "status": "completed",
                "productionExecuted": True,
                "executionCommit": "8b33aac4d" * 4 + "8b33aac4d"[:4],
                "artifactSha256": digest,
            },
            artifact,
        )
    with pytest.raises(ValueError, match="artifact"):
        validate_manifest(
            {
                "status": "completed",
                "productionExecuted": False,
                "executionCommit": "8b33aac4d" * 4 + "8b33aac4d"[:4],
                "artifactSha256": digest,
            },
            artifact,
        )


def test_runner_persists_failure_without_false_success(tmp_path: Path):
    artifact = tmp_path / "fireemu"
    artifact.write_bytes(b"wrong-artifact")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"status": "completed", "productionExecuted": False}),
        encoding="utf-8",
    )
    output = tmp_path / "run"
    result = run(output, manifest, artifact)
    assert result["status"] == "owned-run-failed"
    assert (output / "failure.json").is_file()
    assert not (output / "receipt.json").exists()


def test_substituted_listener_is_rejected():
    import os
    import socket

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        with pytest.raises(ValueError, match="listener owner"):
            _module.observe_listener(listener.getsockname()[1], os.getpid() + 100000)


def test_installed_sdk_mismatch_rejected_even_with_correct_declarations():
    with pytest.raises(ValueError, match="installed SDK"):
        _module.validate_installed_sdk(
            {
                "firebase": {"version": "12.17.0"},
                "firebase-admin": {"version": "14.3.0"},
            }
        )


def test_fixed_manifest_identity_rejects_self_consistent_substitution(tmp_path):
    with pytest.raises(ValueError, match="prepared"):
        _module.validate_prepared_paths(
            tmp_path / "manifest.json", tmp_path / "fireemu"
        )


def test_esm_resolution_detects_relinked_installed_version(tmp_path):
    import shutil
    import subprocess

    smoke = Path(__file__).parent
    modules = smoke / "node_modules"
    if not modules.exists():
        pytest.skip("installed SDK dependencies required")
    fixture_modules = tmp_path / "node_modules"
    fixture_modules.mkdir()
    for entry in modules.iterdir():
        if entry.name != "firebase-admin":
            (fixture_modules / entry.name).symlink_to(entry.resolve())
    shutil.copytree(modules / "firebase-admin", fixture_modules / "firebase-admin")
    metadata = fixture_modules / "firebase-admin/package.json"
    installed = json.loads(metadata.read_text())
    installed["version"] = "14.3.1"
    metadata.write_text(json.dumps(installed))
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": _module.EXPECTED_SDK})
    )
    collector = tmp_path / "collector.mjs"
    shutil.copyfile(smoke / "auth-account-linking-local.mjs", collector)
    observed = json.loads(
        subprocess.check_output(["node", str(collector), "--sdk-info"], text=True)
    )
    assert observed["firebase-admin"]["version"] == "14.3.1"
    with pytest.raises(ValueError, match="installed SDK"):
        _module.validate_installed_sdk(observed)


def test_harness_source_rejects_dirty_collector_and_commit_drift(tmp_path):
    import subprocess

    def git(*args):
        return subprocess.check_output(
            ["git", "-C", str(tmp_path), *args], text=True
        ).strip()

    git("init", "-q")
    paths = [
        "tools/sdk-smoke/auth-account-linking-owned.py",
        "tools/sdk-smoke/auth-account-linking-local.mjs",
    ]
    for relative in paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("reviewed source\n")
    git("add", ".")
    git(
        "-c",
        "user.name=Source Test",
        "-c",
        "user.email=source@example.test",
        "commit",
        "-qm",
        "reviewed",
    )
    commit = git("rev-parse", "HEAD")
    assert _module.verify_harness_source(tmp_path, commit)["commit"] == commit
    (tmp_path / paths[1]).write_text("changed observation semantics\n")
    with pytest.raises(ValueError, match="source"):
        _module.verify_harness_source(tmp_path, commit)
    git("add", ".")
    git(
        "-c",
        "user.name=Source Test",
        "-c",
        "user.email=source@example.test",
        "commit",
        "-qm",
        "drift",
    )
    with pytest.raises(ValueError, match="commit"):
        _module.verify_harness_source(tmp_path, commit)


def config_readback(value=False, **changes):
    return {
        "origin": "http://127.0.0.1:12345",
        "project": "demo-app",
        "path": "/emulator/v1/projects/demo-app/config",
        "status": 200,
        "body": {"signIn": {"allowDuplicateEmails": value}},
        **changes,
    }


def test_config_readback_preserves_true_and_false_without_defaulting():
    for value in (True, False):
        proof = _module.validate_config_readbacks(
            config_readback(value), config_readback(value), "http://127.0.0.1:12345"
        )
        assert proof["allowDuplicateEmails"] is value
    with pytest.raises(ValueError, match="allowDuplicateEmails"):
        _module.validate_config_readbacks(
            config_readback(body={}), config_readback(), "http://127.0.0.1:12345"
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"project": "another-project"},
        {"path": "/emulator/v1/projects/another-project/config"},
        {"origin": "http://127.0.0.1:12346"},
        {"status": 403},
    ],
)
def test_config_readback_rejects_wrong_namespace_or_read_failure(changes):
    with pytest.raises(ValueError, match="configuration"):
        _module.validate_config_readbacks(
            config_readback(**changes), config_readback(), "http://127.0.0.1:12345"
        )


def test_config_readback_rejects_stale_before_claim():
    with pytest.raises(ValueError, match="changed"):
        _module.validate_config_readbacks(
            config_readback(False), config_readback(True), "http://127.0.0.1:12345"
        )
