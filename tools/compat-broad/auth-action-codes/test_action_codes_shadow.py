"""Process ownership, loopback binding and the opt-in real local shadow."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest
from action_codes_shadow import (
    ShadowError,
    artifact_command,
    artifact_source_binding,
    build_parser,
    child_complete,
    loopback_origin,
    parent_environment,
    run,
)

NONCE = uuid.uuid4().hex
ARTIFACT = os.environ.get("FIREEMU_ACTION_CODES_ARTIFACT")


def test_only_a_loopback_instance_is_accepted() -> None:
    assert loopback_origin("127.0.0.1:9099") == "http://127.0.0.1:9099"
    for host in ("identitytoolkit.googleapis.com:443", "10.0.0.5:9099", "127.0.0.1"):
        with pytest.raises(ShadowError, match="loopback"):
            loopback_origin(host)


def test_every_credential_and_redirect_is_stripped_before_the_artifact_starts() -> None:
    environment = parent_environment(
        {
            "PATH": "/usr/bin",
            "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/key.json",
            "FIRESTORE_EMULATOR_HOST": "example.test:80",
            "PRODUCTION_ORACLE_API_KEY": "secret",
            "FIREBASE_AUTH_EMULATOR_HOST": "example.test:80",
        }
    )
    assert environment == {"PATH": "/usr/bin"}


def test_the_artifact_argv_asks_for_auth_only_on_assigned_ports_and_no_secret() -> None:
    command = artifact_command(
        Path("/private/fireemu"),
        Path("/private/config.json"),
        "demo-auth-action",
        Path("/private/out"),
        NONCE,
        None,
        "c" * 64,
        None,
    )
    assert command[1] == "exec"
    assert command[command.index("--only") + 1] == "auth"
    for port in ("--http-port", "--hub-port", "--ui-port", "--logging-port"):
        assert command[command.index(port) + 1] == "0"
    assert "--firestore-port" not in command
    joined = " ".join(command)
    assert "Bearer" not in joined
    assert "password" not in joined.lower()
    assert "oobcode" not in joined.lower()


def test_an_incomplete_recording_only_passes_as_a_declared_rehearsal() -> None:
    complete = {"recordingComplete": True, "cleanupComplete": True}
    stopped = {"recordingComplete": False, "cleanupComplete": True}
    leaked = {"recordingComplete": True, "cleanupComplete": False}
    assert child_complete(complete, False) is True
    assert child_complete(stopped, False) is False
    assert child_complete(stopped, True) is True
    assert child_complete(leaked, True) is False


def test_a_missing_artifact_is_refused_before_anything_starts(tmp_path: Path) -> None:
    with pytest.raises(ShadowError, match="no artifact"):
        run(tmp_path / "out", tmp_path / "absent", "demo-auth-action", NONCE)


def test_the_command_line_never_accepts_a_credential() -> None:
    options = {action.dest for action in build_parser()._actions}
    assert not options & {"credential", "token", "approval", "api_key"}


@pytest.mark.skipif(
    not ARTIFACT,
    reason="set FIREEMU_ACTION_CODES_ARTIFACT to run the real local shadow",
)
def test_the_real_local_shadow_records_and_recovers(tmp_path: Path) -> None:
    report = run(tmp_path / "shadow", Path(ARTIFACT), "demo-auth-action", NONCE)
    assert report["status"] == "shadow-complete"
    assert report["ownedProcess"]["exitCode"] == 0
    assert report["ownedProcess"]["listenersClosed"] is True
    receipt = report["receipt"]
    # The label the report shows and the label the receipt carries are one word.
    assert report["artifact"]["binding"] == receipt["sourceBinding"]["binding"]
    assert report["artifact"]["provenance"] == "retained-external"
    assert receipt["recordingComplete"] is True
    assert receipt["cleanupComplete"] is True
    assert receipt["remainingAccounts"] == 0
    # A secret name may be listed as an observed response key, never as a key.
    assert '"oobCode":' not in json.dumps(receipt)
    # A binary this package did not build binds nothing, so no verdict is possible.
    assert report["artifact"]["binding"] == "unbound"


def test_the_shadow_never_builds_so_a_commit_is_a_caller_assertion() -> None:
    parser = build_parser()
    option = next(
        action
        for action in parser._actions
        if action.dest == "built_from_source_commit"
    )
    assert "asserted" in option.help or "built from" in option.help


def test_a_retained_artifact_is_never_recorded_as_built_from_source() -> None:
    retained = artifact_source_binding("a" * 64, None)
    assert retained["binding"] == "unbound"
    assert retained["builtFromSourceCommit"] is None
    built = artifact_source_binding("a" * 64, "b" * 40)
    assert built == {
        "commit": "b" * 40,
        "artifactSha256": "a" * 64,
        "binding": "built-from-source",
        "builtFromSourceCommit": "b" * 40,
    }


@pytest.mark.skipif(
    not ARTIFACT,
    reason="set FIREEMU_ACTION_CODES_ARTIFACT to run the real local shadow",
)
def test_the_rehearsed_transport_failure_still_recovers(tmp_path: Path) -> None:
    report = run(
        tmp_path / "rehearsal",
        Path(ARTIFACT),
        "demo-auth-action",
        NONCE,
        fail_after="accounts:signInWithEmailLink",
    )
    assert report["status"] == "shadow-complete"
    assert report["rehearsal"] == "accounts:signInWithEmailLink"
    receipt = report["receipt"]
    assert receipt["stopReason"] == "stage-failed:email-link-signin"
    assert receipt["recordingComplete"] is False
    assert len(receipt["stages"]) == 18
    assert receipt["cleanupComplete"] is True
    assert receipt["remainingAccounts"] == 0
    assert receipt["absenceProven"] is True
