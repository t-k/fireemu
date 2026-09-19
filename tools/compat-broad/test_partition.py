"""Retained artifact runs bind exact runtime inputs before starting any process."""

import hashlib
import importlib.util
import json

import pytest


def test_retained_artifact_rejects_changed_source_and_binary(tmp_path):
    assert importlib.util.find_spec("partition"), "partition launcher is required"
    from partition import retained_artifact

    binary = tmp_path / "fireemu"
    binary.write_bytes(b"owned artifact")
    inputs = {"crates/one.rs": "same"}
    receipt = tmp_path / "manifest.json"
    receipt.write_text(
        json.dumps(
            {
                "build": {
                    "command": [
                        "cargo",
                        "build",
                        "--locked",
                        "-p",
                        "fireemu",
                        "--message-format=json",
                    ],
                    "exitCode": 0,
                    "artifactSha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "inputs": inputs,
                }
            }
        )
    )
    assert retained_artifact(binary, receipt, inputs)["exitCode"] == 0
    with pytest.raises(ValueError):
        retained_artifact(binary, receipt, {"crates/one.rs": "changed"})
    binary.write_bytes(b"different")
    with pytest.raises(ValueError):
        retained_artifact(binary, receipt, inputs)


def test_timeout_persists_cleanup_and_input_checks_for_a_real_owned_listener(tmp_path):
    import sys

    import partition

    assert hasattr(partition, "supervise_partition"), "failure finalization is required"
    script = tmp_path / "owned.py"
    script.write_text("""import json,os,signal,socket,subprocess,sys,time
from pathlib import Path
out=Path(sys.argv[1])
if len(sys.argv)>2:
 s=socket.socket();s.bind(("127.0.0.1",0));s.listen()
 (out/"instance.json").write_text(json.dumps({"pid":os.getpid(),"parentPid":os.getppid(),"argv":sys.argv,"nonce":"test-nonce","origins":["http://127.0.0.1:"+str(s.getsockname()[1])]}))
 time.sleep(20)
else:
 p=subprocess.Popen([sys.executable,__file__,str(out),"child"])
 signal.signal(signal.SIGTERM,lambda *_: sys.exit(1))
 try: p.wait()
 finally:
  p.terminate();p.wait()
""")
    report = {"status": "incomplete"}
    partition.supervise_partition(
        [sys.executable, str(script), str(tmp_path)],
        tmp_path,
        "test-nonce",
        report,
        lambda: True,
        timeout=0.7,
    )
    saved = json.loads((tmp_path / "manifest.json").read_bytes())
    assert saved["executionFailure"] == "TimeoutExpired"
    assert saved["status"] == "incomplete" and saved["recordingComplete"] is False
    assert saved["ownedProcess"]["stopped"] and saved["ownedProcess"]["listenersClosed"]
    assert saved["inputsStable"] is True


@pytest.mark.parametrize("launch", ["nonzero", "missing"])
def test_failed_launch_or_exit_retains_incomplete_manifest(tmp_path, launch):
    import sys

    import partition

    assert hasattr(partition, "supervise_partition"), "failure finalization is required"
    command = (
        [sys.executable, "-c", "raise SystemExit(7)"]
        if launch == "nonzero"
        else [str(tmp_path / "missing")]
    )
    report = {"status": "incomplete"}
    partition.supervise_partition(command, tmp_path, "nonce", report, lambda: True)
    saved = json.loads((tmp_path / "manifest.json").read_bytes())
    assert saved["status"] == "incomplete" and saved["recordingComplete"] is False
    assert saved["inputsStable"] is True
    assert saved["ownedProcess"]["listenersClosed"] is False
    if launch == "nonzero":
        assert saved["exitCode"] == 7 and saved["ownedProcess"]["stopped"]
    else:
        assert saved["executionFailure"] == "FileNotFoundError"


def test_failed_final_verifiers_still_persist_each_failure(tmp_path):
    import sys

    from partition import supervise_partition

    (tmp_path / "instance.json").write_text("malformed")
    (tmp_path / "cases.json").write_text("malformed")

    def changed_inputs():
        raise ValueError("input no longer readable")

    report = {"status": "incomplete"}
    supervise_partition(
        [sys.executable, "-c", "pass"], tmp_path, "nonce", report, changed_inputs
    )
    saved = json.loads((tmp_path / "manifest.json").read_bytes())
    assert saved["status"] == "incomplete" and saved["recordingComplete"] is False
    assert (
        saved["ownedProcess"]["stopped"]
        and not saved["ownedProcess"]["listenersClosed"]
    )
    assert saved["inputsStable"] is False
    assert saved["listenerVerificationFailure"] == "JSONDecodeError"
    assert saved["inputVerificationFailure"] == "ValueError"
    assert saved["recordingFailure"] == "JSONDecodeError"


def test_listener_registration_validates_ownership_and_all_origins_before_probing():
    import partition

    assert hasattr(partition, "registered_origins"), (
        "owned local registration validation required"
    )
    valid = {"parentPid": 4567, "nonce": "own", "origins": ["http://127.0.0.1:43210"]}
    assert partition.registered_origins(valid, 4567, "own") == valid["origins"]
    for update in [
        {"parentPid": 4568},
        {"nonce": "other"},
        {"origins": ["http://example.invalid:1234"]},
        {"origins": ["http://127.0.0.1:43210", "https://example.invalid:1234"]},
        {"origins": []},
    ]:
        with pytest.raises(ValueError):
            partition.registered_origins({**valid, **update}, 4567, "own")


def test_initial_incomplete_manifest_exists_before_child_launch(tmp_path):
    import sys

    from partition import supervise_partition

    command = [
        sys.executable,
        "-c",
        "import json,pathlib; p=pathlib.Path('manifest.json'); assert p.exists(); r=json.loads(p.read_text()); assert r['status']=='incomplete' and r['recordingComplete'] is False; pathlib.Path('saw-initial').touch()",
    ]
    supervise_partition(command, tmp_path, "nonce", {}, lambda: True)
    assert (tmp_path / "saw-initial").exists(), "initial report must precede Popen"
