"""Real child failures preserve parent provenance and independently verify cleanup."""

import json
import socket
import sys

import pytest
from broad import supervise


@pytest.fixture
def closed_origin():
    # Bind without listen: reserve a real unused address whose connection is refused.
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"


@pytest.mark.parametrize("mode", ["success", "failure", "timeout"])
def test_initial_manifest_survives_real_child_outcomes(tmp_path, mode, closed_origin):
    child = tmp_path / "child.py"
    child.write_text("""import json,os,subprocess,sys,time
from pathlib import Path
p=Path(sys.argv[1]); mode=sys.argv[2]
r=json.loads((p/'manifest.json').read_text()); assert r['artifactSha256']=='bound-before-launch'
c=subprocess.Popen([sys.executable,'-c','pass']); c.wait()
(p/'instance.json').write_text(json.dumps(dict(pid=c.pid,argv=[sys.executable,'-c','pass'],parentPid=os.getpid(),nonce='n',authOrigin=sys.argv[3],firestoreOrigin=sys.argv[3],controlOrigin=sys.argv[3])))
(p/'cases.json').write_text(json.dumps(dict(recordingComplete=mode=='success',historicalReplayPrograms=[dict(id='legacy')],historicalReplayObservations={'legacy':{'steps':{}}},cases=[dict(id='partial',status='observed',family='test')],artifactSha256='child-must-not-replace-parent')))
if mode=='timeout': time.sleep(10)
sys.exit(0 if mode=='success' else 7)
""")
    report = {
        "status": "incomplete",
        "artifactSha256": "bound-before-launch",
        "executionCommit": "frozen",
        "runtimeInputs": {"input": "hash"},
        "executionInputs": {"observer": "hash"},
    }
    result = supervise(
        [sys.executable, str(child), str(tmp_path), mode, closed_origin],
        tmp_path,
        "n",
        report,
        timeout=0.5,
    )
    stored = json.loads((tmp_path / "manifest.json").read_text())
    assert result == stored
    assert stored["artifactSha256"] == "bound-before-launch"
    assert stored["executionCommit"] == "frozen"
    assert stored["runtimeInputs"] == {"input": "hash"}
    assert stored["cases"][0]["id"] == "partial"
    assert stored["historicalReplayPrograms"] == [{"id": "legacy"}]
    assert stored["historicalReplayObservations"] == {"legacy": {"steps": {}}}
    assert stored["ownedProcess"]["stopped"] is True
    assert stored["ownedProcess"]["listenersClosed"] is True
    assert stored["status"] == ("completed" if mode == "success" else "incomplete")
    assert (
        stored["stopReason"]
        == {
            "success": "child-completed",
            "failure": "child-nonzero",
            "timeout": "child-timeout",
        }[mode]
    )
    assert stored["recordingComplete"] is (mode == "success")


def test_start_failure_still_records_initial_inputs(tmp_path):
    result = supervise(
        ["/nonexistent-fireemu-command"],
        tmp_path,
        "n",
        {"artifactSha256": "known", "status": "incomplete"},
        timeout=1,
    )
    assert result["stopReason"] == "process-start-failure"
    assert result["status"] == "incomplete"
    assert (
        json.loads((tmp_path / "manifest.json").read_text())["artifactSha256"]
        == "known"
    )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"cases": None},
        {"cases": []},
        {"cases": [None]},
        {"cases": [{"id": "x"}]},
        {"cases": [{"id": "x", "status": "fail", "family": "test"}]},
        {"cases": [{"id": "x", "status": "mismatch", "family": "test"}]},
    ],
)
def test_malformed_partial_report_does_not_skip_final_manifest(tmp_path, payload):
    (tmp_path / "cases.json").write_text(json.dumps(payload))
    result = supervise(
        [sys.executable, "-c", "pass"],
        tmp_path,
        "n",
        {"artifactSha256": "known", "status": "incomplete"},
        timeout=1,
    )
    assert result["status"] == "incomplete"
    assert result["recordingComplete"] is False
    assert result["cases"] == []
    assert result["partialResultFailure"] == "ValueError"
    assert result["partialResultSha256"]
    assert json.loads((tmp_path / "manifest.json").read_text()) == result
