"""The second pair gives real owned children a bounded recovery opportunity."""

import json
import os
import socket
import subprocess
import sys
import time

from broad import stop_registered


def test_owned_child_can_finish_recovery_before_forced_termination(tmp_path):
    script = tmp_path / "recover.py"
    script.write_text("""import signal,sys,time
from pathlib import Path
root=Path(sys.argv[1])
def recover(*_):
    time.sleep(0.4)
    (root/'recovered').write_text('yes')
    sys.exit(0)
signal.signal(signal.SIGTERM,recover)
(root/'ready').write_text('yes')
while True: time.sleep(1)
""")
    command = [sys.executable, str(script), str(tmp_path)]
    child = subprocess.Popen(command)
    try:
        deadline = time.monotonic() + 5
        while not (tmp_path / "ready").exists():
            assert child.poll() is None and time.monotonic() < deadline
            time.sleep(0.01)
        (tmp_path / "recover-process.json").write_text(
            json.dumps({"pid": child.pid, "argv": command})
        )
        started = time.monotonic()
        stop_registered(tmp_path, os.getpid(), "local", recovery_grace=1)
        child.wait(timeout=2)
        assert child.returncode == 0
        assert (tmp_path / "recovered").read_text() == "yes"
        assert time.monotonic() - started < 2
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)


def test_supervisor_timeout_preserves_grace_and_partial_manifest(tmp_path):
    from broad import supervise

    script = tmp_path / "child.py"
    script.write_text("""import json,os,signal,sys,time
from pathlib import Path
p=Path(sys.argv[1])
def recover(*_):
    time.sleep(0.4)
    (p/'recovered').write_text('yes')
    (p/'cases.json').write_text(json.dumps(dict(recordingComplete=False,cases=[dict(id='partial',status='indeterminate',family='test')])) )
    sys.exit(0)
signal.signal(signal.SIGTERM,recover)
(p/'instance.json').write_text(json.dumps(dict(pid=os.getpid(),parentPid=os.getppid(),nonce='n',argv=sys.argv,authOrigin='http://127.0.0.1:1',firestoreOrigin='http://127.0.0.1:1',controlOrigin='http://127.0.0.1:1')))
while True: time.sleep(1)
""")
    parent = tmp_path / "parent.py"
    parent.write_text("""import subprocess,sys
sys.exit(subprocess.call([sys.executable,sys.argv[1],sys.argv[2]]))
""")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
    script.write_text(script.read_text().replace("http://127.0.0.1:1", origin))
    result = supervise(
        [sys.executable, str(parent), str(script), str(tmp_path)],
        tmp_path,
        "n",
        {"artifactSha256": "known-before-start"},
        timeout=0.5,
        recovery_grace=1,
    )
    assert (tmp_path / "recovered").read_text() == "yes"
    assert result["stopReason"] == "child-timeout"
    assert result["status"] == "incomplete"
    assert result["recordingComplete"] is False
    assert result["artifactSha256"] == "known-before-start"
    assert result["cases"][0]["id"] == "partial"
    assert result["ownedProcess"]["stopped"] is True
    assert result["ownedProcess"]["listenersClosed"] is True
