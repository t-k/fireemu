"""Local process/pipe/journal tests. No Firebase SDK, binary or cloud traffic."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest
from o6_listen_resume import local_supervisor as m
from o6_listen_resume.campaign import owned_paths


def run_child(tmp_path, text, *, timeout=2, **kw):
    output = tmp_path / "capture"
    output.mkdir(mode=0o700)
    result = m._capture([sys.executable, "-I", "-S", "-c", text],
                        {"PATH": os.defpath}, tmp_path, output, timeout,
                        term_seconds=0.2, drain_seconds=0.1, **kw)
    return result, output


def test_real_child_exits_and_streams_remain_private(tmp_path):
    result, output = run_child(tmp_path, "import sys;print('ok');print('PRIVATE-STDERR', file=sys.stderr)")
    assert result["issues"] == []
    assert result["leaderStopped"] and result["groupAbsent"] and result["pipesClosed"]
    assert result["returnCode"] == 0
    assert (output / "stdout.bin").read_bytes() == b"ok\n"
    assert result["streams"]["stdout"]["sha256"] == hashlib.sha256(b"ok\n").hexdigest()
    assert "PRIVATE-STDERR" not in json.dumps(result)
    for file in output.iterdir(): assert file.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("ignore_term", [False, True])
def test_real_unresponsive_child_is_stopped_without_claiming_resource_recovery(tmp_path, ignore_term):
    code = "import signal,time;" + ("signal.signal(signal.SIGTERM,signal.SIG_IGN);" if ignore_term else "")
    code += "print('ready',flush=True);time.sleep(100)"
    result, output = run_child(tmp_path, code, timeout=0.35)
    assert "execution-deadline" in result["issues"]
    assert result["leaderStopped"] is True and result["groupAbsent"] is True
    assert "SIGTERM" in result["signals"]
    assert ("SIGKILL" in result["signals"]) is ignore_term
    assert result["elapsedSeconds"] < 3
    assert (output / "stdout.bin").read_bytes() == b"ready\n"
    assert "resourceCleanupComplete" not in result


def test_nonzero_exit_even_with_success_text_is_not_success(tmp_path):
    result, _ = run_child(tmp_path, "import sys;print('{\"complete\":true}');sys.exit(3)")
    assert result["returnCode"] == 3
    assert "child-nonzero-exit" in result["issues"]


@pytest.mark.parametrize("name", ["stdout", "stderr"])
def test_output_flood_is_bounded_and_child_is_stopped(tmp_path, monkeypatch, name):
    monkeypatch.setattr(m, "MAX_STDOUT", 4096)
    monkeypatch.setattr(m, "MAX_STDERR", 4096)
    code = f"import os,time;os.write({1 if name == 'stdout' else 2},b'x'*10000);time.sleep(50)"
    result, output = run_child(tmp_path, code)
    assert name + "-limit" in result["issues"]
    assert (output / (name + ".bin")).stat().st_size == 4096
    assert result["leaderStopped"] is True


def test_process_record_failure_stops_child_before_returning(tmp_path, monkeypatch):
    original = m._publish
    def fail(path, value):
        if path.name == "process.json": raise OSError("PRIVATE-PATH")
        return original(path, value)
    monkeypatch.setattr(m, "_publish", fail)
    result, _ = run_child(tmp_path, "import time;time.sleep(50)")
    assert result["leaderStopped"] and result["groupAbsent"]
    assert "process-operation-OSError" in result["issues"]
    assert "PRIVATE-PATH" not in json.dumps(result)


def test_inherited_open_pipes_do_not_block_after_leader_exit(tmp_path, monkeypatch):
    """Simulate descriptors inherited by another process, without leaking it."""
    writers = []
    class Exited:
        pid = 99999999
        def __init__(self):
            self.stdout, self.stderr = [self.pipe() for _ in range(2)]
        def pipe(self):
            rd, wr = os.pipe(); writers.append(wr); return os.fdopen(rd, "rb")
        def poll(self): return 0
    child = Exited()
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **kw: child)
    monkeypatch.setattr(m, "_group_absent", lambda pid: False)
    try:
        result, _ = run_child(tmp_path, "not executed", timeout=1)
        assert "inherited-pipes-remain" in result["issues"]
        assert "process-group-remains-unconfirmed" in result["issues"]
        assert result["signals"] == []
        assert result["elapsedSeconds"] < 0.8
    finally:
        for fd in writers: os.close(fd)


@pytest.mark.parametrize("value", [0, -1, True, "10", float("nan"), float("inf"), 821])
def test_invalid_deadline_is_rejected_before_launch(tmp_path, value):
    with pytest.raises(m.Refused): run_child(tmp_path, "assert False", timeout=value)


def env_for(tmp_path):
    return {"PATH": os.environ["PATH"], "GOOGLE_CLOUD_PROJECT": "demo-local",
            "FIRESTORE_EMULATOR_HOST": "127.0.0.1:18081", "FIREBASE_AUTH_EMULATOR_HOST": "[::1]:18082",
            "O6_FIREBASE_MODULE_DIR": str(tmp_path)}


@pytest.mark.parametrize("key,value", [
    ("O6_LISTEN_MODE", "production"), ("O6_LISTEN_PERMISSION", "pretend-approval"),
    ("O6_LISTEN_NONCE", "a"*32), ("O6_LISTEN_CAMPAIGN_PATH", "/old-receipt"),
    ("O6_LISTEN_PASSWORD_FD", "7"), ("O6_LISTEN_JOURNAL_DIR", "/old-journal"),
    ("FIRESTORE_EMULATOR_HOST", "firestore.googleapis.com:443"),
    ("FIREBASE_AUTH_EMULATOR_HOST", "localhost:9099"),
    ("FIRESTORE_EMULATOR_HOST", "http://127.0.0.1:8080"),
    ("FIRESTORE_EMULATOR_HOST", "127.0.0.1:0"),
    ("FIRESTORE_EMULATOR_HOST", "127.0.0.1:65536"),
    ("GOOGLE_CLOUD_PROJECT", "real-project"),
])
def test_public_launcher_refuses_unsafe_inputs_before_any_process(tmp_path, monkeypatch, key, value):
    monkeypatch.setattr(m, "_capture", lambda *a, **kw: pytest.fail("must not launch"))
    env = env_for(tmp_path); env[key] = value
    with pytest.raises(m.Refused): m.run(tmp_path / "new", env=env)
    assert not (tmp_path / "new").exists()


@pytest.mark.parametrize("kind", ["directory", "file", "symlink", "dangling"])
def test_old_destination_is_not_reused(tmp_path, monkeypatch, kind):
    output = tmp_path / "old"
    if kind == "directory": output.mkdir()
    elif kind == "file": output.write_text("KEEP")
    else: output.symlink_to(tmp_path / ("missing" if kind == "dangling" else "."))
    monkeypatch.setattr(m, "_capture", lambda *a, **kw: pytest.fail("must not launch"))
    with pytest.raises(m.Refused): m.run(output, env=env_for(tmp_path))


def journal(directory, nonce, project, *, value_change=None):
    prev = None
    for idx, phase in enumerate(["ready", "account-create-intent", "account-created", "documents-at-risk", "lifecycle-result"]):
        value = {}
        if idx == 2: value = {"uid": "test-uid", "paths": owned_paths(nonce, "test-uid")}
        if idx == 4: value = {"complete": True, "accountCleanupComplete": True,
                             "clientsComplete": True, "documentsCleanupComplete": True}
        if value_change: value = value_change(phase, value)
        item = {"schema": "local-listen-checkpoint-v1", "nonce": nonce, "projectId": project,
                "phase": phase, "accountEmail": f"o6-{nonce}@example.test", "authorizesCleanup": False,
                "previousSha256": prev, "value": value}
        raw = m._encode(item); (directory / f"{idx}-{phase}.json").write_bytes(raw)
        prev = m._sha(raw)


def public_fixture(tmp_path, monkeypatch, change=lambda v: v, *, child_issue=None, change_journal=None):
    """Synthetic receipt injection tests parent admission; not SDK execution."""
    captures = []
    def capture(command, env, cwd, output, timeout):
        captures.append((command, env))
        process = {"started": True, "returnCode": 0, "leaderStopped": True, "groupAbsent": True,
                   "pipesClosed": True, "issues": [] if child_issue is None else [child_issue]}
        if command[1].endswith("local_shadow_check.mjs"):
            value = {"kind": "local-listen-expectation-check", "complete": True}
        else:
            # This exists and is durable before the process callback executes.
            launch = json.loads((output / "launch.json").read_bytes())
            nonce = launch["nonce"]; project = launch["projectId"]
            campaign = json.loads((output / "campaign.json").read_bytes())
            budget = json.loads((output / "budget.json").read_bytes())
            journal(output / "checkpoints", nonce, project, value_change=change_journal)
            value = {"productionExecuted": False,
                "environment": {"nonceDigest": m._sha(nonce.encode()), "projectId": project},
                "campaignDigest": campaign["campaignDigest"],
                "sourceDigests": {k: launch["sourceDigests"][k] for k in budget["boundSources"]},
                "cleanup": {"rows": [{"name": k, "pathDigest": m._sha(v.encode())}
                                     for k, v in owned_paths(nonce, "test-uid").items() if k != "run"]}}
            value = change(value)
        (output / "stdout.bin").write_bytes(m._encode(value))
        (output / "stderr.bin").write_bytes(b"")
        return process
    monkeypatch.setattr(m, "_capture", capture)
    return captures


def test_parent_success_requires_local_checker_and_durable_scope_but_never_claims_artifact(tmp_path, monkeypatch):
    captures = public_fixture(tmp_path, monkeypatch)
    result = m.run(tmp_path / "new", env=env_for(tmp_path))
    assert result["completed"] is True and result["recoveryRequired"] is False
    assert result["currentArtifactVerified"] is False
    assert result["productionCompatibilityVerified"] is False
    assert result["authorizesCleanup"] is False
    assert len(captures) == 2
    assert captures[0][0][1].endswith("listen_sdk_adapter.mjs")


@pytest.mark.parametrize("issue", ["execution-deadline", "child-nonzero-exit", "stdout-limit",
                                    "process-operation-OSError", "inherited-pipes-remain"])
def test_abnormal_stop_cannot_become_success_even_with_complete_looking_receipt(tmp_path, monkeypatch, issue):
    calls = public_fixture(tmp_path, monkeypatch, child_issue=issue)
    result = m.run(tmp_path / "new", env=env_for(tmp_path))
    assert result["completed"] is False and result["recoveryRequired"] is True
    assert result["resourceCleanupComplete"] is False
    assert len(calls) == 1


@pytest.mark.parametrize("change", [
    lambda v: {**v, "productionExecuted": 0},
    lambda v: {**v, "campaignDigest": "old"},
    lambda v: {**v, "sourceDigests": {}},
    lambda v: {**v, "environment": {**v["environment"], "nonceDigest": "old"}},
    lambda v: {**v, "cleanup": {"rows": []}},
    lambda v: {**v, "cleanup": {"rows": [{**r, "pathDigest": "old"} for r in v["cleanup"]["rows"]]}},
])
def test_forged_or_old_scope_is_rejected(tmp_path, monkeypatch, change):
    calls = public_fixture(tmp_path, monkeypatch, change)
    result = m.run(tmp_path / "new", env=env_for(tmp_path))
    assert not result["completed"] and result["recoveryRequired"]
    assert len(calls) == 1


def test_failed_checkpoint_cannot_be_overridden_by_success_receipt(tmp_path, monkeypatch):
    public_fixture(tmp_path, monkeypatch, change_journal=lambda p,v:
                   {**v, "accountCleanupComplete": False} if p == "lifecycle-result" else v)
    result = m.run(tmp_path / "new", env=env_for(tmp_path))
    assert not result["completed"] and result["recoveryRequired"]


def test_child_does_not_inherit_credentials_or_node_code_injection(tmp_path, monkeypatch):
    calls = public_fixture(tmp_path, monkeypatch)
    env = env_for(tmp_path)
    for key in ("GOOGLE_APPLICATION_CREDENTIALS", "AWS_ACCESS_KEY_ID", "NODE_OPTIONS", "NODE_PATH",
                "FIREEMU_CONTROL_TOKEN", "HTTPS_PROXY", "O6_LISTEN_CATALOG_PATH"):
        env[key] = "PRIVATE-MATERIAL"
    result = m.run(tmp_path / "new", env=env)
    assert result["completed"]
    assert all("PRIVATE-MATERIAL" not in json.dumps(child_env) for _, child_env in calls)
    assert not any("PRIVATE-MATERIAL" in p.read_text() for p in (tmp_path / "new").rglob("*.json"))


def test_launch_publication_failure_prevents_sdk_start(tmp_path, monkeypatch):
    original = m._publish
    def publish(path, value):
        if path.name == "launch.json": raise OSError("disk")
        original(path, value)
    monkeypatch.setattr(m, "_publish", publish)
    monkeypatch.setattr(m, "_capture", lambda *a, **kw: pytest.fail("must not launch"))
    result = m.run(tmp_path / "new", env=env_for(tmp_path))
    assert not result["completed"]


def test_final_result_publication_failure_never_returns_success(tmp_path, monkeypatch):
    public_fixture(tmp_path, monkeypatch)
    original = m._publish
    def publish(path, value):
        if path.name == "result.json": raise OSError("disk")
        original(path, value)
    monkeypatch.setattr(m, "_publish", publish)
    with pytest.raises(OSError): m.run(tmp_path / "new", env=env_for(tmp_path))
    assert (tmp_path / "new/launch.json").exists()


def fake_shim(tmp_path, name="volta-shim"):
    """An executable that records its own invocation; the launcher must never run it."""
    shim = tmp_path / "shim" / name
    shim.parent.mkdir(parents=True, exist_ok=True)
    shim.write_text("#!/bin/sh\ntouch \"$(dirname \"$0\")/SPAWNED\"\nexit 0\n")
    shim.chmod(0o700)
    return shim


def shim_on_path(tmp_path):
    """PATH whose first `node` is a symlink to a volta-shim, like `~/.volta/bin/node`."""
    link = tmp_path / "shim-bin"
    link.mkdir()
    (link / "node").symlink_to(fake_shim(tmp_path))
    return f"{link}{os.pathsep}{os.environ['PATH']}"


def test_fireemu_node_is_honoured_before_path(tmp_path):
    real = tmp_path / "real-node"
    real.write_text("#!/bin/sh\nexit 0\n"); real.chmod(0o700)
    env = {"PATH": shim_on_path(tmp_path), "FIREEMU_NODE": str(real)}
    assert m._resolve_node(env) == str(real)
    assert not (tmp_path / "shim/SPAWNED").exists()


@pytest.mark.parametrize("via", ["FIREEMU_NODE", "PATH"])
def test_volta_shim_is_refused_by_name_and_never_spawned(tmp_path, via):
    env = {"PATH": os.defpath, "VOLTA_HOME": str(tmp_path / "no-volta")}
    if via == "FIREEMU_NODE":
        env["FIREEMU_NODE"] = str(fake_shim(tmp_path))
    else:
        env["PATH"] = shim_on_path(tmp_path)
    with pytest.raises(m.Refused, match="volta-shim-refused"):
        m._resolve_node(env)
    assert not (tmp_path / "shim/SPAWNED").exists()


def test_shim_on_path_is_replaced_by_the_pinned_volta_image(tmp_path):
    volta = tmp_path / "volta"
    image = volta / "tools/image/node/9.9.9/bin"
    image.mkdir(parents=True)
    (image / "node").write_text("#!/bin/sh\nexit 0\n"); (image / "node").chmod(0o700)
    (volta / "tools/user").mkdir(parents=True)
    (volta / "tools/user/platform.json").write_text(json.dumps({"node": {"runtime": "9.9.9"}}))
    env = {"PATH": shim_on_path(tmp_path), "VOLTA_HOME": str(volta)}
    assert m._resolve_node(env) == str(image / "node")
    assert not (tmp_path / "shim/SPAWNED").exists()


def test_shim_without_platform_pin_falls_back_to_the_newest_image(tmp_path):
    volta = tmp_path / "volta"
    for version in ("9.10.0", "9.9.1", "10.0.0"):
        image = volta / "tools/image/node" / version / "bin"
        image.mkdir(parents=True)
        (image / "node").write_text("#!/bin/sh\nexit 0\n"); (image / "node").chmod(0o700)
    env = {"PATH": shim_on_path(tmp_path), "VOLTA_HOME": str(volta)}
    assert m._resolve_node(env) == str(volta / "tools/image/node/10.0.0/bin/node")


@pytest.mark.parametrize("missing", ["absent", "directory", "not-executable"])
def test_fireemu_node_must_be_an_executable_file(tmp_path, missing):
    target = tmp_path / "candidate"
    if missing == "directory":
        target.mkdir()
    elif missing == "not-executable":
        target.write_text("")
    with pytest.raises(m.Refused, match="node-not-found"):
        m._resolve_node({"PATH": os.defpath, "FIREEMU_NODE": str(target)})


def test_launcher_refuses_a_shim_before_any_process_or_output(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "_capture", lambda *a, **kw: pytest.fail("must not launch"))
    env = env_for(tmp_path)
    env["PATH"] = shim_on_path(tmp_path)
    env["VOLTA_HOME"] = str(tmp_path / "no-volta")
    with pytest.raises(m.Refused, match="volta-shim-refused"):
        m.run(tmp_path / "new", env=env)
    assert not (tmp_path / "new").exists()
    assert not (tmp_path / "shim/SPAWNED").exists()


def test_real_cli_with_missing_sdk_fails_after_persisting_launch_without_cloud_access(tmp_path):
    env = env_for(tmp_path)
    code = subprocess.run([sys.executable, "-I", "-S", str(m.HERE / "local_supervisor.py"),
                           "--output", str(tmp_path / "new"), "--timeout-seconds", "5"],
                          env=env, capture_output=True, timeout=10)
    assert code.returncode == 2
    result = json.loads((tmp_path / "new/result.json").read_bytes())
    assert result["completed"] is False
    assert result["execution"]["leaderStopped"] is True
    assert (tmp_path / "new/launch.json").exists()
    assert (tmp_path / "new/checkpoints/0-ready.json").exists()


def test_actual_node_unresolved_sdk_promise_keeps_durable_account_intent(tmp_path):
    """Fixed CLI + real Node + loopback HTTP; SDK methods are test doubles."""
    import http.server
    import threading
    package = tmp_path / "node_modules/firebase"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "firebase", "type": "module",
        "exports": {"./app": "./app.mjs", "./firestore": "./firestore.mjs", "./auth": "./auth.mjs"}}))
    (package / "app.mjs").write_text("export const initializeApp=()=>({}); export const deleteApp=async()=>{};")
    (package / "firestore.mjs").write_text("export const getFirestore=()=>({}); export const connectFirestoreEmulator=()=>{}; export const terminate=async()=>{};")
    (package / "auth.mjs").write_text("""
export const getAuth=()=>({}); export const connectAuthEmulator=()=>{};
export const createUserWithEmailAndPassword=async()=>{
  setInterval(()=>{},1000); return new Promise(()=>{});
};
""")
    calls = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            calls.append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            raw = b'{"users":[]}'
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
        def log_message(self, *args): pass
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            env = env_for(tmp_path)
            env["FIREBASE_AUTH_EMULATOR_HOST"] = f"127.0.0.1:{server.server_port}"
            result = m.run(tmp_path / "unsettled", env=env, timeout=0.8)
        finally:
            server.shutdown(); thread.join(timeout=2)
    assert result["completed"] is False and result["recoveryRequired"] is True
    assert result["processCleanupComplete"] is True
    assert result["resourceCleanupComplete"] is False
    assert "execution-deadline" in result["issues"]
    assert result["journal"]["lastPhase"] == "account-create-intent"
    assert (tmp_path / "unsettled/checkpoints/1-account-create-intent.json").exists()
    # One preflight lookup per principal, then the unsettled signup of the first.
    assert calls == ["/identitytoolkit.googleapis.com/v1/projects/demo-local/accounts:lookup"] * 2
    assert result["execution"]["elapsedSeconds"] < 4


def test_journal_detects_prefix_deletion_and_forged_hashes(tmp_path):
    directory = tmp_path / "journal"; directory.mkdir()
    nonce = "a"*32; journal(directory, nonce, "demo-local")
    good = m._journal_summary(directory, nonce, "demo-local")
    assert good["lastPhase"] == "lifecycle-result"
    (directory / "1-account-create-intent.json").unlink()
    with pytest.raises(m.Refused): m._journal_summary(directory, nonce, "demo-local")


@pytest.mark.parametrize("field,value", [("complete", 1), ("extra", "token")])
def test_journal_rejects_untyped_or_extra_result_values(tmp_path, field, value):
    directory = tmp_path / "journal"; directory.mkdir()
    nonce = "a"*32
    journal(directory, nonce, "demo-local", value_change=lambda p,v:
            {**v, field: value} if p == "lifecycle-result" else v)
    with pytest.raises(m.Refused): m._journal_summary(directory, nonce, "demo-local")


def test_case_input_replacement_during_run_is_detected(tmp_path, monkeypatch):
    public_fixture(tmp_path, monkeypatch)
    original = m._capture
    def changed(*args, **kw):
        result = original(*args, **kw)
        (args[3] / "catalog.json").write_text('{}')
        return result
    monkeypatch.setattr(m, "_capture", changed)
    result = m.run(tmp_path / "new", env=env_for(tmp_path))
    assert not result["completed"] and result["recoveryRequired"]
    assert "input-changed-during-run" in result["issues"]


@pytest.mark.parametrize("field,value", [("returnCode", False), ("returnCode", 3),
                                        ("pipesClosed", False), ("leaderStopped", 1), ("groupAbsent", False)])
def test_process_boolean_flags_do_not_accept_truthy_or_incomplete_states(tmp_path, monkeypatch, field, value):
    public_fixture(tmp_path, monkeypatch)
    original = m._capture
    def changed(*args, **kw): return {**original(*args, **kw), field: value}
    monkeypatch.setattr(m, "_capture", changed)
    result = m.run(tmp_path / "new", env=env_for(tmp_path))
    assert not result["completed"]


def test_ctrl_c_during_capture_still_stops_owned_child_and_records_interruption(tmp_path, monkeypatch):
    original = m.selectors.DefaultSelector
    class Interrupting:
        def __init__(self): self.inner = original()
        def register(self, *a, **kw): return self.inner.register(*a, **kw)
        def get_map(self): return self.inner.get_map()
        def select(self, *a, **kw): raise KeyboardInterrupt
        def close(self): self.inner.close()
    monkeypatch.setattr(m.selectors, "DefaultSelector", Interrupting)
    result, _ = run_child(tmp_path, "import time;time.sleep(100)")
    assert "supervisor-interrupted" in result["issues"]
    assert result["leaderStopped"] is True and result["groupAbsent"] is True
