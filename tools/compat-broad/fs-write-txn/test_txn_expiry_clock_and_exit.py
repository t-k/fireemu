"""Actual loopback control responses and process exit contracts, without fireemu."""
from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parents[1])]
import txn_expiry_shadow as shadow
import test_txn_expiry_shadow as fixtures


@contextlib.contextmanager
def control(*, before=None, after=None, raw=None, status=200, content_type="application/json"):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args): pass
        def reply(self, verb):
            n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n)
            seen.append((verb, self.path, body, self.headers.get("Authorization")))
            if verb == "GET":
                value = before if before is not None else {
                    "session": "default", "clock": {"clock": "2026-09-18T00:00:00Z", "backwardsSets": 0}}
                data = json.dumps(value).encode(); code = 200
            else:
                value = after if after is not None else {"clock": "2026-09-18T00:00:20Z", "backwardsSets": 0}
                data = raw if raw is not None else json.dumps(value).encode(); code = status
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers(); self.wfile.write(data)
        def do_GET(self): self.reply("GET")
        def do_POST(self): self.reply("POST")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
    try: yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize("elapsed", [0, 5, 20, 25])
def test_control_elapsed_comes_from_observed_clocks_not_requested_seconds(elapsed):
    with control(after={"clock": f"2026-09-18T00:00:{elapsed:02d}Z", "backwardsSets": 0}) as (origin, seen):
        advance = shadow.clock_advance(origin, "local-control")
        assert advance(20) == elapsed
        assert advance.requests == 2
        assert [x[:2] for x in seen] == [("GET", "/v1/sessions/default"), ("POST", "/v1/sessions/default/clock:advance")]
        assert json.loads(seen[1][2]) == {"seconds": 20}
        assert all(x[3] == "Bearer local-control" for x in seen)


@pytest.mark.parametrize("after", [
    {}, {"advancedSeconds": 20},
    {"clock": "not-an-instant", "backwardsSets": 0},
    {"clock": "2026-09-18T00:00:20Z", "backwardsSets": True},
    {"clock": "2026-09-18T00:00:20Z", "backwardsSets": 1},
    {"clock": "2026-09-17T23:59:59Z", "backwardsSets": 0},
    {"clock": "2026-09-18T00:00:20Z", "backwardsSets": 0, "error": {}},
])
def test_control_missing_or_contradictory_measurement_never_falls_back(after):
    with control(after=after) as (origin, _):
        with pytest.raises(ValueError): shadow.clock_advance(origin, "local")(20)


@pytest.mark.parametrize("before", [{}, {"session": "other", "clock": {}},
    {"session": "default", "clock": {"clock": "2026-02-30T00:00:00Z", "backwardsSets": 0}}])
def test_unobserved_baseline_sends_no_advance(before):
    with control(before=before) as (origin, seen):
        with pytest.raises(ValueError): shadow.clock_advance(origin, "local")(20)
        assert len(seen) == 1 and seen[0][0] == "GET"


@pytest.mark.parametrize("raw", [b'{"clock":"2026-09-18T00:00:20Z","clock":"2026-09-18T00:00:20Z","backwardsSets":0}',
    b'{"clock":"2026-09-18T00:00:20Z","backwardsSets":NaN}', b'{}', b'[]'])
def test_ambiguous_control_bytes_are_not_measurement(raw):
    with control(raw=raw) as (origin, _):
        with pytest.raises(ValueError): shadow.clock_advance(origin, "local")(20)


@pytest.mark.parametrize("origin", ["http://localhost:8080", "https://127.0.0.1:8080", "http://127.0.0.1", "http://user@127.0.0.1:8080", "http://127.0.0.1:8080/path"])
def test_clock_origin_is_explicit_numeric_loopback(origin):
    with pytest.raises(ValueError):shadow.clock_advance(origin,"local")


@pytest.mark.parametrize("overrides", [
    {"exitCode": 9}, {"exitCode": False}, {"exitCode": None},
    {"stopped": False}, {"stopped": 1}, {"signal": "SIGTERM"},
    {"timedOut": True}, {"timedOut": 0}, {"failure": "stop-failed"},
])
def test_shadow_does_not_promote_failed_or_unknown_child(overrides):
    child = {"stopped": True, "exitCode": 0, "signal": None, **overrides}
    result = fixtures.synthetic_document(child=child)
    assert result["complete"] is False
    assert result["productionExecuted"] is False
    assert result["acquisitionValidated"] is False


def test_shadow_keeps_valid_normal_exit_complete():
    assert fixtures.synthetic_document()["complete"] is True


@pytest.mark.parametrize("raised", [subprocess.CalledProcessError(1, "ps"), subprocess.TimeoutExpired("ps", 2), OSError("missing ps")])
def test_missing_process_identity_is_not_proof_that_live_child_stopped(monkeypatch, raised):
    class Live:
        pid = 12345
        def poll(self):return None
        def send_signal(self, _signal):raise AssertionError("unverified signal")
    def fail(*_args, **_kw):raise raised
    monkeypatch.setattr(shadow.subprocess, "check_output", fail)
    result = shadow.stop_child(Live(), Path("/owned/fireemu"))
    assert result["stopped"] is False
    assert result["exitCode"] is None


def test_artifact_path_in_argument_does_not_identify_process(monkeypatch):
    class Live:
        pid = 12345
        def poll(self):return None
        def send_signal(self, _signal):raise AssertionError("unverified signal")
    monkeypatch.setattr(shadow.subprocess, "check_output", lambda *_a, **_k:"/other/executable --arg=/owned/fireemu")
    with pytest.raises(RuntimeError):shadow.stop_child(Live(), Path("/owned/fireemu"))


def test_control_clock_keeps_submicrosecond_underadvance_visible():
    before = {"session": "default", "clock": {"clock": "2026-09-18T00:00:00.000000001Z", "backwardsSets": 0}}
    with control(before=before) as (origin, _):
        measured = shadow.clock_advance(origin, "local")(20)
        assert measured < 20
        assert measured == 19.999999999


@contextlib.contextmanager
def response_server(status, raw, media="application/json", extra_headers=()):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args): pass
        def do_GET(self):
            seen.append(self.path)
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(raw)))
            for name, value in extra_headers:self.send_header(name, value)
            self.end_headers();self.wfile.write(raw)
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield f"http://127.0.0.1:{server.server_port}",seen
    finally:server.shutdown();server.server_close();thread.join(timeout=2);assert not thread.is_alive()


def get_request():
    return {"rpc":"GetDocument", "database":"(default)", "projectId":"fireemu-test",
            "name":"projects/fireemu-test/databases/(default)/documents/items/a", "body":None,
            "query":None,"maxResponseBytes":65536,"timeoutSeconds":5}


@pytest.mark.parametrize("status,raw,media,headers", [
    (200,b'{}',"text/plain",()),
    (404,b'{"error":{"status":"NOT_FOUND","code":404},"error":{"status":"NOT_FOUND","code":404}}',"application/json",()),
    (404,b'{"error":{"status":"NOT_FOUND","code":404.0}}',"application/json",()),
    (403,b'{"error":{"status":"NOT_FOUND","code":403}}',"application/json",()),
    (500,b'{"error":{"status":"NOT_FOUND","code":404}}',"application/json",()),
    (404,b'{"error":{"status":"NOT_FOUND","code":404},"name":"present"}',"application/json",()),
    (200,b'{"error":{"status":"INTERNAL","code":500}}',"application/json",()),
    (200,b'[]',"application/json",()),
    (200,b'{}',"application/json",(("Content-Length","2"),)),
    (200,b'{"x":NaN}',"application/json",()),
    (200,'{}'.encode('utf-16'),"application/json",()),
    (200,b'{}',"application/json",(("Content-Type","text/plain"),)),
])
def test_actual_rest_boundary_rejects_ambiguous_response(status,raw,media,headers):
    with response_server(status,raw,media,headers) as (origin,seen):
        result=shadow.rest_transport(origin)(get_request())
        assert result["complete"] is False
        assert len(seen)==1


def test_actual_rest_boundary_retains_correct_typed_absence():
    with response_server(404,b'{"error":{"status":"NOT_FOUND","code":404}}') as (origin,seen):
        result=shadow.rest_transport(origin)(get_request())
        assert result["complete"] is True
        assert result["code"] == 5
        assert result["httpStatus"] == 404
        assert len(seen)==1


@pytest.mark.parametrize("status",[401,403])
def test_unparseable_auth_refusal_stops_further_collector_sends(status):
    import test_txn_expiry_collector as cf
    with response_server(status,b'not-json') as (origin,seen):
        col=cf.collection_with(shadow.rest_transport(origin))
        receipt=col.run()
        assert receipt["authorityRefusal"]
        assert receipt["complete"] is False
        assert len(seen)==1


def test_parent_stops_owned_process_even_on_wait_interruption(tmp_path,monkeypatch):
    artifact=tmp_path/'artifact';artifact.write_bytes(b'fixture-not-a-native-artifact')
    class Process:
        def wait(self, **_kw):raise KeyboardInterrupt
    stopped=[]
    monkeypatch.setattr(shadow,'runtime_binding',lambda *_a:{})
    monkeypatch.setattr(shadow.subprocess,'Popen',lambda *_a,**_k:Process())
    monkeypatch.setattr(shadow.subprocess,'check_output',lambda *_a,**_k:'fixture-version')
    monkeypatch.setattr(shadow,'stop_child',lambda proc,art:stopped.append((proc,art)))
    with pytest.raises(KeyboardInterrupt):shadow.run_shadow(artifact,tmp_path/'run')
    assert len(stopped)==1
    assert not (tmp_path/'run'/'shadow.json').exists()


def test_wrong_control_token_status_requires_integer():
    receipt = fixtures.synthetic_document()["receipt"]
    receipt["instance"]["wrongTokenStatus"] = 403.0
    assert fixtures.synthetic_document(receipt=receipt)["complete"] is False
