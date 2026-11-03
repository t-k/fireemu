"""The router in front of the Flask app, driven in process with Werkzeug's test client."""

import json
import os
import time

import pytest
from werkzeug.test import Client

from fireemu_runner.manifest import build_manifest
from fireemu_runner.serve import SECRET_ENVIRON_KEY, RunnerRouter

SECRET = "s3cret"


@pytest.fixture
def client(discovered):
    router = RunnerRouter(discovered, build_manifest(discovered), "demo-proj", SECRET)
    return Client(router)


def get(client, path, secret=SECRET, **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    if secret is not None:
        headers["x-fireemu-runner-secret"] = secret
    # buffered: the server calls `close` on the response body, which releases the environment gate; the test client
    # only does so when it buffers.
    return client.open(path, headers=headers, buffered=True, **kwargs)


def test_the_environ_key_is_the_wsgi_spelling_of_the_header():
    assert SECRET_ENVIRON_KEY == "HTTP_X_FIREEMU_RUNNER_SECRET"


@pytest.mark.parametrize("secret", [None, "", "wrong", SECRET + "x", SECRET[:-1]])
def test_a_missing_or_wrong_secret_is_403_before_any_routing(client, secret):
    response = get(client, "/demo-proj/us-central1/hello", secret=secret)
    assert response.status_code == 403
    assert response.get_data(as_text=True) == "forbidden"
    # Even a path that routes nowhere answers 403, not 404, so the port reveals nothing.
    assert get(client, "/nowhere", secret=secret).status_code == 403


def test_the_function_sees_the_path_below_its_mount_and_the_script_name_is_the_mount(client):
    seen = json.loads(get(client, "/demo-proj/us-central1/hello/a/b/?q=1").get_data())
    assert seen["path"] == "/a/b/"
    assert seen["args"] == {"q": "1"}
    assert json.loads(get(client, "/demo-proj/us-central1/hello").get_data())["path"] == "/"
    assert json.loads(get(client, "/demo-proj/us-central1/hello/").get_data())["path"] == "/"


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/demo-proj",
        "/demo-proj/us-central1",
        "/other/us-central1/hello",
        "/demo-proj/europe-west1/hello",
        "/demo-proj/us-central1/missing",
        "/demo-proj/us-central1/fs_created",
        "relative/path",
        "//demo-proj/us-central1/hello",
    ],
)
def test_anything_but_a_served_http_function_is_404(client, path):
    response = get(client, path)
    assert response.status_code == 404
    assert response.get_data(as_text=True).startswith("no HTTP function")
    assert response.headers["Content-Type"] == "text/plain; charset=utf-8"
    assert int(response.headers["Content-Length"]) == len(response.get_data())


def test_the_404_for_an_unknown_function_names_the_project_region_and_name(client):
    assert get(client, "/demo-proj/us-central1/missing").get_data(as_text=True) == "no HTTP function demo-proj/us-central1/missing"
    assert get(client, "/demo-proj/europe-west1/hello").get_data(as_text=True) == "no HTTP function demo-proj/europe-west1/hello"
    assert get(client, "/").get_data(as_text=True) == "no HTTP function"


def test_the_403_is_a_plain_text_forbidden_with_its_length(client):
    response = get(client, "/demo-proj/us-central1/hello", secret="nope")
    assert response.headers["Content-Type"] == "text/plain; charset=utf-8"
    assert response.headers["Content-Length"] == "9"
    assert response.get_data() == b"forbidden"


def test_the_mount_point_is_the_script_name_and_the_rest_the_path(client):
    seen = json.loads(get(client, "/demo-proj/us-central1/hello/x/y").get_data())
    assert seen["script_root"] == "/demo-proj/us-central1/hello"
    assert seen["path"] == "/x/y"


def test_a_route_is_found_by_the_manifest_name_and_runs_the_entry_point(discovered):
    manifest = {"functions": [{"name": "renamed", "entryPoint": "hello", "generation": 2, "trigger": {"type": "http", "callable": False}}]}
    client = Client(RunnerRouter(discovered, manifest, "demo-proj", SECRET))
    assert json.loads(get(client, "/demo-proj/us-central1/renamed/z").get_data())["path"] == "/z"
    assert get(client, "/demo-proj/us-central1/hello").status_code == 404


def test_only_http_functions_get_a_route(discovered):
    manifest = {
        "functions": [
            {"name": "fs_created", "entryPoint": "fs_created", "generation": 2, "trigger": {"type": "firestore"}},
            {"name": "hello", "entryPoint": "hello", "generation": 2, "trigger": {"type": "http", "callable": False}},
        ]
    }
    router = RunnerRouter(discovered, manifest, "demo-proj", SECRET)
    assert set(router._routes) == {"hello"}


def test_a_function_without_a_region_is_served_in_the_default_region(discovered):
    manifest = {"functions": [{"name": "hello", "entryPoint": "hello", "generation": 2, "trigger": {"type": "http", "callable": False}}]}
    router = RunnerRouter(discovered, manifest, "demo-proj", SECRET)
    assert router._routes["hello"][0] == "us-central1"


def test_a_server_started_on_a_free_port_answers_over_a_socket(discovered):
    import urllib.request

    from fireemu_runner.serve import start_server

    server, port = start_server(discovered, build_manifest(discovered), SECRET)
    try:
        assert port == server.server_port and port > 0
        assert server.server_address[0] == "127.0.0.1"
        request = urllib.request.Request(f"http://127.0.0.1:{port}/demo-proj/us-central1/hello", headers={"x-fireemu-runner-secret": SECRET})
        with urllib.request.urlopen(request, timeout=10) as response:
            assert json.loads(response.read())["path"] == "/"
    finally:
        server.shutdown()


def test_a_function_with_an_explicit_region_is_served_only_there(discovered):
    manifest = {
        "functions": [{"name": "hello", "entryPoint": "hello", "generation": 2, "region": "europe-west1", "trigger": {"type": "http", "callable": False}}]
    }
    client = Client(RunnerRouter(discovered, manifest, "demo-proj", SECRET))
    assert get(client, "/demo-proj/europe-west1/hello").status_code == 200
    assert get(client, "/demo-proj/us-central1/hello").status_code == 404


def test_every_method_reaches_the_function_including_options(client):
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        assert json.loads(get(client, "/demo-proj/us-central1/hello", method=method).get_data())["method"] == method
    preflight = get(
        client,
        "/demo-proj/us-central1/add",
        method="OPTIONS",
        headers={"Origin": "http://localhost", "Access-Control-Request-Method": "POST"},
    )
    assert preflight.status_code == 200
    assert "Access-Control-Allow-Origin" in preflight.headers


def test_a_crash_is_the_frameworks_crash_response(client):
    response = get(client, "/demo-proj/us-central1/boom")
    assert response.status_code == 500
    assert response.headers["X-Google-Status"] == "crash"


def test_the_secret_is_removed_from_the_request_the_function_sees(client):
    assert json.loads(get(client, "/demo-proj/us-central1/hello").get_data())["secret_header"] is None


# --- the router called as a WSGI application, and the real server ---------------------------------


def wsgi_call(router, environ):
    seen = {}

    def start_response(status, headers):
        seen["status"], seen["headers"] = status, dict(headers)

    body = b"".join(router(environ, start_response))
    return seen["status"], seen["headers"], body


def environ_for(path=None, secret=SECRET, **extra):
    environ = {"REQUEST_METHOD": "GET", "wsgi.url_scheme": "http", "SERVER_NAME": "x", "SERVER_PORT": "80", "wsgi.input": __import__("io").BytesIO(b"")}
    if path is not None:
        environ["PATH_INFO"] = path
    if secret is not None:
        environ[SECRET_ENVIRON_KEY] = secret
    environ.update(extra)
    return environ


def test_status_lines_and_headers_of_the_plain_answers_are_exact(discovered):
    router = RunnerRouter(discovered, build_manifest(discovered), "demo-proj", SECRET)
    status, headers, body = wsgi_call(router, environ_for("/demo-proj/us-central1/hello", secret="bad"))
    assert (status, body) == ("403 Forbidden", b"forbidden")
    assert headers == {"Content-Type": "text/plain; charset=utf-8", "Content-Length": "9"}
    status, headers, body = wsgi_call(router, environ_for("/x"))
    assert (status, body) == ("404 Not Found", b"no HTTP function")
    status, headers, body = wsgi_call(router, environ_for("/demo-proj/us-central1/nope"))
    assert (status, body) == ("404 Not Found", b"no HTTP function demo-proj/us-central1/nope")
    assert headers["Content-Length"] == str(len(body))


def test_a_request_without_a_path_is_404_not_an_error(discovered):
    router = RunnerRouter(discovered, build_manifest(discovered), "demo-proj", SECRET)
    assert wsgi_call(router, environ_for(None))[0] == "404 Not Found"


def test_a_missing_secret_is_refused_even_when_the_secret_is_the_text_xxxx(discovered):
    router = RunnerRouter(discovered, build_manifest(discovered), "demo-proj", "XXXX")
    assert wsgi_call(router, environ_for("/demo-proj/us-central1/hello", secret=None))[0] == "403 Forbidden"
    assert wsgi_call(router, environ_for("/demo-proj/us-central1/hello", secret="XXXX"))[0] == "200 OK"


def test_the_script_name_is_the_incoming_prefix_plus_the_mount_and_defaults_to_nothing(discovered):
    router = RunnerRouter(discovered, build_manifest(discovered), "demo-proj", SECRET)
    status, _, body = wsgi_call(router, environ_for("/demo-proj/us-central1/hello/z"))
    assert json.loads(body)["script_root"] == "/demo-proj/us-central1/hello"
    status, _, body = wsgi_call(router, environ_for("/demo-proj/us-central1/hello/z", SCRIPT_NAME="/front"))
    assert json.loads(body)["script_root"] == "/front/demo-proj/us-central1/hello"


def test_the_crash_handler_is_the_one_for_status_500_and_every_method_is_routed(discovered):
    router = RunnerRouter(discovered, build_manifest(discovered), "demo-proj", SECRET)
    app = router._app
    assert 500 in app.error_handler_spec[None]
    assert not any(code in app.error_handler_spec[None] for code in (501, 502, 503))
    # Flask's own `/static/<path:filename>` rule stays, as it does under functions-framework.
    rules = {rule.rule: rule for rule in app.url_map.iter_rules() if rule.endpoint != "static"}
    assert set(rules) == {"/", "/<path:path>"}
    for rule in rules.values():
        assert rule.endpoint == "run"
        assert {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"} <= set(rule.methods)
    assert rules["/"].defaults == {"path": ""}
    assert app.name == "fireemu-runner"


def test_the_server_is_threaded_and_its_thread_is_a_named_daemon(discovered, monkeypatch):
    import threading
    import urllib.request
    from concurrent.futures import ThreadPoolExecutor

    from fireemu_runner.serve import start_server

    monkeypatch.setenv("GCLOUD_PROJECT", "demo-proj")
    server, port = start_server(discovered, build_manifest(discovered), SECRET)
    try:
        thread = next(t for t in threading.enumerate() if t.name == "http")
        assert thread.daemon is True
        assert server.multithread is True and server.multiprocess is False

        def slow(n):
            request = urllib.request.Request(f"http://127.0.0.1:{port}/demo-proj/us-central1/slow?seconds=0.4&tag={n}", headers={"x-fireemu-runner-secret": SECRET})
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.loads(response.read())["done"]

        import time

        started = time.monotonic()
        with ThreadPoolExecutor(4) as pool:
            assert list(pool.map(slow, range(4))) == ["0", "1", "2", "3"]
        assert time.monotonic() - started < 1.4
    finally:
        server.shutdown()


def test_the_project_comes_from_the_environment_and_is_empty_without_one(discovered, monkeypatch):
    from fireemu_runner.serve import start_server

    monkeypatch.delenv("GCLOUD_PROJECT", raising=False)
    server, _ = start_server(discovered, build_manifest(discovered), SECRET)
    try:
        assert server.app._project == ""
        # Nothing but an empty project segment can match, and a real project never does.
        assert wsgi_call(server.app, environ_for("//us-central1/hello"))[0] == "200 OK"
        assert wsgi_call(server.app, environ_for("/demo-proj/us-central1/hello"))[0] == "404 Not Found"
    finally:
        server.shutdown()
    monkeypatch.setenv("GCLOUD_PROJECT", "p-env")
    server, _ = start_server(discovered, build_manifest(discovered), SECRET)
    try:
        assert server.app._project == "p-env"
    finally:
        server.shutdown()


def test_the_server_writes_nothing_to_stderr_for_a_request(discovered, monkeypatch, capfd):
    import urllib.request

    from fireemu_runner.serve import start_server

    monkeypatch.setenv("GCLOUD_PROJECT", "demo-proj")
    server, port = start_server(discovered, build_manifest(discovered), SECRET)
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{port}/demo-proj/us-central1/hello", headers={"x-fireemu-runner-secret": SECRET})
        urllib.request.urlopen(request, timeout=10).read()
    finally:
        server.shutdown()
    assert capfd.readouterr().err == ""


def test_http_dispatch_sets_the_function_identity_variables_as_the_event_path_does(client, monkeypatch):
    for key in ("FUNCTION_TARGET", "FUNCTION_SIGNATURE_TYPE", "K_SERVICE"):
        monkeypatch.setenv(key, "left-by-an-earlier-event")
    seen = json.loads(get(client, "/demo-proj/us-central1/hello").get_data())
    assert (seen["function_target"], seen["function_signature_type"], seen["k_service"]) == ("hello", "http", "hello")


def test_a_renamed_function_reports_its_entry_point_as_the_target_and_its_name_as_the_service(discovered, monkeypatch):
    manifest = {"functions": [{"name": "renamed", "entryPoint": "hello", "generation": 2, "trigger": {"type": "http", "callable": False}}]}
    client = Client(RunnerRouter(discovered, manifest, "demo-proj", SECRET))
    monkeypatch.delenv("FUNCTION_TARGET", raising=False)
    monkeypatch.delenv("K_SERVICE", raising=False)
    seen = json.loads(get(client, "/demo-proj/us-central1/renamed").get_data())
    assert (seen["function_target"], seen["k_service"]) == ("hello", "renamed")


def test_a_sequential_event_then_http_call_sees_each_ones_own_identity(discovered, monkeypatch):
    from fireemu_runner.dispatch import Dispatcher
    from test_dispatch import Collected, event

    manifest = build_manifest(discovered)
    router = RunnerRouter(discovered, manifest, "demo-proj", SECRET)
    client = Client(router)
    writer = Collected()
    dispatcher = Dispatcher(discovered, manifest, writer)
    for key in ("FUNCTION_TARGET", "FUNCTION_SIGNATURE_TYPE", "K_SERVICE"):
        monkeypatch.delenv(key, raising=False)
    assert dispatcher.reserve()
    dispatcher.start({"type": "invoke", "invocationId": "e1", "function": "fs_created", "trigger": "firestore", "event": event()})
    writer.result("e1")
    assert os.environ["FUNCTION_SIGNATURE_TYPE"] == "cloudevent"
    seen = json.loads(get(client, "/demo-proj/us-central1/hello").get_data())
    assert (seen["function_target"], seen["function_signature_type"], seen["k_service"]) == ("hello", "http", "hello")


# --- task queue and blocking Auth functions (slice 2b) -------------------------------------------------

import base64  # noqa: E402
import time  # noqa: E402

BLOCK = "providers/cloud.auth/eventTypes/user."


def post(client, name, body, headers=None, region="us-central1"):
    return client.open(
        f"/demo-proj/{region}/{name}",
        buffered=True,
        method="POST",
        data=json.dumps(body),
        headers={"x-fireemu-runner-secret": SECRET, "content-type": "application/json", **(headers or {})},
    )


def test_a_task_queue_function_is_served_at_its_name_with_the_callable_body_format(client):
    response = post(client, "tk_echo", {"data": {"n": 1}}, headers={"x-cloudtasks-queuename": "tk_echo"})
    assert response.status_code == 200
    assert json.loads(response.get_data()) == {"result": {"echo": {"n": 1}}}


def test_a_task_queue_function_that_raises_an_https_error_answers_its_status(client):
    response = post(client, "tk_refuse", {"data": None})
    assert response.status_code == 400
    assert json.loads(response.get_data())["error"]["status"] == "FAILED_PRECONDITION"


def test_a_task_queue_function_rejects_a_body_that_is_not_the_callable_format(client):
    response = post(client, "tk_echo", {"nothing": 1})
    assert response.status_code == 400
    assert json.loads(response.get_data())["error"]["status"] == "INVALID_ARGUMENT"


def test_a_task_or_blocking_function_is_only_served_in_its_own_region(client):
    for name in ("tk_echo", "bc_user"):
        assert post(client, name, {"data": {}}, region="europe-west1").status_code == 404


def test_the_task_and_blocking_routes_need_the_runner_secret_too(client):
    for name in ("tk_echo", "bc_user"):
        response = client.open(f"/demo-proj/us-central1/{name}", method="POST", data="{}", headers={"content-type": "application/json"}, buffered=True)
        assert response.status_code == 403


def test_the_identity_variables_name_the_task_or_blocking_function_as_an_http_function(client, monkeypatch):
    for name in ("FUNCTION_TARGET", "FUNCTION_SIGNATURE_TYPE", "K_SERVICE"):
        monkeypatch.delenv(name, raising=False)
    post(client, "tk_echo", {"data": 1})
    assert (os.environ["FUNCTION_TARGET"], os.environ["FUNCTION_SIGNATURE_TYPE"], os.environ["K_SERVICE"]) == ("tk_echo", "http", "tk_echo")
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9")
    post(client, "bc_user", {"data": {"jwt": blocking_token("beforeCreate", "plain@example.com")}})
    assert (os.environ["FUNCTION_TARGET"], os.environ["FUNCTION_SIGNATURE_TYPE"], os.environ["K_SERVICE"]) == ("bc_user", "http", "bc_user")


def _segment(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def blocking_token(kind, email, uid="uid-1", provider="password"):
    """The unsigned token the daemon sends (`blocking_auth_claims` in crates/fireemu/src/functions.rs)."""
    now = int(time.time())
    millis = str(now * 1000)
    claims = {
        "iss": "https://securetoken.google.com/demo-proj",
        "aud": "http://127.0.0.1:1/demo-proj/us-central1/f",
        "iat": now,
        "exp": now + 70,
        "event_id": "fireemu-blocking-1",
        "event_type": BLOCK + kind,
        "user_agent": "ua",
        "ip_address": "127.0.0.1",
        "locale": "en",
        "sub": uid,
        "email": email,
        "sign_in_method": provider,
        "user_record": {
            "uid": uid,
            "email": email,
            "email_verified": False,
            "disabled": False,
            "metadata": {"creation_time": millis, "last_sign_in_time": millis},
            "provider_data": [],
            "custom_claims": None,
        },
    }
    return _segment({"alg": "none", "typ": "JWT"}) + "." + _segment(claims) + "."


def blocking(client, name, kind, email, **extra):
    return post(client, name, {"data": {"jwt": blocking_token(kind, email, **extra)}})


@pytest.fixture
def emulated_auth(monkeypatch):
    # The SDK checks the token's signature unless the Auth emulator is configured, as the daemon configures it.
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9")


def test_a_blocking_function_with_no_decision_answers_an_empty_object(client, emulated_auth):
    response = blocking(client, "bc_user", "beforeCreate", "plain@example.com")
    assert (response.status_code, json.loads(response.get_data())) == (200, {})


def test_a_blocking_function_that_changes_the_user_answers_the_update_payload(client, emulated_auth):
    response = blocking(client, "bc_user", "beforeCreate", "claims@example.com")
    body = json.loads(response.get_data())
    assert response.status_code == 200
    assert body["userRecord"]["displayName"] == "Renamed"
    assert json.loads(body["userRecord"]["customClaims"] if isinstance(body["userRecord"]["customClaims"], str) else json.dumps(body["userRecord"]["customClaims"])) == {"tier": "gold"}
    assert body["userRecord"]["updateMask"]


def test_a_blocking_function_that_refuses_answers_the_https_error(client, emulated_auth):
    response = blocking(client, "bc_user", "beforeCreate", "blocked@example.com")
    assert response.status_code == 403
    assert json.loads(response.get_data())["error"] == {"status": "PERMISSION_DENIED", "message": "no accounts for you"}


def test_a_sign_in_function_returns_session_claims(client, emulated_auth):
    response = blocking(client, "bs_user", "beforeSignIn", "s@example.com")
    assert response.status_code == 200
    assert "seen" in json.dumps(json.loads(response.get_data()))


def test_a_blocking_request_without_a_token_is_a_bad_request_and_the_handler_does_not_run(client, emulated_auth, discovered):
    before = len(discovered["bc_user"].__wrapped__.__globals__["SEEN"])
    for body in ({}, {"data": {}}, {"data": {"jwt": "not.a.token"}}):
        response = post(client, "bc_user", body)
        assert response.status_code >= 400
    assert len(discovered["bc_user"].__wrapped__.__globals__["SEEN"]) == before


def test_a_blocking_function_sees_the_user_the_token_names(client, emulated_auth, discovered):
    blocking(client, "bc_user", "beforeCreate", "who@example.com", uid="uid-who")
    entry = [e for e in discovered["bc_user"].__wrapped__.__globals__["SEEN"] if e["function"] == "bc_user"][-1]
    assert (entry["uid"], entry["email"], entry["ip"], entry["event_type"]) == ("uid-who", "who@example.com", "127.0.0.1", BLOCK + "beforeCreate")


# --- secrets (slice 2b) ------------------------------------------------------------------------------

import threading  # noqa: E402

from fireemu_runner.environment import EnvironmentGate  # noqa: E402

LOCAL = {"API_KEY": "key-value", "TOKEN": "token-value"}


@pytest.fixture
def secret_client(discovered, monkeypatch):
    for name in LOCAL:
        monkeypatch.delenv(name, raising=False)
    router = RunnerRouter(discovered, build_manifest(discovered), "demo-proj", SECRET, EnvironmentGate(LOCAL))
    return Client(router)


def env_of(response):
    return json.loads(response.get_data())["env"]


def test_an_http_function_sees_only_the_secrets_it_declares(secret_client):
    assert env_of(get(secret_client, "/demo-proj/us-central1/reads_key")) == {"API_KEY": "key-value", "TOKEN": None}
    assert env_of(get(secret_client, "/demo-proj/us-central1/reads_nothing")) == {"API_KEY": None, "TOKEN": None}


def test_a_secret_parameter_reads_its_value_inside_the_function(secret_client):
    body = json.loads(get(secret_client, "/demo-proj/us-central1/reads_token").get_data())
    assert body["param"] == "token-value" and body["env"] == {"API_KEY": None, "TOKEN": "token-value"}


def test_a_streamed_response_keeps_its_environment_until_it_is_finished(secret_client):
    # The body is produced after the view returned; a plain request must not run, or see the secret, before it ends.
    results = {}

    def stream():
        results["stream"] = get(secret_client, "/demo-proj/us-central1/streams_key").get_data(as_text=True)

    thread = threading.Thread(target=stream, daemon=True)
    thread.start()
    time.sleep(0.1)
    started = time.monotonic()
    plain = env_of(get(secret_client, "/demo-proj/us-central1/reads_nothing"))
    waited = time.monotonic() - started
    thread.join(10)
    assert plain == {"API_KEY": None, "TOKEN": None}
    assert waited > 0.15, "the plain request must wait for the streaming secret request"
    assert json.loads(results["stream"].removeprefix("first ")) == {"API_KEY": "key-value", "TOKEN": None}


def test_a_plain_request_does_not_wait_for_another_plain_request(secret_client):
    results = []

    def slow():
        results.append(get(secret_client, "/demo-proj/us-central1/reads_nothing?hold=0.5"))

    thread = threading.Thread(target=slow, daemon=True)
    thread.start()
    time.sleep(0.1)
    started = time.monotonic()
    get(secret_client, "/demo-proj/us-central1/reads_nothing")
    assert time.monotonic() - started < 0.3
    thread.join(10)


def test_a_failing_secret_function_frees_the_gate(secret_client):
    # `boom` declares nothing, so use the callable that raises with a declared secret through a broken stand-in.
    gate = EnvironmentGate(LOCAL)

    def broken(request):
        raise RuntimeError("boom")

    broken.__firebase_endpoint__ = None
    manifest = {"functions": [{"name": "broken", "entryPoint": "broken", "region": "us-central1", "trigger": {"type": "http"}, "platformOptions": {"secrets": ["API_KEY"]}}]}
    router = RunnerRouter({"broken": broken}, manifest, "demo-proj", SECRET, gate)
    client = Client(router)
    assert get(client, "/demo-proj/us-central1/broken").status_code == 500
    with gate.hold(["API_KEY"]):
        assert os.environ["API_KEY"] == "key-value"
    assert "API_KEY" not in os.environ


def test_a_router_without_a_gate_leaves_the_environment_alone(discovered, monkeypatch):
    monkeypatch.setenv("API_KEY", "process-value")
    client = Client(RunnerRouter(discovered, build_manifest(discovered), "demo-proj", SECRET))
    assert env_of(get(client, "/demo-proj/us-central1/reads_nothing"))["API_KEY"] == "process-value"


# --- an empty runner secret is a configuration error, as in the Node runner (Codex r1 on slice 2b) --------------


@pytest.mark.parametrize("presented", [None, "", "anything"])
def test_a_router_with_no_secret_refuses_every_request_instead_of_accepting_an_empty_one(discovered, presented):
    client = Client(RunnerRouter(discovered, build_manifest(discovered), "demo-proj", ""))
    headers = {} if presented is None else {"x-fireemu-runner-secret": presented}
    for path in ("/demo-proj/us-central1/hello", "/nowhere"):
        response = client.open(path, headers=headers, buffered=True)
        assert response.status_code == 500
        assert response.get_data(as_text=True) == "FIREEMU_RUNNER_SECRET is required"


# --- the refusal table: an error code in a task queue or blocking function becomes this HTTP status --------------

STATUS_OF_CODE = {
    "cancelled": 499,
    "unknown": 500,
    "invalid-argument": 400,
    "deadline-exceeded": 504,
    "not-found": 404,
    "already-exists": 409,
    "permission-denied": 403,
    "resource-exhausted": 429,
    "failed-precondition": 400,
    "aborted": 409,
    "out-of-range": 400,
    "unimplemented": 501,
    "internal": 500,
    "unavailable": 503,
    "data-loss": 500,
    "unauthenticated": 401,
}
CANONICAL_NAME = {code: code.upper().replace("-", "_") for code in STATUS_OF_CODE}


@pytest.mark.parametrize("code, status", sorted(STATUS_OF_CODE.items()))
def test_a_task_queue_function_that_refuses_with_a_code_answers_that_codes_status(client, code, status):
    response = post(client, "tk_code", {"data": {"code": code}})
    body = json.loads(response.get_data())
    assert response.status_code == status
    assert body["error"] == {"status": CANONICAL_NAME[code], "message": "refused with " + code}


@pytest.mark.parametrize("code, status", sorted(STATUS_OF_CODE.items()))
def test_a_blocking_function_that_refuses_with_a_code_answers_that_codes_status(client, emulated_auth, code, status):
    response = blocking(client, "bc_user", "beforeCreate", f"code:{code}@example.com")
    body = json.loads(response.get_data())
    assert response.status_code == status
    assert body["error"] == {"status": CANONICAL_NAME[code], "message": "refused with " + code}


def test_the_table_covers_every_code_the_sdk_knows():
    from firebase_functions import https_fn

    assert {code.value for code in https_fn.FunctionsErrorCode} - {"ok"} == set(STATUS_OF_CODE)


def test_the_sdk_itself_refuses_a_reserved_claim_name(client, emulated_auth):
    response = blocking(client, "bc_user", "beforeCreate", "reserved@example.com")
    assert response.status_code == 400 and json.loads(response.get_data())["error"]["status"] == "INVALID_ARGUMENT"


def test_a_sub_claim_passes_the_sdk_and_the_runner_adds_nothing_to_the_payload(client, emulated_auth):
    # The SDK permits `sub`; the daemon gives the protocol's own claim precedence when it assembles the token
    # (tested end to end in e2e.py).
    response = blocking(client, "bc_user", "beforeCreate", "subclaim@example.com")
    body = json.loads(response.get_data())
    assert response.status_code == 200 and "someone-else" in json.dumps(body)


def test_the_sdk_itself_refuses_an_oversized_claims_payload(client, emulated_auth):
    response = blocking(client, "bc_user", "beforeCreate", "oversized@example.com")
    assert response.status_code == 400 and json.loads(response.get_data())["error"]["status"] == "INVALID_ARGUMENT"
