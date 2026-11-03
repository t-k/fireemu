"""The router in front of the Flask app, driven in process with Werkzeug's test client."""

import json
import os

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
    return client.open(path, headers=headers, **kwargs)


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
