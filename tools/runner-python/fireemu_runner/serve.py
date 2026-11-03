"""The HTTP server for `onRequest` and `onCall` functions.

The daemon proxies `/<project>/<region>/<name>/...` here with the `x-fireemu-runner-secret` header
(`crates/fireemu-adapter-functions/src/http.rs`, `tools/runner-node/http-admission.mjs`). The
function sees the path below its mount point, as it does in production, and answers through the same
`flask.Request` handlers the SDK wraps. An unhandled error is functions-framework's crash response.
"""

import hmac
import os

import flask
from functions_framework import crash_handler, read_request
from werkzeug.serving import WSGIRequestHandler, make_server

from .manifest import DEFAULT_REGION

SECRET_ENVIRON_KEY = "HTTP_X_FIREEMU_RUNNER_SECRET"
_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


def _flask_app() -> flask.Flask:
    app = flask.Flask("fireemu-runner")
    app.register_error_handler(500, crash_handler)
    app.after_request(read_request)

    def run(path):
        return flask.request.environ["fireemu.function"](flask.request._get_current_object())

    # "OPTIONS" is listed so that Flask does not answer a callable's preflight itself.
    app.add_url_rule("/", endpoint="run", view_func=run, defaults={"path": ""}, methods=_METHODS)
    app.add_url_rule("/<path:path>", endpoint="run", view_func=run, methods=_METHODS)
    return app


class RunnerRouter:
    """Admission and routing in front of the Flask app."""

    def __init__(self, functions: dict, manifest: dict, project: str, secret: str):
        self._app = _flask_app()
        self._project = project
        self._secret = secret.encode()
        self._routes = {}
        for spec in manifest["functions"]:
            if spec["trigger"]["type"] == "http":
                self._routes[spec["name"]] = (spec.get("region", DEFAULT_REGION), functions[spec["entryPoint"]])

    @staticmethod
    def _plain(start_response, status: str, text: str):
        body = text.encode()
        start_response(status, [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body)))])
        return [body]

    def __call__(self, environ, start_response):
        presented = environ.pop(SECRET_ENVIRON_KEY, "").encode()
        if not hmac.compare_digest(presented, self._secret):
            return self._plain(start_response, "403 Forbidden", "forbidden")
        parts = environ.get("PATH_INFO", "").split("/")
        # ["", project, region, name, *rest]
        if len(parts) < 4 or parts[0] != "" or parts[1] != self._project:
            return self._plain(start_response, "404 Not Found", "no HTTP function")
        region, name = parts[2], parts[3]
        route = self._routes.get(name)
        if route is None or route[0] != region:
            return self._plain(start_response, "404 Not Found", f"no HTTP function {parts[1]}/{region}/{name}")
        environ["SCRIPT_NAME"] = environ.get("SCRIPT_NAME", "") + "/".join(parts[:4])
        environ["PATH_INFO"] = "/" + "/".join(parts[4:])
        environ["fireemu.function"] = route[1]
        return self._app(environ, start_response)


class _QuietHandler(WSGIRequestHandler):
    def log_request(self, *args, **kwargs):  # the daemon logs requests; the runner's stderr is for user output
        pass


def start_server(functions: dict, manifest: dict, secret: str):
    """Starts the server on a free loopback port; returns `(server, port)`."""
    router = RunnerRouter(functions, manifest, os.environ.get("GCLOUD_PROJECT", ""), secret)
    server = make_server("127.0.0.1", 0, router, threaded=True, request_handler=_QuietHandler)
    import threading

    threading.Thread(target=server.serve_forever, daemon=True, name="http").start()
    return server, server.server_port
