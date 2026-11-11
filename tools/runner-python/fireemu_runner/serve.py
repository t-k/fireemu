"""The HTTP server for `onRequest`, `onCall`, task queue and Auth blocking functions.

The daemon proxies `/<project>/<region>/<name>/...` here with the `x-fireemu-runner-secret` header
(`crates/fireemu-adapter-functions/src/http.rs`, `tools/runner-node/http-admission.mjs`). The
function sees the path below its mount point, as it does in production, and answers through the same
`flask.Request` handlers the SDK wraps. An unhandled error is functions-framework's crash response.
"""

import contextlib
import hmac
import os
import sys

import flask
from functions_framework import crash_handler, read_request
from werkzeug.serving import WSGIRequestHandler, make_server

from .diagnostics import ASYNC_HANDLER, describe, is_async_handler
from .environment import EnvironmentGate
from .manifest import DEFAULT_REGION

SECRET_ENVIRON_KEY = "HTTP_X_FIREEMU_RUNNER_SECRET"
# Task queue and Auth blocking functions enter through the HTTP wrapper as well (the Node runner's `signatureType`).
HTTP_TRIGGERS = frozenset(("http", "tasks", "blockingAuth"))
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


class ResponseBodyFailed(Exception):
    """A response body failed while it was being sent. The details were logged inside the function's environment."""


def _log_failure(name: str, error: BaseException) -> None:
    diagnostic, _ = describe(error)
    sys.stderr.write(f"[functions] {name}: {diagnostic[:8192]}\n")


class _HeldBody:
    """A response body that keeps its function's environment until the body is finished, whatever happens to it.

    Closing the body, and running the callbacks `Response.call_on_close` registered, is user code: if it raises the
    gate must still be released, or the process is locked with a secret in its environment. Errors are described
    here, while the environment is still held, and the server sees only a plain exception.
    """

    def __init__(self, body, held: contextlib.ExitStack, name: str):
        self._body = body
        self._iterator = iter(body)
        self._held = held
        self._name = name

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self._iterator)
        except StopIteration:
            raise
        except BaseException as error:
            _log_failure(self._name, error)
            raise ResponseBodyFailed(type(error).__name__) from None

    def close(self):
        try:
            close = getattr(self._body, "close", None)
            if close is not None:
                close()
        except BaseException as error:  # the response has been sent; there is nobody to tell but the log
            _log_failure(self._name, error)
        finally:
            self._held.close()


class RunnerRouter:
    """Admission and routing in front of the Flask app."""

    def __init__(
        self,
        functions: dict,
        manifest: dict,
        project: str,
        secret: str,
        gate: EnvironmentGate | None = None,
        fixed_identity: bool = False,
    ):
        self._app = _flask_app()
        self._fixed_identity = fixed_identity
        self._gate = gate if gate is not None else EnvironmentGate({})
        self._project = project
        self._secret = secret.encode()
        self._routes = {}
        for spec in manifest["functions"]:
            if spec["trigger"]["type"] in HTTP_TRIGGERS:
                self._routes[spec["name"]] = (
                    spec.get("region", DEFAULT_REGION),
                    functions[spec["entryPoint"]],
                    spec["entryPoint"],
                    spec.get("platformOptions", {}).get("secrets"),
                )

    @staticmethod
    def _plain(start_response, status: str, text: str):
        body = text.encode()
        start_response(status, [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body)))])
        return [body]

    def __call__(self, environ, start_response):
        presented = environ.pop(SECRET_ENVIRON_KEY, "").encode()
        if not self._secret:
            # A runner with no secret would accept any request without the header (an empty value equals an empty
            # secret). The Node runner answers every request this way (`http-admission.mjs`).
            return self._plain(start_response, "500 Internal Server Error", "FIREEMU_RUNNER_SECRET is required")
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
        if is_async_handler(route[1]):
            # Production answers 500 as well (the coroutine is not a response); this says why.
            sys.stderr.write(f"[functions] {name}: {ASYNC_HANDLER}\n")
            return self._plain(start_response, "500 Internal Server Error", ASYNC_HANDLER)
        # The environment this function is entitled to is held until its response is finished, a streamed body
        # included: the secrets it declares are in the process environment for exactly that long.
        held = contextlib.ExitStack()
        held.enter_context(self._gate.hold(route[3]))
        try:
            if not self._fixed_identity:
                # The variables a production instance has from its start name the function it serves. One process
                # serves the whole codebase here, so they name the call that started most recently, as for events.
                # A dedicated runner has them from its spawn.
                os.environ["FUNCTION_TARGET"] = route[2]
                os.environ["FUNCTION_SIGNATURE_TYPE"] = "http"
                os.environ["K_SERVICE"] = name
            body = self._app(environ, start_response)
        except BaseException as error:
            _log_failure(name, error)
            held.close()
            raise ResponseBodyFailed(type(error).__name__) from None
        return _HeldBody(body, held, name)


class _QuietHandler(WSGIRequestHandler):
    def log_request(self, *args, **kwargs):  # the daemon logs requests; the runner's stderr is for user output
        pass


def start_server(functions: dict, manifest: dict, secret: str, gate: EnvironmentGate | None = None, fixed_identity: bool = False):
    """Starts the server on a free loopback port; returns `(server, port)`."""
    router = RunnerRouter(functions, manifest, os.environ.get("GCLOUD_PROJECT", ""), secret, gate, fixed_identity)
    server = make_server("127.0.0.1", 0, router, threaded=True, request_handler=_QuietHandler)
    import threading

    threading.Thread(target=server.serve_forever, daemon=True, name="http").start()
    return server, server.server_port
