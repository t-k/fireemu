"""The HTTP request a CloudEvent function runs inside.

functions-framework serves a CloudEvent function from a Flask view and calls the function inside the request context, so
`flask.request` shows the delivered request. Production's raw twins were recorded on 2026-11-04 (sandbox run
PYCHECK-EVENTS-20261104-01): `POST /` with the binary-mode `ce-*` headers, `content-type`, `content-length` and, in the strict
profile, constants every recorded frame carries (the sender's user agent, the encodings, the protocol) plus Cloud Run's plain
`traceparent` header. The OIDC `Authorization`, `Forwarded`, `X-Forwarded-For`, `Function-Execution-Id`, `X-Cloud-Trace-Context`,
`From`, `Accept` and the Cloud Run host have no local source and are not invented.
"""

import contextlib
import re

import flask
from werkzeug.test import EnvironBuilder

from .events import is_strict

_APP = flask.Flask("fireemu-cloudevent")
_LINE_BREAK = re.compile(r"[\r\n]")
# Constant in every recorded Eventarc delivery (the four raw twins of run 57ab27296dedaedc).
_STRICT_CONSTANTS = {
    "user-agent": "APIs-Google; (+https://developers.google.com/webmasters/APIs-Google.html)",
    "accept-encoding": "gzip, deflate, br",
    "x-forwarded-proto": "https",
}


def request_headers(headers: dict, event: dict) -> dict:
    """The headers of the request: the event's binary-mode headers, and in the strict profile the recorded constants and the
    trace context as the plain `traceparent` header. A line break in a value is replaced by a space (an HTTP header cannot hold
    one); the event the function receives keeps its text."""
    view = {name: _LINE_BREAK.sub(" ", value) for name, value in headers.items()}
    if is_strict():
        view.update(_STRICT_CONSTANTS)
        traceparent = event.get("traceparent")
        if isinstance(traceparent, str):
            view["traceparent"] = _LINE_BREAK.sub(" ", traceparent)
    return view


@contextlib.contextmanager
def delivery_request(headers: dict, body: bytes, event: dict):
    """Runs the block inside the Flask request context of the delivery described by `headers` and `body`."""
    environ = EnvironBuilder(method="POST", path="/", headers=request_headers(headers, event), data=body).get_environ()
    with _APP.request_context(environ):
        yield
