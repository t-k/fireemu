"""The HTTP request a CloudEvent function runs inside.

functions-framework serves a CloudEvent function from a Flask view and calls the function inside the request context, so
`flask.request` shows the delivered request. Production's raw twins were recorded on 2026-11-04 (sandbox run
PYCHECK-EVENTS-20261104-01): `POST /` with the binary-mode `ce-*` headers, `content-type`, `content-length` and, in the strict
profile, constants every recorded frame carries (the sender's user agent, the encodings, the protocol) plus Cloud Run's plain
`traceparent` header. The body is the text the delivery had, not a re-encoding of the event: the layouts recorded per family are in
`bodies.py` (strict Pub/Sub and Storage; Eventarc keeps the publisher's text), and the emulator and unset profiles carry the framed JSON value text
of the data as the daemon sent it (a publisher's surrounding white space is trimmed upstream; a Pub/Sub body is the exception, it gets the SDK's snake-case aliases and is rewritten compactly). A Realtime Database body was not recorded. Header policy: a name that is not an HTTP token (or has an underscore) is
left out of the request, a control character other than TAB in a value becomes a space, and of two names that differ only in case the first one
is the header; the event the function receives is never changed by the view. The OIDC `Authorization`, `Forwarded`, `X-Forwarded-For`, `Function-Execution-Id`, `X-Cloud-Trace-Context`,
`From`, `Accept` and the Cloud Run host have no local source and are not invented.
"""

import contextlib
import re

import flask
from werkzeug.test import EnvironBuilder

from .events import is_strict

_APP = flask.Flask("fireemu-cloudevent")
# What an HTTP header may be called: a token without an underscore. Header names with an underscore are dropped by the usual
# servers, and Werkzeug folds `foo_bar` into `foo-bar`; both are UNRECORDED, so such an attribute stays out of the request
# (the event keeps it).
_HEADER_NAME = re.compile(r"[!#$%&'*+.^`|~0-9A-Za-z-]+")
# A control character other than the tab cannot be in a header value; it becomes a space, as a line break does.
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
# Constant in every recorded Eventarc delivery (the four raw twins of run 57ab27296dedaedc).
_STRICT_CONSTANTS = {
    "user-agent": "APIs-Google; (+https://developers.google.com/webmasters/APIs-Google.html)",
    "accept-encoding": "gzip, deflate, br",
    "x-forwarded-proto": "https",
}


def request_headers(headers: dict, event: dict) -> dict:
    """The headers of the request: the event's binary-mode headers, and in the strict profile the recorded constants and the
    trace context as the plain `traceparent` header.

    The request is what a server would have received, so a name that is not a header name is left out, and when two names
    differ only in case the first one stays. A control character in a value other than the tab, a line break included, is
    replaced by a space. The event the function receives keeps every attribute and its text.
    """
    view = {}
    taken = set()
    for name, value in headers.items():
        if _HEADER_NAME.fullmatch(name) and name.lower() not in taken:
            taken.add(name.lower())
            view[name] = _CONTROL.sub(" ", value)
    if is_strict():
        view.update(_STRICT_CONSTANTS)
        traceparent = event.get("traceparent")
        if isinstance(traceparent, str):
            view["traceparent"] = _CONTROL.sub(" ", traceparent)
    return view


@contextlib.contextmanager
def delivery_request(headers: dict, body: bytes, event: dict):
    """Runs the block inside the Flask request context of the delivery described by `headers` and `body`."""
    environ = EnvironBuilder(method="POST", path="/", headers=request_headers(headers, event), data=body).get_environ()
    with _APP.request_context(environ):
        yield
