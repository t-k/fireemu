"""Observation fixture for the Cloud Tasks family of the Python Functions sandbox check, second recording.

The two Cloud Tasks functions of fixture/main.py under task queue names this project has never used (the queue name is the
function name, and a deleted queue name cannot be created again for up to three days). Every helper below is the helper of
fixture/main.py, byte for byte, and the two functions are the `pctask` and `pctaskraw` of that file under their new names
(`tasks-profile.test.mjs` compares them), so the frames and the judgement are the ones of the first recording.

Every function prints one line `PYCHECK_FRAME <json>` per delivery and nothing else: what it was given, as the SDK shows it
(the `sdk` members) or as the request reached it (the `raw` members). Cloud Logging carries the lines to the recorder.
Nothing here writes to any service, and no credential or token value is printed: `Authorization` is reduced to its scheme and
segment count, and every header outside a short list keeps only its name.
"""

import base64
import dataclasses
import datetime
import importlib.metadata
import json
import re

import flask
from firebase_functions import tasks_fn
from firebase_functions.options import RetryConfig

MARK = "PYCHECK_FRAME "
RUN_PATTERN = re.compile(r"pcrun-[0-9a-f]{16}")
PACKAGES = ("firebase-functions", "functions-framework", "cloudevents", "flask", "werkzeug", "google-events", "protobuf", "firebase-admin", "PyJWT", "gunicorn")
SHOWN_HEADERS = ("content-type", "content-length", "user-agent", "host", "accept-encoding", "x-forwarded-proto")
SHOWN_PREFIXES = ("ce-", "x-cloudscheduler", "x-cloudtasks-", "x-goog-")
MAX_TEXT = 8192
MAX_BYTES = 16384


def _versions():
    found = {}
    for name in PACKAGES:
        try:
            found[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            found[name] = None
    return found


def _run_of(*parts):
    for part in parts:
        match = RUN_PATTERN.search(json.dumps(part, default=str, sort_keys=True))
        if match:
            return match.group(0)
    return None


def _emit(function, kind, run, **members):
    frame = {
        "function": function,
        "kind": kind,
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "run": run,
        "versions": _versions(),
        **members,
    }
    print(MARK + json.dumps(frame, sort_keys=True, default=str), flush=True)


def _request_view():
    """What the request carried, or None outside a request (the emulator's event path has none)."""
    if not flask.has_request_context():
        return None
    request = flask.request
    headers = {name.lower(): value for name, value in request.headers.items()}
    authorization = headers.get("authorization")
    shown = {
        name: value
        for name, value in headers.items()
        if name in SHOWN_HEADERS or name.startswith(SHOWN_PREFIXES)
    }
    body = request.get_data()
    view = {
        "method": request.method,
        "path": request.path,
        "header_names": sorted(headers),
        "headers": shown,
        "authorization": None
        if authorization is None
        else {"scheme": authorization.split(" ", 1)[0], "segments": len(authorization.split(" ", 1)[-1].split("."))},
        "body_length": len(body),
        "body_text": body.decode("utf-8", "replace")[:MAX_TEXT] if _is_text(headers.get("content-type", "")) else None,
        "body_base64": base64.b64encode(body[:MAX_BYTES]).decode() if not _is_text(headers.get("content-type", "")) else None,
    }
    return view


def _is_text(content_type):
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "application/json" or media.startswith("text/") or media.endswith("+json")


# ---- raw functions: the delivery before the SDK parses it ----------------------------------------------------


def _raw_request(name):
    def observe(request):
        body = request.get_data(as_text=True)
        view = _request_view()
        _emit(name, "raw-request", _run_of(body), request=view)
        return flask.make_response("", 200)

    return observe


def _with_trigger(name, prototype, observe):
    """`observe` registered under `name` with the trigger of the SDK function `prototype`."""
    observe.__name__ = name
    observe.__firebase_endpoint__ = dataclasses.replace(prototype.__firebase_endpoint__, entryPoint=name)
    required = getattr(prototype, "__required_apis", None)
    if required is not None:
        setattr(observe, "__required_apis", required)
    return observe


def _prototype(decorator):
    def stand_in(event):
        return None

    return decorator(stand_in)


_PROTOTYPES = {
    "task": _prototype(tasks_fn.on_task_dispatched(retry_config=RetryConfig(max_attempts=1), region="us-central1")),
}

pc3taskraw = _with_trigger("pc3taskraw", _PROTOTYPES["task"], _raw_request("pc3taskraw"))


# ---- SDK functions: what the SDK's own wrappers hand the handler ------------------------------------------------


@tasks_fn.on_task_dispatched(retry_config=RetryConfig(max_attempts=1), region="us-central1")
def pc3task(request):
    _emit("pc3task", "sdk-event", _run_of(request.data), data=request.data, has_auth=request.auth is not None, has_app=request.app is not None)
    return {"ok": True}
