"""Invocation frames: checked against the manifest, run on their own thread, answered with a result."""

import os
import threading

from cloudevents.http import from_http

from .events import database_request, eventarc_request, firestore_request, pubsub_request, storage_request
from .request_view import delivery_request
from .diagnostics import ASYNC_HANDLER, describe, is_async_handler
from .environment import EnvironmentGate
from .framing import FrameWriter
from .scheduler import SchedulerFailure, deliver_schedule

MAX_ACTIVE_INVOCATIONS = 4096
_MAX_ERROR_CHARS = 4096
_MAX_DIAGNOSTIC_CHARS = 256 * 1024

# Trigger types that arrive as an `invoke` frame whose function takes a CloudEvent, and the adapter that builds the request
# (headers and body) that delivers it.
_CLOUD_EVENTS = {
    "firestore": firestore_request,
    "pubsub": pubsub_request,
    "storage": storage_request,
    "eventarc": eventarc_request,
    "database": database_request,
}
# A Gen2 scheduled function is an HTTP function: the SDK wrapper takes the scheduler's request.
_TRIGGERS = frozenset((*_CLOUD_EVENTS, "schedule"))


def _deliver(trigger: str, function, event, raw_data: str | None = None) -> None:
    if trigger == "schedule":
        deliver_schedule(function, event.get("data") if isinstance(event, dict) else None)
    else:
        delivery = _CLOUD_EVENTS[trigger](event, raw_data)
        # As functions-framework does: the function runs inside the request that delivers the event. The event is built
        # from the encoding the adapters have always used; the request shows the layout the recorded delivery had.
        with delivery_request(delivery.headers, delivery.request_body, event):
            function(from_http(delivery.headers, delivery.event_body))


# What `FUNCTION_SIGNATURE_TYPE` says for each (the Node runner's `signatureType`).
_SIGNATURE_TYPES = {"schedule": "http"}


def _bound(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Dispatcher:
    """Runs `invoke` frames against the functions the manifest serves."""

    def __init__(
        self,
        functions: dict,
        manifest: dict,
        writer: FrameWriter,
        gate: EnvironmentGate | None = None,
        fixed_identity: bool = False,
    ):
        self._gate = gate if gate is not None else EnvironmentGate({})
        self._fixed_identity = fixed_identity
        self._functions = functions
        self._specs = {spec["name"]: spec for spec in manifest["functions"]}
        self._writer = writer
        self._active = 0
        self._lock = threading.Lock()

    def _check(self, message: dict) -> tuple[dict, object]:
        spec = self._specs.get(message["function"])
        if spec is None:
            raise LookupError("unknown function")
        if "entryPoint" in message and message["entryPoint"] != spec["entryPoint"]:
            raise LookupError("entry point does not match the function manifest")
        trigger = spec["trigger"]["type"]
        if message["trigger"] != trigger or trigger not in _TRIGGERS:
            raise LookupError("trigger does not match the function manifest")
        function = self._functions.get(spec["entryPoint"])
        if not callable(function):
            raise LookupError("missing function entry point")
        return spec, function

    def reserve(self) -> bool:
        with self._lock:
            if self._active >= MAX_ACTIVE_INVOCATIONS:
                return False
            self._active += 1
            return True

    def start(self, message: dict) -> None:
        """Runs one invoke frame on a new thread; the caller has reserved a slot with `reserve`."""
        threading.Thread(target=self._run, args=(message,), daemon=True, name=f"invoke-{message['invocationId']}").start()

    def _deliver_held(self, message: dict) -> tuple[str, str] | None:
        """Runs the invocation and returns `(diagnostic, text)` of its failure, or None.

        The failure is described here, inside the gate: turning an exception into text can run user code
        (`__str__`), and after the invocation leaves the gate another invocation's secrets may be present.
        """
        try:
            spec, function = self._check(message)
        except BaseException as error:  # not user code, but a malformed frame: still answered, never raised
            return describe(error)
        if is_async_handler(function):
            return ASYNC_HANDLER, ASYNC_HANDLER
        with self._gate.hold(spec.get("platformOptions", {}).get("secrets")):
            try:
                if not self._fixed_identity:
                    # One process serves the whole codebase, so these name the invocation that started most
                    # recently, not a fixed target (the design memo, section 5). A dedicated runner has them from
                    # its spawn.
                    os.environ["FUNCTION_TARGET"] = spec["entryPoint"]
                    os.environ["FUNCTION_SIGNATURE_TYPE"] = _SIGNATURE_TYPES.get(message["trigger"], "cloudevent")
                    os.environ["K_SERVICE"] = spec["name"]
                _deliver(message["trigger"], function, message["event"], message.get("rawEventData"))
            except BaseException as error:  # a SystemExit in user code must still answer the daemon
                diagnostic, text = describe(error)
                # A scheduled attempt the SDK wrapper answered 500 has been logged by the SDK; its status is the news.
                return (str(error) if isinstance(error, SchedulerFailure) else diagnostic), text
        return None

    def _run(self, message: dict) -> None:
        invocation = message["invocationId"]
        try:
            failure = self._deliver_held(message)
            if failure is None:
                result = {"type": "result", "invocationId": invocation, "ok": True}
            else:
                diagnostic, text = failure
                self._send_log("error", f"{message['function']}: {diagnostic}", invocation, message["function"])
                result = {"type": "result", "invocationId": invocation, "ok": False, "error": _bound(text, _MAX_ERROR_CHARS)}
            self._writer.write(result)
        finally:
            with self._lock:
                self._active -= 1

    def _send_log(self, level: str, text: str, invocation: str, function: str) -> None:
        try:
            self._writer.write(
                {
                    "type": "log",
                    "level": level,
                    "message": _bound(text, _MAX_DIAGNOSTIC_CHARS),
                    "invocationId": invocation,
                    "functionName": function,
                    "user": False,
                }
            )
        except Exception:  # a diagnostic can never suppress the result
            pass
