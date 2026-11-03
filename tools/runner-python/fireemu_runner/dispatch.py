"""Invocation frames: checked against the manifest, run on their own thread, answered with a result."""

import os
import threading
import traceback

from .events import (
    database_cloud_event,
    eventarc_cloud_event,
    firestore_cloud_event,
    pubsub_cloud_event,
    storage_cloud_event,
)
from .environment import EnvironmentGate
from .framing import FrameWriter
from .scheduler import SchedulerFailure, deliver_schedule

MAX_ACTIVE_INVOCATIONS = 4096
_MAX_ERROR_CHARS = 4096
_MAX_DIAGNOSTIC_CHARS = 256 * 1024

# Trigger types that arrive as an `invoke` frame whose function takes a CloudEvent, and the adapter that builds it.
_CLOUD_EVENTS = {
    "firestore": firestore_cloud_event,
    "pubsub": pubsub_cloud_event,
    "storage": storage_cloud_event,
    "eventarc": eventarc_cloud_event,
    "database": database_cloud_event,
}
# A Gen2 scheduled function is an HTTP function: the SDK wrapper takes the scheduler's request.
_TRIGGERS = frozenset((*_CLOUD_EVENTS, "schedule"))


def _deliver(trigger: str, function, event) -> None:
    if trigger == "schedule":
        deliver_schedule(function, event.get("data") if isinstance(event, dict) else None)
    else:
        function(_CLOUD_EVENTS[trigger](event))


# What `FUNCTION_SIGNATURE_TYPE` says for each (the Node runner's `signatureType`).
_SIGNATURE_TYPES = {"schedule": "http"}


def _bound(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Dispatcher:
    """Runs `invoke` frames against the functions the manifest serves."""

    def __init__(self, functions: dict, manifest: dict, writer: FrameWriter, gate: EnvironmentGate | None = None):
        self._gate = gate if gate is not None else EnvironmentGate({})
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

    def _run(self, message: dict) -> None:
        invocation = message["invocationId"]
        try:
            try:
                spec, function = self._check(message)
                with self._gate.hold(spec.get("platformOptions", {}).get("secrets")):
                    # One process serves the whole codebase, so these name the invocation that started most
                    # recently, not a fixed target (the design memo, section 5).
                    os.environ["FUNCTION_TARGET"] = spec["entryPoint"]
                    os.environ["FUNCTION_SIGNATURE_TYPE"] = _SIGNATURE_TYPES.get(message["trigger"], "cloudevent")
                    os.environ["K_SERVICE"] = spec["name"]
                    _deliver(message["trigger"], function, message["event"])
                result = {"type": "result", "invocationId": invocation, "ok": True}
            except BaseException as error:  # a SystemExit in user code must still answer the daemon
                # A scheduled attempt the SDK wrapper answered 500 has been logged by the SDK; its status is the news.
                diagnostic = str(error) if isinstance(error, SchedulerFailure) else "".join(traceback.format_exception(error))
                self._send_log("error", f"{message['function']}: {diagnostic}", invocation, message["function"])
                text = str(error) or type(error).__name__
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
