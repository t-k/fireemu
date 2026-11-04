"""The endpoints the Python SDK declares, as fireemu's canonical manifest.

`firebase_functions.private.serving.get_functions()` returns the decorated functions, each with a
`__firebase_endpoint__` (the SDK's `ManifestEndpoint`, the same v1alpha1 endpoint schema the Node
SDK produces). This module is the Python counterpart of `describe()` in
`tools/runner-node/index.mjs`: it resolves option expressions, treats `None` and the SDK's reset
sentinel as unset, and maps each trigger to the daemon's `functions[]` entry
(`crates/fireemu-adapter-functions/src/manifest_json.rs`). A function it cannot serve is reported
under `ignored[]`, never dropped.
"""

import enum
import math
from typing import Any

from firebase_functions.params import Expression
from firebase_functions.private.util import Sentinel

DEFAULT_REGION = "us-central1"

_FIRESTORE_PREFIX = "google.cloud.firestore."
_PUBSUB_EVENT = "google.cloud.pubsub.topic.v1.messagePublished"
_STORAGE_EVENTS = frozenset(
    "google.cloud.storage.object.v1." + kind for kind in ("finalized", "deleted", "archived", "metadataUpdated")
)
_DATABASE_EVENTS = frozenset("google.firebase.database.ref.v1." + kind for kind in ("created", "updated", "deleted", "written"))
# Products the official emulator has a trigger service for and fireemu does not serve, matched on a substring of
# the event type as the Node runner does (`DEFERRED_TRIGGER_PRODUCTS` in `tools/runner-node/index.mjs`).
_UNSERVED_PRODUCTS = (
    ("remoteconfig", "remoteConfig", "deferred", "deferred: Remote Config has no emulator in the active supported surface"),
    ("dataconnect", "dataconnect", "deferred", "deferred: the Data Connect emulator is not in the active supported surface"),
    ("ailogic", "ai", "notPlanned", "not planned: Firebase AI Logic blocking triggers have no local emulator"),
    ("analytics", "analytics", "notPlanned", "not planned: Google Analytics triggers have no local emulator"),
    ("testing", "testLab", "notPlanned", "not planned: Test Lab triggers have no local emulator"),
)
_SCHEDULE_RETRY_FIELDS = frozenset(("retryCount", "maxRetrySeconds", "minBackoffSeconds", "maxBackoffSeconds", "maxDoublings"))
_TASK_RETRY_FIELDS = frozenset(("maxAttempts", "maxRetrySeconds", "minBackoffSeconds", "maxBackoffSeconds", "maxDoublings"))
_TASK_RATE_FIELDS = frozenset(("maxConcurrentDispatches", "maxDispatchesPerSecond"))
_BLOCKING_AUTH_EVENTS = ("beforeCreate", "beforeSignIn", "beforeSendEmail", "beforeSendSms")


class Unserved(Exception):
    """A function the runner reports under `ignored[]`."""

    def __init__(self, trigger_type: str, scope: str, reason: str):
        super().__init__(reason)
        self.trigger_type = trigger_type
        self.scope = scope
        self.reason = reason


def _unset(value: Any) -> bool:
    return value is None or isinstance(value, Sentinel)


def _resolved(value: Any, field: str) -> Any:
    """An option's concrete value, or None when it is unset. Expressions read their parameter."""
    if _unset(value):
        return None
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, Expression):
        resolved = value.value
        if resolved is None:
            raise Unserved("unknown", "unsupported", f"{field} expression did not resolve to a value")
        return resolved
    return value


def _non_negative_integer(value: Any, field: str):
    resolved = _resolved(value, field)
    if resolved is None:
        return None
    if isinstance(resolved, bool) or not isinstance(resolved, int) or resolved < 0:
        raise Unserved("unknown", "unsupported", f"{field} did not resolve to a non-negative integer")
    return resolved


def _first_region(endpoint) -> str | None:
    regions = _resolved(endpoint.region, "region")
    if regions is None:
        return None
    values = [_resolved(region, "region") for region in (regions if isinstance(regions, list) else [regions])]
    for value in values:
        if not isinstance(value, str) or not value:
            raise Unserved("unknown", "unsupported", "region did not resolve to a non-empty string")
    return values[0] if values else None


def _platform_options(endpoint) -> dict | None:
    options: dict[str, Any] = {}
    for field, key in (
        ("availableMemoryMb", "availableMemoryMb"),
        ("minInstances", "minInstances"),
        ("maxInstances", "maxInstances"),
    ):
        value = _non_negative_integer(getattr(endpoint, field), field)
        if value is not None:
            options[key] = value
    for field, key in (("ingressSettings", "ingressSettings"), ("serviceAccountEmail", "serviceAccountEmail")):
        value = _resolved(getattr(endpoint, field), field)
        if value is not None:
            options[key] = value
    invoker = (endpoint.httpsTrigger or {}).get("invoker") if isinstance(endpoint.httpsTrigger, dict) else None
    if invoker:
        options["invoker"] = invoker
    vpc = endpoint.vpc if isinstance(endpoint.vpc, dict) else None
    if vpc:
        if not _unset(vpc.get("connector")):
            options["vpcConnector"] = vpc["connector"]
        egress = _resolved(vpc.get("egressSettings"), "vpc.egressSettings")
        if egress is not None:
            options["vpcEgressSettings"] = egress
        if isinstance(vpc.get("networkInterfaces"), list):
            options["networkInterfaces"] = vpc["networkInterfaces"]
    if isinstance(endpoint.labels, dict) and endpoint.labels:
        options["labels"] = endpoint.labels
    cpu = _resolved(endpoint.cpu, "cpu")
    if cpu is not None:
        options["cpu"] = str(cpu)
    if isinstance(endpoint.secretEnvironmentVariables, list):
        secrets = [secret["key"] for secret in endpoint.secretEnvironmentVariables if secret.get("key")]
        if secrets:
            options["secrets"] = secrets
    return options or None


def _mapping(value) -> dict:
    return value if isinstance(value, dict) else {}


def _text(filters: dict, key: str, field: str, family: str, *, required: bool = False, allow_empty: bool = True):
    """A string filter, resolved. Absent is None (or an error when required); another type is an error."""
    value = _resolved(filters.get(key), field)
    if value is None and not required:
        return None
    if not isinstance(value, str) or (not allow_empty and not value):
        what = "a string" if allow_empty else "a non-empty string"
        raise Unserved(family, "unsupported", f"{field} did not resolve to {what}")
    return value


def _firestore_trigger(event_trigger: dict) -> dict:
    filters = _mapping(event_trigger.get("eventFilters"))
    patterns = _mapping(event_trigger.get("eventFilterPathPatterns"))
    # The SDK keeps a document path without wildcards in `eventFilters.document` and one with
    # wildcards in `eventFilterPathPatterns.document` (`options.py:1065-1075`).
    document = _text(patterns, "document", "eventFilterPathPatterns.document", "firestore") or _text(
        filters, "document", "eventFilters.document", "firestore"
    )
    if not document:
        raise Unserved("firestore", "unsupported", "the Firestore trigger names no document (eventFilters.document)")
    return {
        "type": "firestore",
        "eventType": event_trigger["eventType"],
        "database": _text(filters, "database", "eventFilters.database", "firestore") or "(default)",
        "document": document,
    }


def _pubsub_trigger(event_trigger: dict) -> dict:
    topic = _text(_mapping(event_trigger.get("eventFilters")), "topic", "eventFilters.topic", "pubsub", required=True, allow_empty=False)
    # A full resource name is reduced to the short name the daemon matches on.
    short = topic.rsplit("/topics/", 1)[-1] if "/topics/" in topic else topic
    if not short:
        raise Unserved("pubsub", "unsupported", "eventFilters.topic resolved to an empty topic")
    return {"type": "pubsub", "topic": short}


def _storage_trigger(event_trigger: dict, event_type: str) -> dict:
    bucket = _text(_mapping(event_trigger.get("eventFilters")), "bucket", "eventFilters.bucket", "storage")
    trigger = {"type": "storage", "eventType": event_type}
    if bucket is not None:
        trigger["bucket"] = bucket
    return trigger


def _database_trigger(event_trigger: dict, event_type: str) -> dict:
    filters = _mapping(event_trigger.get("eventFilters"))
    patterns = _mapping(event_trigger.get("eventFilterPathPatterns"))
    # The SDK keeps a reference without wildcards in `eventFilters` and one with wildcards in
    # `eventFilterPathPatterns`; the Node runner reads the patterns first as well.
    reference = _text(patterns, "ref", "eventFilterPathPatterns.ref", "database")
    if reference is None:
        reference = _text(filters, "ref", "eventFilters.ref", "database", required=True)
    instance = _text(patterns, "instance", "eventFilterPathPatterns.instance", "database")
    if instance is None:
        instance = _text(filters, "instance", "eventFilters.instance", "database")
    return {
        "type": "database",
        "eventType": event_type,
        "ref": "/" + reference.strip("/"),
        "instance": instance if instance is not None else "*",
    }


def _eventarc_trigger(event_trigger: dict, event_type: str, channel: str) -> dict:
    filters = _mapping(event_trigger.get("eventFilters"))
    return {
        "type": "eventarc",
        "eventType": event_type,
        "channel": channel,
        "filters": {key: _text(filters, key, f"eventFilters.{key}", "eventarc", required=True) for key in filters},
    }


def _event_trigger(event_trigger: dict) -> dict:
    """The canonical trigger of an `eventTrigger`, or `Unserved` for an event type fireemu does not serve."""
    event_type = str(_resolved(event_trigger.get("eventType"), "eventType") or "")
    if event_type.startswith(_FIRESTORE_PREFIX):
        return _firestore_trigger({**event_trigger, "eventType": event_type})
    if event_type == _PUBSUB_EVENT:
        return _pubsub_trigger(event_trigger)
    if event_type in _STORAGE_EVENTS:
        return _storage_trigger(event_trigger, event_type)
    if event_type in _DATABASE_EVENTS:
        return _database_trigger(event_trigger, event_type)
    # `onCustomEventPublished` is the only SDK trigger that names a channel.
    channel = _text(event_trigger, "channel", "eventTrigger.channel", "eventarc")
    if channel is not None:
        return _eventarc_trigger(event_trigger, event_type, channel)
    for fragment, trigger_type, scope, reason in _UNSERVED_PRODUCTS:
        if fragment in event_type:
            raise Unserved(trigger_type, scope, reason)
    family = "storage" if event_type.startswith("google.cloud.storage.") else (
        "database" if event_type.startswith("google.firebase.database.") else "unknown"
    )
    raise Unserved(family, "unsupported", f"event type {event_type} is not recognised")


def _record(value, field: str, family: str) -> dict:
    """An options record: absent is empty, an object is itself, anything else is an error."""
    if _unset(value):
        return {}
    if not isinstance(value, dict):
        raise Unserved(family, "unsupported", f"{field} must be an object")
    return value


def _numbers(value, field: str, allowed: frozenset, family: str) -> dict:
    """The numbers of a retry or rate record. A member the SDK left unset is null on the wire."""
    record = _record(value, field, family)
    numbers: dict[str, Any] = {}
    for key, original in record.items():
        if key not in allowed:
            raise Unserved(family, "unsupported", f"{field}.{key} is not supported")
        resolved = _resolved(original, f"{field}.{key}")
        if resolved is None:
            numbers[key] = None
            continue
        if isinstance(resolved, bool) or not isinstance(resolved, (int, float)) or not math.isfinite(resolved):
            raise Unserved(family, "unsupported", f"{field}.{key} did not resolve to a finite number")
        numbers[key] = resolved
    return numbers


def _schedule_trigger(trigger) -> tuple[dict, bool]:
    """The canonical trigger of a `scheduleTrigger` and whether the function retries."""
    record = _record(trigger, "scheduleTrigger", "schedule")
    schedule = _text(record, "schedule", "scheduleTrigger.schedule", "schedule", required=True, allow_empty=False)
    time_zone = _text(record, "timeZone", "scheduleTrigger.timeZone", "schedule")
    # The SDK keeps a deployment expression as braced CEL; this runner resolves values, it does not evaluate CEL.
    if "{{" in schedule or (time_zone is not None and "{{" in time_zone):
        raise Unserved("schedule", "unsupported", "scheduleTrigger contains an unresolved deployment expression")
    retry_config = _numbers(record.get("retryConfig"), "scheduleTrigger.retryConfig", _SCHEDULE_RETRY_FIELDS, "schedule")
    # A Gen2 job with a retry window and no count is retried until the window ends (run 156715222b86ea44), so a
    # window alone declares a retry too.
    retry = (retry_config.get("retryCount") or 0) > 0 or (retry_config.get("maxRetrySeconds") or 0) > 0
    described: dict[str, Any] = {"type": "schedule", "schedule": schedule}
    if time_zone is not None:
        described["timeZone"] = time_zone
    described["retryConfig"] = retry_config
    return described, retry


def _task_queue_trigger(queue) -> dict:
    record = _record(queue, "taskQueueTrigger", "tasks")
    return {
        "type": "tasks",
        "retryConfig": _numbers(record.get("retryConfig"), "taskQueueTrigger.retryConfig", _TASK_RETRY_FIELDS, "tasks"),
        "rateLimits": _numbers(record.get("rateLimits"), "taskQueueTrigger.rateLimits", _TASK_RATE_FIELDS, "tasks"),
    }


def _blocking_trigger(blocking) -> dict:
    record = _record(blocking, "blockingTrigger", "blocking")
    event_type = str(_resolved(record.get("eventType"), "blockingTrigger.eventType") or "")
    if not any(event_type.endswith(event) for event in _BLOCKING_AUTH_EVENTS):
        for fragment, trigger_type, scope, reason in _UNSERVED_PRODUCTS:
            if fragment in event_type:
                raise Unserved(trigger_type, scope, reason)
        raise Unserved("blocking", "unsupported", f"blocking identity event {event_type} is not served")
    options = record.get("options") if isinstance(record.get("options"), dict) else {}
    return {
        "type": "blockingAuth",
        "eventType": event_type,
        "accessToken": options.get("accessToken") is True,
        "idToken": options.get("idToken") is True,
        "refreshToken": options.get("refreshToken") is True,
    }


def describe_endpoint(name: str, endpoint, app_check_verified: bool = False) -> dict:
    """The canonical `functions[]` entry of one endpoint, or `Unserved` when it cannot be served."""
    if endpoint.platform != "gcfv2":
        raise Unserved("unknown", "unsupported", "endpoint platform is not recognised")
    described: dict[str, Any] = {"name": name, "entryPoint": name, "generation": 2}
    region = _first_region(endpoint)
    if region:
        described["region"] = region
    timeout = _non_negative_integer(endpoint.timeoutSeconds, "timeoutSeconds")
    if timeout:
        described["timeoutSeconds"] = timeout
    concurrency = _non_negative_integer(endpoint.concurrency, "concurrency")
    if concurrency is not None:
        described["concurrency"] = concurrency
    options = _platform_options(endpoint)
    if options:
        described["platformOptions"] = options
    if endpoint.taskQueueTrigger is not None:
        described["trigger"] = _task_queue_trigger(endpoint.taskQueueTrigger)
        return described
    if endpoint.httpsTrigger is not None:
        described["trigger"] = {"type": "http", "callable": False}
    elif endpoint.callableTrigger is not None:
        described["trigger"] = {"type": "http", "callable": True}
        if app_check_verified:
            # The SDK verifies the token itself, against the App Check emulator's keys, and never consumes it.
            described["trigger"]["consumeAppCheckToken"] = "disabled"
    elif endpoint.scheduleTrigger is not None:
        described["trigger"], described["retry"] = _schedule_trigger(endpoint.scheduleTrigger)
    elif endpoint.blockingTrigger is not None:
        described["trigger"] = _blocking_trigger(endpoint.blockingTrigger)
    elif endpoint.eventTrigger is not None:
        described["trigger"] = _event_trigger(endpoint.eventTrigger)
        retry = _resolved(endpoint.eventTrigger.get("retry"), "eventTrigger.retry")
        if retry is not None and not isinstance(retry, bool):
            raise Unserved(described["trigger"]["type"], "unsupported", "eventTrigger.retry did not resolve to a boolean")
        described["retry"] = retry is True
    else:
        raise Unserved("unknown", "unsupported", "the endpoint declares no trigger")
    return described


def build_manifest(functions: dict, app_check_verified: bool = False) -> dict:
    """`{"functions": [...], "ignored": [...]}` for the decorated functions of a codebase.

    `app_check_verified` says the Admin SDK verifies App Check tokens against the emulator's keys (`appcheck.py`).
    """
    served: list[dict] = []
    ignored: list[dict] = []
    for name, function in functions.items():
        endpoint = function.__firebase_endpoint__
        try:
            served.append(describe_endpoint(name, endpoint, app_check_verified))
        except Unserved as unserved:
            try:
                region = _first_region(endpoint) or DEFAULT_REGION
            except Unserved:
                region = DEFAULT_REGION
            ignored.append(
                {
                    "name": name,
                    "region": region,
                    "triggerType": unserved.trigger_type,
                    "scope": unserved.scope,
                    "reason": unserved.reason,
                }
            )
    return {"functions": served, "ignored": ignored}
