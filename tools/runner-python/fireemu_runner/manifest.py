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
from typing import Any

from firebase_functions.params import Expression
from firebase_functions.private.util import Sentinel

DEFAULT_REGION = "us-central1"

_FIRESTORE_PREFIX = "google.cloud.firestore."
_FAMILIES = (
    ("google.firebase.database.ref.", "database"),
    ("google.cloud.pubsub.", "pubsub"),
    ("google.cloud.storage.object.", "storage"),
)
_PLANNED = "Python {family} triggers are planned for a later slice and are not served yet"


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


def _event_family(event_type: str) -> str:
    for prefix, family in _FAMILIES:
        if event_type.startswith(prefix):
            return family
    return "eventarc"


def _string_filter(filters: dict, key: str, field: str):
    value = _resolved(filters.get(key), field)
    if value is not None and not isinstance(value, str):
        raise Unserved("firestore", "unsupported", f"{field} did not resolve to a string")
    return value


def _firestore_trigger(event_trigger: dict) -> dict:
    filters = event_trigger.get("eventFilters") if isinstance(event_trigger.get("eventFilters"), dict) else {}
    patterns = (
        event_trigger.get("eventFilterPathPatterns")
        if isinstance(event_trigger.get("eventFilterPathPatterns"), dict)
        else {}
    )
    # The SDK keeps a document path without wildcards in `eventFilters.document` and one with
    # wildcards in `eventFilterPathPatterns.document` (`options.py:1065-1075`).
    document = _string_filter(patterns, "document", "eventFilterPathPatterns.document") or _string_filter(
        filters, "document", "eventFilters.document"
    )
    if not document:
        raise Unserved("firestore", "unsupported", "the Firestore trigger names no document (eventFilters.document)")
    return {
        "type": "firestore",
        "eventType": event_trigger["eventType"],
        "database": _string_filter(filters, "database", "eventFilters.database") or "(default)",
        "document": document,
    }


def describe_endpoint(name: str, endpoint) -> dict:
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
        raise Unserved("tasks", "planned", _PLANNED.format(family="task queue"))
    if endpoint.httpsTrigger is not None:
        described["trigger"] = {"type": "http", "callable": False}
    elif endpoint.callableTrigger is not None:
        described["trigger"] = {"type": "http", "callable": True}
    elif endpoint.scheduleTrigger is not None:
        raise Unserved("schedule", "planned", _PLANNED.format(family="schedule"))
    elif endpoint.blockingTrigger is not None:
        raise Unserved("blockingAuth", "planned", _PLANNED.format(family="Auth blocking"))
    elif endpoint.eventTrigger is not None:
        event_type = str(_resolved(endpoint.eventTrigger.get("eventType"), "eventType") or "")
        if not event_type.startswith(_FIRESTORE_PREFIX):
            family = _event_family(event_type)
            raise Unserved(family, "planned", _PLANNED.format(family=family))
        retry = _resolved(endpoint.eventTrigger.get("retry"), "eventTrigger.retry")
        if retry is not None and not isinstance(retry, bool):
            raise Unserved("firestore", "unsupported", "eventTrigger.retry did not resolve to a boolean")
        described["retry"] = retry is True
        described["trigger"] = _firestore_trigger(endpoint.eventTrigger)
    else:
        raise Unserved("unknown", "unsupported", "the endpoint declares no trigger")
    return described


def build_manifest(functions: dict) -> dict:
    """`{"functions": [...], "ignored": [...]}` for the decorated functions of a codebase."""
    served: list[dict] = []
    ignored: list[dict] = []
    for name, function in functions.items():
        endpoint = function.__firebase_endpoint__
        try:
            served.append(describe_endpoint(name, endpoint))
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
