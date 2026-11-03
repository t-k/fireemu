"""Endpoint-to-canonical-manifest mapping, driven by the real SDK's own discovery."""

import pytest
from firebase_functions import params
from firebase_functions.private import manifest as sdk_manifest
from firebase_functions.private.util import Sentinel

from conftest import FIXTURE
from fireemu_runner.manifest import build_manifest, describe_endpoint

FS = "google.cloud.firestore.document.v1."


@pytest.fixture
def manifest(discovered):
    return build_manifest(discovered)


def function(manifest, name):
    (entry,) = [entry for entry in manifest["functions"] if entry["name"] == name]
    return entry


def test_an_on_request_function_is_a_plain_http_function(manifest):
    assert function(manifest, "hello") == {
        "name": "hello",
        "entryPoint": "hello",
        "generation": 2,
        "trigger": {"type": "http", "callable": False},
    }


def test_an_on_call_function_is_a_callable_whose_app_check_options_are_not_stated(manifest):
    # The SDK keeps `enforce_app_check` in a closure, so the endpoint cannot say it; the daemon reads
    # an absent `enforceAppCheck` as false and `consumeAppCheckToken` as undetermined.
    assert function(manifest, "add") == {
        "name": "add",
        "entryPoint": "add",
        "generation": 2,
        # The SDK labels a callable `deployment-callable`, and the Node runner reports that label too.
        "platformOptions": {"labels": {"deployment-callable": "true"}},
        "trigger": {"type": "http", "callable": True},
    }


@pytest.mark.parametrize(
    "name, event_type, document",
    [
        ("fs_created", FS + "created", "items/{id}"),
        ("fs_updated", FS + "updated", "items/{id}"),
        ("fs_deleted", FS + "deleted", "items/{id}"),
        ("fs_written", FS + "written", "items/{id}"),
        ("fs_created_auth", FS + "created.withAuthContext", "items/{id}"),
        # The SDK puts a path without wildcards in `eventFilters.document`, not in
        # `eventFilterPathPatterns.document`; both must reach the manifest.
        ("fs_literal", FS + "written", "settings/global"),
    ],
)
def test_a_firestore_function_names_its_event_type_database_and_document(manifest, name, event_type, document):
    assert function(manifest, name) == {
        "name": name,
        "entryPoint": name,
        "generation": 2,
        "retry": False,
        "trigger": {"type": "firestore", "eventType": event_type, "database": "(default)", "document": document},
    }


def test_region_timeout_memory_and_database_options_are_carried(manifest):
    assert function(manifest, "fs_options") == {
        "name": "fs_options",
        "entryPoint": "fs_options",
        "generation": 2,
        "region": "europe-west1",
        "timeoutSeconds": 90,
        "platformOptions": {"availableMemoryMb": 512},
        "retry": False,
        "trigger": {"type": "firestore", "eventType": FS + "written", "database": "other", "document": "items/{id}"},
    }


def test_every_discovered_function_is_either_served_or_ignored(discovered, manifest):
    names = {entry["name"] for entry in manifest["functions"]} | {entry["name"] for entry in manifest["ignored"]}
    assert names == set(discovered)
    assert manifest["ignored"] == []


def endpoint(**overrides):
    return sdk_manifest.ManifestEndpoint(entryPoint="f", httpsTrigger={}, **overrides)


def test_none_and_the_reset_sentinel_both_mean_unset():
    described = describe_endpoint("f", endpoint(timeoutSeconds=Sentinel("reset"), availableMemoryMb=None, concurrency=Sentinel("reset")))
    assert described == {"name": "f", "entryPoint": "f", "generation": 2, "trigger": {"type": "http", "callable": False}}


def test_a_parameter_expression_is_resolved_to_its_value(monkeypatch):
    # A fresh registry: declaring the same parameter twice (the suite may run twice in a process) is an error.
    monkeypatch.setattr(params, "_params", {})
    monkeypatch.setenv("RUNNER_TEST_MEMORY", "256")
    parameter = params.IntParam("RUNNER_TEST_MEMORY")
    described = describe_endpoint("f", endpoint(availableMemoryMb=parameter, timeoutSeconds=parameter, concurrency=parameter))
    assert described["platformOptions"] == {"availableMemoryMb": 256}
    assert described["timeoutSeconds"] == 256
    assert described["concurrency"] == 256


def test_a_value_that_is_not_a_non_negative_integer_makes_the_function_unserved_not_the_codebase():
    result = build_manifest({"f": _wrapped(endpoint(timeoutSeconds=-3))})
    assert result["functions"] == []
    (entry,) = result["ignored"]
    assert entry["name"] == "f" and entry["scope"] == "unsupported"
    assert "timeoutSeconds" in entry["reason"]


def test_an_endpoint_on_another_platform_is_unsupported():
    result = build_manifest({"f": _wrapped(endpoint(platform="gcfv1"))})
    assert result["functions"] == []
    assert result["ignored"][0]["scope"] == "unsupported"


def test_an_endpoint_with_no_trigger_is_unsupported():
    result = build_manifest({"f": _wrapped(sdk_manifest.ManifestEndpoint(entryPoint="f"))})
    assert result["ignored"][0]["triggerType"] == "unknown"
    assert result["ignored"][0]["scope"] == "unsupported"


def test_task_queue_and_blocking_triggers_are_planned_families():
    tasks = sdk_manifest.ManifestEndpoint(entryPoint="t", taskQueueTrigger={})
    blocking = sdk_manifest.ManifestEndpoint(entryPoint="b", blockingTrigger={"eventType": "providers/cloud.auth/eventTypes/user.beforeCreate"})
    result = build_manifest({"t": _wrapped(tasks), "b": _wrapped(blocking)})
    assert {entry["name"]: (entry["triggerType"], entry["scope"]) for entry in result["ignored"]} == {
        "t": ("tasks", "planned"),
        "b": ("blockingAuth", "planned"),
    }


@pytest.mark.parametrize(
    "event_type, family",
    [
        ("google.cloud.pubsub.topic.v1.messagePublished", "pubsub"),
        ("google.cloud.storage.object.v1.finalized", "storage"),
        ("google.firebase.database.ref.v1.written", "database"),
        ("com.example.custom", "eventarc"),
    ],
)
def test_event_families_other_than_firestore_are_planned(event_type, family):
    trigger = sdk_manifest.EventTrigger(eventType=event_type, retry=False)
    result = build_manifest({"f": _wrapped(sdk_manifest.ManifestEndpoint(entryPoint="f", eventTrigger=trigger))})
    assert result["ignored"][0]["triggerType"] == family
    assert result["ignored"][0]["scope"] == "planned"


def test_the_region_list_serves_its_first_entry_and_an_empty_list_none():
    assert describe_endpoint("f", endpoint(region=["us-east1", "europe-west1"]))["region"] == "us-east1"
    assert "region" not in describe_endpoint("f", endpoint(region=[]))
    assert "region" not in describe_endpoint("f", endpoint(region=None))


def test_secrets_and_other_deployment_options_become_platform_options():
    described = describe_endpoint(
        "f",
        endpoint(
            availableMemoryMb=512,
            minInstances=1,
            maxInstances=5,
            ingressSettings="ALLOW_INTERNAL_ONLY",
            serviceAccountEmail="sa@example.invalid",
            labels={"team": "a"},
            cpu=2,
            vpc={"connector": "projects/p/locations/l/connectors/c", "egressSettings": "ALL_TRAFFIC"},
            secretEnvironmentVariables=[{"key": "TOKEN"}],
        ),
    )
    assert described["platformOptions"] == {
        "availableMemoryMb": 512,
        "minInstances": 1,
        "maxInstances": 5,
        "ingressSettings": "ALLOW_INTERNAL_ONLY",
        "serviceAccountEmail": "sa@example.invalid",
        "vpcConnector": "projects/p/locations/l/connectors/c",
        "vpcEgressSettings": "ALL_TRAFFIC",
        "labels": {"team": "a"},
        "cpu": "2",
        "secrets": ["TOKEN"],
    }


def test_a_firestore_trigger_without_a_document_is_unsupported():
    trigger = sdk_manifest.EventTrigger(eventType=FS + "created", retry=False, eventFilters={"database": "(default)"})
    result = build_manifest({"f": _wrapped(sdk_manifest.ManifestEndpoint(entryPoint="f", eventTrigger=trigger))})
    assert result["ignored"][0]["scope"] == "unsupported"
    assert "document" in result["ignored"][0]["reason"]


def _wrapped(endpoint_value):
    """A stand-in for a decorated function: only `__firebase_endpoint__` matters."""

    def handler():
        pass

    handler.__firebase_endpoint__ = endpoint_value
    return handler


# --- exact answers for everything the runner refuses to serve --------------------------------------


class _Unresolved(params.Expression):
    """An expression that has no value."""

    @property
    def value(self):
        return None


def _unserved(endpoint_value):
    from fireemu_runner.manifest import Unserved

    with pytest.raises(Unserved) as error:
        describe_endpoint("f", endpoint_value)
    return (error.value.trigger_type, error.value.scope, error.value.reason)


def _event(event_type, **fields):
    return sdk_manifest.ManifestEndpoint(entryPoint="f", eventTrigger=sdk_manifest.EventTrigger(eventType=event_type, retry=False, **fields))


@pytest.mark.parametrize(
    "field, value",
    [("timeoutSeconds", -1), ("timeoutSeconds", True), ("timeoutSeconds", "9"), ("timeoutSeconds", 1.5),
     ("concurrency", -2), ("availableMemoryMb", "512"), ("minInstances", -1), ("maxInstances", 2.0)],
)
def test_an_option_that_is_not_a_non_negative_integer_names_itself(field, value):
    assert _unserved(endpoint(**{field: value})) == ("unknown", "unsupported", f"{field} did not resolve to a non-negative integer")


def test_an_expression_without_a_value_names_the_field():
    assert _unserved(endpoint(timeoutSeconds=_Unresolved())) == ("unknown", "unsupported", "timeoutSeconds expression did not resolve to a value")


@pytest.mark.parametrize("region", [[""], [3], [None, "x"][:0] + [7], ""])
def test_a_region_that_is_not_a_non_empty_string_is_unsupported(region):
    assert _unserved(endpoint(region=region)) == ("unknown", "unsupported", "region did not resolve to a non-empty string")


def test_the_exact_reasons_of_the_families_not_served_yet():
    planned = "Python {} triggers are planned for a later slice and are not served yet"
    assert _unserved(sdk_manifest.ManifestEndpoint(entryPoint="f", taskQueueTrigger={})) == ("tasks", "planned", planned.format("task queue"))
    assert _unserved(sdk_manifest.ManifestEndpoint(entryPoint="f", scheduleTrigger={"schedule": "x"})) == ("schedule", "planned", planned.format("schedule"))
    assert _unserved(sdk_manifest.ManifestEndpoint(entryPoint="f", blockingTrigger={"eventType": "x"})) == ("blockingAuth", "planned", planned.format("Auth blocking"))
    for event_type, family in (
        ("google.cloud.pubsub.topic.v1.messagePublished", "pubsub"),
        ("google.cloud.storage.object.v1.finalized", "storage"),
        ("google.firebase.database.ref.v1.written", "database"),
        ("anything.else", "eventarc"),
    ):
        assert _unserved(_event(event_type)) == (family, "planned", planned.format(family))


def test_the_other_unsupported_shapes_have_exact_reasons():
    assert _unserved(endpoint(platform="gcfv1")) == ("unknown", "unsupported", "endpoint platform is not recognised")
    assert _unserved(sdk_manifest.ManifestEndpoint(entryPoint="f")) == ("unknown", "unsupported", "the endpoint declares no trigger")
    assert _unserved(_event(FS + "created", eventFilters={"database": "(default)"})) == (
        "firestore", "unsupported", "the Firestore trigger names no document (eventFilters.document)"
    )
    assert _unserved(_event(FS + "created", eventFilters={"database": 5, "document": "a/b"})) == (
        "firestore", "unsupported", "eventFilters.database did not resolve to a string"
    )
    bad_retry = sdk_manifest.ManifestEndpoint(
        entryPoint="f",
        eventTrigger=sdk_manifest.EventTrigger(eventType=FS + "created", retry="yes", eventFilters={"document": "a/b"}),
    )
    assert _unserved(bad_retry) == ("firestore", "unsupported", "eventTrigger.retry did not resolve to a boolean")


def test_a_retrying_firestore_trigger_says_so():
    trigger = sdk_manifest.EventTrigger(eventType=FS + "written", retry=True, eventFilters={"document": "a/b"})
    described = describe_endpoint("f", sdk_manifest.ManifestEndpoint(entryPoint="f", eventTrigger=trigger))
    assert described["retry"] is True
    assert described["trigger"] == {"type": "firestore", "eventType": FS + "written", "database": "(default)", "document": "a/b"}


def test_the_ignored_entry_takes_the_declared_region_or_the_default():
    unserved = sdk_manifest.ManifestEndpoint(entryPoint="f", region=["europe-west1"], scheduleTrigger={"schedule": "x"})
    entry = build_manifest({"f": _wrapped(unserved)})["ignored"][0]
    assert entry == {
        "name": "f",
        "region": "europe-west1",
        "triggerType": "schedule",
        "scope": "planned",
        "reason": "Python schedule triggers are planned for a later slice and are not served yet",
    }
    broken = sdk_manifest.ManifestEndpoint(entryPoint="f", region=[3], scheduleTrigger={"schedule": "x"})
    assert build_manifest({"f": _wrapped(broken)})["ignored"][0]["region"] == "us-central1"


def test_an_enum_option_resolves_to_its_value_and_the_invoker_is_kept():
    import enum

    class Ingress(enum.Enum):
        INTERNAL = "ALLOW_INTERNAL_ONLY"

    described = describe_endpoint("f", sdk_manifest.ManifestEndpoint(entryPoint="f", httpsTrigger={"invoker": ["private"]}, ingressSettings=Ingress.INTERNAL))
    assert described["platformOptions"] == {"ingressSettings": "ALLOW_INTERNAL_ONLY", "invoker": ["private"]}


def test_vpc_network_interfaces_and_an_unset_connector_are_handled():
    described = describe_endpoint("f", endpoint(vpc={"connector": Sentinel("r"), "networkInterfaces": [{"network": "n"}]}))
    assert described["platformOptions"] == {"networkInterfaces": [{"network": "n"}]}


def test_a_zero_timeout_is_not_reported_but_a_zero_concurrency_is():
    described = describe_endpoint("f", endpoint(timeoutSeconds=0, concurrency=0))
    assert "timeoutSeconds" not in described and described["concurrency"] == 0


def test_a_secret_without_a_key_is_left_out_and_no_secrets_means_no_option():
    described = describe_endpoint("f", endpoint(secretEnvironmentVariables=[{"key": "A"}, {"key": ""}, {}]))
    assert described["platformOptions"] == {"secrets": ["A"]}
    assert "platformOptions" not in describe_endpoint("f", endpoint(secretEnvironmentVariables=[]))
    assert "platformOptions" not in describe_endpoint("f", endpoint(labels={}))


# --- field names in the messages, and shapes that are not what the SDK normally gives ---------------


@pytest.mark.parametrize(
    "build, field",
    [
        (lambda: endpoint(region=_Unresolved()), "region"),
        (lambda: endpoint(region=[_Unresolved()]), "region"),
        (lambda: endpoint(cpu=_Unresolved()), "cpu"),
        (lambda: endpoint(vpc={"egressSettings": _Unresolved()}), "vpc.egressSettings"),
        (lambda: endpoint(availableMemoryMb=_Unresolved()), "availableMemoryMb"),
        (lambda: endpoint(minInstances=_Unresolved()), "minInstances"),
        (lambda: endpoint(maxInstances=_Unresolved()), "maxInstances"),
        (lambda: endpoint(concurrency=_Unresolved()), "concurrency"),
        (lambda: endpoint(serviceAccountEmail=_Unresolved()), "serviceAccountEmail"),
        (lambda: endpoint(ingressSettings=_Unresolved()), "ingressSettings"),
    ],
)
def test_an_expression_without_a_value_is_reported_under_the_name_of_its_field(build, field):
    assert _unserved(build()) == ("unknown", "unsupported", f"{field} expression did not resolve to a value")


def test_firestore_filter_expressions_without_a_value_are_reported_under_their_filter_names():
    assert _unserved(_event(FS + "created", eventFilters={"document": _Unresolved()})) == (
        "unknown", "unsupported", "eventFilters.document expression did not resolve to a value"
    )
    assert _unserved(_event(FS + "created", eventFilterPathPatterns={"document": _Unresolved()})) == (
        "unknown", "unsupported", "eventFilterPathPatterns.document expression did not resolve to a value"
    )
    assert _unserved(_event(FS + "created", eventFilters={"document": "a/b", "database": _Unresolved()})) == (
        "unknown", "unsupported", "eventFilters.database expression did not resolve to a value"
    )
    broken_type = sdk_manifest.ManifestEndpoint(entryPoint="f", eventTrigger={"eventType": _Unresolved(), "retry": False})
    assert _unserved(broken_type) == ("unknown", "unsupported", "eventType expression did not resolve to a value")
    broken_retry = sdk_manifest.ManifestEndpoint(
        entryPoint="f", eventTrigger={"eventType": FS + "created", "retry": _Unresolved(), "eventFilters": {"document": "a/b"}}
    )
    assert _unserved(broken_retry) == ("unknown", "unsupported", "eventTrigger.retry expression did not resolve to a value")


def test_an_unserved_error_carries_its_reason_as_its_message():
    from fireemu_runner.manifest import Unserved

    assert str(Unserved("pubsub", "planned", "because")) == "because"


def test_filters_that_are_not_objects_are_treated_as_empty():
    trigger = sdk_manifest.EventTrigger(eventType=FS + "created", retry=False, eventFilters=None, eventFilterPathPatterns={"document": "a/{id}"})
    described = describe_endpoint("f", sdk_manifest.ManifestEndpoint(entryPoint="f", eventTrigger=trigger))
    assert described["trigger"]["database"] == "(default)" and described["trigger"]["document"] == "a/{id}"
    trigger = sdk_manifest.EventTrigger(eventType=FS + "created", retry=False, eventFilters={"document": "a/b"}, eventFilterPathPatterns="x")
    assert describe_endpoint("f", sdk_manifest.ManifestEndpoint(entryPoint="f", eventTrigger=trigger))["trigger"]["document"] == "a/b"


def test_a_path_pattern_wins_over_a_literal_document_when_both_are_given():
    trigger = sdk_manifest.EventTrigger(
        eventType=FS + "created", retry=False, eventFilters={"document": "literal/doc"}, eventFilterPathPatterns={"document": "items/{id}"}
    )
    assert describe_endpoint("f", sdk_manifest.ManifestEndpoint(entryPoint="f", eventTrigger=trigger))["trigger"]["document"] == "items/{id}"


def test_vpc_and_https_trigger_shapes_that_are_not_objects_are_ignored():
    described = describe_endpoint("f", endpoint(vpc="not-an-object"))
    assert "platformOptions" not in described
    odd = sdk_manifest.ManifestEndpoint(entryPoint="f", httpsTrigger=["x"])
    assert "platformOptions" not in describe_endpoint("f", odd)
    assert describe_endpoint("f", sdk_manifest.ManifestEndpoint(entryPoint="f", httpsTrigger={"invoker": []}).__class__(entryPoint="f", httpsTrigger={"invoker": []})).get("platformOptions") is None


def test_the_http_types_of_a_plain_and_a_callable_function_are_exact():
    plain = describe_endpoint("f", sdk_manifest.ManifestEndpoint(entryPoint="f", httpsTrigger={}))
    callable_ = describe_endpoint("f", sdk_manifest.ManifestEndpoint(entryPoint="f", callableTrigger={}))
    assert plain["trigger"] == {"type": "http", "callable": False}
    assert callable_["trigger"] == {"type": "http", "callable": True}
