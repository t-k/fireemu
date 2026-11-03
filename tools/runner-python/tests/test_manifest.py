"""Endpoint-to-canonical-manifest mapping, driven by the real SDK's own discovery."""

import os

import pytest
from firebase_functions import params
from firebase_functions.private import manifest as sdk_manifest
from firebase_functions.private import serving
from firebase_functions.private.util import Sentinel

from conftest import FIXTURE
from fireemu_runner.manifest import build_manifest, describe_endpoint

FS = "google.cloud.firestore.document.v1."


@pytest.fixture(scope="module")
def discovered():
    """The fixture codebase discovered by `serving.get_functions()`, once (it runs `initialize_app`)."""
    previous = os.getcwd()
    os.chdir(FIXTURE)
    try:
        yield serving.get_functions()
    finally:
        os.chdir(previous)


@pytest.fixture(scope="module")
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


def test_families_the_runner_does_not_serve_yet_are_reported_as_planned_never_dropped(manifest):
    ignored = {entry["name"]: entry for entry in manifest["ignored"]}
    assert set(ignored) == {"ps_later", "sched_later"}
    assert ignored["ps_later"]["triggerType"] == "pubsub"
    assert ignored["sched_later"]["triggerType"] == "schedule"
    for entry in ignored.values():
        assert entry["scope"] == "planned"
        assert entry["region"] == "us-central1"
        assert "Python" in entry["reason"]
    assert {entry["name"] for entry in manifest["functions"]}.isdisjoint(ignored)


def test_every_discovered_function_is_either_served_or_ignored(discovered, manifest):
    names = {entry["name"] for entry in manifest["functions"]} | {entry["name"] for entry in manifest["ignored"]}
    assert names == set(discovered)


def endpoint(**overrides):
    return sdk_manifest.ManifestEndpoint(entryPoint="f", httpsTrigger={}, **overrides)


def test_none_and_the_reset_sentinel_both_mean_unset():
    described = describe_endpoint("f", endpoint(timeoutSeconds=Sentinel("reset"), availableMemoryMb=None, concurrency=Sentinel("reset")))
    assert described == {"name": "f", "entryPoint": "f", "generation": 2, "trigger": {"type": "http", "callable": False}}


def test_a_parameter_expression_is_resolved_to_its_value(monkeypatch):
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
