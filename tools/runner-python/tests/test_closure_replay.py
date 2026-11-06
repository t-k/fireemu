"""Current runner and real SDK replay of the pending Python parent's masked observations.

Identity and timestamp inputs are synthetic aliases. Expectations come from the recorded SDK
frames; rebuilding transport inputs does not establish daemon or full-payload parity.
"""

import datetime
import json
from pathlib import Path

import firebase_admin
import flask
import pytest
from firebase_admin import credentials
from firebase_functions import eventarc_fn, firestore_fn, pubsub_fn, scheduler_fn, storage_fn, tasks_fn
from google.auth.credentials import AnonymousCredentials
from werkzeug.test import Client

from fireemu_runner import dispatch
from fireemu_runner.serve import RunnerRouter

ROOT = Path(__file__).resolve().parents[3]
OBSERVATIONS = json.loads((ROOT / "conformance/functions-python/fixtures/observations.json").read_text())["observations"]
CASES = [(r["condition"], i, c) for r in OBSERVATIONS for i, c in enumerate(r["sdkCases"])]


class _Anonymous(credentials.Base):
    def get_credential(self):
        return AnonymousCredentials()


@pytest.fixture(autouse=True)
def local_sdk(monkeypatch):
    monkeypatch.setenv("FIRESTORE_EMULATOR_HOST", "127.0.0.1:9")
    if firebase_admin._DEFAULT_APP_NAME not in firebase_admin._apps:
        app = firebase_admin.initialize_app(_Anonymous(), {"projectId": "fixture-project"})
        yield
        firebase_admin.delete_app(app)
    else:
        yield


def replay(case, profile, monkeypatch):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", profile)
    seen = []
    trigger = case["trigger"]
    if trigger == "firestore":
        def snapshot(value):
            return value.to_dict()
        def handler(event):
            if case["variant"] == "updated":
                seen.append({"before": snapshot(event.data.before), "after": snapshot(event.data.after)})
            else:
                seen.append({"snapshot": snapshot(event.data)})
        decorator = firestore_fn.on_document_updated if case["variant"] == "updated" else firestore_fn.on_document_created
        function = decorator(document="items/{id}")(handler)
    elif trigger == "pubsub":
        def handler(event):
            message = event.data.message
            seen.append({"attributes": dict(message.attributes), "ordering_key": message.ordering_key, "message_id": message.message_id, "publish_time": message.publish_time.isoformat(), "subscription": event.data.subscription})
        function = pubsub_fn.on_message_published(topic="fixture-topic")(handler)
    elif trigger == "storage":
        def handler(event):
            data = event.data
            seen.append({"bucket": data.bucket, "name": data.name, "generation": data.generation, "size": data.size, "content_type": data.content_type})
        function = storage_fn.on_object_finalized(bucket="fixture-bucket.firebasestorage.app")(handler)
    elif trigger == "eventarc":
        def handler(event):
            seen.append({"data": event.data, "time": event.time.isoformat()})
        function = eventarc_fn.on_custom_event_published(event_type=case["event"]["type"])(handler)
    elif trigger == "schedule":
        def handler(event):
            seen.append({"job_name": event.job_name, "schedule_time": event.schedule_time.isoformat()})
        function = scheduler_fn.on_schedule(schedule="every 5 minutes")(handler)
    else:
        assert trigger == "tasks"
        def handler(request):
            seen.append({"data": request.data, "has_app": request.app is not None, "has_auth": request.auth is not None})
        function = tasks_fn.on_task_dispatched()(handler)
        router = RunnerRouter({"fixture": function}, {"functions": [{"name": "fixture", "entryPoint": "fixture", "trigger": {"type": "tasks"}}]}, "fixture-project", "fixture-secret")
        client = Client(router, flask.Response)
        response = client.post("/fixture-project/us-central1/fixture", data=case["body"], content_type="application/json", headers={"x-fireemu-runner-secret": "fixture-secret"})
        assert response.status_code == 200
        response.close()
        return seen
    dispatch._deliver(trigger, function, case["event"])
    return seen


@pytest.mark.parametrize("profile", ["strict", "emulator"])
@pytest.mark.parametrize("family,index,case", CASES, ids=[f"{family}-{i}" for family, i, _ in CASES])
def test_recorded_sdk_projection_reaches_the_real_handler(family, index, case, profile, monkeypatch):
    expected = dict(case["expected"])
    if case["trigger"] == "schedule" and profile == "emulator":
        expected["schedule_time"] = datetime.datetime.fromisoformat(expected["schedule_time"]).astimezone(datetime.timezone.utc).isoformat()
    assert replay(case, profile, monkeypatch) == [expected]


@pytest.mark.parametrize("family,index,case", CASES, ids=[f"{family}-{i}" for family, i, _ in CASES])
def test_each_sdk_fixture_rejects_a_changed_semantic_expectation(family, index, case, monkeypatch):
    actual = replay(case, "strict", monkeypatch)
    altered = {**case["expected"], next(iter(case["expected"])): "corrupted-observation"}
    with pytest.raises(AssertionError):
        assert actual == [altered]


@pytest.mark.parametrize("profile", ["strict", "emulator"])
def test_whole_second_eventarc_preserves_recorded_absence_and_profile_difference(profile, monkeypatch):
    row = next(r for r in OBSERVATIONS if r["condition"] == "eventarc-custom-events")
    case = {**row["sdkCases"][0], "event": row["wholeSecondInput"]}
    if profile == "strict":
        with pytest.raises(ValueError):
            replay(case, profile, monkeypatch)
        assert row["wholeSecondSdkFrames"] == 0
    else:
        assert len(replay(case, profile, monkeypatch)) == 1


CORPUS = json.loads((ROOT / "conformance/functions-python/corpus.json").read_text())
RECORD = json.loads((ROOT / "spec/compatibility/closure/FUNCTIONS-PYTHON.json").read_text())
INFRASTRUCTURE_HEADERS = ("authorization", "forwarded", "x-forwarded-for", "function-execution-id", "x-cloud-trace-context", "from", "accept")


def actual_replay_differences(profile, monkeypatch):
    """Derive paths from recorded-versus-current output, never from declared fields."""
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", profile)
    differences = set()
    for row in OBSERVATIONS:
        family = row["condition"]
        if family not in {"firestore-events", "pubsub-events", "storage-events", "eventarc-custom-events", "scheduler-events"}:
            continue
        expected = next(f for f in row["frames"] if f["kind"] in {"raw-event", "raw-request"})
        case = row["sdkCases"][0]
        captured = []
        def handler(event):
            captured.append({"method": flask.request.method, "path": flask.request.path, "headers": dict((k.lower(), v) for k, v in flask.request.headers.items()), "attributes": {} if family == "scheduler-events" else dict(event._get_attributes())})
            return flask.Response("ok")
        dispatch._deliver(case["trigger"], handler, case["event"])
        actual = captured[0]
        for field in ("method", "path"):
            if actual[field] != expected["request"][field]:
                differences.add(family + ".request." + field)
        for key, value in expected["request"]["headers"].items():
            if actual["headers"].get(key) != value:
                if profile == "emulator" and family != "scheduler-events" and key in {"user-agent", "accept-encoding", "x-forwarded-proto"}:
                    assert key not in actual["headers"], "declared emulator constant difference is absence only"
                differences.add(family + ".request.headers." + key)
        for key in INFRASTRUCTURE_HEADERS:
            if (key in expected["request"]["headerNames"]) != (key in actual["headers"]):
                differences.add(family + ".request.presence." + key)
        for key, value in expected.get("attributes", {}).items():
            if actual["attributes"].get(key) != value:
                if profile == "emulator" and key == "dataschema":
                    assert key not in actual["attributes"], "declared dataschema difference is absence only"
                differences.add(family + "." + key)
    scheduler = next(r for r in OBSERVATIONS if r["condition"] == "scheduler-events")["sdkCases"][0]
    actual = replay(scheduler, profile, monkeypatch)[0]
    for key, value in scheduler["expected"].items():
        if actual.get(key) != value:
            differences.add("scheduler-events." + key)
    eventarc = next(r for r in OBSERVATIONS if r["condition"] == "eventarc-custom-events")
    case = {**eventarc["sdkCases"][0], "event": eventarc["wholeSecondInput"]}
    try:
        count = len(replay(case, profile, monkeypatch))
    except ValueError:
        count = 0
    if count != eventarc["wholeSecondSdkFrames"]:
        differences.add("eventarc-custom-events.wholeSecondSdkFrames")
    return differences


def assert_declared_replay(profile, differences, record):
    inventory = [{key: entry[key] for key in ("id", "profiles", "fields")} for entry in record["declaredDifferences"]]
    assert inventory == CORPUS["replayDifferences"], "exact replay difference inventory"
    declared = {field for entry in inventory if profile in entry["profiles"] for field in entry["fields"]}
    assert differences == declared, "actual replay differences must equal the declared inventory"


@pytest.mark.parametrize("profile", ["strict", "emulator"])
def test_raw_cloudevent_request_constants_and_pending_infrastructure(profile, monkeypatch):
    assert_declared_replay(profile, actual_replay_differences(profile, monkeypatch), RECORD)


@pytest.mark.parametrize("profile", ["strict", "emulator"])
def test_actual_replay_refuses_removed_or_widened_declarations_and_neighbor_differences(profile, monkeypatch):
    differences = actual_replay_differences(profile, monkeypatch)
    for i, entry in enumerate(RECORD["declaredDifferences"]):
        removed = json.loads(json.dumps(RECORD))
        removed["declaredDifferences"].pop(i)
        with pytest.raises(AssertionError, match="difference inventory"):
            assert_declared_replay(profile, differences, removed)
        for field in entry["fields"]:
            widened = json.loads(json.dumps(RECORD))
            widened["declaredDifferences"][i]["fields"].append(field + "-neighbor")
            with pytest.raises(AssertionError, match="difference inventory"):
                assert_declared_replay(profile, differences, widened)
            with pytest.raises(AssertionError, match="actual replay differences"):
                assert_declared_replay(profile, differences | {field + "-neighbor"}, RECORD)


def test_recorded_task_bytes_survive_current_http_router():
    row = next(r for r in OBSERVATIONS if r["condition"] == "tasks-events")
    body = next(f["bodyText"] for f in row["frames"] if "bodyText" in f)
    seen = []
    def handler(request):
        seen.append(request.get_data(as_text=True))
        return flask.Response("ok")
    router = RunnerRouter({"fixture": handler}, {"functions": [{"name": "fixture", "entryPoint": "fixture", "trigger": {"type": "tasks"}}]}, "fixture-project", "fixture-secret")
    response = Client(router, flask.Response).post("/fixture-project/us-central1/fixture", data=body, content_type="application/json", headers={"x-fireemu-runner-secret": "fixture-secret"})
    assert response.status_code == 200
    response.close()
    assert seen == [body]


@pytest.mark.parametrize("profile", ["strict", "emulator"])
@pytest.mark.parametrize("field", ["user-agent", "accept-encoding", "x-cloudscheduler", "x-forwarded-proto"])
def test_scheduler_recorded_constant_change_is_rejected(profile, field, monkeypatch):
    row = next(r for r in OBSERVATIONS if r["condition"] == "scheduler-events")
    frame = next(f for f in row["frames"] if f["kind"] == "raw-request")
    old = frame["request"]["headers"][field]
    try:
        frame["request"]["headers"][field] = "corrupted-observation"
        with pytest.raises(AssertionError):
            test_raw_cloudevent_request_constants_and_pending_infrastructure(profile, monkeypatch)
    finally:
        frame["request"]["headers"][field] = old


@pytest.mark.parametrize("profile", ["strict", "emulator"])
def test_undeclared_request_method_change_fails_against_actual_scheduler(profile, monkeypatch):
    row = next(r for r in OBSERVATIONS if r["condition"] == "scheduler-events")
    request = next(f["request"] for f in row["frames"] if f["kind"] == "raw-request")
    old = request["method"]
    try:
        request["method"] = "DELETE"
        with pytest.raises(AssertionError, match="actual replay differences"):
            assert_declared_replay(profile, actual_replay_differences(profile, monkeypatch), RECORD)
    finally:
        request["method"] = old


@pytest.mark.parametrize("field", ["user-agent", "accept-encoding", "x-forwarded-proto"])
def test_declared_emulator_header_absence_does_not_accept_a_wrong_value(field, monkeypatch):
    from fireemu_runner import request_view
    original = request_view.request_headers
    def wrong_value(headers, event):
        return {**original(headers, event), field: "unexpected-local-value"}
    monkeypatch.setattr(request_view, "request_headers", wrong_value)
    with pytest.raises(AssertionError, match="absence only"):
        actual_replay_differences("emulator", monkeypatch)


def test_declared_dataschema_absence_does_not_accept_a_wrong_schema(monkeypatch):
    case = next(r for r in OBSERVATIONS if r["condition"] == "firestore-events")["sdkCases"][0]
    assert "dataschema" not in case["event"]
    try:
        case["event"]["dataschema"] = "unexpected-schema"
        with pytest.raises(AssertionError, match="absence only"):
            actual_replay_differences("emulator", monkeypatch)
    finally:
        del case["event"]["dataschema"]
