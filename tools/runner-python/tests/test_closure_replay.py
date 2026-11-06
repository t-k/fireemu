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


@pytest.mark.parametrize("profile", ["strict", "emulator"])
def test_raw_cloudevent_request_constants_and_pending_infrastructure(profile, monkeypatch):
    monkeypatch.setenv("FIREEMU_HTTP_PROFILE", profile)
    for row in OBSERVATIONS:
        if row["condition"] not in {"firestore-events", "pubsub-events", "storage-events", "eventarc-custom-events"}:
            continue
        expected = next(f for f in row["frames"] if f["kind"] == "raw-event")
        case = row["sdkCases"][0]
        captured = []
        def handler(event):
            captured.append({"method": flask.request.method, "path": flask.request.path, "headers": dict((k.lower(), v) for k, v in flask.request.headers.items()), "attributes": dict(event._get_attributes())})
        dispatch._deliver(case["trigger"], handler, case["event"])
        actual = captured[0]
        assert actual["method"] == expected["request"]["method"]
        assert actual["path"] == expected["request"]["path"]
        for key, value in expected["request"]["headers"].items():
            if profile == "emulator" and key in {"user-agent", "accept-encoding", "x-forwarded-proto"}:
                assert key not in actual["headers"]
            else:
                assert actual["headers"][key] == value
        for key, value in expected["attributes"].items():
            if key == "dataschema" and profile == "emulator":
                assert key not in actual["attributes"]
            else:
                assert actual["attributes"][key] == value
        assert "authorization" in expected["request"]["headerNames"]
        assert "authorization" not in actual["headers"]


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
