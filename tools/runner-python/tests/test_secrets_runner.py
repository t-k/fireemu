"""Local secrets through the real runner: the daemon's `FIREEMU_LOCAL_SECRETS_JSON` and the gate in front of every call."""

import json
import threading
import time

import pytest

from harness import Runner

SECRETS = {"API_KEY": "key-value", "TOKEN": "token-value"}


@pytest.fixture(scope="module")
def runner():
    process = Runner(extra_env={"FIREEMU_LOCAL_SECRETS_JSON": json.dumps(SECRETS), "API_KEY": "from the process environment"})
    process.hello()
    yield process
    process.kill()


def env_of(process, path):
    status, _, body = process.request(path)
    assert status == 200, body
    return json.loads(body)["env"]


def test_the_secrets_are_not_in_the_environment_between_invocations_or_at_import(runner):
    # `API_KEY` is also set in the runner's own environment by the daemon's dotenv chain: a plain function must not
    # see it either, as the Node runner hides every local secret name from functions that do not declare it.
    assert env_of(runner, "/demo-proj/us-central1/reads_nothing") == {"API_KEY": None, "TOKEN": None}


def test_a_function_sees_only_the_secrets_it_declares(runner):
    assert env_of(runner, "/demo-proj/us-central1/reads_key") == {"API_KEY": "key-value", "TOKEN": None}
    status, _, body = runner.request("/demo-proj/us-central1/reads_token")
    answer = json.loads(body)
    assert status == 200 and answer["param"] == "token-value" and answer["env"] == {"API_KEY": None, "TOKEN": "token-value"}


def test_the_channel_that_carried_the_secrets_is_not_visible_to_user_code(runner):
    status, _, body = runner.request("/demo-proj/us-central1/hello")
    assert status == 200 and "FIREEMU_LOCAL_SECRETS_JSON" not in body.decode()


def test_event_functions_are_gated_the_same_way(runner):
    document = lambda path: {"name": f"projects/demo-proj/databases/(default)/documents/{path}", "fields": {}, "createTime": "2026-01-01T00:00:00Z", "updateTime": "2026-01-01T00:00:00Z"}  # noqa: E731
    for function, path in (("fs_secret", "secret/a"), ("fs_plain", "plain/a")):
        ev = {
            "specversion": "1.0", "id": "i", "type": "google.cloud.firestore.document.v1.created", "time": "2026-01-01T00:00:02Z",
            "source": "//firestore.googleapis.com/projects/demo-proj/databases/(default)", "subject": f"documents/{path}",
            "datacontenttype": "application/json", "location": "nam5", "project": "demo-proj", "namespace": "(default)",
            "document": path, "database": "(default)", "data": {"value": document(path)},
        }
        assert runner.invoke(f"gate-{function}", function, "firestore", ev)["ok"] is True
    seen = {entry["function"]: entry["env"] for entry in runner.seen() if entry["function"] in ("fs_secret", "fs_plain")}
    assert seen == {"fs_secret": {"API_KEY": "key-value", "TOKEN": None}, "fs_plain": {"API_KEY": None, "TOKEN": None}}


FIRST = {"nothing": ("reads_nothing?hold=0.8", True), "key": ("reads_key?hold=0.8", False), "stream": ("streams_key", False)}
SECOND = {"nothing": ("reads_nothing", True), "key": ("reads_key", False), "token": ("reads_token", False)}


@pytest.mark.parametrize("first", sorted(FIRST))
@pytest.mark.parametrize("second", sorted(SECOND))
def test_two_overlapping_calls_run_together_only_when_neither_declares_a_secret(runner, first, second):
    first_path, first_plain = FIRST[first]
    second_path, second_plain = SECOND[second]
    started = threading.Event()

    def run_first():
        started.set()
        runner.request(f"/demo-proj/us-central1/{first_path}")

    thread = threading.Thread(target=run_first, daemon=True)
    thread.start()
    started.wait(5)
    time.sleep(0.2)
    begun = time.monotonic()
    env = env_of(runner, f"/demo-proj/us-central1/{second_path}")
    waited = time.monotonic() - begun
    thread.join(10)
    if first_plain and second_plain:
        assert waited < 0.4, "two plain calls must not wait for each other"
    else:
        assert waited > 0.15, "a call with a secret, or behind one, waits for the other to finish"
    expected = {"API_KEY": "key-value" if second == "key" else None, "TOKEN": "token-value" if second == "token" else None}
    assert env == expected


def test_secrets_that_are_not_json_stop_the_runner_before_hello():
    process = Runner(extra_env={"FIREEMU_LOCAL_SECRETS_JSON": "not json"})
    assert process.close() == 1
    assert [frame for frame in process.frames if frame["type"] == "hello"] == []
    assert "local secrets" in process.stderr
