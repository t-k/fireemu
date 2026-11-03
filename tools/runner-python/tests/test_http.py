"""HTTP and callable functions through the runner's own server, the way the daemon proxies them."""

import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from harness import Runner

BASE = "/demo-proj/us-central1"


@pytest.fixture(scope="module")
def runner():
    process = Runner()
    process.hello()
    yield process
    process.kill()


def unsigned_token(uid="u1"):
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    now = int(time.time())
    claims = {
        "aud": "demo-proj",
        "iss": "https://securetoken.google.com/demo-proj",
        "sub": uid,
        "user_id": uid,
        "iat": now,
        "exp": now + 3600,
        "auth_time": now,
        "firebase": {"sign_in_provider": "anonymous", "identities": {}},
    }
    return part({"alg": "none", "typ": "JWT"}) + "." + part(claims) + "."


def test_the_function_sees_the_path_below_its_mount_point_and_the_query(runner):
    status, headers, body = runner.request(f"{BASE}/hello/a/b?q=1&q2=x", method="POST", body=b"payload")
    assert status == 200
    seen = json.loads(body)
    assert seen["path"] == "/a/b"
    assert seen["method"] == "POST"
    assert seen["args"] == {"q": "1", "q2": "x"}
    assert seen["body"] == "payload"
    status, _, body = runner.request(f"{BASE}/hello")
    assert json.loads(body)["path"] == "/"


def test_the_runner_secret_gates_every_request_and_never_reaches_the_function(runner):
    assert runner.request(f"{BASE}/hello", secret=None)[0] == 403
    assert runner.request(f"{BASE}/hello", secret="wrong")[0] == 403
    status, _, body = runner.request(f"{BASE}/hello")
    assert status == 200
    assert json.loads(body)["secret_header"] is None


@pytest.mark.parametrize(
    "path",
    ["/other-project/us-central1/hello", "/demo-proj/europe-west1/hello", f"{BASE}/nope", f"{BASE}/fs_created", f"{BASE}/ps_later", "/", f"/demo-proj/us-central1"],
)
def test_a_request_for_anything_but_a_served_http_function_is_404(runner, path):
    assert runner.request(path)[0] == 404


def test_an_unhandled_exception_is_the_frameworks_crash_response(runner):
    status, headers, _ = runner.request(f"{BASE}/boom")
    assert status == 500
    assert headers.get("X-Google-Status") == "crash"


def test_a_callable_answers_with_its_result_and_sees_the_emulator_auth(runner):
    status, _, body = runner.request(f"{BASE}/add", method="POST", body={"data": {"a": 2, "b": 3}})
    assert (status, json.loads(body)) == (200, {"result": {"sum": 5, "uid": None}})
    status, _, body = runner.request(
        f"{BASE}/add", method="POST", body={"data": {"a": 2, "b": 3}}, headers={"Authorization": "Bearer " + unsigned_token("u7")}
    )
    assert (status, json.loads(body)) == (200, {"result": {"sum": 5, "uid": "u7"}})


def test_a_callable_error_and_a_malformed_call_use_the_callable_protocol(runner):
    status, _, body = runner.request(f"{BASE}/refuse", method="POST", body={"data": {}})
    assert (status, json.loads(body)) == (404, {"error": {"message": "nope", "status": "NOT_FOUND"}})
    status, _, body = runner.request(f"{BASE}/add", method="POST", body=b"x", headers={"Content-Type": "text/plain"})
    assert status == 400
    assert json.loads(body)["error"]["status"] == "INVALID_ARGUMENT"


def test_a_callable_preflight_is_answered_by_the_sdk(runner):
    status, headers, _ = runner.request(
        f"{BASE}/add", method="OPTIONS", headers={"Origin": "http://localhost", "Access-Control-Request-Method": "POST"}
    )
    assert status == 200
    assert "Access-Control-Allow-Origin" in headers


def test_overlapping_requests_run_at_the_same_time(runner):
    started = time.monotonic()
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda n: runner.request(f"{BASE}/slow?seconds=0.5&tag={n}"), range(8)))
    elapsed = time.monotonic() - started
    assert [json.loads(body)["done"] for _, _, body in results] == [str(n) for n in range(8)]
    # Serial execution would take 4 s.
    assert elapsed < 2.5
