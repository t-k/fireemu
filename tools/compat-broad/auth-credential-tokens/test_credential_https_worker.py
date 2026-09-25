"""Production-mode request validation without opening a network connection."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import credential_https_worker as worker

IDENTITY = "https://identitytoolkit.googleapis.com"
OWNER = {
    "Authorization": "Bearer fixture-owner",
    "x-goog-user-project": "fireemu-35fe6",
}


def envelope(path, *, owner=False, body="{}"):
    return {
        "url": IDENTITY + path,
        "body": body,
        "headers": {
            **(OWNER if owner else {}),
            **({"Content-Type": "application/json"} if body is not None else {}),
        },
        "seconds": 5.0,
    }


@pytest.mark.parametrize(
    "rpc",
    [
        "signUp",
        "signInWithPassword",
        "signInWithCustomToken",
        "lookup",
        "resetPassword",
        "update",
        "delete",
        "signInWithEmailLink",
    ],
)
def test_production_client_auth_post_is_not_misclassified_as_metadata(rpc):
    value = envelope("/v1/accounts:" + rpc + "?key=fixture-key")
    request = worker.prepare_request(value, fixture=False)
    assert request.get_method() == "POST"
    assert request.data == b"{}"
    assert request.get_header("Authorization") is None


@pytest.mark.parametrize("rpc", ["lookup", "update", "delete", "sendOobCode"])
def test_production_owner_auth_post_keeps_bearer_and_quota_binding(rpc):
    value = envelope("/v1/projects/fireemu-35fe6/accounts:" + rpc, owner=True)
    request = worker.prepare_request(value, fixture=False)
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == OWNER["Authorization"]
    assert request.get_header("X-goog-user-project") == "fireemu-35fe6"


def test_production_session_cookie_is_an_owner_post():
    value = envelope("/v1/projects/fireemu-35fe6:createSessionCookie", owner=True)
    assert worker.prepare_request(value, fixture=False).get_method() == "POST"


@pytest.mark.parametrize(
    "url",
    [
        "https://cloudresourcemanager.googleapis.com/v1/projects/fireemu-35fe6",
        IDENTITY + "/admin/v2/projects/fireemu-35fe6/config",
    ],
)
def test_metadata_remains_get_with_owner_authority(url):
    value = {"url": url, "body": None, "headers": dict(OWNER), "seconds": 5}
    assert worker.prepare_request(value, fixture=False).get_method() == "GET"
    for changed in (
        {"body": "{}"},
        {"headers": {}},
        {"headers": {**OWNER, "x-goog-user-project": "other"}},
    ):
        with pytest.raises(ValueError):
            worker.prepare_request({**value, **changed}, fixture=False)


@pytest.mark.parametrize(
    "change",
    [
        {"body": None},
        {"body": "[]"},
        {"body": "not-json"},
        {"headers": {}},
        {"headers": {"Content-Type": "application/json", **OWNER}},
        {"headers": {"Content-Type": "application/json", "Host": "foreign.invalid"}},
        {"headers": {"Content-Type": "application/json\rX-Injected: yes"}},
        {"url": IDENTITY + "/v1/accounts:unknown?key=fixture-key"},
        {"url": IDENTITY + "/v1/accounts:signUp"},
        {"url": IDENTITY + "/v1/accounts:signUp?key=a&key=b"},
        {"url": IDENTITY + "/v1/accounts:signUp?key=a&extra=b"},
        {"url": IDENTITY + "/v1/accounts:signUp?key="},
        {"url": IDENTITY + "/v1/projects/other/accounts:lookup"},
        {"url": IDENTITY + "/v1/projects/fireemu-35fe6/config"},
        {"url": "https://foreign.invalid/v1/accounts:signUp?key=k"},
        {"url": "http://127.0.0.1:9/v1/accounts:signUp?key=k"},
    ],
)
def test_production_auth_post_rejects_route_method_and_header_drift(change):
    with pytest.raises(ValueError):
        worker.prepare_request(
            {**envelope("/v1/accounts:signUp?key=fixture-key"), **change}, fixture=False
        )


@pytest.mark.parametrize(
    "change",
    [
        {"headers": {"Content-Type": "application/json"}},
        {
            "headers": {
                "Content-Type": "application/json",
                **OWNER,
                "Authorization": "Bearer ",
            }
        },
        {
            "headers": {
                "Content-Type": "application/json",
                **OWNER,
                "x-goog-user-project": "other",
            }
        },
        {"url": IDENTITY + "/v1/projects/fireemu-35fe6/accounts:lookup?key=k"},
        {"url": IDENTITY + "/v1/projects/fireemu-35fe6/accounts:unknown"},
    ],
)
def test_production_owner_auth_post_requires_exact_authority(change):
    value = envelope("/v1/projects/fireemu-35fe6/accounts:lookup", owner=True)
    with pytest.raises(ValueError):
        worker.prepare_request({**value, **change}, fixture=False)


def test_all_frozen_credential_observation_posts_pass_production_validation():
    import credential_gate as gate

    for operation in gate.observation_operations(
        "fireemu-35fe6", "a" * 32, signing=True
    ):
        if not operation["path"].startswith("identitytoolkit.googleapis.com/"):
            continue
        owner = operation.get("owner") is True
        path = "/" + operation["path"].split("/", 1)[1]
        if not owner:
            path += "?key=fixture-key"
        value = envelope(path, owner=owner, body=json.dumps(operation["body"]))
        assert worker.prepare_request(value, fixture=False).get_method() == "POST"
