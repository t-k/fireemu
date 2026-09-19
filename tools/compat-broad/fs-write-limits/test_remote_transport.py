"""Offline remote admission tests; never contact a production endpoint."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from compiler import compile_limits_plan
from remote_transport import _request, prepare, request

NONCE = "a" * 32
TOKEN = "synthetic-test-token"


def payload(index=4, phase="observation"):
    plan = compile_limits_plan("fireemu-35fe6", "(default)", NONCE)
    operation = copy.deepcopy(plan["localGatePlan"]["jobs"]["limits"][phase][index])
    return {
        "nonce": NONCE,
        "phase": phase,
        "index": index,
        "operation": operation,
        "token": TOKEN,
    }


def test_fixed_origin_caps_and_header_binding():
    value = payload()
    prepared = prepare(value)
    assert prepared["url"].startswith(
        "https://firestore.googleapis.com/v1/projects/fireemu-35fe6/databases/(default)/documents/oracle/"
    )
    assert len(prepared["data"]) > 16384
    assert prepared["headers"]["Authorization"] == "Bearer " + TOKEN
    assert prepared["headers"]["x-goog-user-project"] == "fireemu-35fe6"
    assert 65536 < prepared["response_cap"] <= 2 * 1024 * 1024


@pytest.mark.parametrize(
    "change",
    [
        "host",
        "path",
        "project",
        "body",
        "method",
        "privileged",
        "token",
        "nonce",
        "index",
        "phase",
        "cap",
    ],
)
def test_unbound_input_is_refused_without_worker_or_network(change):
    value = payload()
    if change == "host":
        value["origin"] = "https://attacker.invalid"
    elif change == "path":
        value["operation"]["path"] = "//attacker.invalid/v1/x"
    elif change == "project":
        value["operation"]["path"] = value["operation"]["path"].replace(
            "fireemu-35fe6", "other"
        )
    elif change == "body":
        value["operation"]["body"]["fields"]["blob"] = {"stringValue": "wrong"}
    elif change == "method":
        value["operation"]["method"] = "POST"
    elif change == "privileged":
        value["operation"]["privileged"] = 1
    elif change == "token":
        value["token"] = "secret\r\nInjected: header"
    elif change == "nonce":
        value["nonce"] = "old"
    elif change == "index":
        value["index"] = True
    elif change == "phase":
        value["phase"] = "unknown"
    else:
        value["response_cap"] = 1000000000
    with pytest.raises(ValueError):
        prepare(value)


def test_recovery_delete_requires_bound_version_query():
    value = payload(1, "recovery")
    value["operation"].pop("versionFrom")
    with pytest.raises(ValueError):
        prepare(value)
    value["operation"]["path"] += "?currentDocument.updateTime=2026-09-17T00%3A00%3A00Z"
    assert prepare(value)["method"] == "DELETE"
    value["operation"]["path"] += "&unexpected=true"
    with pytest.raises(ValueError):
        prepare(value)


def test_direct_worker_revalidates_and_never_prints_input_secrets():
    value = payload()
    value["operation"]["path"] = "//attacker.invalid/"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(__file__).with_name("remote_transport.py")),
            "--worker",
        ],
        input=json.dumps(value),
        text=True,
        capture_output=True,
        env={},
        timeout=5,
        check=False,
    )
    assert result.returncode != 0
    assert TOKEN not in result.stdout + result.stderr
    assert result.stdout == ""
    assert result.stderr == ""


def test_direct_production_request_requires_private_admission():
    with pytest.raises(TypeError, match="bridge-only"):
        request(payload())
    with pytest.raises(TypeError, match="active production bridge session"):
        _request(payload())
