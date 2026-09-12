"""Current received HTTP is not silently promoted to historical compatibility."""

import copy
import subprocess

from broad_contract import ROOT
from current_contract import compare_current, received


def wire(kind="json"):
    return {
        "status": 200,
        "code": "OK",
        "body": {},
        "http": {
            "contract": "bounded-http-v1",
            "status": 200,
            "complete": True,
            "failure": None,
            "truncated": False,
            "digestScope": "full",
            "bodyKind": kind,
            "contentType": "application/json",
            "contentTypeTruncated": False,
            "receivedBytes": 2,
            "retainedBytes": 2,
            "bodySha256": "a" * 64,
        },
    }


def test_json_bridge_and_non_json_collection_are_separate():
    p = {"id": "p", "steps": [{"id": "read", "method": "GET", "path": "/v1/x"}]}
    got = wire()
    expected = {"read": {"production": {"status": 200, "code": "OK", "body": {}}}}

    def compare(v):
        return compare_current(p, p, {"steps": {"read": v}}, expected)[0]

    assert compare(got)["status"] == "match"
    changed = copy.deepcopy(got)
    changed["body"] = {"extra": True}
    assert compare(changed)["status"] == "mismatch"
    nonjson = wire("non-json")
    nonjson.pop("body")
    nonjson["code"] = "non-json"
    assert received(nonjson)
    row = compare(nonjson)
    assert row["collectionComplete"] and row["status"] == "indeterminate"
    assert row["reason"] == "no-compatible-historical-body-contract"
    for patch in [
        {"complete": False},
        {"truncated": True},
        {"failure": "timeout"},
        {"bodyKind": "unavailable"},
        {"retainedBytes": 1},
        {"bodySha256": None},
        {"contentTypeTruncated": True},
    ]:
        bad = copy.deepcopy(got)
        bad["http"].update(patch)
        assert not received(bad)
        assert compare(bad)["status"] == "indeterminate"
    assert not received({"status": 404, "code": "non-json"})


def test_current_json_normalizer_is_exact_legacy_source():
    old = (ROOT / "conformance/src/firestore-probe/session.mjs").read_text()
    current = (ROOT / "tools/compat-broad/current-session.mjs").read_text()

    def body(source):
        return source.split('function normalize(value, key = "") {', 1)[1].split(
            "\n}\n", 1
        )[0]

    assert body(old) == body(current)
    assert "clearThroughPublicApi" not in current
    assert "current recorder is local-only" in current


def test_actual_bounded_http_fixture():
    subprocess.run(
        ["node", "--test", str(ROOT / "tools/compat-broad/record-http.test.mjs")],
        check=True,
        capture_output=True,
        timeout=20,
    )


def test_received_nonjson_cannot_satisfy_json_state_readback():
    from second_cases import usable_readback

    name = "projects/demo-firestore-probe/databases/(default)/documents/cur/c"
    value = wire("non-json")
    value["body"] = {"name": name, "fields": {}}
    assert received(value)
    assert not usable_readback(value, name)


def test_current_execution_manifest_binds_separate_contract():
    import json

    from second_cases import execution_manifest

    assert (
        json.loads(
            (ROOT / "spec/compatibility/broad-second-http-candidate.json").read_text()
        )
        == execution_manifest()
    )
    assert execution_manifest()["productionApproval"] is None
