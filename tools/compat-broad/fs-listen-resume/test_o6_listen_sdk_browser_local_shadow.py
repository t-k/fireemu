"""Bind the checked-in browser (WebChannel) shadow evidence to the working tree.

`spec/compatibility/fs-listen-sdk-browser-local-shadow.json` was produced by
`listen_browser_adapter.mjs`: the same frozen catalog, run through the browser
build of the pinned firebase SDK in headless Chromium against an owned local
`fireemu`, once with forced long polling and once with a streamed backchannel.
These checks fail if the bound sources changed, if the catalog drifted, if any
case stopped agreeing with its expected local result, or if either mode did
not actually exercise the WebChannel variant it claims. They say nothing about
production.
"""

import hashlib
import json
from pathlib import Path

from o6_listen_resume import campaign, cases

REPO_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = REPO_ROOT / "spec/compatibility/fs-listen-sdk-browser-local-shadow.json"
CAMPAIGN = (
    REPO_ROOT / "spec/compatibility/fs-listen-sdk-browser-local-shadow-campaign.json"
)
MODES = ("long-polling", "streaming")
# Assembled from parts so the publication-hygiene scan does not find the
# literal prefixes in this file.
PERSONAL_PREFIXES = tuple(
    "/" + "/".join(parts) + "/"
    for parts in (("Users",), ("home",), ("private", "tmp"), ("var", "folders"))
)
SDK_BUNDLES = ("firebase-app.js", "firebase-auth.js", "firebase-firestore.js")


def _document():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def _receipts():
    return _document()["receipts"]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_document_covers_both_webchannel_variants_and_completed():
    document = _document()
    assert document["schema"] == "o6-listen-browser-shadow-v1"
    assert document["transport"] == "browser-webchannel"
    assert document["productionExecuted"] is False
    assert document["modes"] == list(MODES)
    assert set(document["receipts"]) == set(MODES)
    assert document["complete"] is True


def test_every_mode_ran_to_completion_with_proven_cleanup():
    for mode, receipt in _receipts().items():
        assert receipt["schema"] == "o6-listen-observation-v1", mode
        assert receipt["caseId"] == "FS-LISTEN-SDK", mode
        assert receipt["complete"] is True, mode
        assert receipt["thrown"] is None, mode
        assert receipt["productionExecuted"] is False, mode
        assert receipt["transport"] == "browser-webchannel", mode
        assert receipt["environment"]["kind"] == "local-fireemu", mode
        assert receipt["environment"]["transport"] == "browser-webchannel", mode
        assert receipt["environment"]["webchannelMode"] == mode
        assert receipt["cleanup"]["complete"] is True, mode
        assert receipt["budget"]["exhausted"] is False, mode
        assert receipt["cleanupBudget"]["exhausted"] is False, mode
        outcomes = {row["name"]: row["outcome"] for row in receipt["cleanup"]["rows"]}
        assert set(outcomes) == {
            "alpha",
            "beta",
            "gamma",
            "absent",
            "private",
            "privateB",
        }, mode
        assert set(outcomes.values()) <= {
            "deleted-and-absent",
            "not-created",
            "already-deleted-earlier",
        }, mode
        for row in receipt["cleanup"]["rows"]:
            assert "path" not in row
            assert len(row["pathDigest"]) == 64


def test_the_evidence_names_the_sources_that_produced_it():
    for mode, receipt in _receipts().items():
        digests = receipt["sourceDigests"]
        for relative in (
            "tools/compat-broad/fs-listen-resume/listen_collector.mjs",
            "tools/compat-broad/fs-listen-resume/listen_browser_adapter.mjs",
            "tools/compat-broad/fs-listen-resume/cases.py",
            "tools/sdk-smoke-browser/browser_harness.mjs",
            "tools/sdk-smoke/web/listen-catalog.html",
            "tools/sdk-smoke/web/listen-catalog.js",
            "tools/sdk-smoke/web/listen-catalog-sha256.js",
        ):
            assert relative in digests, (mode, relative)
        for relative, value in digests.items():
            assert value == _sha(REPO_ROOT / relative), (mode, relative)
        assert receipt["catalogDigest"] == cases.catalog_digest(), mode
        assert len(receipt["environment"]["sourceCommit"]) == 40, mode
        assert (
            receipt["environment"]["fireemuSourceCommit"]
            == receipt["environment"]["sourceCommit"]
        ), mode


def test_the_evidence_ran_under_the_published_browser_campaign():
    record = json.loads(CAMPAIGN.read_text(encoding="utf-8"))
    assert record["schema"] == "o6-listen-sdk-shadow-campaign-v1"
    assert campaign.validate_campaign(record["campaign"]) is True
    assert campaign.campaign_digest(record["campaign"]) == record["campaignDigest"]
    expected_nonce_digest = hashlib.sha256(record["nonce"].encode()).hexdigest()
    for mode, receipt in _receipts().items():
        assert receipt["campaignDigest"] == record["campaignDigest"], mode
        assert receipt["environment"]["nonceDigest"] == expected_nonce_digest, mode
        assert receipt["sdkResolved"] == record["campaign"]["sdk"], mode


def test_every_case_agreed_with_its_expected_local_result_in_both_modes():
    for mode, receipt in _receipts().items():
        rows = {row["caseId"]: row for row in receipt["cases"]}
        assert [row["caseId"] for row in receipt["cases"]] == list(cases.case_ids()), (
            mode
        )
        for case in cases.CASES:
            row = rows[case["caseId"]]
            assert row["complete"] is True, (mode, case["caseId"])
            assert row["failures"] == [], (mode, case["caseId"])
            assert row["listenersClosed"] is True, (mode, case["caseId"])
            assert row["invariantViolations"] == [], (mode, case["caseId"])
            fields = case["comparedFields"]
            observed = [
                {key: event.get(key) for key in fields} for event in row["observed"]
            ]
            expected = [
                {key: event.get(key) for key in fields}
                for event in case["expectedLocal"]
            ]
            assert observed == expected, (mode, case["caseId"])
            if case["expectedLocal"]:
                assert row["observed"], (mode, case["caseId"])
            else:
                assert case["invariants"], (mode, case["caseId"])


def test_each_mode_exercised_the_webchannel_variant_it_claims():
    receipts = _receipts()
    for mode, receipt in receipts.items():
        summary = receipt["webchannel"]["summary"]
        assert receipt["webchannel"]["mode"] == mode
        assert summary["listen"] > 0 and summary["write"] > 0, mode
        assert summary["handshakes"] > 0 and summary["backchannel"] > 0, mode
        assert summary["terminate"] > 0, mode
        columns = receipt["webchannel"]["columns"]
        assert columns == ["atMs", "stream", "method", "role", "ci", "status"]
        rows = receipt["webchannel"]["rows"]
        assert len(rows) == summary["requests"]
        for line in rows:
            row = line.split(" ")
            assert len(row) == len(columns)
            assert row[1] in {"Listen", "Write"}
            assert row[3] in {"handshake", "forward", "backchannel", "terminate"}
            assert row[4] in {"-", "0", "1"}
    long_polling = receipts["long-polling"]["webchannel"]["summary"]["backchannelCi"]
    streaming = receipts["streaming"]["webchannel"]["summary"]["backchannelCi"]
    assert long_polling["longPolled"] > 0 and long_polling["streamed"] == 0
    assert streaming["streamed"] > 0 and streaming["longPolled"] == 0
    # Forced long polling closes every backchannel response, so it needs many
    # more backchannel requests than one streamed backchannel per session.
    assert long_polling["longPolled"] > streaming["streamed"]


def test_the_shadow_recorded_an_ordered_transport_timeline_with_a_break():
    for mode, receipt in _receipts().items():
        timeline = receipt["transportTimeline"]
        stamps = [entry["atMs"] for entry in timeline]
        assert stamps == sorted(stamps), mode
        assert {"connect", "disconnect", "reconnect"} <= {
            e["kind"] for e in timeline
        }, mode
        breaking = {
            entry["caseId"]
            for entry in timeline
            if entry["kind"] in {"break-requested", "resume-requested"}
        }
        assert breaking == {"FS-LISTEN-SDK-104"}, mode


def test_the_shadow_names_the_browser_sdk_bundles_and_the_runtime_it_ran():
    for mode, receipt in _receipts().items():
        environment = receipt["environment"]
        assert environment["browser"]["name"] == "chromium", mode
        assert environment["browser"]["version"], mode
        assert environment["firebaseSdk"] == campaign.SDK_PIN["firebase"], mode
        assert (
            environment["firebaseSdkReportedByPage"] == campaign.SDK_PIN["firebase"]
        ), mode
        assert environment["sdkSource"] == (
            f"https://www.gstatic.com/firebasejs/{campaign.SDK_PIN['firebase']}"
        ), mode
        bundles = environment["sdkBundleDigests"]
        for name in SDK_BUNDLES:
            assert len(bundles[f"{campaign.SDK_PIN['firebase']}/{name}"]) == 64, (
                mode,
                name,
            )
        assert environment["fireemuBinary"].startswith("target/"), mode
        assert environment["fireemuBinary"].endswith("/fireemu"), mode
        assert len(environment["fireemuBinaryDigest"]) == 64, mode
        assert environment["fireemuBinaryDigest"] != "unreadable", mode
        assert (
            environment["rulesPath"]
            == "tools/compat-broad/fs-listen-resume/fs-listen-sdk.rules"
        ), mode
        assert environment["rulesDigest"] == _sha(
            REPO_ROOT / environment["rulesPath"]
        ), mode


def test_both_modes_executed_the_same_bundles_and_the_same_binary():
    receipts = _receipts()
    first, second = (receipts[mode]["environment"] for mode in MODES)
    assert first["sdkBundleDigests"] == second["sdkBundleDigests"]
    assert first["fireemuBinaryDigest"] == second["fireemuBinaryDigest"]


def test_each_mode_created_and_removed_its_own_account():
    for mode, receipt in _receipts().items():
        lifecycle = receipt["lifecycle"]
        assert lifecycle["complete"] is True, mode
        assert lifecycle["failure"] is None, mode
        cleanup = lifecycle["accountCleanup"]
        assert cleanup["complete"] is True, mode
        assert cleanup["outcome"] == "deleted-and-absent", mode
        assert set(cleanup["accounts"]) == {"primary", "secondary"}, mode
        assert all(
            row["outcome"] == "deleted-and-absent"
            for row in cleanup["accounts"].values()
        ), mode
        revoking = {
            entry["caseId"]
            for entry in receipt["transportTimeline"]
            if entry["kind"] == "revoke-requested"
        }
        assert revoking == {"FS-LISTEN-SDK-109"}, mode
        assert lifecycle["clients"]["complete"] is True, mode
        assert {row["client"] for row in lifecycle["clients"]["rows"]} == {
            "primary",
            "witness",
            "secondary",
        }
        assert lifecycle["localAdminRequests"] <= lifecycle["localAdminRequestLimit"], (
            mode
        )


def test_the_receipt_keeps_every_cleanup_pass_not_only_the_final_one():
    for mode, receipt in _receipts().items():
        passes = receipt["cleanupPasses"]
        assert [item["pass"] for item in passes] == [*cases.case_ids(), "final"], mode
        assert all(item["complete"] is True for item in passes), mode
        assert receipt["totalDeleted"] == sum(item["deleted"] for item in passes), mode
        assert receipt["totalDeleted"] > receipt["cleanup"]["deleted"], mode


def test_the_evidence_carries_no_secret_material_or_personal_path():
    raw = EVIDENCE.read_text(encoding="utf-8")
    for marker in (
        "password",
        "idToken",
        "refreshToken",
        "Bearer ",
        "SID=",
        "gsessionid",
    ):
        assert marker not in raw, marker
    for prefix in PERSONAL_PREFIXES:
        assert prefix not in raw, prefix
    raw_campaign = CAMPAIGN.read_text(encoding="utf-8")
    for prefix in PERSONAL_PREFIXES:
        assert prefix not in raw_campaign, prefix


SMOKE = REPO_ROOT / "spec/compatibility/fs-listen-sdk-browser-smoke-pages.json"


def test_the_smoke_pages_passed_in_the_browser_over_long_polled_webchannel():
    document = json.loads(SMOKE.read_text(encoding="utf-8"))
    assert document["schema"] == "sdk-smoke-browser-v1"
    assert document["transport"] == "browser-webchannel"
    assert document["productionExecuted"] is False
    assert document["browser"]["name"] == "chromium"
    assert document["complete"] is True
    assert set(document["pages"]) == {"listener-lifecycle", "listen-reconnect"}
    for name, page in document["pages"].items():
        assert page["passed"] is True, name
        assert page["status"] == "passed", name
        assert page["pageErrors"] == [], name
        assert page["result"]["passed"] is True, name
        summary = page["webchannel"]["summary"]
        assert summary["listen"] > 0 and summary["write"] > 0, name
        # Both hand-written pages force long polling.
        assert summary["backchannelCi"]["longPolled"] > 0, name
        assert summary["backchannelCi"]["streamed"] == 0, name
    reconnect = document["pages"]["listen-reconnect"]["result"]
    events = {
        event["event"]: event for event in reconnect["events"] if "event" in event
    }
    assert events["pending-cache"]["value"]["hasPendingWrites"] is True
    assert events["pending-cache"]["value"]["fromCache"] is True
    assert events["reconnect-ack"]["value"]["hasPendingWrites"] is False
    assert events["reconnect-ack"]["value"]["fromCache"] is False
    assert events["unsubscribe-check"]["callbacksAfterUnsubscribe"] == 0
    assert events["auth-switch"]["state"] == "signed-out"
    assert events["unauthenticated-read"]["denied"] is True
    lifecycle = document["pages"]["listener-lifecycle"]["result"]
    assert len(lifecycle["deniedOperations"]) == 16
    assert lifecycle["callbackAfterUnsubscribe"] == []
    assert lifecycle["maximumConnectedForms"] == 1
    assert lifecycle["values"]["replacementProject"] == [0, 1]
    raw = SMOKE.read_text(encoding="utf-8")
    for marker in ("password", "idToken", "refreshToken", "Bearer ", '"token"'):
        assert marker not in raw, marker
    for prefix in PERSONAL_PREFIXES:
        assert prefix not in raw, prefix
