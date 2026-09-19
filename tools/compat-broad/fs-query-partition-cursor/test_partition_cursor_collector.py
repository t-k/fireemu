"""Contract tests for the bounded loopback-only partition/cursor collector."""

from __future__ import annotations

import hashlib
import json

import pytest
from partition_cursor_case import OBSERVATION_COUNT, RECOVERY_COUNT
from partition_cursor_collector import LOOPBACK_ORIGINS, collect_local
from partition_cursor_offline_fixture import TIME, Transport, partition_cursor, plan


def _reconstruction(result: dict) -> tuple[dict, dict]:
    rows = [
        row
        for row in result["rows"]
        if row["kind"].startswith("partition-reconstruction")
    ]
    assert len(rows) == 2
    return rows[0], rows[1]


def run(
    directory, *, transport: Transport | None = None, **kwargs
) -> tuple[dict, Transport]:
    value = plan()
    transport = transport or Transport(value)
    return collect_local(value, transport, directory, **kwargs), transport


def test_a_non_loopback_origin_sends_nothing(tmp_path) -> None:
    value = plan()
    transport = Transport(value)
    with pytest.raises(PermissionError):
        collect_local(
            value,
            transport,
            tmp_path / "out",
            origin="https://firestore.googleapis.com",
        )
    assert transport.sent == []
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("origin", sorted(LOOPBACK_ORIGINS))
def test_declared_loopback_origins_are_accepted(tmp_path, origin) -> None:
    result, _ = run(
        tmp_path / origin.replace(":", "-").replace("/", "_"), origin=origin
    )
    assert result["origin"] == origin


def test_an_unparsable_origin_sends_nothing(tmp_path) -> None:
    value = plan()
    transport = Transport(value)
    with pytest.raises(PermissionError):
        collect_local(value, transport, tmp_path / "out", origin="not an origin")
    assert transport.sent == []


def test_a_drifted_plan_sends_nothing(tmp_path) -> None:
    value = plan()
    value["observation"].pop()
    transport = Transport(value)
    with pytest.raises(ValueError):
        collect_local(value, transport, tmp_path / "out")
    assert transport.sent == []


def test_every_compiled_slot_is_sent_once_in_order(tmp_path) -> None:
    result, transport = run(tmp_path / "out")
    assert result["status"] == "pass"
    assert len(result["rows"]) == OBSERVATION_COUNT
    assert len(result["cleanup"]["rows"]) == RECOVERY_COUNT
    value = plan()
    expected = [operation["kind"] for operation in value["observation"]]
    reconstruction = {
        "partition-page-token-continuation",
        "partition-reconstruction-range-1",
    }
    assert [request["kind"] for request in transport.sent] == [
        kind for kind in expected if kind not in reconstruction
    ] + [operation["kind"] for operation in value["recovery"]]


def test_rows_record_the_request_that_was_actually_sent(tmp_path) -> None:
    result, _transport = run(tmp_path / "out")
    for row in result["rows"]:
        if row["status"] != "skipped":
            assert row["request"]["path"].startswith("/v1/")
            assert row["request"]["kind"] == row["kind"]


def test_the_continuation_is_skipped_without_a_next_page_token(tmp_path) -> None:
    result, transport = run(tmp_path / "out")
    row = result["rows"][8]
    assert row["kind"] == "partition-page-token-continuation"
    assert row["status"] == "skipped"
    assert row["skipReason"] == "no-page-token"
    assert all("pageToken" not in (request["body"] or {}) for request in transport.sent)


def test_a_recorded_next_page_token_is_substituted_exactly(tmp_path) -> None:
    value = plan()
    transport = Transport(value, page_token="opaque-token")
    result = collect_local(value, transport, tmp_path / "out")
    row = result["rows"][8]
    assert row["status"] == "pass"
    assert row["request"]["body"]["pageToken"] == "opaque-token"
    assert row["boundFrom"] == {"pageTokenFrom": 7}


def test_zero_partitions_use_one_reconstruction_slot(tmp_path) -> None:
    result, _ = run(tmp_path / "out")
    first, second = _reconstruction(result)
    assert first["status"] == "pass"
    assert "startAt" not in first["request"]["body"]["structuredQuery"]
    assert "endAt" not in first["request"]["body"]["structuredQuery"]
    assert second["status"] == "skipped"
    assert second["skipReason"] == "range-not-required"


def test_one_partition_binds_both_reconstruction_ranges(tmp_path) -> None:
    value = plan()
    transport = Transport(value, partitions=1)
    result = collect_local(value, transport, tmp_path / "out")
    first, second = _reconstruction(result)
    cursor = partition_cursor(value["ownedResources"][2])
    assert first["request"]["body"]["structuredQuery"]["endAt"] == cursor
    assert "startAt" not in first["request"]["body"]["structuredQuery"]
    assert second["request"]["body"]["structuredQuery"]["startAt"] == cursor
    assert "endAt" not in second["request"]["body"]["structuredQuery"]


def test_more_partitions_than_slots_send_no_reconstruction_request(tmp_path) -> None:
    value = plan()
    transport = Transport(value, partitions=3)
    result = collect_local(value, transport, tmp_path / "out")
    for row in _reconstruction(result):
        assert row["status"] == "skipped"
        assert row["skipReason"] == "reconstruction-slots-exceeded"
    assert not any(
        request["kind"].startswith("partition-reconstruction")
        for request in transport.sent
    )
    assert result["status"] == "incomplete"


def test_cleanup_deletes_carry_the_recorded_creation_versions(tmp_path) -> None:
    result, transport = run(tmp_path / "out")
    deletes = [
        request
        for request in transport.sent
        if request["kind"] == "cleanup-seed-delete"
    ]
    assert len(deletes) == 1
    writes = deletes[0]["body"]["writes"]
    assert len(writes) == 20
    for write in writes:
        assert write["currentDocument"] == {"updateTime": TIME}
    root = [
        request
        for request in transport.sent
        if request["kind"] == "cleanup-root-delete"
    ]
    assert root[0]["path"].endswith("?currentDocument.updateTime=" + TIME)
    assert result["cleanup"]["complete"] is True


def test_cleanup_is_skipped_when_this_run_never_created_the_root(tmp_path) -> None:
    value = plan()
    transport = Transport(value)
    transport.create_status = 409
    result = collect_local(value, transport, tmp_path / "out")
    kinds = [request["kind"] for request in transport.sent]
    assert "cleanup-seed-delete" not in kinds
    assert "cleanup-root-delete" not in kinds
    assert result["cleanup"]["complete"] is False
    assert result["cleanup"]["rows"][1]["skipReason"] == "no-current-run-ownership"


def test_cleanup_is_skipped_when_the_seed_receipt_is_not_version_bound(
    tmp_path,
) -> None:
    value = plan()
    transport = Transport(value)
    transport.write_results = 19
    result = collect_local(value, transport, tmp_path / "out")
    assert "cleanup-seed-delete" not in [request["kind"] for request in transport.sent]
    assert result["cleanup"]["rows"][1]["skipReason"] == "unbound-write-versions"


def test_a_transport_failure_stops_sending_but_still_attempts_cleanup(tmp_path) -> None:
    value = plan()
    transport = Transport(value)
    transport.fail_at = 5
    result = collect_local(value, transport, tmp_path / "out")
    assert result["status"] == "incomplete"
    assert result["rows"][5]["status"] == "failed"
    assert result["rows"][5]["failure"] == "ConnectionError"
    assert [row["status"] for row in result["rows"][6:]] == ["skipped"] * (
        OBSERVATION_COUNT - 6
    )
    assert "cleanup-seed-delete" in [request["kind"] for request in transport.sent]


def test_a_refused_observation_is_recorded_as_a_pass_against_its_expectation(
    tmp_path,
) -> None:
    result, _ = run(tmp_path / "out")
    refusals = [
        row
        for row in result["rows"]
        if plan()["observation"][row["index"]]["expect"].get("outcome") == "refused"
    ]
    assert len(refusals) == 11
    for row in refusals:
        assert row["status"] == "pass"
        assert row["receipt"]["status"] == 400


def test_raw_sidecars_are_published_with_verified_digests(tmp_path) -> None:
    directory = tmp_path / "out"
    result, _ = run(directory)
    manifest = json.loads((directory / "raw" / "manifest.json").read_bytes())
    assert result["raw"]["complete"] is True
    assert len(manifest["bindings"]) == len(
        [row for row in result["rows"] if row["status"] != "skipped"]
    ) + len([row for row in result["cleanup"]["rows"] if row["status"] != "skipped"])
    for binding in manifest["bindings"]:
        payload = (directory / "raw" / binding["path"]).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == binding["sha256"]
        assert binding["byteCount"] == len(payload)


def test_absent_transport_bytes_are_never_reconstructed_from_the_decoded_body(
    tmp_path,
) -> None:
    value = plan()
    transport = Transport(value)
    transport.raw = False
    directory = tmp_path / "out"
    result = collect_local(value, transport, directory)
    assert result["raw"]["complete"] is False
    assert result["raw"]["bindings"] == 0
    assert not (directory / "raw").exists() or not list(
        (directory / "raw").glob("*.raw")
    )


def test_an_oversized_raw_response_is_recorded_as_incomplete_evidence(tmp_path) -> None:
    value = plan()

    class Oversized(Transport):
        def __call__(self, request: dict) -> dict:
            receipt = super().__call__(request)
            receipt["rawBody"] = b"x" * 70000
            receipt["byteCount"] = 70000
            return receipt

    result = collect_local(value, Oversized(value), tmp_path / "out")
    assert result["raw"]["complete"] is False
    assert result["status"] == "incomplete"


def test_published_rows_match_the_returned_result(tmp_path) -> None:
    directory = tmp_path / "out"
    result, _ = run(directory)
    published = json.loads((directory / "collection.json").read_bytes())
    assert published == result


def test_an_existing_output_directory_is_refused(tmp_path) -> None:
    directory = tmp_path / "out"
    directory.mkdir()
    value = plan()
    transport = Transport(value)
    with pytest.raises(FileExistsError):
        collect_local(value, transport, directory)
    assert transport.sent == []


def test_the_result_is_never_marked_production(tmp_path) -> None:
    result, _ = run(tmp_path / "out")
    assert result["productionExecuted"] is False
    assert result["promotionReady"] is False
    assert result["campaignId"] == plan()["campaignId"]
    assert result["planDigest"] == plan()["planDigest"]


def test_cleanup_is_skipped_when_the_ownership_read_does_not_return_our_document(
    tmp_path,
) -> None:
    value = plan()

    class Replaced(Transport):
        def _body(self, request: dict) -> tuple[int, dict]:
            status, body = super()._body(request)
            if request["kind"] == "cleanup-ownership-read":
                body = dict(body, fields={"marker": {"stringValue": "someone-else"}})
            return status, body

    transport = Replaced(value)
    result = collect_local(value, transport, tmp_path / "out")
    kinds = [request["kind"] for request in transport.sent]
    assert "cleanup-seed-delete" not in kinds
    assert "cleanup-root-delete" not in kinds
    assert result["cleanup"]["rows"][1]["skipReason"] == "no-current-run-ownership"
    assert result["cleanup"]["rows"][2]["skipReason"] == "no-current-run-ownership"


def test_the_reconstruction_ranges_are_verified_against_the_baseline(tmp_path) -> None:
    value = plan()
    result = collect_local(value, Transport(value, partitions=1), tmp_path / "out")
    assert result["reconstruction"]["checked"] is True
    assert result["reconstruction"]["matches"] is True
    assert result["reconstruction"]["ranges"] == 2
    assert result["reconstruction"]["documents"] == 12


def test_a_single_range_still_reconstructs_the_whole_baseline(tmp_path) -> None:
    result, _ = run(tmp_path / "out")
    assert result["reconstruction"] == {
        "checked": True,
        "matches": True,
        "ranges": 1,
        "documents": 12,
        "reason": None,
    }


def test_ranges_that_do_not_rebuild_the_baseline_fail_the_run(tmp_path) -> None:
    value = plan()

    class Truncated(Transport):
        def _body(self, request: dict) -> tuple[int, dict]:
            status, body = super()._body(request)
            if request["kind"] == "partition-reconstruction-range-0":
                body = body[:2]
            return status, body

    result = collect_local(value, Truncated(value), tmp_path / "out")
    assert result["reconstruction"]["matches"] is False
    assert result["status"] == "incomplete"


def test_no_dispatched_range_leaves_the_reconstruction_unchecked(tmp_path) -> None:
    value = plan()
    result = collect_local(value, Transport(value, partitions=3), tmp_path / "out")
    assert result["reconstruction"]["checked"] is False
    assert result["reconstruction"]["reason"] == "no-dispatched-range"
    assert result["status"] == "incomplete"


def test_a_404_ownership_read_does_not_authorize_the_deletes(tmp_path) -> None:
    value = plan()

    class Vanished(Transport):
        def _body(self, request: dict) -> tuple[int, dict]:
            if request["kind"] == "cleanup-ownership-read":
                return 404, {"error": {"status": "NOT_FOUND", "code": 404}}
            return super()._body(request)

    transport = Vanished(value)
    result = collect_local(value, transport, tmp_path / "out")
    kinds = [request["kind"] for request in transport.sent]
    assert "cleanup-seed-delete" not in kinds
    assert "cleanup-root-delete" not in kinds
    assert result["cleanup"]["rows"][1]["skipReason"] == "no-current-run-ownership"


def test_an_unreadable_sidecar_still_publishes_the_receipt(tmp_path) -> None:
    import os

    directory = tmp_path / "out"
    value = plan()

    class Removing(Transport):
        def __call__(self, request: dict) -> dict:
            receipt = super().__call__(request)
            target = directory / "raw" / "observation-00.raw"
            if len(self.sent) > 3 and target.exists():
                os.chmod(target, 0o000)
                target.unlink()
            return receipt

    result = collect_local(value, Removing(value), directory)
    assert (directory / "collection.json").is_file()
    assert result["raw"]["complete"] is False
    assert result["status"] == "incomplete"
    assert json.loads((directory / "collection.json").read_bytes()) == result


def test_a_throwing_sidecar_verification_marks_the_publication_incomplete(
    tmp_path, monkeypatch
) -> None:
    import partition_cursor_collector as module

    def explode(raw_fd, bindings):
        raise OSError("sidecar unreadable")

    monkeypatch.setattr(module, "_verify_raw", explode)
    result, _ = run(tmp_path / "out")
    assert result["publication"]["complete"] is False
    assert result["publication"]["failures"][0]["file"] == "raw"
    assert result["raw"]["complete"] is False
    assert result["status"] == "incomplete"
