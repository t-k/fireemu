"""Durable responsibility is recorded before dispatch and contains no credentials."""

import base64
import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_expiry_collector as collector
from test_txn_expiry_collector import Endpoint, LostCreateResponseEndpoint, advances, options


def run(endpoint, observer):
    return collector.collect(options(), endpoint, advance=advances([]), responsibility=observer)


def test_dispatch_has_prior_intent_and_creation_responsibility():
    snapshots = []
    endpoint = Endpoint()

    def transport(request):
        snapshot = snapshots[-1]
        assert snapshot["event"] == "dispatch-intent"
        assert snapshot["requestCount"] == len(endpoint.calls)
        assert snapshot["inFlight"]["ordinal"] == len(endpoint.calls) + 1
        assert snapshot["inFlight"]["site"] == request["site"]
        if request["site"].startswith("setup/create/"):
            role = request["site"].split("/")[-1]
            assert snapshot["resourceStates"][role] == collector.SENT_UNKNOWN
        if request["rpc"] == "BeginTransaction":
            assert snapshot["pendingBegins"]
        return endpoint(request)

    receipt = run(transport, snapshots.append)
    assert len([s for s in snapshots if s["event"] == "dispatch-intent"]) == receipt["requestCount"]
    assert [s["sequence"] for s in snapshots] == list(range(1, len(snapshots) + 1))
    assert snapshots[0]["event"] == "prepared"
    assert snapshots[-1]["event"] == "finished"
    for snapshot in snapshots:
        assert snapshot["authorizesCleanup"] is False
        assert snapshot["authorizesResume"] is False
    serialized = json.dumps(snapshots)
    for issued in range(1, endpoint.issued + 1):
        raw = f"token-{issued}"
        assert raw not in serialized
        assert base64.b64encode(raw.encode()).decode() not in serialized


def test_initial_writer_failure_sends_nothing_and_cannot_report_complete():
    endpoint = Endpoint()

    def fail(_snapshot):
        raise OSError("credential-secret-must-not-be-saved")

    receipt = run(endpoint, fail)
    assert endpoint.calls == []
    assert receipt["requestCount"] == 0
    assert receipt["complete"] is False
    assert receipt["responsibilityJournalFailure"] == "OSError"
    assert "credential-secret" not in json.dumps(receipt)


def test_writer_failure_after_begin_response_stops_all_later_sends():
    endpoint = Endpoint()
    saved = []
    failed_at = []

    def observe(snapshot):
        if snapshot["event"] == "response-received" and snapshot["inFlight"]["rpc"] == "BeginTransaction":
            failed_at.append(len(endpoint.calls))
            raise OSError("disk-full")
        saved.append(copy.deepcopy(snapshot))

    receipt = run(endpoint, observe)
    assert failed_at and len(endpoint.calls) == failed_at[0]
    assert saved[-1]["event"] == "dispatch-intent"
    assert saved[-1]["pendingBegins"]
    assert receipt["complete"] is False
    assert receipt["unconfirmedTransactionStarts"]


@pytest.mark.parametrize("stop_at", ["create", "begin"])
def test_abrupt_transport_exit_leaves_conservative_last_snapshot(stop_at):
    endpoint = Endpoint()
    saved = []

    class AbruptExit(BaseException):
        pass

    def transport(request):
        if ((stop_at == "create" and request["site"].startswith("setup/create/")) or
                (stop_at == "begin" and request["rpc"] == "BeginTransaction")):
            raise AbruptExit()
        return endpoint(request)

    with pytest.raises(AbruptExit):
        run(transport, lambda s: saved.append(copy.deepcopy(s)))
    assert saved[-1]["event"] == "dispatch-intent"
    if stop_at == "create":
        assert collector.SENT_UNKNOWN in saved[-1]["resourceStates"].values()
    else:
        assert saved[-1]["pendingBegins"]


def test_observer_cannot_mutate_live_resource_state():
    endpoint = Endpoint()

    def mutate(snapshot):
        snapshot["resourceStates"].clear()
        snapshot["pendingBegins"].clear()
        snapshot["openTransactions"].clear()

    observed = run(endpoint, mutate)
    baseline = collector.collect(options(), Endpoint(), advance=advances([]))
    assert observed["resourceStates"] == baseline["resourceStates"]
    assert observed["requestCount"] == baseline["requestCount"]
    assert observed["unrecovered"] == baseline["unrecovered"]


def test_final_writer_failure_prevents_success_even_after_cleanup():
    endpoint = Endpoint()

    def observe(snapshot):
        if snapshot["event"] == "finished":
            raise OSError("finish-fsync")

    receipt = run(endpoint, observe)
    assert receipt["complete"] is False
    assert receipt["responsibilityJournalFailure"] == "OSError"
    assert receipt["failure"] == "responsibility-journal-failed"


def test_cleanup_snapshot_failure_does_not_duplicate_resource_receipts():
    def observe(snapshot):
        if snapshot["event"] == "cleanup-result":
            raise OSError("cleanup-fsync")

    receipt = run(Endpoint(), observe)
    roles = [entry["role"] for entry in receipt["cleanup"]]
    assert len(roles) == len(set(roles))
    assert receipt["complete"] is False


def test_private_journal_publishes_bounded_write_once_snapshots(tmp_path):
    import txn_expiry_shadow as shadow

    observer = shadow.make_responsibility_journal(tmp_path)
    receipt = run(Endpoint(), observer)
    paths = sorted((tmp_path / "responsibility").glob("*.json"))
    assert paths and len(paths) < shadow.MAX_RESPONSIBILITY_ENTRIES
    values = [json.loads(path.read_text()) for path in paths]
    assert [v["sequence"] for v in values] == list(range(1, len(values) + 1))
    assert values[-1]["event"] == "finished"
    assert values[-1]["requestCount"] == receipt["requestCount"]
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in paths)
    assert (tmp_path / "responsibility").stat().st_mode & 0o777 == 0o700
    with pytest.raises(ValueError, match="sequence"):
        observer(values[0])
    assert paths[0].read_text() == json.dumps(values[0], indent=2, sort_keys=True) + "\n"


def test_private_journal_refuses_existing_or_linked_directory(tmp_path):
    import txn_expiry_shadow as shadow

    target = tmp_path / "responsibility"
    target.mkdir()
    with pytest.raises(FileExistsError):
        shadow.make_responsibility_journal(tmp_path)
    target.rmdir()
    target.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(FileExistsError):
        shadow.make_responsibility_journal(tmp_path)


def test_private_journal_bound_stops_before_an_unrecorded_request(tmp_path, monkeypatch):
    import txn_expiry_shadow as shadow

    monkeypatch.setattr(shadow, "MAX_RESPONSIBILITY_ENTRIES", 2)
    endpoint = Endpoint()
    receipt = run(endpoint, shadow.make_responsibility_journal(tmp_path))
    assert len(endpoint.calls) == 1
    assert receipt["complete"] is False
    assert len(list((tmp_path / "responsibility").glob("*.json"))) == 2


def test_private_journal_size_limit_precedes_publication(tmp_path, monkeypatch):
    import txn_expiry_shadow as shadow

    monkeypatch.setattr(shadow, "MAX_RESPONSIBILITY_BYTES", 1)
    endpoint = Endpoint()
    receipt = run(endpoint, shadow.make_responsibility_journal(tmp_path))
    assert endpoint.calls == []
    assert receipt["complete"] is False
    assert not list((tmp_path / "responsibility").glob("*.json"))


def test_size_bound_includes_pretty_printing_and_final_newline(tmp_path, monkeypatch):
    import txn_expiry_shadow as shadow

    values = []
    run(Endpoint(), values.append)
    first = values[0]
    compact_size = len(json.dumps(first, sort_keys=True).encode("utf-8"))
    monkeypatch.setattr(shadow, "MAX_RESPONSIBILITY_BYTES", compact_size)
    with pytest.raises(ValueError, match="exceeds limit"):
        shadow.make_responsibility_journal(tmp_path)(first)
    assert not list((tmp_path / "responsibility").glob("*.json"))


def test_journal_directory_is_synced_before_dispatch(tmp_path, monkeypatch):
    import os
    import txn_expiry_shadow as shadow

    synced = []
    original = os.fsync

    def sync(descriptor):
        synced.append(os.fstat(descriptor).st_ino)
        return original(descriptor)

    monkeypatch.setattr(os, "fsync", sync)
    shadow.make_responsibility_journal(tmp_path)
    assert synced == [tmp_path.stat().st_ino]


def test_journal_directory_sync_failure_aborts_setup(tmp_path, monkeypatch):
    import os
    import txn_expiry_shadow as shadow

    def fail(_descriptor):
        raise OSError("parent directory fsync failed")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError):
        shadow.make_responsibility_journal(tmp_path)
    assert not list((tmp_path / "responsibility").glob("*.json"))


@pytest.mark.parametrize("stop_at", ["create", "begin"])
def test_child_exit_retains_complete_intent_file(tmp_path, stop_at):
    script = '''
import os, sys
from test_txn_responsibility import Endpoint, run
from txn_expiry_shadow import make_responsibility_journal
endpoint = Endpoint()
def transport(request):
    if ((sys.argv[2] == "create" and request["site"].startswith("setup/create/")) or
            (sys.argv[2] == "begin" and request["rpc"] == "BeginTransaction")):
        os._exit(91)
    return endpoint(request)
run(transport, make_responsibility_journal(sys.argv[1]))
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path), stop_at],
                            cwd=Path(__file__).parent, timeout=20, capture_output=True)
    assert result.returncode == 91, result.stderr.decode()
    paths = sorted((tmp_path / "responsibility").glob("*.json"))
    values = [json.loads(path.read_text()) for path in paths]
    assert [v["sequence"] for v in values] == list(range(1, len(values) + 1))
    last = values[-1]
    assert last["event"] == "dispatch-intent"
    assert last["terminalComplete"] is None
    if stop_at == "create":
        assert collector.SENT_UNKNOWN in last["resourceStates"].values()
    else:
        assert last["pendingBegins"]


def test_unknown_create_and_not_found_do_not_prove_cleanup():
    saved = []
    receipt = run(LostCreateResponseEndpoint(applies=False), saved.append)
    assert receipt["complete"] is False
    assert saved[-1]["resourceStates"]["control"] == collector.SENT_UNKNOWN
    assert "control" not in saved[-1]["typedAbsenceConfirmed"]


def test_confirmed_cleanup_has_typed_absence_snapshot():
    saved = []
    receipt = run(Endpoint(), saved.append)
    confirmed = {entry["role"] for entry in receipt["cleanup"] if entry.get("absent")}
    assert confirmed
    assert set(saved[-1]["typedAbsenceConfirmed"]) == confirmed


@pytest.mark.parametrize("event", ["resource-state", "transaction-opened",
                                   "transaction-released", "typed-absence"])
def test_state_publication_failure_permanently_stops_sends(event):
    endpoint = Endpoint()
    failures = []

    def observe(snapshot):
        if snapshot["event"] == event:
            failures.append(len(endpoint.calls))
            raise OSError("state publication failed")

    receipt = run(endpoint, observe)
    assert failures
    assert len(endpoint.calls) == failures[0]
    assert receipt["complete"] is False
    assert receipt["responsibilityJournalFailure"] == "OSError"


@pytest.mark.parametrize("phase", ["observation", "recovery"])
def test_journal_latency_cannot_send_after_phase_deadline(phase):
    now = [0.0]
    endpoint = Endpoint()
    expired = []

    def observe(snapshot):
        if snapshot["event"] != "dispatch-intent" or expired:
            return
        site = snapshot["inFlight"]["site"]
        if ((phase == "observation" and site == "setup/create/control") or
                (phase == "recovery" and site.startswith("release/"))):
            expired.append(site)
            now[0] += 10000

    receipt = collector.collect(options(), endpoint, advance=advances([]),
                                monotonic=lambda: now[0], responsibility=observe)
    assert expired
    assert all(request["site"] != expired[0] for request in endpoint.calls)
    assert receipt["complete"] is False
    assert receipt["requestCount"] == len(endpoint.calls)


def test_dispatch_timeout_uses_time_remaining_after_publication():
    now = [0.0]
    endpoint = Endpoint()

    def observe(snapshot):
        if (snapshot["event"] == "dispatch-intent" and
                snapshot["inFlight"]["site"] == "setup/create/control"):
            now[0] = 299.5

    collector.collect(options(), endpoint, advance=advances([]),
                      monotonic=lambda: now[0], responsibility=observe)
    create = next(q for q in endpoint.calls if q["site"] == "setup/create/control")
    assert create["timeoutSeconds"] == 0.5
