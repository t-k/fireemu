"""Program tables keep the shared project by default and admit the txn and query projects explicitly."""

import pytest

import fs_txn_table_p13a as p13a
from txn_program_program import PROJECT, compile_plan, corpus_digest, request_for_step

NONCE, OWNER = "a" * 32, "b" * 32
TXN = "fireemu-oracle-txn"


def with_project(table, project):
    return {**table, "project": project}


def test_the_default_project_is_unchanged_and_its_digest_does_not_move():
    plan = compile_plan(p13a.TABLE, NONCE, OWNER)
    assert plan["project"] == PROJECT == "fireemu-oracle-sbx"
    assert plan["database"] == "projects/fireemu-oracle-sbx/databases/(default)"
    # naming the default explicitly is the same table: the key is only bound into the digest when it differs
    assert corpus_digest(with_project(p13a.TABLE, PROJECT)) == corpus_digest(p13a.TABLE) == "8ef5cfc17df36c81844790b92d1439654d12e084f8b9323342eec3a6273be77e"


@pytest.mark.parametrize("project", [TXN, "fireemu-oracle-query"])
def test_an_explicit_project_changes_the_plan_the_documents_and_the_digest(project):
    table = with_project(p13a.TABLE, project)
    plan = compile_plan(table, NONCE, OWNER)
    assert plan["project"] == project
    assert plan["database"] == f"projects/{project}/databases/(default)"
    assert all(name.startswith(f"projects/{project}/databases/(default)/documents/oracle/") for name in plan["documents"].values())
    assert corpus_digest(table) != corpus_digest(p13a.TABLE)
    # a request names the project's documents
    read = next(step for step in plan["steps"] if step["id"] == "rest/uc/read-a")
    request = request_for_step(plan, read, {"rest-uc": "aXNzdWVk"}, table)
    assert request["name"].startswith(f"projects/{project}/")


@pytest.mark.parametrize("project", ["fireemu-oracle-idp", "fireemu-oracle-query2", "fireemu-35fe6", "demo-program", "", None, 7, "fireemu-oracle-txn ", "FIREEMU-ORACLE-TXN"])
def test_any_other_project_is_refused(project):
    with pytest.raises(ValueError, match="txn-program table"):
        compile_plan(with_project(p13a.TABLE, project), NONCE, OWNER)


# --- the metadata session of the txn project: no Rules release, and the baseline's "no Rules release" is checked, not assumed ---

import json
from pathlib import Path

import txn_program_http as http_module
import txn_program_management as management
import txn_sandbox_management as shared_management

TOKEN = "test-access-token"
TXN_BASELINE = {
    "projectNumber": "123456789012",
    "databaseExpected": {"name": f"projects/{TXN}/databases/(default)", "type": "FIRESTORE_NATIVE", "databaseEdition": "STANDARD", "locationId": "us-central1", "concurrencyMode": "PESSIMISTIC"},
    "credentialPrincipal": {"clientId": "client-a", "subject": "owner@example.com", "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"]},
}


class Budget:
    def __init__(self):
        self.management = 0

    def charge(self, phase):
        assert phase == "management"
        self.management += 1


def txn_answer(slot, rules=404):
    bodies = {
        "oauth-tokeninfo": {"issued_to": "client-a", "user_id": "owner@example.com", "scope": "https://www.googleapis.com/auth/cloud-platform", "expires_in": 3600},
        "project": {"projectId": TXN, "projectNumber": "123456789012"},
        "database": {**TXN_BASELINE["databaseExpected"], "uid": "synthetic-database-uid"},
    }
    if slot == "rules-release":
        return {"complete": rules == 200, "workerReaped": True, "status": rules, "body": {"name": f"projects/{TXN}/releases/cloud.firestore", "rulesetName": f"projects/{TXN}/rulesets/r"} if rules == 200 else None}
    return {"complete": True, "workerReaped": True, "status": 200, "body": bodies[slot]}


def session(monkeypatch, *, baseline=None, request=None):
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    seen = []
    def default(slot, token, resource=None):
        seen.append((slot, resource))
        return txn_answer(slot)
    budget = Budget()
    return management.MetadataSession(TOKEN, baseline or TXN_BASELINE, budget, request_fn=request or default, project=TXN), seen, budget


def test_the_txn_project_session_uses_five_slots_and_proves_there_is_no_rules_release(monkeypatch):
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    seen = []
    budget = Budget()
    def request(slot, token, resource=None):
        seen.append((slot, resource))
        return txn_answer(slot)
    run = management.MetadataSession(TOKEN, TXN_BASELINE, budget, request_fn=request, project=TXN)
    first, second = run.preflight(), run.postflight()
    # tokeninfo, project, database and the Rules-release absence before; project and database after: six charged slots
    assert seen == [("oauth-tokeninfo", None), ("project", None), ("database", None), ("rules-release", None), ("project", None), ("database", None)]
    assert budget.management == 6
    assert first["rules-absent"] == "absent" and "rulesSourceSha256" not in first and "rulesetName" not in first
    assert set(second) == {"project", "database", "databaseSettings"}
    assert TOKEN not in repr(first) + repr(second)


def test_a_rules_release_that_appears_refuses_the_run(monkeypatch):
    run, _seen, _budget = session(monkeypatch, request=lambda slot, token, resource=None: txn_answer(slot, rules=200))
    with pytest.raises(ValueError, match="Rules release exists"):
        run.preflight()


@pytest.mark.parametrize("status", [401, 403, 500, 429, 200])
def test_anything_but_a_clean_404_for_the_rules_release_refuses_the_run(monkeypatch, status):
    run, _seen, _budget = session(monkeypatch, request=lambda slot, token, resource=None: txn_answer(slot, rules=status))
    with pytest.raises(ValueError):
        run.preflight()


def test_a_project_or_database_that_differs_refuses_the_txn_session(monkeypatch):
    def wrong_project(slot, token, resource=None):
        answer = txn_answer(slot)
        if slot == "project":
            answer["body"] = {"projectId": "fireemu-oracle-sbx", "projectNumber": "123456789012"}
        return answer
    run, _s, _b = session(monkeypatch, request=wrong_project)
    with pytest.raises(ValueError, match="project identity differs"):
        run.preflight()
    def wrong_number(slot, token, resource=None):
        answer = txn_answer(slot)
        if slot == "project":
            answer["body"] = {"projectId": TXN, "projectNumber": "210987654321"}
        return answer
    run, _s, _b = session(monkeypatch, request=wrong_number)
    with pytest.raises(ValueError, match="project identity differs"):
        run.preflight()
    def wrong_database(slot, token, resource=None):
        answer = txn_answer(slot)
        if slot == "database":
            answer["body"] = {**answer["body"], "concurrencyMode": "OPTIMISTIC"}
        return answer
    run, _s, _b = session(monkeypatch, request=wrong_database)
    with pytest.raises(ValueError, match="PESSIMISTIC"):
        run.preflight()


def test_the_txn_baseline_has_exactly_its_keys_and_names_its_own_database(monkeypatch):
    with pytest.raises(ValueError):
        session(monkeypatch, baseline={**TXN_BASELINE, "rulesSourceSha256": "a" * 64})
    with pytest.raises(ValueError):
        session(monkeypatch, baseline={key: value for key, value in TXN_BASELINE.items() if key != "projectNumber"})
    other = {**TXN_BASELINE, "databaseExpected": {**TXN_BASELINE["databaseExpected"], "name": "projects/fireemu-oracle-sbx/databases/(default)"}}
    with pytest.raises(ValueError):
        session(monkeypatch, baseline=other)
    with pytest.raises(ValueError, match="project differs"):
        management.MetadataSession(TOKEN, TXN_BASELINE, Budget(), request_fn=lambda *a, **k: {}, project="fireemu-oracle-idp")


def test_the_shared_project_session_still_takes_its_rules_slots_and_a_baseline_with_a_rules_hash(monkeypatch):
    monkeypatch.setattr(management.preflight, "verify_token", lambda *args, **kwargs: object())
    with pytest.raises(ValueError):
        management.MetadataSession(TOKEN, TXN_BASELINE, Budget(), request_fn=lambda *a, **k: {})   # no rulesSourceSha256, and the wrong database name
    sbx = {**TXN_BASELINE, "databaseExpected": shared_management.EXPECTED_DATABASE, "rulesSourceSha256": "a" * 64}
    management.MetadataSession(TOKEN, sbx, Budget(), request_fn=lambda *a, **k: {})


# --- the fixed REST worker names the project it is given, and only the two sandbox projects ---

def capture_worker(monkeypatch, project=None, slot="database", resource=None):
    events = []

    class Response:
        status = 404
        def read(self, limit):
            return b""
        def getheader(self, name):
            return "application/json"

    class Connection:
        def __init__(self, host, timeout):
            events.append(("host", host))
        def request(self, method, path, body=None, headers=None):
            events.append(("request", method, path, headers))
        def getresponse(self):
            return Response()
        def close(self):
            pass

    monkeypatch.setattr(http_module.http.client, "HTTPSConnection", Connection)
    call = {"slot": slot, "secret": "ya29.token-value", "resource": resource, **({"project": project} if project else {})}
    http_module.worker_call(call)
    return events


@pytest.mark.parametrize("project,expected", [(None, "fireemu-oracle-sbx"), ("fireemu-oracle-sbx", "fireemu-oracle-sbx"), ("fireemu-oracle-txn", "fireemu-oracle-txn"), ("fireemu-oracle-query", "fireemu-oracle-query")])
def test_the_rest_worker_names_the_project_in_its_paths_and_user_project_header(monkeypatch, project, expected):
    for slot, path in (("project", f"/v1/projects/{expected}"), ("database", f"/v1/projects/{expected}/databases/(default)"), ("rules-release", f"/v1/projects/{expected}/releases/cloud.firestore")):
        events = capture_worker(monkeypatch, project, slot)
        request = next(event for event in events if event[0] == "request")
        assert request[2] == path and request[3]["x-goog-user-project"] == expected


def test_the_rest_worker_refuses_any_other_project_and_a_ruleset_of_another_project(monkeypatch):
    for project in ("fireemu-oracle-idp", "fireemu-35fe6", "", "fireemu-oracle-txn2", None.__class__):
        with pytest.raises(ValueError):
            http_module.worker_call({"slot": "database", "secret": "ya29.token-value", "resource": None, "project": project})
    with pytest.raises(ValueError):
        http_module.request_once("database", "ya29.token-value", None, project="fireemu-oracle-idp")
    with pytest.raises(ValueError):
        capture_worker(monkeypatch, "fireemu-oracle-txn", "ruleset-source", "projects/fireemu-oracle-sbx/rulesets/a")


def test_the_request_payload_carries_the_project_only_when_it_is_not_the_shared_one(monkeypatch):
    sent = []
    class Pipe:
        closed = True
        def close(self): pass

    class Worker:
        returncode = 0
        stdin = stdout = Pipe()
        def communicate(self, payload, timeout):
            sent.append(json.loads(payload))
            return (json.dumps({"complete": True, "status": 200, "body": {}}).encode(), None)
        def kill(self): pass
        def wait(self, *a, **k): return 0
        def poll(self): return 0
    monkeypatch.setattr(http_module.subprocess, "Popen", lambda *a, **k: Worker())
    http_module.request_once("project", "ya29.token-value")
    http_module.request_once("project", "ya29.token-value", project="fireemu-oracle-txn")
    http_module.request_once("project", "ya29.token-value", project="fireemu-oracle-query")
    assert "project" not in sent[0] and sent[1]["project"] == "fireemu-oracle-txn"
    assert sent[2]["project"] == "fireemu-oracle-query"


# --- authority, packet and budget follow the packet's project ---

import datetime as dt

import txn_program_authority as authority
import txn_program_cli as cli
import txn_program_runner as runner
from test_txn_program_authority import AUTHORITY, ENVELOPE_ID, NAME, NOW, PINS, SCOPE, approve_row, envelope_row

TXN_SCOPE = {**SCOPE, "project": f"{TXN}/(default)"}
TXN_PINS = {**PINS, "project": TXN, "estimatedUsdPerRecording": 0.0, "scope": TXN_SCOPE}
TXN_DECISIONS = AUTHORITY + envelope_row(scope=TXN_SCOPE, reserveUsd="0") + approve_row(estimatedUsdPerRecording="0")
SBX_ROW = {"ts": "2026-09-28T04:50:00Z", "project": "fireemu-oracle-sbx", "taskId": "FS-TRANSACTION-SANDBOX", "attemptId": "sbx-recent", "outcome": "recorded", "estimatedUsd": 0.05}
TXN_ROW = {**SBX_ROW, "project": TXN, "attemptId": "txn-recent", "estimatedUsd": 0.0}


def test_the_envelope_scope_names_the_tables_project():
    assert authority.envelope_scope({**__import__("txn_program_support_for_tests").TABLE, "project": TXN})["project"] == f"{TXN}/(default)"
    assert authority.envelope_scope(__import__("txn_program_support_for_tests").TABLE)["project"] == "fireemu-oracle-sbx/(default)"


def test_a_free_tier_envelope_reserves_nothing_and_a_shared_project_envelope_still_reserves_four_cents():
    assert authority.authorize(TXN_DECISIONS, TXN_PINS)[1] == 0.0
    with pytest.raises(ValueError):
        authority.authorize(AUTHORITY + envelope_row(scope=TXN_SCOPE) + approve_row(), TXN_PINS)           # reserveUsd 0.04 on the free-tier project
    with pytest.raises(ValueError):
        authority.authorize(AUTHORITY + envelope_row(reserveUsd="0") + approve_row(), PINS)                  # reserveUsd 0 on the shared project
    with pytest.raises(ValueError):
        authority.authorize(TXN_DECISIONS, {**TXN_PINS, "estimatedUsdPerRecording": 0.01})                    # the estimate must be the project's
    with pytest.raises(ValueError):
        authority.authorize(AUTHORITY + envelope_row() + approve_row(), {**PINS, "project": TXN})            # the sbx scope does not authorize the txn project


def test_the_30_minute_spacing_and_open_attempts_are_per_project():
    # a recent shared-project attempt does not delay the txn project, and the other way round
    assert authority.verify_initial_gates([SBX_ROW], NOW, TXN_DECISIONS, TXN_PINS) is None
    assert authority.verify_initial_gates([TXN_ROW], NOW, AUTHORITY + envelope_row() + approve_row(), PINS) is None
    with pytest.raises(ValueError, match="fireemu-oracle-txn needs 30 minutes"):
        authority.verify_initial_gates([TXN_ROW], NOW, TXN_DECISIONS, TXN_PINS)
    quiet = NOW + dt.timedelta(minutes=31)
    assert authority.verify_initial_gates([TXN_ROW], quiet, TXN_DECISIONS, TXN_PINS) == TXN_ROW["ts"]
    opened = {**TXN_ROW, "attemptId": "open", "outcome": "reserved"}
    with pytest.raises(ValueError, match="fireemu-oracle-txn has an open attempt"):
        authority.verify_initial_gates([opened], quiet, TXN_DECISIONS, TXN_PINS)
    sbx_open = {**SBX_ROW, "attemptId": "open", "outcome": "reserved"}
    assert authority.verify_initial_gates([sbx_open], quiet, TXN_DECISIONS, TXN_PINS) is None


def test_a_row_the_runner_writes_names_the_packets_project_and_its_estimate():
    for pins, project in ((TXN_PINS, TXN), (PINS, "fireemu-oracle-sbx")):
        row = runner._row({**pins, "requestsPerRecording": 10, "envelopeId": ENVELOPE_ID, "packetId": "p", "sourceCommit": "b" * 40, "runnerSha256": "c" * 64}, "attempt", Path("/tmp/x"), "n" * 32, "reserved", None, dt.datetime(2026, 9, 28, tzinfo=dt.timezone.utc))
        assert row["project"] == project


def test_the_packet_is_built_for_the_tables_project_with_its_budget():
    import fs_txn_table_p13a as p13a
    runtime = {"reviewed": True}
    baseline = envelope = "0" * 64
    for table, project, estimate, reserve in ((p13a.TABLE, "fireemu-oracle-sbx", 0.01, 0.04), (with_project(p13a.TABLE, TXN), TXN, 0.0, 0.0)):
        value = cli.packet_value(table=table, source_commit="b" * 40, runtime=runtime, baseline_sha256=baseline, envelope_sha256=envelope, packet_id="fs-transaction-p13a-inferred-answers-a001", envelope_relative="docs.local/reviews/x.md")
        assert (value["project"], value["estimatedUsdPerRecording"], value["reserveUsd"]) == (project, estimate, reserve)
        assert value["scope"]["project"] == f"{project}/(default)"
    assert cli.packet_value(table=p13a.TABLE, source_commit="b" * 40, runtime=runtime, baseline_sha256=baseline, envelope_sha256=envelope, packet_id="fs-transaction-p13a-inferred-answers-a001", envelope_relative="docs.local/reviews/x.md")["corpusDigest"] == "8ef5cfc17df36c81844790b92d1439654d12e084f8b9323342eec3a6273be77e"


def test_the_wire_names_the_project_it_was_built_for_and_refuses_another(monkeypatch):
    import txn_program_wire as wire
    monkeypatch.setattr(wire, "verify_runtime", lambda _runtime: None)
    for project in ("fireemu-oracle-sbx", TXN):
        instance = wire.NodeWire({}, {"slug": "txn-x", "documents": ["a"], "states": ["created"]}, project=project)
        assert instance.project == project
    with pytest.raises(ValueError, match="project differs"):
        wire.NodeWire({}, {"slug": "txn-x", "documents": ["a"], "states": ["created"]}, project="fireemu-oracle-idp")
    assert wire.NodeWire({}, {"slug": "txn-x", "documents": ["a"], "states": ["created"]}).project == "fireemu-oracle-sbx"


def test_the_runner_hands_the_tables_project_to_the_metadata_session_the_request_function_and_the_wire(tmp_path, monkeypatch):
    import txn_program_support_for_tests as support
    from test_txn_program_collector import Clock, Service
    seen = {}
    clock = Clock()
    monkeypatch.setattr(runner.time, "monotonic", clock.now)
    class Metadata:
        def __init__(self, _bearer, _baseline, budget, **kwargs):
            seen["metadata"] = kwargs
            self.budget = budget
        def preflight(self):
            for _ in range(4):
                self.budget.charge("management")
            return {"rules-absent": "absent"}
        def postflight(self):
            for _ in range(2):
                self.budget.charge("management")
            return {}
    monkeypatch.setattr(runner, "MetadataSession", Metadata)
    monkeypatch.setattr(runner, "refresh", lambda *_args, **_kwargs: "owner")
    def wire(_runtime, _scope, **kwargs):
        seen["wire"] = kwargs
        return Service(clock)
    monkeypatch.setattr(runner, "NodeWire", wire)
    collector = runner.Collector
    monkeypatch.setattr(runner, "Collector", lambda *args, **kwargs: collector(*args, **kwargs, monotonic=clock.now, utc=clock.utc))
    table = {**support.TABLE, "project": TXN, "envelopeId": support.TABLE["envelopeId"]}
    runner.run_once(0, table, "a" * 32, "b" * 32, tmp_path, baseline={}, runtime={}, check=lambda: None)
    assert seen["metadata"]["project"] == TXN and seen["wire"] == {"project": TXN}
    assert seen["metadata"]["request_fn"].keywords == {"project": TXN}
    # the shared project's call is exactly as it was: no extra argument anywhere
    seen.clear()
    (tmp_path / "sbx").mkdir()
    runner.run_once(0, support.TABLE, "a" * 32, "b" * 32, tmp_path / "sbx", baseline={}, runtime={}, check=lambda: None)
    assert "project" not in seen["metadata"] and seen["wire"] == {} and seen["metadata"]["request_fn"] is runner.request_once


def test_the_whole_task_limit_reserves_what_the_projects_budget_says():
    # 9.99 spent: the free-tier project reserves nothing and still fits; the shared project's four cents do not
    spent = {**SBX_ROW, "ts": "2026-09-20T04:50:00Z", "taskId": authority.TASK_ID, "attemptId": "old", "estimatedUsd": 9.99}
    assert authority.verify_initial_gates([spent], NOW, TXN_DECISIONS, TXN_PINS) is None
    with pytest.raises(ValueError, match="US\\$10 limit"):
        authority.verify_initial_gates([spent], NOW, AUTHORITY + envelope_row() + approve_row(), PINS)


def test_a_loaded_packet_hands_back_its_project_and_reserve(tmp_path, monkeypatch):
    import fs_txn_table_p13a as p13a
    monkeypatch.setattr(cli, "verify_runtime", lambda _runtime: None)
    baseline = tmp_path / "baseline.json"; baseline.write_text("{}\n")
    envelope = tmp_path / "envelope.md"; envelope.write_text("scope proposal\n")
    for table, project, reserve in ((p13a.TABLE, "fireemu-oracle-sbx", 0.04), (with_project(p13a.TABLE, TXN), TXN, 0.0)):
        value = cli.packet_value(table=table, source_commit="b" * 40, runtime={"reviewed": True}, baseline_sha256=cli.sha(baseline.read_bytes()), envelope_sha256=cli.sha(envelope.read_bytes()),
                                 packet_id="fs-transaction-p13a-inferred-answers-a001", envelope_relative="docs.local/reviews/x.md")
        path = tmp_path / f"{project}.json"
        path.write_text(json.dumps(value, sort_keys=True) + "\n")
        loaded = cli.load_packet(path, cli.sha(path.read_bytes()), baseline, envelope, table=table, source_commit="b" * 40, packet_relative="docs.local/reviews/p.json", envelope_relative="docs.local/reviews/x.md")
        assert (loaded["project"], loaded["reserveUsd"]) == (project, reserve)


def test_the_session_lock_is_the_packets_projects(tmp_path, monkeypatch):
    import test_txn_program_runner as runner_tests
    tmp_path.chmod(0o700)
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(SBX_ROW) + "\n"); ledger.chmod(0o600)
    asked = []
    def lock(_directory, projects, **_kwargs):
        asked.append(list(projects))
        raise RuntimeError("stop after the lock request")
    monkeypatch.setattr(runner.shared, "acquire_project_locks", lock)
    for pins, decisions, project in ((TXN_PINS, TXN_DECISIONS, TXN), (PINS, AUTHORITY + envelope_row() + approve_row(), "fireemu-oracle-sbx")):
        with pytest.raises(RuntimeError, match="stop after the lock request"):
            runner.record_twice(table=runner_tests.TABLE, ledger_path=ledger, private_dir=tmp_path, pins=pins, decisions=lambda: decisions, now=lambda: NOW + dt.timedelta(days=1), record_once=None, admission_check=lambda: None)
        assert asked[-1] == [project]


def test_a_call_names_the_wires_project_in_its_spec(monkeypatch):
    import txn_program_wire as wire
    monkeypatch.setattr(wire, "verify_runtime", lambda _runtime: None)
    for project in ("fireemu-oracle-sbx", TXN):
        instance = wire.NodeWire({}, {"slug": "txn-x", "documents": ["a"], "states": ["created"]}, project=project)
        seen = []
        def child(spec, _timeout):
            seen.append(spec)
            raise RuntimeError("stop after the spec")
        monkeypatch.setattr(instance, "_child", child)
        with pytest.raises(RuntimeError, match="stop after the spec"):
            instance.send("rest", "GetDocument", {"name": f"projects/{project}/databases/(default)/documents/x/a"}, nonce="n" * 32, owner_id="o" * 32, bearer="b")
        assert seen[0]["projectId"] == project


TXN_LOCK = "sandbox-locks/fireemu-oracle-txn.lock"


def txn_record(table):
    """One recording of the txn project as the runner produces it: the metadata is the session's preflight, which has no Rules release."""
    from test_txn_program_collector import Clock, Service
    from txn_program_collector import Collector
    from txn_program_program import RequestBudget

    def record(_index, nonce, owner, _directory):
        plan = compile_plan(table, nonce, owner)
        clock = Clock()
        receipt = Collector(plan, table, RequestBudget(plan, table), Service(clock), "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc).run()
        receipt["metadata"] = {"oauth-tokeninfo": {"verified": True, "requiredSeconds": 1600}, "project": "a" * 64, "database": "b" * 64, "rules-absent": "absent"}
        return receipt
    return record


def txn_session(tmp_path):
    import test_txn_program_runner as runner_tests
    tmp_path.chmod(0o700)
    ledger = tmp_path / "sandbox-ledger.jsonl"
    ledger.write_text(json.dumps(SBX_ROW) + "\n"); ledger.chmod(0o600)
    table = with_project(runner_tests.TABLE, TXN)
    kwargs = {"table": table, "ledger_path": ledger, "private_dir": tmp_path, "pins": TXN_PINS, "decisions": lambda: TXN_DECISIONS, "now": lambda: NOW + dt.timedelta(days=1),
              "record_once": txn_record(table), "admission_check": lambda: None}
    return ledger, kwargs


def test_two_recordings_of_the_txn_project_freeze_and_release_its_lock(tmp_path):
    ledger, kwargs = txn_session(tmp_path)
    result = runner.record_twice(**kwargs)
    frozen = json.loads((result["freezePath"]).read_text())
    assert frozen["kind"] == "txn-program-freeze-v1" and frozen["rules"] == {"rulesRelease": "absent"}
    assert not (tmp_path / TXN_LOCK).exists()
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert [row["outcome"] for row in rows[1:]] == ["reserved", "recorded", "reserved", "recorded"]
    assert all(row["project"] == TXN for row in rows[1:])


def test_a_txn_recording_that_shows_a_rules_release_does_not_freeze_and_keeps_the_lock(tmp_path):
    ledger, kwargs = txn_session(tmp_path)
    inner = kwargs["record_once"]
    def once(index, nonce, owner, directory):
        receipt = inner(index, nonce, owner, directory)
        if index == 1:
            receipt["metadata"]["rules-absent"] = "present"
        return receipt
    kwargs["record_once"] = once
    with pytest.raises(ValueError, match="differ"):
        runner.record_twice(**kwargs)
    assert (tmp_path / TXN_LOCK).exists()
    assert json.loads(ledger.read_text().splitlines()[-1])["outcome"] == "stopped-needs-review"


def test_the_approval_line_carries_the_projects_own_estimate():
    # the free-tier project's estimate is zero: an approval that still says 0.01 is not the packet's version, and the other way round
    for estimate in ("0", "0.0", "0.00"):
        assert authority.authorize(AUTHORITY + envelope_row(scope=TXN_SCOPE, reserveUsd="0") + approve_row(estimatedUsdPerRecording=estimate), TXN_PINS)[1] == 0.0
    with pytest.raises(ValueError, match="APPROVE"):
        authority.authorize(AUTHORITY + envelope_row(scope=TXN_SCOPE, reserveUsd="0") + approve_row(estimatedUsdPerRecording="0.01"), TXN_PINS)
    assert authority.authorize(AUTHORITY + envelope_row() + approve_row(), PINS)[1] == 0.04
    with pytest.raises(ValueError, match="APPROVE"):
        authority.authorize(AUTHORITY + envelope_row() + approve_row(estimatedUsdPerRecording="0"), PINS)


def test_a_ledger_row_records_the_projects_own_estimate():
    for pins, expected in ((TXN_PINS, 0.0), (PINS, 0.01)):
        row = runner._row({**pins, "requestsPerRecording": 10, "envelopeId": ENVELOPE_ID, "packetId": "p", "sourceCommit": "b" * 40, "runnerSha256": "c" * 64}, "attempt", Path("/tmp/x"), "n" * 32, "reserved", None, dt.datetime(2026, 9, 28, 5, tzinfo=dt.timezone.utc))
        assert row["estimatedUsd"] == expected


@pytest.mark.parametrize("proof", ["present", None, "unknown"])
def test_two_txn_recordings_that_agree_without_proving_the_absence_of_a_rules_release_do_not_freeze(tmp_path, proof):
    # Both recordings carry the same metadata, so equality alone would freeze them: the proof itself has to be the session's "absent".
    ledger, kwargs = txn_session(tmp_path)
    inner = kwargs["record_once"]
    def once(index, nonce, owner, directory):
        receipt = inner(index, nonce, owner, directory)
        if proof is None:
            del receipt["metadata"]["rules-absent"]
        else:
            receipt["metadata"]["rules-absent"] = proof
        return receipt
    kwargs["record_once"] = once
    with pytest.raises(ValueError, match="differ"):
        runner.record_twice(**kwargs)
    assert (tmp_path / TXN_LOCK).exists()
    assert json.loads(ledger.read_text().splitlines()[-1])["outcome"] == "stopped-needs-review"


# --- the database settings the read-time retention condition compares: stored from the database GET, in the receipt's metadata ---

PITR, RETENTION = "POINT_IN_TIME_RECOVERY_DISABLED", "3600s"


def with_settings(pitr=PITR, retention=RETENTION, *, change_after=None):
    calls = {"database": 0}

    def request(slot, token, resource=None):
        answer = txn_answer(slot)
        if slot == "database":
            calls["database"] += 1
            body = dict(answer["body"])
            changed = change_after is not None and calls["database"] > change_after
            if pitr is not None:
                body["pointInTimeRecoveryEnablement"] = "POINT_IN_TIME_RECOVERY_ENABLED" if changed else pitr
            if retention is not None:
                body["versionRetentionPeriod"] = retention
            answer["body"] = body
        return answer
    return request


def test_the_database_settings_the_retention_condition_compares_are_stored_before_and_after(monkeypatch):
    run, _seen, _budget = session(monkeypatch, request=with_settings())
    first, second = run.preflight(), run.postflight()
    expected = {"pointInTimeRecoveryEnablement": PITR, "versionRetentionPeriod": RETENTION}
    assert first["databaseSettings"] == expected and second["databaseSettings"] == expected
    # nothing but those two values: the digest and the slots are as before
    assert set(first) == {"oauth-tokeninfo", "project", "database", "rules-absent", "databaseSettings"} and set(second) == {"project", "database", "databaseSettings"}
    assert first["database"] == second["database"]


def test_a_database_that_reports_no_settings_stores_them_as_not_reported(monkeypatch):
    run, _seen, _budget = session(monkeypatch)
    assert run.preflight()["databaseSettings"] == {"pointInTimeRecoveryEnablement": None, "versionRetentionPeriod": None}


@pytest.mark.parametrize("pitr,retention", [(7, RETENTION), (PITR, ["3600s"]), ({"x": 1}, RETENTION), (PITR, 3600)])
def test_a_setting_that_is_not_a_string_refuses_the_run(monkeypatch, pitr, retention):
    run, _seen, _budget = session(monkeypatch, request=with_settings(pitr, retention))
    with pytest.raises(ValueError, match="database settings"):
        run.preflight()


def test_settings_that_change_between_the_preflight_and_the_postflight_refuse_the_run(monkeypatch):
    run, _seen, _budget = session(monkeypatch, request=with_settings(change_after=1))
    run.preflight()
    with pytest.raises(ValueError, match="changed after observation"):
        run.postflight()



@pytest.mark.parametrize("slot,method,suffix", [("named-database", "GET", ""), ("create-database", "POST", ""), ("delete-database", "DELETE", ""), ("database-operation", "GET", "/operations/create-1")])
def test_query_management_worker_authorizes_exact_named_database_paths(monkeypatch, slot, method, suffix):
    resource = "projects/fireemu-oracle-query/databases/txn-" + "a" * 32
    requests = []
    class Response:
        status = 404 if slot == "named-database" else 200
        def read(self, limit): return json.dumps({"error": {"status": "NOT_FOUND"}} if self.status == 404 else {}).encode()
        def getheader(self, name): return "application/json"
    class Connection:
        def __init__(self, host, timeout): assert host == "firestore.googleapis.com"
        def request(self, method, path, body=None, headers=None): requests.append((method, path, body, headers))
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr(http_module.http.client, "HTTPSConnection", Connection)
    result = http_module.worker_call({"slot": slot, "secret": "synthetic-token", "resource": resource + suffix, "project": "fireemu-oracle-query"})
    sent_method, path, body, headers = requests[0]
    assert sent_method == method
    assert headers["Authorization"] == "Bearer synthetic-token"
    assert headers["x-goog-user-project"] == "fireemu-oracle-query"
    if slot == "create-database":
        assert path == "/v1/projects/fireemu-oracle-query/databases?databaseId=txn-" + "a" * 32
        assert json.loads(body) == {"name": resource, "locationId": "eur3", "type": "FIRESTORE_NATIVE", "databaseEdition": "STANDARD"}
        assert headers["Content-Type"] == "application/json"
    else:
        assert path == "/v1/" + resource + suffix
        assert body is None
    assert result["complete"] is True
    assert result["status"] == Response.status
    if slot == "named-database": assert result["body"]["error"]["status"] == "NOT_FOUND"


@pytest.mark.parametrize("slot", ["named-database", "create-database", "delete-database", "database-operation"])
@pytest.mark.parametrize("change", ["foreign", "shared", "default", "prefix", "suffix", "uppercase", "encoded", "template", "operation", "short", "foreign-project-only"])
def test_query_management_worker_refuses_resource_near_misses_before_connect(monkeypatch, slot, change):
    resource = "projects/fireemu-oracle-query/databases/txn-" + "a" * 32
    project = "fireemu-oracle-query"
    if change in ("foreign", "shared"):
        project = "fireemu-oracle-txn" if change == "foreign" else "fireemu-oracle-sbx"
        resource = resource.replace("fireemu-oracle-query", project)
    elif change == "default": resource = resource.replace("txn-" + "a" * 32, "(default)")
    elif change == "prefix": resource = "other/" + resource
    elif change == "suffix": resource += "/extra"
    elif change == "uppercase": resource = resource.replace("a" * 32, "A" * 32)
    elif change == "encoded": resource = resource.replace("txn-", "%74xn-")
    elif change == "template": resource = resource.replace("a" * 32, "{nonce}")
    elif change == "operation": resource += "/operations/other"
    elif change == "short": resource = resource.replace("a" * 32, "a" * 31)
    elif change == "foreign-project-only": project = "fireemu-oracle-txn"
    if slot == "database-operation": resource += "/operations/create-1"
    monkeypatch.setattr(http_module.http.client, "HTTPSConnection", lambda *args, **kwargs: pytest.fail("invalid resource reached the network"))
    with pytest.raises(ValueError):
        http_module.worker_call({"slot": slot, "secret": "synthetic-token", "resource": resource, "project": project})


@pytest.mark.parametrize("failure", [None, "project", "database", "settings", "missing-project", "missing-database", "missing-databaseSettings", "oauth", "both-missing-project", "both-missing-database", "both-missing-databaseSettings", "both-oauth"])
def test_query_freeze_compares_metadata_without_assuming_an_absent_rules_release(tmp_path, failure):
    import test_txn_program_runner as runner_tests
    ledger, kwargs = runner_tests.fixture(tmp_path)
    project = "fireemu-oracle-query"
    table = with_project(runner_tests.TABLE, project)
    scope = {**SCOPE, "project": project + "/(default)"}
    kwargs.update(table=table, pins={**PINS, "project": project, "scope": scope}, decisions=lambda: AUTHORITY + envelope_row(scope=scope) + approve_row())
    inner = txn_record(table)
    def once(index, nonce, owner, directory):
        receipt = inner(index, nonce, owner, directory)
        receipt["metadata"].pop("rules-absent")
        receipt["metadata"]["databaseSettings"] = {"pointInTimeRecoveryEnablement": None, "versionRetentionPeriod": "3600s"}
        if failure and (index == 1 or failure.startswith("both-")):
            change = failure.removeprefix("both-")
            if change in ("project", "database"): receipt["metadata"][change] = "c" * 64
            elif change == "settings": receipt["metadata"]["databaseSettings"]["versionRetentionPeriod"] = "7200s"
            elif change.startswith("missing-"): receipt["metadata"].pop(change[8:])
            elif change == "oauth": receipt["metadata"]["oauth-tokeninfo"]["verified"] = False
        return receipt
    kwargs["record_once"] = once
    lock = tmp_path / "sandbox-locks/fireemu-oracle-query.lock"
    if failure:
        with pytest.raises(ValueError, match="differ"): runner.record_twice(**kwargs)
        assert lock.exists()
        assert not list(tmp_path.glob("fs-transaction-*/freeze.json"))
        assert json.loads(ledger.read_text().splitlines()[-1])["outcome"] == "stopped-needs-review"
    else:
        result = runner.record_twice(**kwargs)
        frozen = json.loads(result["freezePath"].read_text())
        assert frozen["rules"] == {"project": "a" * 64, "database": "b" * 64, "databaseSettings": {"pointInTimeRecoveryEnablement": None, "versionRetentionPeriod": "3600s"}}
        assert frozen["authorizesProduction"] is False
        assert not lock.exists()
