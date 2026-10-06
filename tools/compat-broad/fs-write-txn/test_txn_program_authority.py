"""Program-scoped authority: exact scope, revocation, shared history and send-time authorization."""

import importlib
from datetime import datetime, timezone

import pytest

import txn_program_authority as authority
from test_txn_sandbox_runtime_and_wire_integration import AUTHORITY

support = importlib.import_module("txn_program_support_for_tests")
SCOPE = authority.envelope_scope(support.TABLE)
REQUESTS = 19 + 4 + 14 + 7 + 2
PACKET = "toy-failed-commit"
ENVELOPE_ID = f"FS-TRANSACTION-{PACKET}-001"
PINS = {"packetName": PACKET, "packetId": "fs-transaction-toy-test", "packetSha256": "a" * 64, "sourceCommit": "b" * 40, "runnerSha256": "c" * 64, "packetPath": "docs.local/reviews/toy-test.json", "envelopeId": ENVELOPE_ID, "envelopePath": "docs.local/reviews/toy-envelope.md", "requestsPerRecording": REQUESTS, "estimatedUsdPerRecording": 0.01, "scope": SCOPE}
ACTOR = "Claude（委任。オーナーの裁量の委任 2026-09-28）"
NAME = f"FS-TRANSACTION {PACKET}"


def envelope_row(actor=ACTOR, scope=None, **changes):
    values = {"envelopeId": ENVELOPE_ID, **(scope or SCOPE), "maxRequests": str(2 * REQUESTS), "reserveUsd": "0.04", "根拠": "2026-09-28 調整役への委任（本番の送信）", **changes}
    body = "; ".join(f"{key}={value}" for key, value in values.items())
    return f"- 2026-09-28 | {NAME} envelope | {body} | {actor} | {PINS['envelopePath']}\n"


def approve_row(actor=ACTOR, **changes):
    values = {"decision": "APPROVE", "envelopeId": ENVELOPE_ID, "packetSha256": PINS["packetSha256"], "sourceCommit": PINS["sourceCommit"], "runnerSha256": PINS["runnerSha256"], "requestsPerRecording": str(REQUESTS), "estimatedUsdPerRecording": "0.01", "recordings": "2", **changes}
    body = "; ".join(f"{key}={value}" for key, value in values.items() if value is not None)
    return f"- 2026-09-28 | {NAME} | {body} | {actor} | {PINS['packetPath']}\n"


ENVELOPE, APPROVE = envelope_row(), approve_row()
DECISIONS = AUTHORITY + ENVELOPE + APPROVE
NOW = datetime(2026, 9, 28, 5, tzinfo=timezone.utc)
LAST = {"ts": "2026-09-28T04:00:00Z", "project": "fireemu-oracle-sbx", "taskId": "FS-TRANSACTION-SANDBOX", "attemptId": "prior", "outcome": "recorded", "estimatedUsd": 0.05}


def test_the_envelope_scope_comes_from_the_table():
    assert SCOPE == {
        "project": "fireemu-oracle-sbx/(default)", "writes": "owned-2-documents", "iamConfig": "none", "retries": "none", "onStop": "needs-recovery-lock-held",
        "observationSeconds": "240", "recoverySeconds": "180", "maxTokens": "2", "maxUnresolvedTokens": "1", "releasePolicy": "rollback-zero-before-next-chain",
        "timing": "wall-clock", "timingSource": "parent-wire-envelope", "transports": "grpc+rest", "writerDeadlineSeconds": "30",
    }
    no_writer = {**support.TABLE, "steps": tuple(step for step in support.TABLE["steps"] if step["role"] != "outside-writer"), "caps": {**support.TABLE["caps"], "observation": 17}}
    assert authority.envelope_scope(no_writer)["writerDeadlineSeconds"] == "none"


def _with_writer_deadlines(*deadlines):
    """The toy table with its outside writers' deadlines replaced, in order (the toy has two writers)."""
    steps, queue = [], list(deadlines)
    for step in support.TABLE["steps"]:
        steps.append({**step, "deadlineMs": queue.pop(0)} if step["role"] == "outside-writer" else step)
    return {**support.TABLE, "steps": tuple(steps)}


def test_the_envelope_states_the_longest_writer_deadline_the_table_declares():
    # an approval must not understate how long a writer may stay in flight against production
    assert authority.envelope_scope(_with_writer_deadlines(30000, 30000))["writerDeadlineSeconds"] == "30"
    assert authority.envelope_scope(_with_writer_deadlines(30000, 90000))["writerDeadlineSeconds"] == "90"
    assert authority.envelope_scope(_with_writer_deadlines(90000, 30000))["writerDeadlineSeconds"] == "90"
    assert authority.envelope_scope(_with_writer_deadlines(45000, 60000))["writerDeadlineSeconds"] == "60"
    # a deadline that is not a whole second rounds up
    assert authority.envelope_scope(_with_writer_deadlines(30500, 30000))["writerDeadlineSeconds"] == "31"


def test_only_the_outside_writers_deadlines_state_the_writer_deadline():
    # the other steps' deadline (the 10 s default, longer than these writers') must not leak into the statement
    table = _with_writer_deadlines(5000, 4000)
    assert authority.envelope_scope(table)["writerDeadlineSeconds"] == "5"


def test_an_envelope_that_states_the_shorter_deadline_does_not_authorize_a_table_with_the_longer_one():
    scope90 = authority.envelope_scope(_with_writer_deadlines(30000, 90000))
    assert scope90["writerDeadlineSeconds"] == "90"
    pins = {**PINS, "scope": scope90}
    truthful = AUTHORITY + envelope_row(scope=scope90) + approve_row()
    assert authority.authorize(truthful, pins) == (2 * REQUESTS, 0.04)
    # the envelope of the 30 s table, offered for the table whose writer waits 90 s, is refused: the line understates how long a writer stays in flight
    understated = AUTHORITY + envelope_row(scope=SCOPE) + approve_row()
    with pytest.raises(ValueError):
        authority.authorize(understated, pins)


def test_delegation_with_exact_foundation_envelope_and_version_is_accepted():
    assert authority.authorize(DECISIONS, PINS) == (2 * REQUESTS, 0.04)
    assert authority.verify_initial_gates([LAST], NOW, DECISIONS, PINS) == LAST["ts"]


@pytest.mark.parametrize("old,new", [("owned-2-documents", "owned-5-documents"), (f"maxRequests={2 * REQUESTS}", f"maxRequests={2 * REQUESTS - 1}"), ("reserveUsd=0.04", "reserveUsd=10.01"), ("reserveUsd=0.04", "reserveUsd=0.03"), (f"maxRequests={2 * REQUESTS}", f"maxRequests={2 * REQUESTS + 1}"), ("decision=APPROVE;", ""), ("recordings=2", "recordings=1"), ("根拠=2026-09-28 調整役への委任（本番の送信）", "根拠=unknown"), ("writerDeadlineSeconds=30", "writerDeadlineSeconds=60"), ("transports=grpc+rest", "transports=grpc"), ("observationSeconds=240", "observationSeconds=900"), ("recoverySeconds=180", "recoverySeconds=360"), ("maxTokens=2", "maxTokens=3"), ("maxUnresolvedTokens=1", "maxUnresolvedTokens=2"), ("releasePolicy=rollback-zero-before-next-chain", "releasePolicy=assume-invalidated"), ("timingSource=parent-wire-envelope", "timingSource=local-control-clock")])
def test_scope_and_explicit_approval_are_not_inferred(old, new):
    with pytest.raises(ValueError):
        authority.authorize(DECISIONS.replace(old, new), PINS)


def test_a_missing_or_altered_owner_delegation_fails():
    for text in [ENVELOPE + APPROVE, DECISIONS.replace("費用が10ドル以内", "費用が20ドル以内"), DECISIONS + APPROVE]:
        with pytest.raises(ValueError):
            authority.authorize(text, PINS)


def test_revocation_is_rechecked_for_dispatch_and_cannot_be_undone_by_a_later_approve():
    revoked = DECISIONS + f"- 2026-09-28 | {NAME} | decision=REVOKED; envelopeId={ENVELOPE_ID} | オーナー（直接） | {PINS['packetPath']}\n" + APPROVE
    with pytest.raises(ValueError):
        authority.authorize(revoked, PINS)


@pytest.mark.parametrize("scope", ["packet", "envelope", "malformed"])
def test_the_correction_topic_raw_cancellation_is_seen(scope):
    target = {"packet": "packetSha256=" + PINS["packetSha256"], "envelope": "envelopeId=" + ENVELOPE_ID, "malformed": "packetSha256=" + "d" * 64 + "; envelopeId:broken"}[scope]
    row = "- 2026-09-29 | FS-TRANSACTION correction | REVOKED（" + target + "） | owner | synthetic.md | extra\n"
    with pytest.raises(ValueError, match="[Rr][Ee][Vv][Oo][Kk][Ee][Dd]"):
        authority.authorize(DECISIONS + row, PINS)


def test_shared_history_idle_replay_and_open_attempts_fail_closed():
    for rows in [[{**LAST, "ts": "2026-09-28T04:45:00Z"}], [LAST, {**LAST, "outcome": "reserved", "attemptId": "open"}], [{**LAST, "envelopeId": ENVELOPE_ID}], [{**LAST, "packetId": PINS["packetId"], "outcome": "reserved"}], [{**LAST, "estimatedUsd": 9.99}]]:
        with pytest.raises(ValueError):
            authority.verify_initial_gates(rows, NOW, DECISIONS, PINS)


def test_project_isolation_does_not_ignore_an_equal_timestamp_open_sbx_attempt():
    opened, closed = {**LAST, "outcome": "reserved"}, {**LAST, "outcome": "recorded"}
    assert authority.verify_initial_gates([opened, closed, {**opened, "project": "fireemu-oracle-idp"}], NOW, DECISIONS, PINS)
    with pytest.raises(ValueError):
        authority.verify_initial_gates([closed, opened], NOW, DECISIONS, PINS)


def test_the_explicit_owner_version_is_the_alternative_to_an_envelope():
    direct = approve_row("オーナー（直接）")
    assert authority.authorize(direct, PINS) == (2 * REQUESTS, 0.02)
    revoked = f"- 2026-09-28 | FS-TRANSACTION | decision=REVOKED; envelopeId={ENVELOPE_ID} | オーナー（直接） | {PINS['packetPath']}\n"
    with pytest.raises(ValueError):
        authority.authorize(direct + revoked, PINS)


def test_owner_envelope_and_documented_within_envelope_actor_are_accepted():
    owner_envelope = envelope_row("オーナー（直接）")
    within = approve_row("Claude（委任。枠の内の承認し直し）")
    assert authority.authorize(AUTHORITY + owner_envelope + within, PINS) == (2 * REQUESTS, 0.04)
    with pytest.raises(ValueError):
        authority.authorize(within, PINS)


def test_another_programs_namespace_cannot_authorize_this_one():
    with pytest.raises(ValueError):
        authority.authorize(DECISIONS.replace(PACKET, "p09-grpc-retry"), PINS)
    for name in ["p09-grpc-retry", "p10-grpc-boundary", "expiry-retry-04", "Toy", "toy failed"]:
        with pytest.raises(ValueError, match="scope"):
            authority.authorize(DECISIONS, {**PINS, "packetName": name})
    with pytest.raises(ValueError):
        authority.authorize(DECISIONS.replace("reserveUsd=0.04", "reserveUsd=0.05"), PINS)
    with pytest.raises(ValueError, match="scope"):
        authority.authorize(DECISIONS, {**PINS, "envelopeId": "FS-TRANSACTION-p10-grpc-boundary-001"})
    with pytest.raises(ValueError, match="scope"):
        authority.authorize(DECISIONS, {**PINS, "requestsPerRecording": True})
    with pytest.raises(ValueError, match="scope"):
        authority.authorize(DECISIONS, {**PINS, "estimatedUsdPerRecording": 0.02})


def test_a_new_envelope_reserve_fits_the_whole_task_before_any_reservation():
    with pytest.raises(ValueError, match="limit"):
        authority.verify_initial_gates([{**LAST, "estimatedUsd": 9.97}], NOW, DECISIONS, PINS)
    assert authority.verify_initial_gates([{**LAST, "estimatedUsd": 9.96}], NOW, DECISIONS, PINS)


@pytest.mark.parametrize("scope", [{}, {key: value for key, value in SCOPE.items() if key != "writes"}, {**SCOPE, "extra": "x"}, {**SCOPE, "writes": ""}, {**SCOPE, "writes": 2}])
def test_the_pinned_scope_must_be_the_full_scope(scope):
    bare = AUTHORITY + envelope_row(scope={}) + APPROVE
    with pytest.raises(ValueError, match="scope"):
        authority.authorize(bare, {**PINS, "scope": scope})


@pytest.mark.parametrize("name", ["p09-grpc-retry", "p10-grpc-boundary", "p10-grpc-idle", "expiry-retry-04"])
def test_a_taken_name_never_authorizes_even_with_a_matching_envelope_id(name):
    with pytest.raises(ValueError, match="scope"):
        authority.authorize(DECISIONS, {**PINS, "packetName": name, "envelopeId": f"FS-TRANSACTION-{name}-001"})


def test_the_transports_in_the_scope_come_from_the_table():
    grpc_only = {**support.TABLE, "steps": tuple(step for step in support.TABLE["steps"] if step["transport"] == "grpc"), "caps": {**support.TABLE["caps"], "observation": 11}, "maxTokens": 1}
    assert authority.envelope_scope(grpc_only)["transports"] == "grpc"
    assert authority.envelope_scope(support.TABLE)["transports"] == "grpc+rest"


def test_query_is_billed_and_authority_scope_binds_each_declared_database():
    from txn_program_program import PROJECTS, budget_for
    assert "fireemu-oracle-query" in PROJECTS
    assert budget_for("fireemu-oracle-query") == (0.01, 0.04)
    assert budget_for("fireemu-oracle-txn") == (0.0, 0.0)
    table = {**support.TABLE, "project": "fireemu-oracle-query", "databases": {"foreign": "projects/fireemu-oracle-txn/databases/(default)", "named": "projects/fireemu-oracle-query/databases/txn-{nonce}"}}
    scope = authority.envelope_scope(table)
    assert scope["project"] == "fireemu-oracle-query/(default)+fireemu-oracle-query/txn-{nonce}+fireemu-oracle-txn/(default)"
    pins = {**PINS, "project": "fireemu-oracle-query", "scope": scope}
    assert authority.authorize(AUTHORITY + envelope_row(scope=scope) + APPROVE, pins) == (2 * REQUESTS, 0.04)
    with pytest.raises(ValueError, match="scope"):
        authority.authorize(AUTHORITY + envelope_row(scope={**scope, "project": "fireemu-oracle-query/(default)"}) + APPROVE, pins)
    with pytest.raises(ValueError):
        authority.authorize(DECISIONS, {**PINS, "project": "fireemu-oracle-idp"})


@pytest.mark.parametrize("kind", ["secondary-open", "secondary-active", "multi-project-open"])
def test_initial_gates_check_every_project_in_envelope_scope(kind):
    pins = {**PINS, "scope": {**SCOPE, "project": "fireemu-oracle-sbx/(default)+fireemu-oracle-txn/(default)"}}
    decisions = AUTHORITY + envelope_row(scope=pins["scope"]) + approve_row()
    row = {**LAST, "project": "fireemu-oracle-txn", "taskId": authority.TASK_ID}
    if kind == "secondary-active": row["ts"] = "2026-09-28T04:59:00Z"
    else: row.update(outcome="reserved", attemptId="open-secondary")
    if kind == "multi-project-open": row.update(project="fireemu-oracle-query", projects=["fireemu-oracle-query", "fireemu-oracle-txn"])
    with pytest.raises(ValueError): authority.verify_initial_gates([LAST, row], NOW, decisions, pins)


ACTION = {"command": "recover-database", "packetId": "fs-transaction-p16-recover-unit", "packetSha256": "d" * 64, "packetPath": "docs.local/reviews/recover-unit.json", "originalPacketSha256": PINS["packetSha256"], "envelopeId": "FS-TRANSACTION-p16-recover-unit", "envelopePath": "docs.local/reviews/recover-unit.md", "sourceCommit": PINS["sourceCommit"], "runnerSha256": PINS["runnerSha256"], "maxRequests": 8, "reserveUsd": 0.02, "resources": "projects/fireemu-oracle-query/databases/txn-" + "a" * 32}


def action_decisions(action=ACTION):
    fields = {key: action[key] for key in ("command", "originalPacketSha256", "sourceCommit", "runnerSha256", "envelopeId", "maxRequests", "reserveUsd", "resources")}
    fields.update(retries="none", onStop="lock-held", writes="none" if action["command"] == "readback-a2" else "one-owned-database-delete")
    text = "; ".join(f"{key}={value}" for key, value in fields.items())
    approve = f"- 2026-10-06 | FS-TRANSACTION p16 database action | decision=APPROVE; packetSha256={action['packetSha256']}; {text} | オーナー（直接） | {action['packetPath']}\n"
    envelope = f"- 2026-10-06 | FS-TRANSACTION p16 database action envelope | {text} | オーナー（直接） | {action['envelopePath']}\n"
    return approve + envelope


@pytest.mark.parametrize("change", [None, "approval", "envelope", "revoked", "resource", "command", "reserve"])
def test_database_action_requires_its_own_exact_approval_and_envelope(change):
    text = action_decisions()
    if change == "approval": text = text.splitlines(keepends=True)[1]
    elif change == "envelope": text = text.splitlines(keepends=True)[0]
    elif change == "revoked": text += f"- 2026-10-06 | FS-TRANSACTION p16 database action | REVOKED packetSha256={ACTION['packetSha256']} | オーナー（直接） | unit\n"
    elif change == "resource": text = text.replace(ACTION["resources"], "foreign")
    elif change == "command": text = text.replace("recover-database", "readback-a2")
    elif change == "reserve": text = text.replace("reserveUsd=0.02", "reserveUsd=0")
    if change is None: assert authority.authorize_database_action(text, ACTION) == (8, 0.02)
    else:
        with pytest.raises(ValueError): authority.authorize_database_action(text, ACTION)


@pytest.mark.parametrize("identity", ["packetSha256", "envelopeId", "sourceCommit", "runnerSha256"])
def test_database_action_rejects_revocation_outside_its_approval_topic(identity):
    text = action_decisions() + f"- 2026-10-06 | Other authority | REVOKED {identity}={ACTION[identity]} | オーナー（直接） | unit\n"
    with pytest.raises(ValueError, match="revoked"):
        authority.authorize_database_action(text, ACTION)


@pytest.mark.parametrize("source", ["fixture", "live"])
def test_initial_gates_accept_real_project_history_read_only(source):
    import json
    from pathlib import Path
    if source == "fixture":
        path = Path(__file__).with_name("fixtures") / "p16-project-history-masked.jsonl"
    else:
        path = next((parent / "docs.local/runs/sandbox-ledger.jsonl" for parent in Path(__file__).resolve().parents if (parent / "docs.local/runs/sandbox-ledger.jsonl").is_file()), None)
        if path is None:
            pytest.skip("real sandbox ledger is absent")
    original = path.read_bytes()
    rows = [json.loads(line) for line in original.splitlines() if line.strip()]
    scope = {**SCOPE, "project": "fireemu-oracle-query/(default)+fireemu-oracle-query/txn-{nonce}+fireemu-oracle-txn/(default)"}
    pins = {**PINS, "project": "fireemu-oracle-query", "scope": scope}
    decisions = AUTHORITY + envelope_row(scope=scope) + approve_row()
    now = datetime(2026, 10, 7, tzinfo=timezone.utc)
    assert authority.verify_initial_gates(rows, now, decisions, pins)
    assert path.read_bytes() == original


@pytest.mark.parametrize("project", ["fireemu-oracle-query", "fireemu-oracle-txn"])
@pytest.mark.parametrize("identity", ["taskId", "task-alias", "packetId", "envelopeId"])
def test_history_excludes_other_tasks_but_never_an_open_current_attempt(project, identity):
    scope = {**SCOPE, "project": "fireemu-oracle-query/(default)+fireemu-oracle-txn/(default)"}
    pins = {**PINS, "project": "fireemu-oracle-query", "scope": scope}
    decisions = AUTHORITY + envelope_row(scope=scope) + approve_row()
    row = {"ts": LAST["ts"], "project": project, "taskId": "OTHER", "event": "started", "run": "historical"}
    assert authority.verify_initial_gates([row], NOW, decisions, pins) == (row["ts"] if project == "fireemu-oracle-query" else None)
    if identity == "task-alias":
        row["taskId"] = "FS-TRANSACTION"
    else:
        row[identity] = authority.TASK_ID if identity == "taskId" else pins[identity]
    with pytest.raises(ValueError):
        authority.verify_initial_gates([row], NOW, decisions, pins)


@pytest.mark.parametrize("event,outcome", [("started", None), (None, "reserved"), (None, "recorded")])
@pytest.mark.parametrize("seconds", [1799, 1800])
def test_spacing_uses_last_project_row_of_any_task(event, outcome, seconds):
    from datetime import timedelta
    scope = {**SCOPE, "project": "fireemu-oracle-query/(default)+fireemu-oracle-txn/(default)"}
    pins = {**PINS, "project": "fireemu-oracle-query", "scope": scope}
    decisions = AUTHORITY + envelope_row(scope=scope) + approve_row()
    row = {"ts": (NOW - timedelta(seconds=seconds)).isoformat(), "project": "fireemu-oracle-txn", "taskId": "OTHER", "event": event, "outcome": outcome}
    if seconds == 1799:
        with pytest.raises(ValueError, match="30 minutes"):
            authority.verify_initial_gates([row], NOW, decisions, pins)
    else:
        authority.verify_initial_gates([row], NOW, decisions, pins)
