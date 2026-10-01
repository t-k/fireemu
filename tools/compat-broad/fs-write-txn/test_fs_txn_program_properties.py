"""Seeded random program tables: `compile_plan` either refuses a table or yields a plan whose recording keeps the framework's invariants.

For every generated valid table, against a stand-in service with randomly chosen behaviour (limits that expire tokens or not, refused commits, a lost
answer that stops the run), the receipt must show: every issued token is resolved (no open token is left behind, even when the run stops); no token is
released by an accepted Rollback twice; at every begin no earlier token is still open except the one a retry names; and the request count stays within
the plan's declared maximum, phase by phase. Generated invalid tables must be refused with the table error, never compiled and never crash.

The seeds that found something are kept in REGRESSION_SEEDS and always run first; the rest are `range(SEEDS)`. A failure prints its seed, so a case is
reproduced with `generate(random.Random(seed))`."""

import copy
import random
from pathlib import Path

import pytest

from txn_program_collector import Collector
from txn_program_program import RequestBudget, compile_plan
from test_txn_program_collector import Clock, Service

NONCE, OWNER = "a" * 32, "b" * 32
ANY = (0, 3, 5, 9, 10)
SEEDS = 150
REGRESSION_SEEDS = (0, 1, 2, 3, 7, 11, 23, 42, 97, 128)   # kept: the first generated cases of each shape, replayed first on every run
RESOLVED = ("committed", "rolled-back", "released-refused", "released-expired")


def step(step_id, rpc, role, *, transport="rest", document=None, token_in=None, token_out=None, writes=(), case=None, allow=(0,), wait=None, retry_of=None):
    row = {"id": step_id, "transport": transport, "rpc": rpc, "document": document, "tokenInput": token_in, "tokenOutput": token_out,
           "writes": tuple({"document": name, "state": state, "exists": exists} for name, state, exists in writes),
           "caseId": case, "role": role, "allow": allow}
    if wait:
        row["waitSeconds"] = wait
    if retry_of:
        row["retryOf"] = retry_of
    return row


def generate(rng):
    """One random table: a setup and one to four chains, each plain, retried after a Rollback, or ending in a retry of an idle or aged token."""
    steps = [step("setup/absence-a", "GetDocument", "control", transport="grpc", document="a", allow=(5,)),
             step("setup/create-a", "Commit", "control", transport="grpc", writes=(("a", "created", False),))]
    tokens, cases = [], 0
    for chain in range(rng.randint(1, 4)):
        kind = rng.choice(["plain", "plain", "retry-after-rollback", "idle-retry"])
        name = f"c{chain}"
        token = f"{name}t"
        tokens.append(token)
        steps.append(step(f"rest/{name}/begin", "BeginTransaction", "control", token_out=token))
        steps.append(step(f"rest/{name}/read-a", "GetDocument", "control", document="a", token_in=token))

        def observe(label, rpc, **extra):
            nonlocal cases
            cases += 1
            return step(f"rest/{name}/{label}", rpc, "observation", token_in=extra.pop("token", token), case=f"rest/{name}-{label}", allow=ANY, **extra)

        if kind == "plain":
            for index in range(rng.randint(0, 3)):
                steps.append(observe(f"read-{index}", "GetDocument", document="a", wait=rng.choice([None, 5, 24, 90, 130, 200])))
            ending = rng.choice(["commit", "rollback", "none"])
            if ending == "commit":
                steps.append(observe("commit", "Commit", writes=(("a", "written", True),), wait=rng.choice([None, 10])))
            elif ending == "rollback":
                steps.append(observe("rollback", "Rollback", wait=rng.choice([None, 10, 150])))
        elif kind == "retry-after-rollback":
            steps.append(step(f"rest/{name}/rollback", "Rollback", "observation", token_in=token, case=f"rest/{name}-rollback", allow=(0, 10)))
            cases += 1
            retried = f"{name}r"
            tokens.append(retried)
            steps.append(step(f"rest/{name}/retry-begin", "BeginTransaction", "control", token_out=retried, retry_of=token))
            if rng.random() < 0.7:
                steps.append(step(f"rest/{name}/retry-read", "GetDocument", "observation", document="a", token_in=retried, case=f"rest/{name}-retry-read", allow=ANY))
                cases += 1
        else:
            # an idle (or aged) token, then a retry that ends the chain
            tokens.append(f"{name}r")
            steps.append(step(f"rest/{name}/retry-idle", "BeginTransaction", "observation", token_out=f"{name}r", retry_of=token, case=f"rest/{name}-retry-idle", allow=ANY,
                              wait=rng.choice([30, 130, 200, 285])))
            cases += 1
    steps.append(step("final/post-read-a", "GetDocument", "post-state", document="a"))
    waits = sum(row.get("waitSeconds", 0) for row in steps)
    table = {"name": "toy-properties", "program": "FS-TRANSACTION-TOY-PROPERTIES", "envelopeId": "FS-TRANSACTION-toy-properties-001", "slug": "txn-prop", "documents": ("a",),
             "states": ("created", "written"), "steps": tuple(steps), "thresholds": {"totalAgeSeconds": 270, "releaseAfterAgeSeconds": 275},
             "caps": {"observation": len(steps), "tokenCleanup": len(tokens) + 1, "documentCleanup": 7, "management": 7, "credential": 2},
             "observationSeconds": waits + 6 * len(steps) + 120, "recoverySeconds": 180, "maxTokens": len(tokens), "sourceFile": Path(__file__)}
    return table


INVALID = ("duplicate-id", "unknown-retry-role", "retry-on-read", "wait-on-begin", "grpc-retry", "unissued-token", "bad-allow", "extra-token")


def corrupt(table, rng):
    """Break a valid table in one way the validation must catch."""
    steps = [dict(row) for row in table["steps"]]
    how = rng.choice(INVALID)
    reads = [i for i, row in enumerate(steps) if row["rpc"] == "GetDocument" and row["tokenInput"]]
    begins = [i for i, row in enumerate(steps) if row["rpc"] == "BeginTransaction" and "retryOf" not in row]
    retries = [i for i, row in enumerate(steps) if "retryOf" in row]
    if how == "duplicate-id":
        steps[-1]["id"] = steps[2]["id"]
    elif how == "unknown-retry-role" and retries:
        steps[rng.choice(retries)]["retryOf"] = "nothing"
    elif how == "retry-on-read" and reads:
        steps[rng.choice(reads)]["retryOf"] = steps[begins[0]]["tokenOutput"]
    elif how == "wait-on-begin" and begins:
        steps[rng.choice(begins)]["waitSeconds"] = 5
    elif how == "grpc-retry" and retries:
        steps[rng.choice(retries)]["transport"] = "grpc"
    elif how == "unissued-token" and reads:
        steps[rng.choice(reads)]["tokenInput"] = "never-issued"
    elif how == "bad-allow":
        steps[2]["allow"] = (0, 0)
    else:
        table = {**table, "maxTokens": table["maxTokens"] + 1}
    return {**table, "steps": tuple(steps)}, how


def service_for(rng, clock):
    return Service(clock, expiry=rng.random() < 0.7, lifetime=270, idle=120, rpc_seconds=rng.choice([0.5, 1.0, 2.0]), rw_commit_code=rng.choice([0, 0, 10]),
                   fail_at=rng.choice([None, None, None, rng.randint(4, 30)]))


def resolving_rows(receipt):
    """Per token role, the sequence numbers of the rows that resolve it: any Rollback that names it, and an accepted Commit that carries it."""
    rows = receipt["steps"] + receipt["cleanupSteps"]
    values = {role: entry["value"] for role, entry in receipt["tokens"].items()}
    resolved = {role: [] for role in values}
    for row in rows:
        request = row.get("request") or {}
        for role, value in values.items():
            if request.get("transaction") == value and (row["rpc"] == "Rollback" or (row["rpc"] == "Commit" and row["result"]["code"] == 0)):
                resolved[role].append(row["sequence"])
    return rows, values, resolved


def check_invariants(table, plan, receipt):
    # nothing is left open, even when the run stopped, except a token whose release answer was lost (an unknown outcome is never resent: the run
    # reports itself unrecovered and keeps the lock for a human, which is the design; an unknown commit or document cleanup does the same)
    states = {role: entry["state"] for role, entry in receipt["tokens"].items()}
    if receipt["unrecovered"]:
        assert set(receipt["openTokens"]) == {role for role, state in states.items() if state == "unconfirmed-release"}, (receipt["openTokens"], states)
    else:
        assert receipt["openTokens"] == [], receipt["openTokens"]
    assert all(state in RESOLVED or state == "unconfirmed-release" for state in states.values()), states
    assert all(state in RESOLVED for state in states.values()) or receipt["unrecovered"], states
    rows, values, resolved = resolving_rows(receipt)
    # no token is released by an accepted Rollback twice
    for role, value in values.items():
        accepted = [row for row in rows if row["rpc"] == "Rollback" and (row.get("request") or {}).get("transaction") == value and row["result"]["code"] == 0]
        assert len(accepted) <= 1, f"{role} released twice"
        cleanup = [row for row in rows if row["site"] == f"cleanup/token/{role}"]
        assert len(cleanup) <= 1, f"{role} has {len(cleanup)} cleanup releases"
    # at every begin, every earlier token is resolved, except the one a retry names
    begins = sorted((row for row in rows if row["rpc"] == "BeginTransaction"), key=lambda row: row["sequence"])
    for row in begins:
        named = ((row["request"].get("options") or {}).get("readWrite") or {}).get("retryTransaction")
        for role, value in values.items():
            issued_before = any(other["rpc"] == "BeginTransaction" and other["sequence"] < row["sequence"] and other["result"]["code"] == 0
                                and other["result"]["response"].get("transaction") == value for other in begins)
            if not issued_before or value == named:
                continue
            assert any(sequence < row["sequence"] for sequence in resolved[role]), f"{role} is still open at {row['site']}"
    # the request count stays inside the declared maximum, phase by phase
    assert receipt["sandboxRequests"] <= plan["maxRequests"]
    for phase, count in receipt["phaseRequests"].items():
        assert count <= plan["caps"][phase], (phase, count)


def run(seed):
    rng = random.Random(seed)
    table = generate(rng)
    plan = compile_plan(table, NONCE, OWNER)
    clock = Clock()
    service = service_for(rng, clock)
    receipt = Collector(plan, table, RequestBudget(plan, table), service, "owner", save=lambda _state: None, monotonic=clock.now, utc=clock.utc, sleep=clock.sleep).run()
    check_invariants(table, plan, receipt)
    return receipt


@pytest.mark.parametrize("seed", list(REGRESSION_SEEDS) + [seed for seed in range(SEEDS) if seed not in REGRESSION_SEEDS])
def test_a_generated_valid_table_compiles_and_its_recording_keeps_the_invariants(seed):
    run(seed)


@pytest.mark.parametrize("seed", range(SEEDS))
def test_a_generated_invalid_table_is_refused_with_the_table_error(seed):
    rng = random.Random(10_000 + seed)
    table = generate(rng)
    broken, how = corrupt(copy.deepcopy(table), rng)
    if broken["steps"] == table["steps"] and broken["maxTokens"] == table["maxTokens"]:
        pytest.skip(f"{how} had nothing to break in this table")
    with pytest.raises(ValueError, match="txn-program table"):
        compile_plan(broken, NONCE, OWNER)


def test_the_generator_covers_every_chain_shape_and_the_recordings_both_complete_and_stop():
    shapes, completed, stopped = set(), 0, 0
    for seed in range(SEEDS):
        receipt = run(seed)
        rng = random.Random(seed)
        table = generate(rng)
        for row in table["steps"]:
            if "retryOf" in row:
                shapes.add("control-retry" if row["role"] == "control" else "observation-retry")
        completed += bool(receipt["complete"])
        stopped += not receipt["complete"]
    assert shapes == {"control-retry", "observation-retry"}
    assert completed > 10 and stopped > 5, (completed, stopped)
