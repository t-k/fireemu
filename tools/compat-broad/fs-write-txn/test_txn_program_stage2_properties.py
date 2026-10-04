"""Properties of the stage 2 step keys' pure rules, over generated inputs (seeded, so a failure reproduces): the read time ago, the replay's tolerance, the cancel's outcome class,
and the bounds of the cancel and the read time ago."""

import copy
import importlib
import random

import pytest

program = importlib.import_module("txn_program_program")
support = importlib.import_module("txn_program_support_for_tests")
NONCE, OWNER = "a" * 32, "b" * 32
WIDE = (0, 3, 5, 9, 10)
SEED = 20261005


def rng():
    return random.Random(SEED)


def test_a_read_time_ago_is_the_time_now_less_the_seconds_to_the_microsecond_and_never_finer():
    random_ = rng()
    for _ in range(3000):
        now = 1_600_000_000 + random_.random() * 300_000_000
        seconds = random_.randint(1, program.READ_AGO_MAX)
        stamp = program.read_time_ago(now, seconds)
        assert stamp["nanos"] % 1000 == 0 and 0 <= stamp["nanos"] < 1_000_000_000 and stamp["seconds"].isdigit()
        assert abs(program._epoch(stamp) - (now - seconds)) < 2e-6
        # a longer time ago is an earlier time
        assert program._epoch(program.read_time_ago(now, seconds + 1)) < program._epoch(stamp) + 1e-6


def test_the_replay_accepts_a_recorded_read_time_exactly_when_it_precedes_the_dispatch_derived_one_by_at_most_five_seconds():
    random_ = rng()
    step = {"readAgoSeconds": 3540}
    for _ in range(3000):
        now = 1_700_000_000 + random_.randint(0, 100_000_000)
        expected_time = program.read_time_ago(now, 3540)
        offset_ms = random_.randint(-3000, 9000)
        total_micros = int(expected_time["seconds"]) * 1_000_000 + expected_time["nanos"] // 1000 - offset_ms * 1000
        recorded_time = {"seconds": str(total_micros // 1_000_000), "nanos": (total_micros % 1_000_000) * 1000}
        accepted = program.same_request(step, {"name": "n", "readTime": recorded_time}, {"name": "n", "readTime": expected_time})
        assert accepted == (0 <= offset_ms <= 5000), offset_ms


def test_a_cancel_is_a_client_cancel_only_as_code_1_on_a_step_that_cancels():
    for code in range(0, 17):
        for cancels in (False, True):
            step = {"cancelAfter": 1} if cancels else {}
            expected = "CLIENT_CANCEL" if code == 1 and cancels else program.outcome_class(code)
            assert program.step_outcome_class(step, code) == expected
    assert program.outcome_class(1) == "UNKNOWN"


def query_table(**fields):
    table = copy.deepcopy(support.TABLE)
    step = {"id": "q/step", "transport": "grpc", "rpc": "RunQuery", "document": None, "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": "q/step", "role": "observation", "allow": (1,), "query": {}}
    step.update(fields)
    table["steps"] = tuple(table["steps"]) + (step,)
    table["caps"] = {**table["caps"], "observation": len(table["steps"])}
    return table


def compiles(table):
    try:
        program.compile_plan(table, NONCE, OWNER)
    except ValueError:
        return False
    return True


def test_a_cancel_is_admitted_exactly_for_one_to_the_frame_cap():
    for frames in range(-5, 26):
        assert compiles(query_table(cancelAfter=frames)) == (1 <= frames <= program.MAX_CANCEL_FRAMES), frames


def test_a_read_time_ago_is_admitted_exactly_for_one_second_to_the_limit():
    random_ = rng()
    values = [-10, -1, 0, 1, 2, 3540, 3660, program.READ_AGO_MAX - 1, program.READ_AGO_MAX, program.READ_AGO_MAX + 1] + [random_.randint(-100, 10_000) for _ in range(40)]
    for seconds in values:
        step = {"id": "g/step", "transport": "rest", "rpc": "GetDocument", "document": "a", "tokenInput": None, "tokenOutput": None, "writes": (), "caseId": "g/step", "role": "observation", "allow": WIDE, "readAgoSeconds": seconds}
        table = copy.deepcopy(support.TABLE)
        table["steps"] = tuple(table["steps"]) + (step,)
        table["caps"] = {**table["caps"], "observation": len(table["steps"])}
        assert compiles(table) == (1 <= seconds <= program.READ_AGO_MAX), seconds


@pytest.mark.parametrize("transport", ["rest", "grpc"])
def test_a_query_in_any_declared_state_compiles_and_names_the_runs_collection(transport):
    table = query_table(transport=transport, allow=WIDE)
    for state in table["states"]:
        step = dict(table["steps"][-1], query={"stateEquals": state}, id=f"q/{state}", caseId=f"q/{state}")
        value = dict(table, steps=tuple(table["steps"][:-1]) + (step,))
        plan = program.compile_plan(value, NONCE, OWNER)
        request = program.request_for_step(plan, plan["steps"][-1], {}, value)
        assert request["parent"].endswith(f"/documents/oracle/{NONCE}") and request["structuredQuery"]["from"] == [{"collectionId": "txn-toy"}]
        assert request["structuredQuery"]["where"]["fieldFilter"]["value"] == {"stringValue": state}
