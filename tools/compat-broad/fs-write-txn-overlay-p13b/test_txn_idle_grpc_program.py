"""P10-A graph preserves its idle candidates and recovery reservations."""

import pytest

import txn_idle_grpc_program as p


def test_closed_graph_has_26_slots_six_tokens_and_four_idle_waits():
    plan = p.compile_plan('a' * 32, 'b' * 32)
    assert len(plan['steps']) == 26
    assert plan['caps'] == {'observation': 26, 'tokenCleanup': 6, 'documentCleanup': 7, 'management': 7, 'credential': 2}
    assert plan['maxRequests'] == sum(plan['caps'].values()) == 48
    assert plan['observationSeconds'] == 900 and plan['recoverySeconds'] == 180
    assert plan['waits'] == {'live/commit': 55, 'expired/commit': 65, 'rollback-first/rollback': 65, 'get-first/expired-read': 65}
    assert len({row['tokenOutput'] for row in plan['steps'] if row['tokenOutput']}) == 6
    assert plan['document'].endswith('/oracle/' + 'a' * 32 + '/txn-p10/control')
    assert plan['conditionalSkips'] == ['rollback-first/snapshot', 'rollback-first/finish', 'get-first/snapshot', 'get-first/finish']


def test_scope_and_plan_tampering_are_rejected():
    with pytest.raises(ValueError): p.compile_plan('../foreign', 'b' * 32)
    plan = p.compile_plan('a' * 32, 'b' * 32)
    plan['waits']['live/commit'] = 0
    with pytest.raises(ValueError): p.validate_plan(plan)


def test_observation_cannot_borrow_the_six_token_cleanup_reserve():
    budget = p.RequestBudget(p.compile_plan('a' * 32, 'b' * 32))
    for _ in range(26): budget.charge('observation')
    with pytest.raises(ValueError): budget.charge('observation')
    for phase, count in [('tokenCleanup', 6), ('documentCleanup', 7), ('management', 7), ('credential', 2)]:
        for _ in range(count): budget.charge(phase)
        with pytest.raises(ValueError): budget.charge(phase)
    assert budget.total == 48
