"""Per-task production budget: US$10 per observation task, never program-wide.

The owner's authorization is per production observation task, identified by
the campaign id (`FS-LIMIT-API-REQUEST-BYTES`, for example), and covers
everything that task ever charges: preparation, failed attempts, retries,
re-checks after a fix and recovery. Independent tasks each have their own
US$10. The program-wide total is reported elsewhere; it is never a stop
condition here.

Every reservation of a task counts whatever state it reached, because the
shared Ledger never refunds an allocation: a released, aborted, escalated,
abandoned or still-held row all keep their full claim charged.
"""

from __future__ import annotations

TASK_CAP_MICROUSD = 10_000_000
REFUSAL_PREFIX = "task-budget-exceeded:"


def task_spent_microusd(ledger_state, campaign_id):
    """Micro-USD already allocated to one task, across every reservation state."""
    if not isinstance(ledger_state, dict) or not isinstance(campaign_id, str):
        raise ValueError("ledger state and campaign id required")  # noqa: TRY004 -- refusal class, not a type report
    total = 0
    for row in ledger_state.get("reservations", {}).values():
        claim = row.get("claim") if isinstance(row, dict) else None
        if not isinstance(claim, dict) or claim.get("campaignId") != campaign_id:
            continue
        cost = claim.get("budget", {}).get("costMicrousd")
        if type(cost) is not int or cost < 0:
            raise ValueError("closed integer budget required")
        total += cost
    return total


def task_budget_check(
    ledger_state, campaign_id, new_cost_microusd, cap_microusd=TASK_CAP_MICROUSD
):
    """Refuse a claim that would take one task past its cap.

    Returns the task's projected total when admitted. The sum is over every
    reservation whose claim names the task, in every state, plus the new
    claim; the refusal names the task so the operator knows which US$10 is
    exhausted.
    """
    if (
        type(new_cost_microusd) is not int
        or new_cost_microusd < 0
        or type(cap_microusd) is not int
        or cap_microusd <= 0
    ):
        raise ValueError("closed integer task budget required")
    projected = task_spent_microusd(ledger_state, campaign_id) + new_cost_microusd
    if projected > cap_microusd:
        raise ValueError(
            f"{REFUSAL_PREFIX}{campaign_id} ({projected} > {cap_microusd} micro-USD)"
        )
    return projected
