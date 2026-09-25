"""Preparation receipts cannot establish production parity."""

from __future__ import annotations

from typing import Any

from o1_auth_account_linking_compiler import CONTRACT


def compare(left: Any, right: Any) -> dict[str, Any]:
    """Fail closed until a separate, reviewed executable case has bound evidence."""
    _ = left, right
    return {
        "contract": CONTRACT,
        "status": "PREPARATION_ONLY",
        "classification": "INDETERMINATE",
        "productionCompared": False,
        "reason": "no-bound-production-and-local-observations",
    }
