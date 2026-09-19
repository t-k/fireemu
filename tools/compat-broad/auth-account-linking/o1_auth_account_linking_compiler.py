"""Record unresolved preparation for the existing v10 account-linking case."""

from __future__ import annotations

from typing import Any

CONTRACT = "auth-settings-v1"
CASE_ID = "account-linking-duplicate-email"
PARENT_PATH = "spec/compatibility/broad-runs/auth-settings-sdk-next-v10.json"
BINDINGS = {key: "UNBOUND" for key in ("source", "artifact", "configuration", "sdk")}
BOUNDS = {
    "concurrencyMax": 1,
    "requestRateMax": 1,
    "elapsedSecondsMax": 90,
    "httpCredentialOperationsMax": 12,
    "accountsMax": 2,
}
OBSERVATIONS = {
    "allowDuplicateEmailsFalse": "LOCAL_ONLY",
    "allowDuplicateEmailsTrue": "UNOBSERVED",
    "production": "UNOBSERVED",
}
UNRESOLVED = [
    "Bind source files and commit, built artifact, configuration readback, and installed SDK.",
    "Observe both duplicate-email modes and the production collision outcome.",
    "Record operation responses, readback, and absence of every owned UID after cleanup.",
]


def compile_case() -> dict[str, Any]:
    """Describe an unresolved subtask without creating a runnable case."""
    return {
        "contract": CONTRACT,
        "parentCase": {"path": PARENT_PATH, "id": CASE_ID},
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "productionAllowed": False,
        "bindings": BINDINGS.copy(),
        "bounds": BOUNDS.copy(),
        "observations": OBSERVATIONS.copy(),
        "unresolved": UNRESOLVED.copy(),
    }


def validate_plan(plan: Any) -> None:
    if plan != compile_case():
        raise ValueError("preparation-only plan mismatch")
