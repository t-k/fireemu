"""Local `fireemu` shadow contract for the user-token Rules matrix.

The shadow runs the same compiled matrix against a locally owned `fireemu`
instance, so the production side of the comparison has something to be compared
with. Nothing here starts a process: the module fixes the launch specification
and the expected local outcome, and collects through the same injected
transport the production collector uses.

Wiring the specification to `tools/compat-inventory/owned_runner.py` is the
next unit. It is kept out of this module deliberately, because an untested
process launcher in a preparation package would be a liability, not evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from o5_user_token_case import validate_case
from o5_user_token_collector import ROLE_LOCAL_SHADOW, collect

SHADOW_CONTRACT = "fs-rules-user-token-shadow-v1"

# Only these variables are passed to the local instance. A production endpoint
# or credential must not be reachable from the shadow run.
ENVIRONMENT_ALLOWLIST = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL")

FORBIDDEN_ENVIRONMENT = (
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "GCLOUD_PROJECT",
    "FIREBASE_TOKEN",
)


def launch_specification(plan: Mapping[str, Any]) -> dict[str, Any]:
    """The owned local instance this matrix needs, with OS-assigned ports.

    `fireemu exec` requires a trailing command, so the driver runs *inside* the
    instance's lifetime as the `--` child and inherits the assigned origins
    through its environment. That is the pattern the other lanes use, and it is
    why the argv ends with a placeholder for the driver command.
    """
    validate_case(plan)
    return {
        "contract": SHADOW_CONTRACT,
        "binary": "fireemu",
        "buildCommand": ["cargo", "build", "--locked", "-p", "fireemu"],
        "argv": [
            "exec",
            "--firebase-json",
            "<owned-firebase.json>",
            "--project",
            plan["project"],
            "--only",
            "auth,firestore",
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--hub-port",
            "0",
            "--ui-port",
            "0",
            "--logging-port",
            "0",
            "--log-verbosity",
            "silent",
            "--",
            "<driver-command>",
        ],
        "driverEnvironment": [
            "FIRESTORE_EMULATOR_HOST",
            "FIREBASE_AUTH_EMULATOR_HOST",
        ],
        "portAssignment": "os-assigned",
        "environmentAllowlist": list(ENVIRONMENT_ALLOWLIST),
        "forbiddenEnvironment": list(FORBIDDEN_ENVIRONMENT),
        "rulesFiles": {
            label: body["source"] for label, body in plan["rulesets"].items()
        },
        "rulesPublishRoute": (
            "PUT /emulator/v1/projects/{project}:securityRules on the Firestore origin"
        ),
        "tenant": plan["tenant"],
        "teardown": [
            "terminate the owned process",
            "wait, then kill only that pid",
            "assert both origins are closed",
        ],
        "notes": (
            "the local Auth emulator mints unsigned tokens, so a local allow "
            "proves the Rules decision, never production token verification"
        ),
    }


def expected_local_bundle(plan: Mapping[str, Any]) -> dict[str, Any]:
    """The statuses a correct local runtime must produce for this matrix."""
    validate_case(plan)
    return {
        "contract": SHADOW_CONTRACT,
        "planDigest": plan["planDigest"],
        "expected": [
            {
                "index": row["index"],
                "caseId": row["caseId"],
                "condition": row["condition"],
                "role": row["role"],
                "status": row["expect"]["status"],
            }
            for row in plan["observation"]
        ],
    }


def collect_shadow(
    plan: Mapping[str, Any],
    execute: Callable[[dict[str, Any]], Any],
    *,
    run_id: str,
    deadline_seconds: float = 300.0,
    clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    """Collect the local side of the comparison through an injected transport."""
    kwargs: dict[str, Any] = {}
    if clock is not None:
        kwargs["clock"] = clock
    return collect(
        plan,
        execute,
        role=ROLE_LOCAL_SHADOW,
        run_id=run_id,
        deadline_seconds=deadline_seconds,
        **kwargs,
    )


def local_deviations(
    bundle: Mapping[str, Any],
    plan: Mapping[str, Any],
    uids: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Rows where the local runtime disagreed with the compiled expectation.

    A deviation is a repair ticket for the local runtime. It is never evidence
    about production behavior.

    When ``uids`` is supplied, a row that froze expected fields is also checked
    field by field, with ``{"$principal": ref}`` resolved through the map. That
    is what turns the atomic-multiwrite post-state row into a proof that the
    allowed half of the refused commit was not applied.
    """
    validate_case(plan)
    deviations = []
    for row, operation in zip(
        bundle.get("rows", []), plan["observation"], strict=False
    ):
        observed = row.get("observed") or {}
        status = observed.get("status")
        expected = operation["expect"]
        if row.get("failure") is not None:
            deviations.append(
                {
                    "caseId": operation["caseId"],
                    "condition": operation["condition"],
                    "expected": expected["status"],
                    "observed": None,
                    "reason": row["failure"],
                }
            )
            continue
        if status != expected["status"]:
            deviations.append(
                {
                    "caseId": operation["caseId"],
                    "condition": operation["condition"],
                    "expected": expected["status"],
                    "observed": status,
                    "reason": "status-deviation",
                }
            )
            continue
        if uids is None or "fields" not in expected:
            continue
        wanted = _resolve(expected["fields"], uids)
        seen = observed.get("fields")
        if seen != wanted:
            deviations.append(
                {
                    "caseId": operation["caseId"],
                    "condition": operation["condition"],
                    "expected": wanted,
                    "observed": seen,
                    "reason": "field-deviation",
                }
            )
    return deviations


def _resolve(fields: Mapping[str, Any], uids: Mapping[str, str]) -> dict[str, Any]:
    resolved = {}
    for key, value in fields.items():
        if isinstance(value, dict):
            resolved[key] = uids[value["$principal"]]
        else:
            resolved[key] = value
    return resolved
