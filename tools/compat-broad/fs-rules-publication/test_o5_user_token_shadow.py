from __future__ import annotations

from o5_user_token_case import compile_case
from o5_user_token_collector import ROLE_LOCAL_SHADOW
from o5_user_token_shadow import (
    ENVIRONMENT_ALLOWLIST,
    collect_shadow,
    expected_local_bundle,
    launch_specification,
    local_deviations,
)
from test_o5_user_token_collector import Transport

PROJECT = "fireemu-35fe6"
NONCE = "e" * 32


def case() -> dict:
    return compile_case(PROJECT, "(default)", NONCE)


def test_launch_specification_uses_os_assigned_ports_only() -> None:
    spec = launch_specification(case())
    argv = spec["argv"]
    for flag in (
        "--firestore-port",
        "--http-port",
        "--hub-port",
        "--ui-port",
        "--logging-port",
    ):
        assert argv[argv.index(flag) + 1] == "0"
    assert spec["portAssignment"] == "os-assigned"


def test_exec_argv_carries_a_trailing_driver_command() -> None:
    """`fireemu exec` refuses an argv with no command after `--`."""
    argv = launch_specification(case())["argv"]
    assert argv[0] == "exec"
    assert "--" in argv
    separator = argv.index("--")
    assert argv[separator + 1 :], "exec needs a command after the separator"
    assert argv[-1] == "<driver-command>"


def test_launch_specification_starts_auth_and_firestore_for_this_matrix() -> None:
    spec = launch_specification(case())
    assert spec["argv"][spec["argv"].index("--only") + 1] == "auth,firestore"
    assert spec["argv"][spec["argv"].index("--project") + 1] == PROJECT
    assert "FIRESTORE_EMULATOR_HOST" in spec["driverEnvironment"]
    assert "FIREBASE_AUTH_EMULATOR_HOST" in spec["driverEnvironment"]


def test_launch_specification_excludes_production_credentials() -> None:
    spec = launch_specification(case())
    assert set(spec["environmentAllowlist"]) == set(ENVIRONMENT_ALLOWLIST)
    assert "GOOGLE_APPLICATION_CREDENTIALS" in spec["forbiddenEnvironment"]
    for name in spec["environmentAllowlist"]:
        assert name not in spec["forbiddenEnvironment"]


def test_launch_specification_carries_both_ruleset_sources() -> None:
    plan = case()
    spec = launch_specification(plan)
    assert set(spec["rulesFiles"]) == {"A", "B"}
    assert spec["rulesFiles"]["A"] == plan["rulesets"]["A"]["source"]
    assert spec["teardown"]
    assert "securityRules" in spec["rulesPublishRoute"]


def test_expected_local_bundle_mirrors_the_compiled_matrix() -> None:
    plan = case()
    expected = expected_local_bundle(plan)
    assert expected["planDigest"] == plan["planDigest"]
    assert [row["status"] for row in expected["expected"]] == [
        row["expect"]["status"] for row in plan["observation"]
    ]


def test_a_conforming_local_run_reports_no_deviation() -> None:
    plan = case()
    result = collect_shadow(plan, Transport(plan), run_id="local-1")
    assert result["provenance"]["role"] == ROLE_LOCAL_SHADOW
    assert local_deviations(result, plan) == []


def test_a_local_status_deviation_becomes_a_repair_ticket() -> None:
    plan = case()
    result = collect_shadow(plan, Transport(plan), run_id="local-1")
    result["rows"][1]["observed"]["status"] = "OK"
    tickets = local_deviations(result, plan)
    assert len(tickets) == 1
    assert tickets[0]["caseId"] == plan["observation"][1]["caseId"]
    assert tickets[0]["expected"] == "PERMISSION_DENIED"
    assert tickets[0]["observed"] == "OK"


def test_a_failed_local_row_is_a_repair_ticket_too() -> None:
    plan = case()
    result = collect_shadow(plan, Transport(plan, incomplete_at=0), run_id="local-1")
    tickets = local_deviations(result, plan)
    assert tickets[0]["observed"] is None


def test_frozen_expected_fields_are_checked_when_uids_are_supplied() -> None:
    plan = case()
    uids = {entry["ref"]: f"uid-{entry['ref']}" for entry in plan["ownedAccounts"]}
    poststate = next(row for row in plan["observation"] if row["role"] == "poststate")
    result = collect_shadow(plan, Transport(plan), run_id="local-1")

    def resolve(fields: dict) -> dict:
        return {
            key: uids[value["$principal"]] if isinstance(value, dict) else value
            for key, value in fields.items()
        }

    for row, operation in zip(result["rows"], plan["observation"], strict=True):
        if "fields" in operation["expect"]:
            row["observed"]["fields"] = resolve(operation["expect"]["fields"])
    assert local_deviations(result, plan, uids) == []

    # An applied half of the refused commit changes the post-state field.
    result["rows"][poststate["index"]]["observed"]["fields"]["generation"] = "updated"
    tickets = local_deviations(result, plan, uids)
    assert [ticket["reason"] for ticket in tickets] == ["field-deviation"]
    assert tickets[0]["caseId"] == poststate["caseId"]


def test_field_checks_are_skipped_without_a_uid_map() -> None:
    plan = case()
    result = collect_shadow(plan, Transport(plan), run_id="local-1")
    assert local_deviations(result, plan) == []
