"""Canonical Rules management scheduling using real private Gate state."""

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
import shared_gate
from shared_gate import Gate, create

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "fs-rules-publication"))
sys.path.insert(0, str(HERE / "o8-core"))
import o5_user_token_case as case
import o5_user_token_descriptor as descriptor


def rules_plan():
    compiled = case.compile_case("fireemu-35fe6", "(default)", "a" * 32, "tenant-test")
    value = descriptor.gate_plan(compiled, permission_expires_at=time.time() + 900)
    value["jobs"]["rules-management"]["resources"] = []
    return value


def test_canonical_rules_empty_data_gate_reserves_all_management_time(tmp_path):
    value = rules_plan()
    assert shared_gate._observation_time(value, 8) == 289.75
    create(tmp_path / "gate", value)
    state = Gate(tmp_path / "gate", "rules-management").snapshot()
    assert state["reservedRecovery"] == 73
    assert state["plan"]["costMicrousd"] == 144
    assert state["jobs"]["rules-management"]["resources"] == []


@pytest.mark.parametrize(
    "fault",
    [
        "source",
        "contract",
        "effect",
        "dependency",
        "data-principal",
        "observation-time",
        "recovery-time",
    ],
)
def test_rules_plan_drift_refused_before_gate_creation(tmp_path, fault):
    value = rules_plan()
    if fault == "source":
        value["rulesCompilerSources"]["o5_user_token_case.py"] = "0" * 64
    elif fault == "contract":
        value["rulesManagementContract"]["subjects"].pop()
    elif fault == "effect":
        value["management"]["observation"][0]["effects"] = []
    elif fault == "dependency":
        value["management"]["recovery"][0]["dependency"]["subject"] = "account/owner-a"
    elif fault == "data-principal":
        value["planDigest"] = "0" * 64
    elif fault == "observation-time":
        value["wallSeconds"] = 580
    else:
        value["recoverySeconds"] = 260
    with pytest.raises(ValueError):
        create(tmp_path / "gate", value)
    assert not (tmp_path / "gate").exists()


def test_unattempted_rules_cancel_and_skip_are_uncharged_and_terminal(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.claim()
    gate.cancel_management_observation()
    for slot in gate.snapshot()["plan"]["management"]["recovery"]:
        before = gate.snapshot()
        gate.skip_management_recovery(
            slot["id"],
            expected_plan_digest=before["planDigest"],
            expected_prefix_digest=shared_gate.digest(
                {
                    "used": before["managementUsed"],
                    "skipped": before["managementSkipped"],
                }
            ),
        )
        after = gate.snapshot()
        assert after["total"] == after["costMicrousd"] == 0
        assert after["reservedRecovery"] == before["reservedRecovery"] - 1
    gate.finish()
    assert gate.snapshot()["jobs"]["rules-management"]["complete"] is True


def test_rules_finish_cannot_bypass_incomplete_management(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.claim()
    before = gate.snapshot()
    with pytest.raises(ValueError):
        gate.finish()
    assert gate.snapshot() == before


def test_persisted_terminal_requires_the_claimed_coordinator_identity(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.cancel_management_observation()
    for slot in gate.snapshot()["plan"]["management"]["recovery"]:
        skip_next(gate, slot["id"])
    state = gate.snapshot()
    state["jobs"]["rules-management"]["complete"] = True
    shared_gate._save(gate.path, state)
    with pytest.raises(ValueError):
        gate.snapshot()


def response(effects=(), *, status=200, complete=True, reaped=True):
    return {
        "status": status,
        "complete": complete,
        "workerReaped": reaped,
        "bodyKind": "json",
        "body": {
            "kind": "rules-management-proof-v1",
            "responseDigest": "f" * 64,
            "effects": list(effects),
        },
    }


def atomic_refusal(row):
    result = response(status=403)
    result["body"]["refusal"] = {
        "kind": "rules-atomic-commit-refusal-v1",
        "slotId": "data/" + str(row["index"]),
        "rowDigest": shared_gate.digest(row),
        "principal": row["principal"],
        "operation": "Commit",
        "restCode": 403,
        "status": "PERMISSION_DENIED",
        "canonicalCode": 7,
    }
    return result


def test_typed_atomic_commit_refusal_is_bound_to_recompiled_row():
    plan = rules_plan()
    canonical = shared_gate._validate_rules_management_plan(plan)
    row = next(row for row in canonical["observation"] if row["index"] == 18)
    slot = next(
        slot for slot in plan["management"]["observation"] if slot["id"] == "data/18"
    )
    shared_gate._validate_rules_receipt(plan, "observation", slot, atomic_refusal(row))


@pytest.mark.parametrize(
    "fault",
    [
        "get",
        "batch-write",
        "principal",
        "row",
        "slot",
        "rest-code",
        "canonical-code",
        "error-status",
        "http-status",
        "incomplete",
        "unreaped",
        "effects",
        "digest",
        "text",
    ],
)
def test_atomic_refusal_cannot_escape_its_typed_commit_boundary(fault):
    plan = rules_plan()
    canonical = shared_gate._validate_rules_management_plan(plan)
    row = next(row for row in canonical["observation"] if row["index"] == 18)
    slot = next(
        slot for slot in plan["management"]["observation"] if slot["id"] == "data/18"
    )
    result = atomic_refusal(row)
    refusal = result["body"]["refusal"]
    if fault == "get":
        row = next(row for row in canonical["observation"] if row["method"] == "get")
        slot = next(
            slot
            for slot in plan["management"]["observation"]
            if slot["id"] == "data/" + str(row["index"])
        )
        result = atomic_refusal(row)
    elif fault == "batch-write":
        refusal["operation"] = "BatchWrite"
    elif fault == "principal":
        refusal["principal"] = "other-b"
    elif fault == "row":
        refusal["rowDigest"] = "0" * 64
    elif fault == "slot":
        refusal["slotId"] = "data/17"
    elif fault == "rest-code":
        refusal["restCode"] = 7
    elif fault == "canonical-code":
        refusal["canonicalCode"] = 403
    elif fault == "error-status":
        refusal["status"] = "UNAUTHENTICATED"
    elif fault == "http-status":
        result["status"] = 500
    elif fault == "incomplete":
        result["complete"] = False
    elif fault == "unreaped":
        result["workerReaped"] = False
    elif fault == "effects":
        result["body"]["effects"] = [
            {
                "subject": slot["effects"][0]["subject"],
                "proof": {"kind": "absence", "resource": "foreign"},
            }
        ]
    elif fault == "digest":
        result["body"]["responseDigest"] = None
    elif fault == "text":
        result["bodyKind"] = "text"
    with pytest.raises(ValueError):
        shared_gate._validate_rules_receipt(plan, "observation", slot, result)


def skip_next(gate, slot):
    before = gate.snapshot()
    return gate.skip_management_recovery(
        slot,
        expected_plan_digest=before["planDigest"],
        expected_prefix_digest=shared_gate.digest(
            {"used": before["managementUsed"], "skipped": before["managementSkipped"]}
        ),
    )


def first_creation(gate):
    state = gate.snapshot()
    slot = state["plan"]["management"]["observation"][0]
    subject_id = slot["effects"][0]["subject"]
    subject = next(
        item
        for item in state["plan"]["rulesManagementContract"]["subjects"]
        if item["id"] == subject_id
    )
    if subject["kind"] == "document":
        proof = {
            "kind": "document",
            "name": subject["resource"],
            "fieldsDigest": "e" * 64,
            "updateTime": "2026-09-22T00:00:00Z",
        }
    else:
        proof = {
            "kind": "account",
            "accountRef": subject["resource"],
            "tenantId": None,
            "uid": "real-response-uid",
        }
    return slot, subject, {"subject": subject_id, "proof": proof}


def test_public_rules_ownership_is_immutable_and_replays_actual_acknowledgement(
    tmp_path,
):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    slot, subject, effect = first_creation(gate)
    initial = gate.rules_management_ownership()
    assert initial[subject["id"]] == {"status": "not-attempted", "proof": None}
    gate.management_dispatch(
        "observation", slot["id"], lambda deadline: response([effect])
    )
    before = gate.snapshot()
    owned = gate.rules_management_ownership()
    assert owned[subject["id"]]["status"] == "owned"
    assert owned[subject["id"]]["proof"] == effect["proof"]
    assert initial[subject["id"]]["status"] == "not-attempted"
    with pytest.raises(TypeError):
        owned[subject["id"]]["status"] = "recovered"
    with pytest.raises(TypeError):
        owned[subject["id"]]["proof"]["uid"] = "foreign"
    assert gate.snapshot() == before


def test_public_rules_ownership_validates_persisted_evidence_before_projection(
    tmp_path,
):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    state = gate.snapshot()
    state["total"] += 1
    shared_gate._save(gate.path, state)
    with pytest.raises(ValueError):
        gate.rules_management_ownership()


def test_public_rules_ownership_refuses_other_campaigns_without_mutation(tmp_path):
    from test_shared_gate import plan as local_plan

    create(tmp_path / "gate", local_plan())
    gate = Gate(tmp_path / "gate", "a")
    before = gate.snapshot()
    with pytest.raises(ValueError):
        gate.rules_management_ownership()
    assert gate.snapshot() == before


def test_partial_creation_typed_absence_releases_without_delete_or_refund(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.claim()
    slot, subject, effect = first_creation(gate)
    gate.management_dispatch(
        "observation", slot["id"], lambda deadline: response([effect])
    )
    gate.cancel_management_observation()
    for recovery in gate.snapshot()["plan"]["management"]["recovery"]:
        if recovery["dependency"] == {"subject": subject["id"], "step": "read"}:
            gate.management_dispatch(
                "recovery",
                recovery["id"],
                lambda deadline: response(
                    [
                        {
                            "subject": subject["id"],
                            "proof": {
                                "kind": "absence",
                                "resource": subject["resource"],
                            },
                        }
                    ],
                    status=404,
                ),
            )
        else:
            skip_next(gate, recovery["id"])
    gate.finish()
    final = gate.snapshot()
    assert final["total"] == final["costMicrousd"] == 2
    assert final["reservedRecovery"] == 0
    assert len(final["managementEvents"]) == 2


@pytest.mark.parametrize(
    "fault",
    [
        "out-of-order",
        "wrong-plan",
        "wrong-prefix",
        "wire-for-unattempted",
        "forged-complete",
    ],
)
def test_rules_negative_paths_leave_state_unchanged(tmp_path, fault):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.claim()
    gate.cancel_management_observation()
    before = gate.snapshot()
    slots = before["plan"]["management"]["recovery"]
    if fault == "forged-complete":
        forged = json.loads(json.dumps(before))
        forged["jobs"]["rules-management"]["complete"] = True
        shared_gate._save(gate.path, forged)
        raw = (gate.path / "state.json").read_bytes()
        with pytest.raises(ValueError):
            Gate(gate.path, "rules-management").snapshot()
        assert (gate.path / "state.json").read_bytes() == raw
        return
    with pytest.raises(ValueError):
        if fault == "wire-for-unattempted":
            gate.management_dispatch(
                "recovery",
                slots[0]["id"],
                lambda deadline: pytest.fail("must not invoke wire"),
            )
        else:
            gate.skip_management_recovery(
                slots[int(fault == "out-of-order")]["id"],
                expected_plan_digest="0" * 64
                if fault == "wrong-plan"
                else before["planDigest"],
                expected_prefix_digest="0" * 64
                if fault == "wrong-prefix"
                else shared_gate.digest(
                    {
                        "used": before["managementUsed"],
                        "skipped": before["managementSkipped"],
                    }
                ),
            )
    assert gate.snapshot() == before


def test_unknown_worker_refuses_cancel_and_retains_charged_call(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    slot, _, _ = first_creation(gate)
    gate.management_dispatch(
        "observation",
        slot["id"],
        lambda deadline: response(complete=False, reaped=False),
    )
    before = gate.snapshot()
    with pytest.raises(ValueError):
        gate.cancel_management_observation()
    assert gate.snapshot() == before
    assert before["total"] == before["costMicrousd"] == 1


@pytest.mark.parametrize("outcome", ["unknown-create", "changed-read", "delete-failed"])
def test_held_subject_never_becomes_absent_or_terminal(tmp_path, outcome):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.claim()
    slot, subject, effect = first_creation(gate)
    gate.management_dispatch(
        "observation",
        slot["id"],
        lambda deadline: response(
            [] if outcome == "unknown-create" else [effect],
            complete=outcome != "unknown-create",
        ),
    )
    gate.cancel_management_observation()
    for recovery in gate.snapshot()["plan"]["management"]["recovery"]:
        dependency = recovery["dependency"]
        if (
            dependency["subject"] == subject["id"]
            and outcome != "unknown-create"
            and dependency["step"] == "read"
        ):
            changed = json.loads(json.dumps(effect))
            if outcome == "changed-read":
                field = "uid" if subject["kind"] == "account" else "fieldsDigest"
                changed["proof"][field] = "changed-user" if field == "uid" else "0" * 64
            gate.management_dispatch(
                "recovery", recovery["id"], lambda deadline: response([changed])
            )
        elif (
            dependency["subject"] == subject["id"]
            and outcome == "delete-failed"
            and dependency["step"] == "delete"
        ):
            gate.management_dispatch(
                "recovery", recovery["id"], lambda deadline: response(status=500)
            )
        else:
            skip_next(gate, recovery["id"])
    before = gate.snapshot()
    assert before["reservedRecovery"] == 0
    assert gate.rules_management_ownership()[subject["id"]]["status"] == "held"
    with pytest.raises(ValueError):
        gate.finish()
    assert gate.snapshot() == before
    assert before["jobs"]["rules-management"]["absent"] == []


def test_rules_skip_journal_tampering_is_rejected_even_after_rebinding_plan_digest(
    tmp_path,
):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.cancel_management_observation()
    skip_next(gate, gate.snapshot()["plan"]["management"]["recovery"][0]["id"])
    state = gate.snapshot()
    state["managementSkipped"][-1]["reason"] = "typed-absence"
    shared_gate._save(gate.path, state)
    raw = (gate.path / "state.json").read_bytes()
    with pytest.raises(ValueError):
        Gate(gate.path, "rules-management").snapshot()
    assert (gate.path / "state.json").read_bytes() == raw


def test_unknown_skip_phase_cannot_remove_reserved_recovery_obligation(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.cancel_management_observation()
    skip_next(gate, gate.snapshot()["plan"]["management"]["recovery"][0]["id"])
    state = gate.snapshot()
    state["managementSkipped"][-1]["phase"] = "unknown"
    state["reservedRecovery"] += 1
    shared_gate._save(gate.path, state)
    with pytest.raises(ValueError):
        gate.snapshot()


def test_cancellation_binds_completed_observation_proof_bytes(tmp_path):
    create(tmp_path / "gate", rules_plan())
    gate = Gate(tmp_path / "gate", "rules-management")
    slot, _, effect = first_creation(gate)
    gate.management_dispatch(
        "observation", slot["id"], lambda deadline: response([effect])
    )
    gate.cancel_management_observation()
    state = gate.snapshot()
    event = state["managementEvents"][0]
    event["rulesReceipt"]["body"]["responseDigest"] = "0" * 64
    event["responseDigest"] = shared_gate.digest(event["rulesReceipt"])
    event["bodyDigest"] = shared_gate.digest(event["rulesReceipt"]["body"])
    shared_gate._save(gate.path, state)
    with pytest.raises(ValueError):
        gate.snapshot()


def test_failed_signup_cannot_gain_ownership_through_later_claim_update(tmp_path):
    plan = rules_plan()
    create(tmp_path / "gate", plan)
    gate = Gate(tmp_path / "gate", "rules-management")
    for index, slot in enumerate(plan["management"]["observation"][:7]):
        subject = slot["effects"][0]["subject"]
        ref = subject.removeprefix("account/")
        proof = {
            "kind": "account",
            "accountRef": ref,
            "tenantId": "tenant-test" if ref == "tenant-d" else None,
            "uid": "response-" + ref,
        }
        result = response(
            [] if index == 0 else [{"subject": subject, "proof": proof}],
            status=500 if index == 0 else 200,
        )
        gate.management_dispatch(
            "observation", slot["id"], lambda deadline, result=result: result
        )
    before = gate.snapshot()
    with pytest.raises(ValueError):
        gate.management_dispatch(
            "observation",
            plan["management"]["observation"][7]["id"],
            lambda deadline: pytest.fail("unknown account must not be mutated"),
        )
    assert gate.snapshot() == before


@pytest.mark.parametrize("mode", ["normal", "foreign-restore", "status-only-denial"])
def test_full_rules_management_real_child_receipts_and_application_denial(
    tmp_path, mode
):
    plan = rules_plan()
    create(tmp_path / "gate", plan)
    gate = Gate(tmp_path / "gate", "rules-management")
    gate.claim()
    canonical = case.compile_case("fireemu-35fe6", "(default)", "a" * 32, "tenant-test")
    rows = {"data/" + str(row["index"]): row for row in canonical["observation"]}
    tenants = {
        account["ref"]: account["tenant"] for account in canonical["ownedAccounts"]
    }
    proofs = {}
    for subject in plan["rulesManagementContract"]["subjects"]:
        if subject["kind"] == "document":
            proof = {
                "kind": "document",
                "name": subject["resource"],
                "fieldsDigest": "e" * 64,
                "updateTime": "2026-09-22T00:00:00Z",
            }
        else:
            proof = {
                "kind": "account",
                "accountRef": subject["resource"],
                "tenantId": tenants[subject["resource"]],
                "uid": "response-" + subject["resource"],
            }
        proofs[subject["id"]] = proof
    release = {
        "kind": "release",
        "name": "projects/fireemu-35fe6/releases/cloud.firestore",
        "rulesetName": "projects/fireemu-35fe6/rulesets/baseline",
    }
    for label in ("a", "b"):
        proofs["ruleset/" + label] = {
            "kind": "ruleset",
            "name": "projects/fireemu-35fe6/rulesets/owned-" + label,
            "sourceDigest": plan["rulesManagementContract"]["rulesets"][label],
        }
    denied_id = "data/" + str(
        next(
            row["index"]
            for row in canonical["observation"]
            if row["expect"]["status"] == "PERMISSION_DENIED" and not row["writes"]
        )
    )

    def send_child(result, deadline):
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            raw, _ = child.communicate(
                json.dumps(result), timeout=max(0.01, deadline - time.monotonic())
            )
        finally:
            if child.poll() is None:
                child.terminate()
                child.communicate(timeout=5)
        assert child.returncode == 0
        return json.loads(raw)

    for slot in plan["management"]["observation"]:
        effects = [
            {"subject": effect["subject"], "proof": proofs[effect["subject"]]}
            for effect in slot["effects"]
            if effect["action"] != "delete"
        ]
        if slot["id"].startswith("baseline-"):
            proof = (
                {
                    "kind": "ruleset",
                    "name": release["rulesetName"],
                    "sourceDigest": "d" * 64,
                }
                if slot["id"] == "baseline-ruleset-get"
                else release
            )
            effects = [{"subject": "release/baseline", "proof": proof}]
        elif slot["id"].startswith("create-"):
            label = slot["id"].split("-")[1]
            effects = [
                {"subject": "ruleset/" + label, "proof": proofs["ruleset/" + label]}
            ]
        elif slot["id"].startswith("patch-"):
            label = slot["id"].split("-")[1]
            effects = [
                {
                    "subject": "release/baseline",
                    "proof": {
                        **release,
                        "rulesetName": proofs["ruleset/" + label]["name"],
                    },
                }
            ]
        elif (
            slot["id"].startswith("action/")
            and slot["id"].endswith("/readback")
            and slot["effects"] == [{"subject": "account/deleted-g", "action": "read"}]
        ):
            effects = [
                {
                    "subject": "account/deleted-g",
                    "proof": {"kind": "absence", "resource": "deleted-g"},
                }
            ]
        result = response(
            [] if slot["id"] == denied_id else effects,
            status=403 if slot["id"] == denied_id else 200,
        )
        row = rows.get(slot["id"])
        if (
            row
            and row["method"] == "commit"
            and row["expect"]["status"] == "PERMISSION_DENIED"
        ):
            result = (
                response(status=403)
                if mode == "status-only-denial" and row["index"] == 17
                else atomic_refusal(row)
            )
        before = gate.snapshot()
        gate.management_dispatch(
            "observation",
            slot["id"],
            lambda deadline, result=result: send_child(result, deadline),
        )
        if result["body"].get("refusal"):
            after = gate.snapshot()
            assert after["total"] == before["total"] + 1
            assert after["costMicrousd"] == before["costMicrousd"] + 1
            assert (
                after["managementEvents"][-1]["rulesReceipt"]["body"]["effects"] == []
            )
            if row["index"] == 18:
                assert (
                    shared_gate._rules_subject_states(after)["document/multiwrite-x"]
                    == shared_gate._rules_subject_states(before)[
                        "document/multiwrite-x"
                    ]
                )
            with pytest.raises(ValueError):
                gate.management_dispatch(
                    "observation",
                    slot["id"],
                    lambda deadline: pytest.fail("consumed refusal must not replay"),
                )
            assert gate.snapshot() == after
    assert not gate.snapshot().get("credentialRejected")
    assert (
        next(
            event
            for event in gate.snapshot()["managementEvents"]
            if event["id"] == "observation:" + denied_id
        )["status"]
        == 403
    )
    gate.cancel_management_observation()
    denied_subjects = {"document/getafter-control-target", "document/multiwrite-y"}
    derived = gate.rules_management_ownership()
    for subject in denied_subjects:
        assert derived[subject]["proof"] is None
        assert derived[subject]["status"] == (
            "held"
            if mode == "status-only-denial"
            and subject == "document/getafter-control-target"
            else "attempted-no-effect"
        )
    restore_failed = False
    for slot in plan["management"]["recovery"]:
        subject, step = slot["dependency"]["subject"], slot["dependency"]["step"]
        if (
            subject == "account/deleted-g"
            or subject in denied_subjects
            or restore_failed
        ):
            skip_next(gate, slot["id"])
            continue
        status = 200
        if subject == "release/baseline":
            current = (
                {**release, "rulesetName": proofs["ruleset/b"]["name"]}
                if step == "restore-patch"
                else release
            )
            if mode == "foreign-restore" and step == "restore-patch":
                current = {
                    **release,
                    "rulesetName": "projects/fireemu-35fe6/rulesets/foreign",
                }
                restore_failed = True
            effects = [{"subject": subject, "proof": current}]
        elif step == "read" or step.endswith("-get"):
            effects = [{"subject": subject, "proof": proofs[subject]}]
        elif step == "absence" or step.endswith("-absence"):
            resource = (
                proofs[subject]["name"]
                if subject.startswith("ruleset/")
                else next(
                    item["resource"]
                    for item in plan["rulesManagementContract"]["subjects"]
                    if item["id"] == subject
                )
            )
            effects = [
                {"subject": subject, "proof": {"kind": "absence", "resource": resource}}
            ]
            status = 404
        else:
            effects = []
        result = response(effects, status=status)
        gate.management_dispatch(
            "recovery",
            slot["id"],
            lambda deadline, result=result: send_child(result, deadline),
        )
    if mode != "normal":
        before = gate.snapshot()
        with pytest.raises(ValueError):
            gate.finish()
        assert gate.snapshot() == before
        assert (
            before["total"]
            == before["costMicrousd"]
            == (126 if mode == "foreign-restore" else 135)
        )
        return
    gate.finish()
    final = gate.snapshot()
    assert final["total"] == final["costMicrousd"] == 135
    assert final["reservedRecovery"] == 0
    assert final["jobs"]["rules-management"]["complete"] is True
