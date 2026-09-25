"""One-host, fixed-queue local admission. No production authorization is implied.

The lock covers transport completion: two scenario slots, one in-flight HTTP call.
An interrupted callback leaves a durable uncertain marker and blocks all dispatch.
"""

from __future__ import annotations

import builtins
import contextlib
import fcntl
import functools
import hashlib
import json
import math
import os
import re
import sys
import time
import types
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from broad_contract import digest

REQUEST_SECONDS = 13  # 12-second wire deadline plus adapter spacing allowance.
MAX_JOB_SLOTS = 8
# The floor on request spacing and the ceiling on a campaign wall. Named so a
# campaign can import them instead of keeping its own copy: a copied constant is
# how a lane once re-derived this module's charging formula and agreed with a
# Gate that no longer existed.
INTERVAL_FLOOR_SECONDS = 0.25
WALL_CAP_SECONDS = 1200
AUTH_REV3_WALL_SECONDS = 1500
AUTH_REV3_MIN_RECOVERY_SECONDS = 300
AUTH_REV3_CAMPAIGN_ID = "AUTH-MFA-AGE-TOTP-01"
AUTH_REV3_SELECTOR = "pending-lifetime-rev3-v1"
PHASES = ("observation", "recovery")
MANAGEMENT_SKIP_REASON = "management-not-run"
LIMITS_PREPARATION_TRANSPORT = "limits-03-baseline-preparation-v2"
LIMITS_PREPARATION_RECEIPT = "limits-03-baseline-preparation-receipt-v1"
LIMITS_PREPARATION_SLOTS = ("refresh", "oauth-tokeninfo", "project", "database", "auth", "key")
RULES_MANAGEMENT_KIND = "rules-management-dependencies-v1"


def _rules_management(plan):
    return "rulesManagementContract" in plan


@functools.lru_cache(maxsize=4)
def _rules_compiler_modules(case_source, campaign_source, directory):
    """Load the two pinned pure compilers without ambient module resolution."""
    case = types.ModuleType("_shared_rules_case")
    case.__file__ = str(Path(directory) / "o5_user_token_case.py")
    exec(compile(case_source, case.__file__, "exec"), case.__dict__)  # noqa: S102 -- Source-pinned repository compiler.
    campaign = types.ModuleType("_shared_rules_campaign")
    campaign.__file__ = str(Path(directory) / "o5_user_token_campaign.py")

    def compiler_import(name, *args, **kwargs):
        return (
            case
            if name == "o5_user_token_case"
            else builtins.__import__(name, *args, **kwargs)
        )

    campaign.__dict__["__builtins__"] = {
        **vars(builtins),
        "__import__": compiler_import,
    }
    exec(compile(campaign_source, campaign.__file__, "exec"), campaign.__dict__)  # noqa: S102 -- Source-pinned repository compiler.
    return case, campaign


def _validate_rules_management_plan(plan):
    """Recompile the exact matrix, effects and cleanup dependencies locally."""
    directory = Path(__file__).resolve().parent / "fs-rules-publication"
    names = ("o5_user_token_case.py", "o5_user_token_campaign.py")
    sources = [(directory / name).read_bytes() for name in names]
    expected_sources = {
        name: hashlib.sha256(source).hexdigest()
        for name, source in zip(names, sources, strict=True)
    }
    if plan.get("rulesCompilerSources") != expected_sources:
        raise ValueError("Rules compiler source closure changed")
    contract = plan.get("rulesManagementContract")
    if not isinstance(contract, dict) or contract.get("kind") != RULES_MANAGEMENT_KIND:
        raise ValueError("closed Rules management dependencies required")
    case, compiler = _rules_compiler_modules(*sources, str(directory))
    canonical = case.compile_case(
        plan.get("project"),
        plan.get("database"),
        plan.get("nonce"),
        contract.get("tenantId"),
    )
    management = compiler.gate_management_plan(canonical)
    if (
        plan.get("contract") != "shared-local-v1"
        or plan.get("kind") != "fs-rules-user-token-gate-plan-v1"
        or plan.get("campaignId") != "FS-RULES-USER-TOKEN-MATRIX-01"
        or plan.get("project") != "fireemu-35fe6"
        or plan.get("database") != "(default)"
        or plan.get("transport") != "bounded-rules-worker"
        or plan.get("receiptKind") != "fs-rules-management-receipt-v1"
        or plan.get("planDigest") != canonical["planDigest"]
        or contract != compiler.rules_management_contract(canonical)
        or plan.get("management") != management
        or len(contract["subjects"]) != 21
        or len(management["observation"]) != 71
        or len(management["recovery"]) != 73
        or plan.get("observationRequests") != 71
        or plan.get("managementRequests") != 144
        or plan.get("requestCostMicrousd") != 1
        or plan.get("costMicrousd") != 144
        or plan.get("dataRequests") != 33
        or plan.get("requestSeconds") != 12.0
        or plan.get("intervalSeconds") != 0.25
        or plan.get("jobSlots") != 1
        or plan.get("wallSeconds") != 600
        or plan.get("recoverySeconds") != 300
        or plan.get("coordinatorRequests", 0) != 0
        or plan.get("fixedCostMicrousd", 0) != 0
        or plan.get("jobs")
        != {"rules-management": {"resources": [], "observation": [], "recovery": []}}
    ):
        raise ValueError("canonical Rules management plan required")
    return canonical


def _rules_declared(plan):
    return [
        (phase + ":" + slot["id"], phase, slot)
        for phase in PHASES
        for slot in plan["management"][phase]
    ]


def _rules_cursor(state):
    """Merge the two journals without allowing either to reorder the queue."""
    declared = _rules_declared(state["plan"])
    used, skipped = state["managementUsed"], state["managementSkipped"]
    if [event.get("id") for event in state["managementEvents"]] != used:
        raise ValueError("Rules charged journal mismatch")
    skip_ids = [entry.get("id") for entry in skipped]
    phases = {identity: phase for identity, phase, _ in declared}
    if any(
        entry.get("phase") not in PHASES
        or entry.get("phase") != phases.get(entry.get("id"))
        for entry in skipped
    ):
        raise ValueError("Rules skipped phase is not compiled")
    if len(set(used + skip_ids)) != len(used + skip_ids):
        raise ValueError("Rules duplicate consumed slot")
    count = len(used) + len(skipped)
    prefix = [identity for identity, _, _ in declared[:count]]
    if (
        set(prefix) != set(used + skip_ids)
        or [identity for identity in prefix if identity in used] != used
        or [identity for identity in prefix if identity in skip_ids] != skip_ids
    ):
        raise ValueError("Rules management prefix mismatch")
    return declared, count


def _rules_settled(state):
    if (
        state["coordinatorInflight"]
        or state.get("credentialRejected")
        or any(job["inflight"] for job in state["jobs"].values())
        or any(
            event.get("workerReaped") is not True for event in state["managementEvents"]
        )
    ):
        raise ValueError("Rules process outcome is unknown; ownership retained")


def _rules_proof_subjects(phase, slot):
    if phase == "recovery":
        return {slot["dependency"]["subject"]}
    if slot["effects"]:
        return {effect["subject"] for effect in slot["effects"]}
    if slot["id"].startswith("baseline-"):
        return {"release/baseline"}
    for label in ("a", "b"):
        if slot["id"] in {"create-" + label, "create-" + label + "-get"}:
            return {"ruleset/" + label}
        if slot["id"].startswith("patch-" + label):
            return {"release/baseline"}
    return set()


def _rules_delete_readback(plan, slot, subject):
    if not slot["id"].startswith("action/") or not slot["id"].endswith("/readback"):
        return False
    mutation_id = slot["id"].removesuffix("/readback") + "/mutation"
    return any(
        entry["id"] == mutation_id
        and {"subject": subject, "action": "delete"} in entry["effects"]
        for entry in plan["management"]["observation"]
    )


def _validate_rules_receipt(plan, phase, slot, result):
    if not _management_receipt_valid(result, slot["id"]):
        raise ValueError("Rules bounded receipt required")
    body = result["body"]
    if body is None and result["complete"] is False:
        return
    if (
        not isinstance(body, dict)
        or set(body)
        not in (
            {"kind", "responseDigest", "effects"},
            {"kind", "responseDigest", "effects", "refusal"},
        )
        or body["kind"] != "rules-management-proof-v1"
        or not _preparation_hash(body["responseDigest"])
        or not isinstance(body["effects"], list)
    ):
        raise ValueError("Rules sanitized proof envelope required")
    canonical = _validate_rules_management_plan(plan)
    if "refusal" in body:
        row = next(
            (
                row
                for row in canonical["observation"]
                if slot["id"] == "data/" + str(row["index"])
            ),
            None,
        )
        if (
            phase != "observation"
            or row is None
            or row["method"] != "commit"
            or result["status"] != 403
            or result["complete"] is not True
            or result["workerReaped"] is not True
            or result["bodyKind"] != "json"
            or body["effects"] != []
            or body["refusal"]
            != {
                "kind": "rules-atomic-commit-refusal-v1",
                "slotId": slot["id"],
                "rowDigest": digest(row),
                "principal": row["principal"],
                "operation": "Commit",
                "restCode": 403,
                "status": "PERMISSION_DENIED",
                "canonicalCode": 7,
            }
        ):
            raise ValueError(
                "Rules refusal is not the actual typed canonical Commit denial"
            )
        # The source-bound synchronous transport validates the actual prepared
        # request and REST error. This projection is not a cryptographic seal.
        return
    allowed = _rules_proof_subjects(phase, slot)
    subjects = {
        subject["id"]: subject
        for subject in plan["rulesManagementContract"]["subjects"]
    }
    tenants = {
        account["ref"]: account["tenant"] for account in canonical["ownedAccounts"]
    }
    seen = set()
    schemas = {
        "document": {"kind", "name", "fieldsDigest", "updateTime"},
        "account": {"kind", "accountRef", "tenantId", "uid"},
        "ruleset": {"kind", "name", "sourceDigest"},
        "release": {"kind", "name", "rulesetName"},
        "absence": {"kind", "resource"},
    }
    for effect in body["effects"]:
        if (
            not isinstance(effect, dict)
            or set(effect) != {"subject", "proof"}
            or not isinstance(effect["subject"], str)
            or effect["subject"] not in allowed
            or effect["subject"] in seen
        ):
            raise ValueError("Rules proof subject is not compiled")
        subject_id, proof = effect["subject"], effect["proof"]
        seen.add(subject_id)
        if not isinstance(proof, dict) or set(proof) != schemas.get(proof.get("kind")):
            raise ValueError("Rules proof fields are not sanitized")
        kind = proof["kind"]
        if phase == "recovery" and (
            slot["dependency"]["step"] == "delete"
            or slot["dependency"]["step"] in ("delete-a", "delete-b")
        ):
            raise ValueError(
                "Rules delete acknowledgement cannot assert readback proof"
            )
        if kind == "document":
            if (
                subject_id not in subjects
                or subjects[subject_id]["kind"] != kind
                or proof["name"] != subjects[subject_id]["resource"]
                or not _preparation_hash(proof["fieldsDigest"])
                or not isinstance(proof["updateTime"], str)
                or re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", proof["updateTime"]
                )
                is None
            ):
                raise ValueError("Rules document proof identity mismatch")
        elif kind == "account":
            if (
                subject_id not in subjects
                or subjects[subject_id]["kind"] != kind
                or proof["accountRef"] != subjects[subject_id]["resource"]
                or proof["tenantId"] != tenants.get(proof["accountRef"])
                or not isinstance(proof["uid"], str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", proof["uid"]) is None
            ):
                raise ValueError("Rules account proof identity mismatch")
        elif kind == "ruleset":
            if (
                subject_id not in {"ruleset/a", "ruleset/b", "release/baseline"}
                or not isinstance(proof["name"], str)
                or re.fullmatch(
                    r"projects/fireemu-35fe6/rulesets/[A-Za-z0-9_-]{1,128}",
                    proof["name"],
                )
                is None
                or not _preparation_hash(proof["sourceDigest"])
                or (
                    subject_id.startswith("ruleset/")
                    and proof["sourceDigest"]
                    != plan["rulesManagementContract"]["rulesets"][subject_id[-1]]
                )
            ):
                raise ValueError("Rules source proof mismatch")
        elif kind == "release":
            if (
                subject_id != "release/baseline"
                or proof["name"] != "projects/fireemu-35fe6/releases/cloud.firestore"
                or not isinstance(proof["rulesetName"], str)
                or re.fullmatch(
                    r"projects/fireemu-35fe6/rulesets/[A-Za-z0-9_-]{1,128}",
                    proof["rulesetName"],
                )
                is None
            ):
                raise ValueError("Rules release proof identity mismatch")
        elif (
            (phase != "recovery" and not _rules_delete_readback(plan, slot, subject_id))
            or result["status"] not in (200, 404)
            or (
                subject_id in subjects
                and proof["resource"] != subjects[subject_id]["resource"]
            )
            or (
                subject_id not in subjects
                and (
                    not isinstance(proof["resource"], str)
                    or re.fullmatch(
                        r"projects/fireemu-35fe6/rulesets/[A-Za-z0-9_-]{1,128}",
                        proof["resource"],
                    )
                    is None
                )
            )
        ):
            raise ValueError("Rules typed absence identity mismatch")


def _rules_data_slot(plan, phase, slot):
    """Only the recompiled user-token matrix owns application denial outcomes."""
    if phase != "observation":
        return False
    canonical = _validate_rules_management_plan(plan)
    return any(
        slot["id"] == "data/" + str(row["index"]) for row in canonical["observation"]
    )


def _rules_subject_states(state):
    """Derive ownership solely from acknowledged, source-bound wire events."""
    subjects = {
        item["id"]: {"status": "not-attempted", "proof": None}
        for item in state["plan"]["rulesManagementContract"]["subjects"]
    }
    subjects.update(
        {
            key: {"status": "not-attempted", "proof": None}
            for key in ("ruleset/a", "ruleset/b", "release/baseline")
        }
    )
    baseline = subjects["release/baseline"]
    slots = {
        identity: (phase, slot)
        for identity, phase, slot in _rules_declared(state["plan"])
    }
    for event in state["managementEvents"]:
        phase, slot = slots[event["id"]]
        receipt = event.get("rulesReceipt")
        effects = receipt["body"]["effects"] if receipt and receipt.get("body") else []
        proofs = {effect["subject"]: effect["proof"] for effect in effects}
        good = event.get("completed") is True and 200 <= event.get("status", 0) < 300
        if phase == "observation":
            if (
                event.get("completed") is True
                and receipt
                and receipt.get("body", {}).get("refusal") is not None
            ):
                # Atomic denial describes this attempt, never target absence.
                # Earlier owned versions and unknown outcomes remain untouched.
                for effect in slot["effects"]:
                    subject = subjects[effect["subject"]]
                    if (
                        effect["action"] == "create"
                        and subject["status"] == "not-attempted"
                    ):
                        subject["status"] = "attempted-no-effect"
                continue
            for effect in slot["effects"]:
                subject = subjects[effect["subject"]]
                proof = proofs.get(effect["subject"])
                if effect["action"] == "read":
                    if (
                        _rules_delete_readback(state["plan"], slot, effect["subject"])
                        and subject.get("deleteAcknowledged")
                        and subject["proof"] is not None
                        and event.get("completed")
                        and event.get("status") in (200, 404)
                        and proof is not None
                        and proof["kind"] == "absence"
                    ):
                        subject["status"] = "recovered"
                    continue
                if good and proof is not None and proof["kind"] != "absence":
                    prior = subject["proof"]
                    if effect["action"] != "create" and (
                        prior is None or (prior["kind"] == "account" and proof != prior)
                    ):
                        subject["status"] = "held"
                    else:
                        subject.update(status="owned", proof=proof)
                elif (
                    good
                    and effect["action"] == "delete"
                    and subject["proof"] is not None
                ):
                    # A delete acknowledgement is not absence. Keep authority
                    # to issue the reserved read, which must establish absence.
                    subject["status"] = "owned"
                    subject["deleteAcknowledged"] = True
                elif (
                    effect["action"] == "create" or subject["status"] != "not-attempted"
                ):
                    subject["status"] = "held"
            # Rules mutations have a separate canonical lifecycle dependency.
            baseline_proof = proofs.get("release/baseline")
            if (
                slot["id"] == "baseline-release-get"
                and good
                and baseline_proof
                and baseline_proof["kind"] == "release"
            ):
                baseline["proof"] = baseline_proof
            if (
                slot["id"] == "baseline-ruleset-get"
                and good
                and baseline_proof
                and baseline_proof["kind"] == "ruleset"
                and baseline.get("proof")
                and baseline_proof["name"] == baseline["proof"]["rulesetName"]
            ):
                baseline["sourceProof"] = baseline_proof
            if (
                slot["id"] == "baseline-executable-get"
                and good
                and baseline_proof == baseline["proof"]
                and baseline.get("sourceProof")
            ):
                baseline["verified"] = True
            for label in ("a", "b"):
                if slot["id"] == "create-" + label:
                    proof = proofs.get("ruleset/" + label)
                    subjects["ruleset/" + label].update(
                        status="owned" if good and proof else "held", proof=proof
                    )
                if slot["id"] == "create-" + label + "-get":
                    subject = subjects["ruleset/" + label]
                    subject["status"] = (
                        "verified"
                        if good
                        and proofs.get("ruleset/" + label) == subject["proof"]
                        and subject["proof"]
                        else "held"
                    )
                if slot["id"] == "patch-" + label:
                    subjects["release/baseline"]["status"] = "held"
                    subjects["release/baseline"]["patched"] = True
        else:
            dependency = slot["dependency"]
            subject = subjects[dependency["subject"]]
            proof = proofs.get(dependency["subject"])
            if (
                event.get("completed") is True
                and proof
                and proof["kind"] == "absence"
                and event.get("status") in (200, 404)
                and subject["proof"] is not None
                and subject["status"] in ("owned", "verified", "deleted")
                and (
                    not dependency["subject"].startswith("ruleset/")
                    or proof["resource"] == subject["proof"]["name"]
                )
            ):
                subject["status"] = "recovered"
            elif dependency["step"] == "read":
                subject["status"] = (
                    "verified" if good and proof == subject["proof"] else "held"
                )
            elif dependency["step"] == "delete":
                subject["status"] = (
                    "deleted" if good and subject["status"] == "verified" else "held"
                )
            elif dependency["step"] == "absence":
                subject["status"] = "held"
            elif dependency["subject"].startswith("ruleset/"):
                step = dependency["step"]
                if step.endswith("-get"):
                    subject["status"] = (
                        "verified" if good and proof == subject["proof"] else "held"
                    )
                elif step in ("delete-a", "delete-b"):
                    subject["status"] = (
                        "deleted"
                        if good and subject["status"] == "verified"
                        else "held"
                    )
                else:
                    subject["status"] = "held"
            elif dependency["subject"] == "release/baseline":
                stages = (
                    "restore-patch",
                    "restore-get",
                    "restore-executable",
                    "restore-get-executable",
                )
                stage = subject.get("restoreStage", 0)
                owned_targets = {
                    entry["proof"]["name"]
                    for key, entry in subjects.items()
                    if key.startswith("ruleset/") and entry["proof"] is not None
                }
                current_owned = (
                    proof is not None
                    and proof.get("kind") == "release"
                    and subject["proof"] is not None
                    and proof["name"] == subject["proof"]["name"]
                    and proof["rulesetName"]
                    in owned_targets | {subject["proof"]["rulesetName"]}
                )
                if (
                    stage < len(stages)
                    and dependency["step"] == stages[stage]
                    and good
                    and (current_owned if stage == 0 else proof == subject["proof"])
                    and subject.get("verified")
                ):
                    subject["restoreStage"] = stage + 1
                    subject["status"] = "recovered" if stage == 3 else "held"
                else:
                    subject["restoreFailed"] = True
    if baseline.get("restoreFailed"):
        # No delete can follow a failed guard/restore while an owned ruleset
        # might still be active. The reserved suffix settles as held, not absent.
        for key, subject in subjects.items():
            if key.startswith("ruleset/") and subject["status"] != "not-attempted":
                subject["status"] = "held"
    for subject_id, disposition in state.get("rulesRecoveryHeld", {}).items():
        if (
            isinstance(disposition, dict)
            and disposition.get("kind") == "identity-proof-unavailable-v1"
            and subject_id in subjects
            and subjects[subject_id]["status"] in {"owned", "verified"}
        ):
            subjects[subject_id]["status"] = "held"
    return subjects


def _rules_skip_reason(subject, dependency):
    if subject["status"] == "not-attempted":
        return "dependency-not-attempted"
    if subject["status"] == "recovered":
        return "typed-absence"
    if subject["status"] == "attempted-no-effect":
        return "atomic-commit-denied-no-effect"
    if subject["status"] == "held" and not (
        dependency["subject"] == "release/baseline"
        and subject.get("verified")
        and not subject.get("restoreFailed")
    ):
        return "dependency-held"
    raise ValueError("Rules dependency requires its reserved wire call")


def _rules_dispatch_dependency(state, phase, slot):
    subjects = _rules_subject_states(state)
    if phase == "observation":
        for effect in slot["effects"]:
            if effect["action"] in ("write", "delete"):
                subject = subjects[effect["subject"]]
                if subject["proof"] is None or subject["status"] not in (
                    "owned",
                    "verified",
                ):
                    raise ValueError(
                        "Rules mutation lacks acknowledged creation ownership"
                    )
        if slot["id"] in ("patch-a", "patch-b"):
            if (
                not subjects["release/baseline"].get("verified")
                or subjects["ruleset/" + slot["id"][-1]]["status"] != "verified"
            ):
                raise ValueError(
                    "Rules patch lacks verified baseline and owned ruleset"
                )
        return
    dependency = slot["dependency"]
    subject = subjects[dependency["subject"]]
    step = dependency["step"]
    if dependency["subject"] == "release/baseline":
        stages = (
            "restore-patch",
            "restore-get",
            "restore-executable",
            "restore-get-executable",
        )
        stage = subject.get("restoreStage", 0)
        allowed = (
            subject.get("patched")
            and subject.get("verified")
            and not subject.get("restoreFailed")
            and stage < 4
            and step == stages[stage]
        )
    elif step == "read" or step.endswith("-get"):
        allowed = subject["status"] in ("owned", "verified")
    elif step == "delete" or step in ("delete-a", "delete-b"):
        allowed = subject["status"] == "verified"
    else:
        allowed = subject["status"] == "deleted"
    if not allowed:
        raise ValueError("Rules recovery lacks acknowledged dependency ownership")


def _validate_rules_state(state, *, terminal=False):
    _validate_rules_management_plan(state["plan"])
    held = state.get("rulesRecoveryHeld", {})
    subject_ids = {
        subject["id"]
        for subject in state["plan"]["rulesManagementContract"]["subjects"]
    }
    if not isinstance(held, dict) or any(
        subject_id not in subject_ids
        or not isinstance(disposition, dict)
        or set(disposition) != {"kind", "failure"}
        or disposition["kind"] != "identity-proof-unavailable-v1"
        or not isinstance(disposition["failure"], str)
        or not disposition["failure"]
        or len(disposition["failure"]) > 80
        for subject_id, disposition in held.items()
    ):
        raise ValueError("Rules held recovery disposition changed")
    declared, count = _rules_cursor(state)
    account_subjects = {
        subject["id"]
        for subject in state["plan"]["rulesManagementContract"]["subjects"]
        if subject.get("kind") == "account"
    }
    before_holds = dict(state)
    before_holds["rulesRecoveryHeld"] = {}
    before_hold_subjects = _rules_subject_states(before_holds)
    for subject_id in held:
        if subject_id not in account_subjects:
            raise ValueError("Rules held recovery subject must be an account")
        if before_hold_subjects[subject_id]["status"] not in {"owned", "verified"}:
            raise ValueError("Rules held recovery subject lacks pre-recovery ownership")
        subject_slots = {
            identity
            for identity, phase, slot in declared
            if phase == "recovery" and slot["dependency"]["subject"] == subject_id
        }
        used_subject_slots = set(state["managementUsed"]) & subject_slots
        if used_subject_slots:
            raise ValueError("Rules held recovery subject already entered recovery")
        skipped_by_id = {
            item["id"]: item
            for item in state["managementSkipped"]
            if item["id"] in subject_slots
        }
        if any(
            item.get("reason") != "dependency-held"
            for item in skipped_by_id.values()
        ):
            raise ValueError("Rules held recovery skip disposition changed")
    slots = {identity: (phase, slot) for identity, phase, slot in declared}
    for event in state["managementEvents"]:
        receipt = event.get("rulesReceipt")
        if receipt is not None:
            phase, slot = slots[event["id"]]
            _validate_rules_receipt(state["plan"], phase, slot, receipt)
            if (
                event.get("responseDigest") != digest(receipt)
                or event.get("bodyDigest") != digest(receipt["body"])
                or any(
                    event.get(key) != receipt[key]
                    for key in ("status", "complete", "workerReaped", "bodyKind")
                )
                or event.get("completed")
                != bool(
                    receipt["complete"]
                    and receipt["workerReaped"]
                    and event["ended"] <= event["deadline"]
                )
            ):
                raise ValueError("Rules durable response proof changed")
        elif event.get("completed") or event.get("workerReaped"):
            raise ValueError("Rules durable response proof missing")
    marker = state.get("managementAbort")
    obs_skips = [
        item
        for item in state["managementSkipped"]
        if item.get("phase") == "observation"
    ]
    if marker is not None:
        expected = {
            "version": "rules-cancel-v1",
            "planDigest": state["planDigest"],
            "nonceDigest": digest(state["plan"]["nonce"]),
            "prefix": [
                identity
                for identity in state["managementUsed"]
                if identity.startswith("observation:")
            ],
            "coordinatorPid": state["coordinatorPid"],
            "prefixEventsDigest": digest(
                [
                    event
                    for event in state["managementEvents"]
                    if event["id"].startswith("observation:")
                ]
            ),
        }
        if marker != expected:
            raise ValueError("Rules cancellation binding changed")
        remaining = [
            identity for identity, phase, _ in declared if phase == "observation"
        ][len(marker["prefix"]) :]
        if obs_skips != [
            {"id": identity, "phase": "observation", "reason": MANAGEMENT_SKIP_REASON}
            for identity in remaining
        ]:
            raise ValueError("Rules cancellation suffix changed")
    elif obs_skips:
        raise ValueError("Rules observation skip lacks cancellation")
    rec_skips = [
        item for item in state["managementSkipped"] if item.get("phase") == "recovery"
    ]
    for skipped in rec_skips:
        if set(skipped) != {"id", "phase", "reason", "prefixDigest", "eventsDigest"}:
            raise ValueError("Rules skip schema changed")
        index = next(
            index for index, entry in enumerate(declared) if entry[0] == skipped["id"]
        )
        preceding = {entry[0] for entry in declared[:index]}
        before = dict(state)
        before["managementEvents"] = [
            event for event in state["managementEvents"] if event["id"] in preceding
        ]
        before["managementUsed"] = [
            identity for identity in state["managementUsed"] if identity in preceding
        ]
        before["managementSkipped"] = [
            item for item in state["managementSkipped"] if item["id"] in preceding
        ]
        dependency = declared[index][2]["dependency"]
        reason = _rules_skip_reason(
            _rules_subject_states(before)[dependency["subject"]], dependency
        )
        if (
            skipped["eventsDigest"] != digest(before["managementEvents"])
            or skipped["reason"] != reason
            or skipped["prefixDigest"]
            != digest(
                {
                    "used": before["managementUsed"],
                    "skipped": before["managementSkipped"],
                }
            )
        ):
            raise ValueError("Rules skip evidence changed")
    used = state["managementUsed"]
    if set(state["jobs"]) != {"rules-management"}:
        raise ValueError("Rules data job set changed")
    job = state["jobs"]["rules-management"]
    expected_job = {
        "resources": [],
        "pid": job["pid"],
        "stopped": False,
        "inflight": False,
        "observation": 0,
        "recovery": 0,
        "owned": [],
        "creationProofs": {},
        "absent": [],
        "captures": {},
        "complete": job["complete"],
    }
    if job != expected_job or type(job["complete"]) is not bool:
        raise ValueError("Rules legacy data journal changed")
    obs_count = sum(identity.startswith("observation:") for identity in used)
    rec_count = len(used) - obs_count
    if (
        state["total"] != len(used)
        or state["observation"] != obs_count
        or state["recovery"] != rec_count
        or state["costMicrousd"] != len(used)
        or state["reservedRecovery"] != 73 - rec_count - len(rec_skips)
        or state["events"]
        or state["coordinatorDone"]
    ):
        raise ValueError("Rules management accounting changed")
    if terminal:
        _rules_settled(state)
        if (
            type(job["pid"]) is not int
            or job["pid"] <= 0
            or job["pid"] != state["coordinatorPid"]
            or state["reservedRecovery"] != 0
            or count != len(declared)
            or any(
                subject["status"]
                not in ("not-attempted", "recovered", "attempted-no-effect")
                for subject in _rules_subject_states(state).values()
            )
        ):
            raise ValueError("Rules cleanup incomplete; ownership retained")
    return count


def validate_limits_preparation_plan(plan):
    """Validate the sole empty-resource Shared Gate contract, without I/O."""
    if (
        plan.get("contract") != "shared-local-v2"
        or plan.get("transport") != LIMITS_PREPARATION_TRANSPORT
        or plan.get("receiptKind") != LIMITS_PREPARATION_RECEIPT
        or plan.get("campaignId") != "FS-WRITE-LIMITS-03"
        or plan.get("jobs")
        != {
            "limits": {
                "resources": [],
                "observation": [],
                "recovery": [],
                "schedule": [],
            }
        }
        or plan.get("management")
        != {
            "dispatchKind": "closed-v1",
            "credentialIds": ["oauth-tokeninfo"],
            "credentialSlots": ["oauth-tokeninfo"],
            "observation": [
                {"id": slot, "timeout": 12} for slot in LIMITS_PREPARATION_SLOTS
            ],
            "recovery": [],
        }
        or any(
            type(plan.get(key, default)) is not int
            or plan.get(key, default) != expected
            for key, default, expected in (
                ("observationRequests", None, 6),
                ("costMicrousd", None, 600),
                ("requestCostMicrousd", None, 100),
                ("fixedCostMicrousd", 0, 0),
                ("coordinatorRequests", 0, 0),
            )
        )
    ):
        raise ValueError("closed limits preparation plan required")


def _preparation_hash(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def validate_limits_preparation_response(slot, result):
    """Accept only source-owned public attestations, never raw worker bodies."""
    if slot not in LIMITS_PREPARATION_SLOTS or not _management_receipt_valid(
        result, slot
    ):
        raise ValueError("closed preparation response required")
    if (
        result["complete"] is False
        and result["workerReaped"] is True
        and result["body"] is None
    ):
        return
    body = result["body"]
    if (
        result["status"] != 200
        or result["complete"] is not True
        or result["workerReaped"] is not True
        or result["bodyKind"] != "json"
        or not isinstance(body, dict)
    ):
        raise ValueError("sanitized successful preparation response required")
    if slot == "oauth-tokeninfo":
        return  # The shared token attestation has an exact, secret-free schema.
    if slot == "refresh":
        if (
            set(body) != {"kind", "expiresInSeconds", "authorizedUserDigest"}
            or body["kind"] != "limits-03-preparation-refresh-v1"
            or type(body["expiresInSeconds"]) is not int
            or not 420 <= body["expiresInSeconds"] <= 3600
            or not _preparation_hash(body["authorizedUserDigest"])
        ):
            raise ValueError("sanitized refresh attestation required")
        return
    if (
        set(body) != {"kind", "slot", "responseDigest", "value"}
        or body["kind"] != "limits-03-preparation-metadata-v1"
        or body["slot"] != slot
        or not _preparation_hash(body["responseDigest"])
        or not isinstance(body["value"], dict)
    ):
        raise ValueError("sanitized metadata attestation required")
    value = body["value"]
    if slot == "project":
        valid = value == {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}
    elif slot == "auth":
        valid = value == {"name": "projects/592603257417/config"}
    elif slot == "key":
        parent = "projects/592603257417/locations/global"
        valid = (
            set(value) == {"parent", "name"}
            and value["parent"] == parent
            and isinstance(value["name"], str)
            and re.fullmatch(
                re.escape(parent) + r"/keys/[A-Za-z0-9_-]{1,128}", value["name"]
            )
            is not None
        )
    else:
        from batch_contract import DATABASE_PROJECTION

        projection = value.get("projection")
        valid = (
            set(value)
            == {
                "projection",
                "projectionDigest",
                "identityProjectionDigest",
                "responseDigest",
                "contractDigest",
            }
            and isinstance(projection, dict)
            and set(projection)
            == {"name", "uid", "databaseEdition", "type", "locationId"}
            and projection["name"] == "projects/fireemu-35fe6/databases/(default)"
            and projection["databaseEdition"] == "STANDARD"
            and projection["type"] == "FIRESTORE_NATIVE"
            and isinstance(projection["uid"], str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", projection["uid"]) is not None
            and isinstance(projection["locationId"], str)
            and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", projection["locationId"])
            is not None
            and all(
                _preparation_hash(value[key])
                for key in (
                    "projectionDigest",
                    "identityProjectionDigest",
                    "responseDigest",
                    "contractDigest",
                )
            )
            and value["identityProjectionDigest"] == digest(projection)
            and value["contractDigest"] == digest(DATABASE_PROJECTION)
            and value["responseDigest"] == body["responseDigest"]
        )
    if not valid:
        raise ValueError("closed preparation metadata identity required")


def validate_limits_preparation_success(state):
    """Require every declared read to have completed and its worker reaped."""
    validate_limits_preparation_plan(state["plan"])
    expected = ["observation:" + slot for slot in LIMITS_PREPARATION_SLOTS]
    events = state.get("managementEvents", [])
    job = state.get("jobs", {}).get("limits", {})
    if (
        state.get("planDigest") != digest(state["plan"])
        or state.get("managementUsed") != expected
        or [event.get("id") for event in events] != expected
        or state.get("managementSkipped") != []
        or state.get("managementAbort") is not None
        or state.get("noDataAbort") is not None
        or state.get("credentialRejected")
        or state.get("stopped") is not False
        or state.get("coordinatorInflight") is not False
        or state.get("events") != []
        or state.get("total") != 6 or state.get("observation") != 6
        or state.get("recovery") != 0 or state.get("reservedRecovery") != 0
        or state.get("costMicrousd") != 600 or state.get("coordinatorDone") != 0
        or set(state.get("jobs", {})) != {"limits"}
        or any(job.get(key) != value for key, value in {
            "resources": [], "observation": 0, "recovery": 0, "owned": [],
            "creationProofs": {}, "absent": [], "captures": {}, "inflight": False,
            "stopped": False, "scheduleDone": 0, "skippedByStop": 0,
        }.items())
        or any(
            event.get("completed") is not True or event.get("complete") is not True
            or event.get("workerReaped") is not True or event.get("status") != 200
            or event.get("failure") is not None
            for event in events
        )
    ):
        raise ValueError("limits preparation completion proof required")
    previous = state["started"] - state["plan"]["intervalSeconds"]
    for event in events:
        if (
            set(event) != {"id", "started", "durationReserved", "deadline", "completed", "status", "complete", "workerReaped", "bodyKind", "responseDigest", "bodyDigest", "ended"}
            or event.get("bodyKind") != "json"
            or not _preparation_hash(event.get("responseDigest")) or not _preparation_hash(event.get("bodyDigest"))
            or any(type(event.get(key)) not in (int, float) or not math.isfinite(event[key])
                for key in ("started", "ended", "deadline", "durationReserved"))
            or event["durationReserved"] != 12
            or event["started"] < previous + state["plan"]["intervalSeconds"]
            or not event["started"] <= event["ended"] <= event["deadline"]
            or event["deadline"] > event["started"] + 12
            or event["deadline"] > state["started"] + state["plan"]["wallSeconds"] - state["plan"]["recoverySeconds"]
        ):
            raise ValueError("limits preparation event deadline proof required")
        previous = event["started"]


def request_seconds(plan, policy=None):
    """The per-request reservation, declared by the campaign or the lane default.

    Thirteen seconds is the Commit lane's wire deadline plus its spacing, not a
    property of every campaign. A plan may declare its own, and a stream plan may
    not, because its policy fixes the number.
    """
    if policy is not None:
        return policy.REQUEST_SECONDS
    if "requestSeconds" not in plan:
        return REQUEST_SECONDS
    return plan["requestSeconds"]


def _valid_request_seconds(plan, policy):
    if "requestSeconds" not in plan:
        return True
    declared = plan["requestSeconds"]
    return (
        policy is None
        and type(declared) in (int, float)
        and not isinstance(declared, bool)
        and math.isfinite(declared)
        and 0 < declared <= plan["wallSeconds"]
    )


def slot_seconds(entry, default):
    """The reservation for one scheduled slot.

    A campaign whose requests are not one population declares the bound per
    slot: a ten-mebibyte upload and a small cleanup read cannot share one
    honest upper bound, and a single plan-wide value would either under-reserve
    the upload or refuse the plan outright.
    """
    # A present-but-malformed value, None included, is refused by `create`, so
    # by the time a slot is dispatched the default only stands in for absence.
    return entry.get("seconds", default)


def job_schedule(job):
    """The campaign-declared dispatch order for one job, or None.

    A job without one keeps the historical order: every observation, then every
    recovery, with recovery a one-way transition. A job with one may interleave
    the two phases, and the Gate then admits only the next unconsumed slot.
    """
    return job.get("schedule")


def _valid_positive(value):
    return (
        type(value) in (int, float)
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def published_allocation(plan):
    """The wall and recovery reserve the campaign's budget artifact publishes.

    `create` can prove a plan internally consistent but has no access to the
    artifact the campaign was approved against, so the two could drift: a Gate
    plan reserving 345 seconds of cleanup against a published 300 was admitted
    with nothing to compare them. A campaign that names its published allocation
    here makes that comparison part of admission.

    The binding is the two numbers, not the file. The Gate never reads the
    artifact, so this closes the drift only for a campaign that declares it; the
    place to require the declaration is the O7 admission of the Gate plan.
    """
    return plan.get("publishedAllocation")


def _valid_allocation(plan):
    if "publishedAllocation" not in plan:
        return True
    declared = plan["publishedAllocation"]
    return (
        isinstance(declared, dict)
        and set(declared) == {"wallSeconds", "recoverySeconds"}
        and all(_valid_positive(value) for value in declared.values())
    )


def _within_published(plan):
    declared = published_allocation(plan)
    if declared is None:
        return True
    return (
        plan["wallSeconds"] <= declared["wallSeconds"]
        and plan["recoverySeconds"] <= declared["recoverySeconds"]
    )


def _valid_ceiling(plan):
    if "transportCeilingSeconds" not in plan:
        return True
    return _valid_positive(plan["transportCeilingSeconds"])


def _valid_slot_seconds(entry):
    if "seconds" not in entry:
        return True
    return _valid_positive(entry["seconds"])


def _valid_schedule(job):
    schedule = job_schedule(job)
    if schedule is None:
        return True
    if not isinstance(schedule, list) or any(
        not isinstance(entry, dict)
        or not {"phase", "index"}
        <= set(entry)
        <= {"phase", "index", "seconds", "creates"}
        or entry["phase"] not in PHASES
        or type(entry["index"]) is not int
        or isinstance(entry["index"], bool)
        or not _valid_slot_seconds(entry)
        or ("creates" in entry and type(entry["creates"]) is not bool)
        for entry in schedule
    ):
        return False
    covered = sorted((entry["phase"], entry["index"]) for entry in schedule)
    return covered == sorted(
        (phase, index) for phase in PHASES for index in range(len(job[phase]))
    )


def _stream_policy(plan):
    if plan.get("contract") == "shared-stream-v1":
        if plan.get("protocol") != "firestore-grpc-stream-v1":
            raise ValueError("unknown shared stream protocol")
        import importlib.util

        module_path = Path(__file__).parent / "fs-write-txn" / "stream_bridge.py"
        spec = importlib.util.spec_from_file_location(
            "_shared_stream_policy", module_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    if plan.get("protocol") is not None:
        raise ValueError("unexpected shared protocol")
    return None


def _typed_firestore_error(status, body, expected_status, expected_code):
    """A top-level error envelope, not a document/write result plus an error.

    Diagnostic fields inside the error are preserved. Unknown top-level fields
    cannot grant authority: this closed evidence contract cannot establish that
    such a response did not also acknowledge a document or a write.
    """
    if not isinstance(body, dict) or set(body) != {"error"}:
        return False
    error = body["error"]
    return (
        type(status) is int
        and status == expected_status
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error["code"] == expected_status
        and error.get("status") == expected_code
    )


def typed_absence(status, body):
    return _typed_firestore_error(status, body, 404, "NOT_FOUND")


_AUTH_ACCOUNT_IDENTIFIER = re.compile(r"[A-Za-z0-9_.@+-]{1,128}")
_AUTH_UID_BINDING = re.compile(r"[A-Za-z][A-Za-z0-9]*Uid")
BINDING_PREFIX = "$binding:"


def _auth_account_form(resource, project=None):
    if not isinstance(resource, str):
        return False
    parts = resource.split("/")
    return (
        len(parts) == 5
        and parts[0] == "projects"
        and bool(parts[1])
        and (project is None or parts[1] == project)
        and parts[2] == "auth"
        and parts[3] == "accounts"
        and _AUTH_ACCOUNT_IDENTIFIER.fullmatch(parts[4]) is not None
        and parts[4] not in {".", ".."}
    )


def _auth_operation(operation):
    return isinstance(operation, dict) and operation.get("service") == "auth"


def _operation_resource(operation):
    if _auth_operation(operation):
        resource = operation.get("resource")
        return resource if isinstance(resource, str) else ""
    return operation["path"].split("?", 1)[0].removeprefix("/v1/")


def auth_typed_absence(status, body):
    if type(status) is not int or status != 200 or not isinstance(body, dict) or not body:
        return False
    if set(body) - {"kind", "users"}:
        return False
    if "kind" in body and body["kind"] != "identitytoolkit#GetAccountInfoResponse":
        return False
    if "users" in body:
        return isinstance(body["users"], list) and body["users"] == []
    return body == {"kind": "identitytoolkit#GetAccountInfoResponse"}


def _auth_binding_name(operation, account_bindings=None):
    explicit = operation.get("uidBinding")
    if isinstance(explicit, str):
        return explicit
    account = operation.get("account")
    if isinstance(account_bindings, dict):
        entry = account_bindings.get(account)
        if isinstance(entry, dict) and isinstance(entry.get("uidBinding"), str):
            return entry["uidBinding"]
    return f"{account}Uid" if isinstance(account, str) and account else None


def _auth_recovery_operation_valid(operation, project, account_bindings=None):
    if not _auth_operation(operation):
        return True
    path = operation.get("path")
    body = operation.get("body")
    binding = _auth_binding_name(operation, account_bindings)
    if not isinstance(path, str) or not isinstance(body, dict) or binding is None:
        return False
    prefix = f"identitytoolkit.googleapis.com/v1/projects/{project}/accounts:"
    if path.endswith("/accounts:lookup"):
        if "email" in body:
            return path == prefix + "lookup" and set(body) == {"email"}
        return (
            path == prefix + "lookup"
            and set(body) == {"localId"}
            and isinstance(body["localId"], list)
            and len(body["localId"]) == 1
            and body["localId"][0] == BINDING_PREFIX + binding
        )
    if path.endswith("/accounts:delete"):
        return (
            path == prefix + "delete"
            and set(body) == {"localId"}
            and body["localId"] == BINDING_PREFIX + binding
        )
    return True


def _validate_auth_account_bindings(plan, job):
    """Validate an optional frozen account/resource/UID-binding projection."""
    account_bindings = job.get("accountBindings")
    if account_bindings is None:
        return None
    if not isinstance(account_bindings, dict) or not account_bindings:
        raise ValueError("Auth account binding map required")
    resources = set(job.get("resources", []))
    seen_bindings = set()
    project = plan.get("project")
    for account, entry in account_bindings.items():
        if not isinstance(account, str) or not account or not isinstance(entry, dict):
            raise ValueError("Auth account binding map malformed")
        resource = entry.get("resource")
        binding = entry.get("uidBinding")
        if (
            not _auth_account_form(resource, project)
            or resource not in resources
            or not isinstance(binding, str)
            or _AUTH_UID_BINDING.fullmatch(binding) is None
            or binding in seen_bindings
        ):
            raise ValueError("Auth account binding resource or binding differs")
        seen_bindings.add(binding)
    for phase in ("observation", "recovery"):
        for operation in job.get(phase, []):
            if not _auth_operation(operation) or operation.get("account") is None:
                continue
            account = operation["account"]
            entry = account_bindings.get(account)
            if not isinstance(entry, dict):
                raise ValueError("Auth operation account binding missing")
            if operation.get("resource") != entry["resource"]:
                raise ValueError("Auth operation resource binding differs")
            if operation.get("uidBinding") != entry["uidBinding"]:
                raise ValueError("Auth operation UID binding differs")
            if phase == "observation" and operation.get("kind") == "sign-up":
                if operation.get("binds", {}).get(entry["uidBinding"]) != "localId":
                    raise ValueError("Auth signup UID binding differs")
    return account_bindings


def _auth_uid_absence_operation_valid(operation, project, account_bindings=None):
    """Only a bound UID read can settle an Auth account resource."""
    return (
        operation.get("kind") == "uid-absence"
        and operation.get("method") == "POST"
        and operation.get("path", "").endswith("/accounts:lookup")
        and _auth_recovery_operation_valid(operation, project, account_bindings)
        and isinstance(operation.get("body"), dict)
        and set(operation["body"]) == {"localId"}
    )


def _action_observation_delete_plan_allowed(plan, job, operation):
    """Recognize only the frozen AUTH-ACTION intentional delete slot."""
    candidates = [
        candidate
        for candidate in plan.get("jobs", {}).values()
        if isinstance(candidate, dict)
        and candidate.get("resources") == job.get("resources")
    ]
    if isinstance(job.get("accountBindings"), dict):
        candidates = [job]
    if len(candidates) != 1:
        return False
    declared = candidates[0].get("accountBindings", {}).get("accountB", {})
    return (
        plan.get("campaignId") == "AUTH-ACTION-OOB-DELIVERY-BOUNDARY-01"
        and plan.get("observationDeletePolicy") == "auth-action-account-b-delete-v1"
        and operation.get("id") == "account-b-delete"
        and _auth_operation(operation)
        and operation.get("method") == "POST"
        and operation.get("path") == (
            f"identitytoolkit.googleapis.com/v1/projects/{plan.get('project')}/accounts:delete"
        )
        and operation.get("account") == "accountB"
        and operation.get("uidBinding") == "accountBUid"
        and operation.get("body") == {"localId": "$binding:accountBUid"}
        and operation.get("resource") in set(job.get("resources", []))
        and isinstance(declared, dict)
        and operation.get("resource") == declared.get("resource")
        and operation.get("uidBinding") == declared.get("uidBinding")
    )


def _auth_creation_ownership(state, job, operation):
    """Require a journaled creation event for this exact Auth account resource."""
    account = operation.get("account")
    record = job.get("authAccounts", {}).get(account)
    if not isinstance(record, dict) or "createEvent" not in record:
        return False
    event_index = record["createEvent"]
    if type(event_index) is not int or not 0 <= event_index < len(state["events"]):
        return False
    event = state["events"][event_index]
    evidence = event.get("authEvidence")
    uid = record.get("uid")
    if not isinstance(uid, str) or sum(
        other.get("uid") == uid
        for other in job.get("authAccounts", {}).values()
        if isinstance(other, dict)
    ) != 1:
        return False
    ordinary = (
        record.get("resource") == operation.get("resource")
        and event.get("phase") == "observation"
        and event.get("completed") is True
        and event.get("creationOutcome") == "created"
        and isinstance(evidence, dict)
        and evidence.get("account") == account
        and evidence.get("uid") == uid
        and evidence.get("creationOutcome") == "created"
    )
    job_name = next((name for name, candidate in state["jobs"].items() if candidate is job), None)
    recipe = state["plan"].get("jobs", {}).get(job_name) if job_name is not None else None
    observation = recipe.get("observation", []) if isinstance(recipe, dict) else []
    observed_slot = event.get("index")
    observed_operation = observation[observed_slot] if (
        type(observed_slot) is int
        and 0 <= observed_slot < len(observation)
    ) else None
    custom_creation = (
        isinstance(observed_operation, dict)
        and observed_operation.get("kind") == "custom-sign-in"
        and observed_operation.get("account") == "custom"
        and observed_operation.get("service") == "auth"
        and observed_operation.get("method") == "POST"
        and observed_operation.get("path") == "identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken"
        and observed_operation.get("form") is False
        and observed_operation.get("body") == {
            "token": "$binding:customToken",
            "returnSecureToken": True,
        }
    )
    if (
        type(observed_slot) is not int
        or not 0 <= observed_slot < len(observation)
        or (
            observation[observed_slot].get("kind") != "sign-up"
            and not custom_creation
        )
        or event.get("requestDigest") != digest(observation[observed_slot])
    ):
        return False
    if ordinary:
        return True
    # MFA lost-signup recovery is accepted only as a closed two-event chain. The
    # original wire event remains pending/unknown; a typed address lookup from its
    # frozen recovery slot supplies the independent UID and response digest.
    if record.get("adopted") is not True:
        return False
    reconcile_index = record.get("reconcileEvent")
    if type(reconcile_index) is not int or not 0 <= reconcile_index < len(state["events"]):
        return False
    if job_name is None:
        return False
    recipe = state["plan"]["jobs"].get(job_name)
    if not isinstance(recipe, dict):
        return False
    observation = recipe.get("observation", [])
    recovery = recipe.get("recovery", [])
    reconcile = state["events"][reconcile_index]
    reconcile_slot = reconcile.get("index")
    observed_slot = event.get("index")
    if type(observed_slot) is not int or observed_slot >= len(observation) or type(reconcile_slot) is not int or not 0 <= reconcile_slot < len(recovery):
        return False
    observed_operation = observation[observed_slot]
    reconcile_operation = recovery[reconcile_slot]
    reconcile_evidence = reconcile.get("authEvidence")
    reconcile_body = reconcile_operation.get("body")
    chain = (
        event.get("phase") == "observation"
        and observed_operation.get("kind") == "sign-up"
        and observed_operation.get("account") == account
        and event.get("requestDigest") == digest(observed_operation)
        and reconcile.get("phase") == "recovery"
        and reconcile_operation.get("kind") == "address-reconcile"
        and reconcile_operation.get("account") == account
        and reconcile_operation.get("resource") == operation.get("resource")
        and reconcile_operation.get("method") == "POST"
        and reconcile_operation.get("path", "").endswith("/accounts:lookup")
        and isinstance(reconcile_body, dict)
        and set(reconcile_body) == {"email"}
        and isinstance(reconcile_body["email"], list)
        and len(reconcile_body["email"]) == 1
        and reconcile.get("requestDigest") == digest(reconcile_operation)
        and reconcile.get("completed") is True
        and reconcile.get("status") == 200
        and isinstance(reconcile_evidence, dict)
        and reconcile_evidence.get("account") == account
        and reconcile_evidence.get("email") == reconcile_body["email"][0]
        and reconcile_evidence.get("uid") == record.get("uid")
        and reconcile_evidence.get("responseDigest") == reconcile.get("responseDigest")
        and isinstance(event.get("settledBy"), dict)
        and event["settledBy"].get("responseDigest") == reconcile.get("responseDigest")
    )
    return bool(chain)


def validate_absence_proofs(state, job_name):
    """Validate final typed readback against the registered recovery plan and journal."""
    policy = _stream_policy(state["plan"])
    if policy:
        return policy.validate_absence(state, job_name)
    job = state["jobs"][job_name]
    proofs = job.get("absenceProofs", {})
    if set(proofs) != set(job["resources"]):
        raise ValueError("typed cleanup absence evidence incomplete")
    operations = state["plan"]["jobs"][job_name]["recovery"]
    for resource, proof in proofs.items():
        if _auth_account_form(resource):
            candidates = [
                index
                for index, operation in enumerate(operations)
                if _auth_operation(operation)
                and operation.get("resource") == resource
                and operation["method"] == "POST"
                and _auth_uid_absence_operation_valid(
                    operation,
                    state["plan"].get("project"),
                    job.get("accountBindings"),
                )
            ]
            absent = auth_typed_absence
        else:
            candidates = [
                index
                for index, operation in enumerate(operations)
                if operation["method"] == "GET"
                and operation["service"] == "firestore"
                and operation["path"] == "/v1/" + resource
            ]
            absent = typed_absence
        index = proof.get("eventIndex")
        if (
            not candidates
            or type(index) is not int
            or not 0 <= index < len(state["events"])
        ):
            raise ValueError("typed cleanup absence event missing")
        event = state["events"][index]
        expected = dict(operations[candidates[-1]])
        # versionFrom is a planning annotation, removed before dispatch. An
        # explicit null must hash exactly like its absence on the wire.
        if expected.pop("versionFrom", None) is not None:
            raise ValueError("final absence read cannot depend on a version capture")
        if (
            event.get("job") != job_name
            or event.get("phase") != "recovery"
            or type(event.get("index")) is not int
            or event["index"] != candidates[-1]
            or event.get("requestDigest") != digest(expected)
            or event.get("completed") is not True
            or event.get("failure") is not None
            or not absent(event.get("status"), proof.get("body"))
            or event.get("responseDigest") != digest(proof["body"])
        ):
            raise ValueError("typed cleanup absence evidence differs")


def _save(path, state):
    temporary = path / "state.tmp"
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "w") as stream:
        json.dump(state, stream, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path / "state.json")
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _ceiling_honoured(plan, seconds):
    """A slot whose request carries a body must reserve the declared wire ceiling.

    Without this the per-slot reservation is a convention: an edit could shrink
    the allowance for a ten-mebibyte upload to whatever made the totals fit, and
    the Gate would admit the plan. The ceiling is the campaign's own transport
    deadline, so a slot that can spend it must reserve it.
    """
    if "transportCeilingSeconds" not in plan:
        return True
    ceiling = plan["transportCeilingSeconds"]
    for name, job in plan["jobs"].items():
        schedule = job_schedule(job)
        if schedule is None:
            # Legacy slots use the plan-wide allowance. Omitting a schedule
            # must not bypass the same declared wire ceiling.
            schedule = (
                {"phase": phase, "index": index}
                for phase in PHASES
                for index in range(len(job[phase]))
            )
        for entry in schedule:
            operation = plan["jobs"][name][entry["phase"]][entry["index"]]
            if (
                isinstance(operation, dict)
                and (
                    operation.get("body") is not None
                    or operation.get("bodyRef") is not None
                )
                and slot_seconds(entry, seconds) < ceiling
            ):
                return False
    return True


def _observation_time(plan, seconds):
    """Time the scheduled observation slots reserve, for jobs that declared one."""
    interval = plan["intervalSeconds"]
    total = 0
    if _rules_management(plan):
        total += sum(entry["timeout"] + interval for entry in plan["management"]["observation"])
    for job in plan["jobs"].values():
        schedule = job_schedule(job)
        if schedule is None:
            continue
        total += sum(
            slot_seconds(entry, seconds) + interval
            for entry in schedule
            if entry["phase"] == "observation"
        )
    return total


def creating_slots(plan, job_name):
    """The observation slots of a job that its plan says could write."""
    schedule = job_schedule(plan["jobs"][job_name])
    if schedule is None:
        # Legacy plans omit a schedule and use the fixed observation-then-
        # recovery order. Infer creating slots from the frozen operation shape
        # so uncertain writes remain owned in that format too.
        return {
            index
            for index, operation in enumerate(plan["jobs"][job_name]["observation"])
            if can_create(operation)
        }
    return {
        entry["index"]
        for entry in schedule
        if entry["phase"] == "observation" and entry.get("creates", True) is not False
    }


def creating_outcome(state, job_name):
    """How this job's creating requests ended, read from the journal.

    `"none"` when none was dispatched, `"refused"` when every one that was
    dispatched answered with a typed refusal, and `"unsettled"` otherwise, which
    covers a successful create and, importantly, a request whose answer was
    lost. The classification is by `completed` and status, never by whether a
    creation proof came back: no proof is also what a lost answer looks like.
    """
    indices = creating_slots(state["plan"], job_name)
    if not indices:
        return "unsettled" if indices is None else "none"
    seen = 0
    for event in state["events"]:
        if (
            event.get("job") != job_name
            or event.get("phase") != "observation"
            or event.get("index") not in indices
        ):
            continue
        seen += 1
        # New journals carry the result of the creation-specific response
        # validation.  A received HTTP response is not enough to establish
        # that a conditional write was refused: 5xx responses and malformed
        # success bodies can both follow a server-side write.
        outcome = event.get("creationOutcome")
        if outcome == "refused":
            continue
        if outcome == "created":
            return "unsettled"
        if outcome in ("pending", "unknown"):
            return "unsettled"
        # Archived journals predate creationOutcome.  They cannot carry the
        # response body needed to prove a refusal, so fail closed and retain
        # recovery responsibility instead of inferring it from the status.
        return "unsettled"
    return "refused" if seen else "none"


def unconfirmed_creates(state, job_name):
    """Creating requests this job dispatched whose outcome never came back.

    Derived from the journal at every read rather than kept as a counter, so it
    cannot drift from the events it describes. An event is counted while it is
    open and once it has failed; a typed answer, whether it created or refused,
    settles it.
    """
    indices = creating_slots(state["plan"], job_name)
    if not indices:
        return 0
    return sum(
        1
        for event in state["events"]
        if event.get("job") == job_name
        and event.get("phase") == "observation"
        and event.get("index") in indices
        and event.get("creationOutcome") != "refused"
        and event.get("creationOutcome") != "created"
        and not (
            event.get("settlementOutcome") in {"present", "absent"}
            and isinstance(event.get("settledBy"), dict)
            and isinstance(event["settledBy"].get("responseDigest"), str)
        )
    )


def abandoned_cleanup_complete(state):
    """The documents an abandoned run created, when every one is proven absent.

    `None` when the state cannot support that claim: a job that dispatched but
    proved no creation, a job with creation proofs that never abandoned or whose
    scheduled cleanup did not run to the end, or one whose typed absence journal
    does not cover exactly its assigned resources. A created document still
    present therefore stays with the owner-attested exit, which is the whole
    point of separating the two.
    """
    created = []
    abandoned_created = False
    for name, job in state["jobs"].items():
        if unconfirmed_creates(state, name):
            # A request that could have written and never confirmed an outcome
            # leaves documents that may exist and cannot be proven absent here.
            return None
        proofs = job.get("creationProofs") or {}
        if not proofs:
            if job.get("complete") is True and job.get("stopReason") is None:
                # A normally completed no-write job may be one member of a
                # campaign whose other job was stopped after creating data. Its
                # terminal state is already proven by Gate.finish(); do not make
                # the abandoned close pretend that this job was abandoned too.
                continue
            if job["observation"] or job["recovery"]:
                # It ran and proved no creation: that is a no-data stop or an
                # uncertain one, and neither is this.
                return None
            continue
        schedule = job_schedule(state["plan"]["jobs"][name])
        if (
            schedule is None
            or job.get("scheduleDone", 0) != len(schedule)
            or job["inflight"]
            # Only the resources this job actually created need a creation
            # proof; a resource the plan merely assigned but never created
            # (expected-refused, or a stop before its slot ran) is closed by
            # its typed absence read alone, checked below for every resource.
            or not set(proofs) <= set(job["resources"])
            or set(job.get("absent") or []) != set(job["resources"])
        ):
            return None
        stopped = job.get("stopReason") is not None
        if not stopped and job.get("complete") is not True:
            # A created job that was neither abandoned nor normally finished
            # has no terminal ownership proof for this close path.
            return None
        abandoned_created = abandoned_created or stopped
        try:
            validate_absence_proofs(state, name)
        except Exception:  # noqa: BLE001 -- any failure to validate means the claim is unsupported
            return None
        created.extend(proofs)
    # The abandoned close is deliberately disjoint from the normal close. A
    # campaign whose created jobs all finished normally must use Ledger.finish;
    # at least one created job must have an explicit stop reason here.
    return sorted(created) if created and abandoned_created else None


def non_creating_dispatches(state):
    """How many data slots ran, when every one of them could not create a document.

    `None` when the state cannot support that claim: any recovery dispatch, a
    job that dispatched without a declared schedule, or a consumed slot the plan
    did not declare non-creating. A slot is treated as creating unless it says
    otherwise, so a campaign that declares nothing keeps the older and stricter
    rule, which is that no data request may have been sent at all.

    The declaration is load-bearing and belongs to the reviewed plan. Empty
    creation proofs are a second line under it, but they only catch a
    mis-declared slot whose creation was conditional.
    """
    plan = state["plan"]
    total = 0
    for name, job in state["jobs"].items():
        if job["recovery"]:
            return None
        if not job["observation"]:
            continue
        schedule = job_schedule(plan["jobs"][name])
        if schedule is None:
            return None
        consumed = schedule[: job.get("scheduleDone", 0)]
        if len(consumed) != job["observation"] or any(
            entry.get("creates", True) is not False for entry in consumed
        ):
            return None
        total += job["observation"]
    return total


def _recovery_time(plan, seconds):
    """Time reserved for cleanup, taken per slot wherever the campaign declared one."""
    interval = plan["intervalSeconds"]
    total = 0
    for job in plan["jobs"].values():
        schedule = job_schedule(job)
        if schedule is None:
            total += len(job["recovery"]) * (seconds + interval)
            continue
        total += sum(
            slot_seconds(entry, seconds) + interval
            for entry in schedule
            if entry["phase"] == "recovery"
        )
    return total


def create(path, plan):
    path = Path(path)
    rules_management = _rules_management(plan)
    if rules_management:
        _validate_rules_management_plan(plan)
    preparation = plan.get("transport") == LIMITS_PREPARATION_TRANSPORT
    if preparation:
        validate_limits_preparation_plan(plan)
    policy = _stream_policy(plan)
    if policy:
        policy.validate_plan(plan)
    project = plan.get("project")
    for job in plan.get("jobs", {}).values():
        account_bindings = _validate_auth_account_bindings(plan, job)
        resources = set(job.get("resources", []))
        for operation in job.get("observation", []) + job.get("recovery", []):
            if not _auth_operation(operation):
                continue
            if account_bindings is None and "uidBinding" in operation:
                raise ValueError("explicit Auth UID binding requires account map")
            resource = operation.get("resource")
            if resource is not None and not _auth_account_form(resource, project):
                raise ValueError("canonical Auth account resource required")
            if resource is not None and resource not in resources:
                raise ValueError("Auth operation resource outside assigned resources")
            if operation in job.get("recovery", []) and resource not in resources:
                raise ValueError("cleanup target outside assigned resources")
            if (
                operation in job.get("observation", [])
                and operation.get("method") == "POST"
                and operation.get("path", "").endswith("/accounts:delete")
                and not _action_observation_delete_plan_allowed(plan, job, operation)
            ):
                raise ValueError("destructive Auth delete is recovery-only")
            if (
                operation in job.get("recovery", [])
                and resource is not None
                and not _auth_recovery_operation_valid(
                    operation, project, account_bindings
                )
            ):
                raise ValueError("canonical Auth UID binding or lookup route required")
    if (
        not _valid_request_seconds(plan, policy)
        or not _valid_ceiling(plan)
        or not _valid_allocation(plan)
        or not _valid_marker(plan)
    ):
        # Checked before they are used, so a malformed value cannot reach arithmetic.
        raise ValueError("invalid shared allocation")
    seconds = request_seconds(plan, policy)
    jobs = plan["jobs"]
    slots = plan.get("jobSlots", 2)
    resources = [r for job in jobs.values() for r in job["resources"]]
    recovery = sum(len(job["recovery"]) for job in jobs.values())
    management_recovery = plan.get("management", {}).get("recovery", [])
    recovery_time = _recovery_time(plan, seconds) + sum(
        item["timeout"] + plan["intervalSeconds"] for item in management_recovery
    )
    recovery += len(management_recovery)
    overhead = plan.get("coordinatorRequests", 0)
    fixed_cost = plan.get("fixedCostMicrousd", 0)
    if (
        plan["contract"]
        not in {"shared-local-v1", "shared-local-v2", "shared-stream-v1"}
        or type(slots) is not int
        or isinstance(slots, bool)
        or not 1 <= slots <= MAX_JOB_SLOTS
        or not 1 <= len(jobs) <= slots
        or not _valid_request_seconds(plan, policy)
        or not _valid_bodies(plan)
        or any(not _valid_schedule(job) for job in jobs.values())
        or not _ceiling_honoured(plan, seconds)
        or not _within_published(plan)
        or not _nonce_scoped(plan)
        or _observation_time(plan, seconds)
        > plan["wallSeconds"] - plan["recoverySeconds"]
        or len(resources) != len(set(resources))
        or (not resources and not preparation and not rules_management)
        or not 0 < plan["recoverySeconds"] < plan["wallSeconds"]
        or (
            plan["wallSeconds"] > WALL_CAP_SECONDS
            and not (
                plan.get("campaignId") == AUTH_REV3_CAMPAIGN_ID
                and plan.get("selector") == AUTH_REV3_SELECTOR
                and plan["wallSeconds"] <= AUTH_REV3_WALL_SECONDS
                and plan["recoverySeconds"] >= AUTH_REV3_MIN_RECOVERY_SECONDS
            )
        )
        or plan["recoverySeconds"] < recovery_time
        or not math.isfinite(plan["intervalSeconds"])
        or plan["intervalSeconds"] < INTERVAL_FLOOR_SECONDS
        or type(plan["costMicrousd"]) is not int
        or type(plan["observationRequests"]) is not int
        or plan["observationRequests"] < 0
        or type(plan["requestCostMicrousd"]) is not int
        or plan["requestCostMicrousd"] <= 0
        or type(fixed_cost) is not int
        or fixed_cost < 0
        or type(overhead) is not int
        or not 0 <= overhead <= 2
        or plan["costMicrousd"]
        < fixed_cost + (recovery + overhead) * plan["requestCostMicrousd"]
    ):
        raise ValueError("invalid shared allocation")
    _resolve_all_aliases(plan)
    _check_creates_declarations(plan)
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    (path / "lock").touch(mode=0o600, exist_ok=False)
    state = {
        "plan": plan,
        "planDigest": digest(plan),
        "started": time.monotonic(),
        "total": overhead,
        "observation": 0,
        "recovery": 0,
        "reservedRecovery": recovery,
        "costMicrousd": fixed_cost + overhead * plan["requestCostMicrousd"],
        "lastSent": 0,
        "stopped": False,
        "coordinatorPid": os.getpid(),
        "coordinatorDone": 0,
        "managementUsed": [],
        "managementEvents": [],
        "managementSkipped": [],
        "rulesRecoveryHeld": {},
        "managementAbort": None,
        "coordinatorInflight": False,
        "events": [],
        "jobs": {},
    }
    for key, job in jobs.items():
        state["jobs"][key] = {
            "resources": job["resources"],
            "pid": None,
            "stopped": False,
            "inflight": False,
            "observation": 0,
            "recovery": 0,
            "owned": [],
            "creationProofs": {},
            "absent": [],
            "captures": {},
            "complete": False,
        }
        if job_schedule(job) is not None:
            state["jobs"][key]["skippedByStop"] = 0
            # Only a scheduled job carries a cursor, so every existing campaign's
            # job row keeps the exact shape its archived receipts record.
            state["jobs"][key]["scheduleDone"] = 0
    _save(path, state)


MARKER_BINDINGS = ("resource-name", "nonce")
BODY_REFERENCE_FIELDS = {"sha256", "bytes"}


def canonical_body_bytes(body):
    """The exact wire bytes of a request body, as the campaigns encode them."""
    return json.dumps(
        body, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def body_reference(body):
    """What a plan carries in place of a body too large to embed.

    A campaign that probes a ten-mebibyte request cannot put three of those in a
    plan that a bounded receipt has to carry, so the plan carries the digest and
    the length instead. The reference enters the digested plan, so the plan digest
    still binds the exact bytes, and `dispatch` refuses a body that does not
    reproduce it.
    """
    encoded = canonical_body_bytes(body)
    return {"sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}


def _valid_body_reference(operation):
    reference = operation.get("bodyRef")
    if reference is None:
        return True
    return (
        isinstance(reference, dict)
        and set(reference) == BODY_REFERENCE_FIELDS
        and isinstance(reference["sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]) is not None
        and type(reference["bytes"]) is int
        and not isinstance(reference["bytes"], bool)
        and reference["bytes"] > 0
        # A slot carries its body one way or the other, never both.
        and operation.get("body") is None
    )


def _valid_bodies(plan):
    """Every reference is well formed, and nothing oversized is carried inline."""
    threshold = plan.get("bodyReferenceThresholdBytes")
    if threshold is not None and (
        type(threshold) is not int or isinstance(threshold, bool) or threshold <= 0
    ):
        return False
    for job in plan["jobs"].values():
        for phase in PHASES:
            for operation in job[phase]:
                if not isinstance(operation, dict) or not _valid_body_reference(
                    operation
                ):
                    return False
                body = operation.get("body")
                if (
                    threshold is not None
                    and body is not None
                    and len(canonical_body_bytes(body)) > threshold
                ):
                    return False
    return True


# Why a slot was consumed without a wire call. Each names a fact from the
# journal, never the absence of a creation proof: "no proof" is also what a lost
# answer looks like, and that one must never be skippable.
NEVER_DISPATCHED_REASON = "creating-slot-never-dispatched"
REFUSED_CREATE_REASON = "skipped-refused-create"
ZERO_WIRE_REASON = "no-creation-proof"
GATE_SKIP_REASONS = (
    NEVER_DISPATCHED_REASON,
    REFUSED_CREATE_REASON,
    ZERO_WIRE_REASON,
)
MAX_STOP_REASON = 128


def _bulk_writes(operation):
    """Only the known Firestore bulk-write envelope can prove non-creation."""
    path = operation.get("path")
    body = operation.get("body")
    if (
        operation.get("service") == "firestore"
        and operation.get("method") == "POST"
        and isinstance(path, str)
        and re.fullmatch(
            r"/v1/projects/[^/?#]+/databases/[^/?#]+/documents:(?:commit|batchWrite)",
            path,
        )
        and operation.get("bodyRef") is None
        and isinstance(body, dict)
        and isinstance(body.get("writes"), list)
        and body["writes"]
    ):
        return body["writes"]
    return None


def _existing_transform(write):
    """An unambiguous transform guarded by a JSON boolean, not Python equality."""
    return (
        isinstance(write, dict)
        and set(write) == {"transform", "currentDocument"}
        and isinstance(write["transform"], dict)
        and isinstance(write["currentDocument"], dict)
        and set(write["currentDocument"]) == {"exists"}
        and write["currentDocument"]["exists"] is True
    )


def _document_read_rpc(operation):
    """Recognize only the body-carrying, non-creating read recipes we support.

    Legacy plans infer creation from the operation, not a schedule. Treating
    every POST body as a create strands Query Explain cleanup even when its
    writes were acknowledged and every owned document was removed. Match the
    service, method, canonical parent and exact RPC rather than a path suffix:
    a collection with a similar name must never exempt a write. A request that
    starts a transaction, carries unknown fields, or uses a body reference is
    deliberately outside this narrow exception.
    """
    if (
        operation.get("service") != "firestore"
        or operation.get("method") != "POST"
        or operation.get("bodyRef") is not None
        or not isinstance(operation.get("path"), str)
        or not isinstance(operation.get("body"), dict)
    ):
        return False
    path = operation["path"]
    match = re.fullmatch(
        r"/v1/projects/([^/?#:%]+)/databases/([^/?#:%]+)/documents"
        r"((?:/[^/?#:%]+/[^/?#:%]+)*):"
        r"(runQuery|runAggregationQuery|listCollectionIds|partitionQuery)",
        path,
    )
    if match is None or any(
        part in {".", ".."}
        for part in (match.group(1), match.group(2), *match.group(3).split("/")[1:])
    ):
        return False
    allowed = {
        "runQuery": {"structuredQuery", "explainOptions", "readTime"},
        "runAggregationQuery": {
            "structuredAggregationQuery",
            "explainOptions",
            "readTime",
        },
        "listCollectionIds": {"pageSize", "pageToken", "readTime"},
        "partitionQuery": {
            "structuredQuery",
            "partitionCount",
            "pageSize",
            "pageToken",
            "readTime",
        },
    }
    return set(operation["body"]) <= allowed[match.group(4)]


def _auth_noncreating_rpc(operation):
    """Only the exact password, refresh and lookup recipes cannot create users.

    Non-creating is not read-only: sign-in and refresh issue credentials. Other
    sign-in methods can create accounts and must remain conservative. Unknown
    fields, body references, path variants and wire encodings are not exempted.
    """
    if (
        operation.get("service") != "auth"
        or operation.get("method") != "POST"
        or operation.get("bodyRef") is not None
        or not isinstance(operation.get("body"), dict)
        or not isinstance(operation.get("path"), str)
    ):
        return False
    body, path = operation["body"], operation["path"]
    if path == "securetoken.googleapis.com/v1/token":
        return (
            operation.get("form") is True
            and set(body) == {"grant_type", "refresh_token"}
            and body["grant_type"] == "refresh_token"
            and isinstance(body["refresh_token"], str)
            and bool(body["refresh_token"])
        )
    if operation.get("form") is not False:
        return False
    if path == "identitytoolkit.googleapis.com/v1/accounts:signInWithPassword":
        return (
            set(body) == {"email", "password", "returnSecureToken"}
            and body["returnSecureToken"] is True
            and all(
                isinstance(body[key], str) and body[key]
                for key in ("email", "password")
            )
        )
    if path == "identitytoolkit.googleapis.com/v1/accounts:lookup":
        return (
            set(body) == {"idToken"}
            and isinstance(body["idToken"], str)
            and bool(body["idToken"])
        )
    match = re.fullmatch(
        r"identitytoolkit\.googleapis\.com/v1/projects/([A-Za-z0-9_-]+)/accounts:lookup",
        path,
    )
    return (
        match is not None
        and set(body) == {"localId"}
        and isinstance(body["localId"], str)
        and bool(body["localId"])
    )


_ACTION_NONCREATING_CONTRACTS = {
    "reset-link-generate": ("/v1/projects/{project}/accounts:sendOobCode", {"requestType": "PASSWORD_RESET", "email": "$binding:accountA.email", "returnOobLink": True}),
    "reset-code-lookup": ("/v1/accounts:resetPassword", {"oobCode": "$binding:resetCode"}),
    "reset-weak-password": ("/v1/accounts:resetPassword", {"oobCode": "$binding:resetCode", "newPassword": "$binding:weakPassword"}),
    "reset-weak-password-retry": ("/v1/accounts:resetPassword", {"oobCode": "$binding:resetCode"}),
    "reset-consume": ("/v1/accounts:resetPassword", {"oobCode": "$binding:resetCode", "newPassword": "$binding:accountA.nextPassword"}),
    "reset-reuse": ("/v1/accounts:resetPassword", {"oobCode": "$binding:resetCode", "newPassword": "$binding:accountA.thirdPassword"}),
    "reset-wrong-code": ("/v1/accounts:resetPassword", {"oobCode": "$binding:wrongCode", "newPassword": "$binding:accountA.thirdPassword"}),
    "reset-link-generate-second": ("/v1/projects/{project}/accounts:sendOobCode", {"requestType": "PASSWORD_RESET", "email": "$binding:accountA.email", "returnOobLink": True}),
    "admin-password-update": ("/v1/projects/{project}/accounts:update", {"localId": "$binding:accountAUid", "password": "$binding:accountA.fourthPassword"}),
    "reset-after-password-change": ("/v1/accounts:resetPassword", {"oobCode": "$binding:resetCodeSecond", "newPassword": "$binding:accountA.fifthPassword"}),
    "account-a-readback": ("/v1/projects/{project}/accounts:lookup", {"localId": "$binding:accountAUid"}),
    "verify-link-generate": ("/v1/projects/{project}/accounts:sendOobCode", {"requestType": "VERIFY_EMAIL", "email": "$binding:accountA.email", "returnOobLink": True}),
    "verify-apply": ("/v1/accounts:update", {"oobCode": "$binding:verifyCode"}),
    "verify-reuse": ("/v1/accounts:update", {"oobCode": "$binding:verifyCode"}),
    "verify-wrong-code": ("/v1/accounts:update", {"oobCode": "$binding:wrongCode"}),
    "email-link-generate": ("/v1/projects/{project}/accounts:sendOobCode", {"requestType": "EMAIL_SIGNIN", "email": "$binding:accountA.email", "returnOobLink": True}),
    "email-link-signin": ("/v1/accounts:signInWithEmailLink", {"email": "$binding:accountA.email", "oobCode": "$binding:emailLinkCode"}),
    "email-link-reuse": ("/v1/accounts:signInWithEmailLink", {"email": "$binding:accountA.email", "oobCode": "$binding:emailLinkCode"}),
    "email-link-generate-second": ("/v1/projects/{project}/accounts:sendOobCode", {"requestType": "EMAIL_SIGNIN", "email": "$binding:accountA.email", "returnOobLink": True}),
    "email-link-mismatched-email": ("/v1/accounts:signInWithEmailLink", {"email": "$binding:accountB.email", "oobCode": "$binding:emailLinkCodeSecond"}),
    "deleted-user-link-generate": ("/v1/projects/{project}/accounts:sendOobCode", {"requestType": "PASSWORD_RESET", "email": "$binding:accountB.email", "returnOobLink": True}),
    "account-b-delete": ("/v1/projects/{project}/accounts:delete", {"localId": "$binding:accountBUid"}),
    "reset-after-delete": ("/v1/accounts:resetPassword", {"oobCode": "$binding:deletedUserCode", "newPassword": "$binding:accountB.nextPassword"}),
    "link-generate-unknown-email": ("/v1/projects/{project}/accounts:sendOobCode", {"requestType": "PASSWORD_RESET", "email": "$binding:unknownEmail", "returnOobLink": True}),
}


def _action_noncreating_contract_matches(operation):
    contract = _ACTION_NONCREATING_CONTRACTS.get(operation.get("id"))
    if contract is None:
        return False
    suffix, expected_body = contract
    path = operation.get("path")
    if not isinstance(path, str) or not path.startswith("identitytoolkit.googleapis.com"):
        return False
    canonical_path = path.removeprefix("identitytoolkit.googleapis.com")
    if "/projects/" in suffix:
        resource = operation.get("resource")
        project = operation.get("project")
        if project != "fireemu-35fe6":
            return False
        if isinstance(resource, str) and resource.startswith("projects/"):
            if resource.split("/", 2)[1] != project:
                return False
        if canonical_path != suffix.format(project=project):
            return False
    elif canonical_path != suffix:
        return False
    body = operation.get("body")
    if not isinstance(body, dict) or set(body) != set(expected_body):
        return False
    return all(body[key] == value for key, value in expected_body.items())


def can_create(operation):
    """Whether a request could bring a document into existence.

    The Ledger relaxes its retirement contract on a slot declared `creates`
    false, so the declaration is not the campaign's word alone: a plan whose
    slot could write is refused here. A request that carries a body is treated
    as able to create unless an exact known operation proves otherwise, because
    the conservative direction is to refuse an unknown declaration.
    """
    if not isinstance(operation, dict):
        return True
    path = operation.get("path")
    path = path if isinstance(path, str) else ""
    method = operation.get("method")
    body = operation.get("body")
    if (
        operation.get("kind") == "action-stage"
        and operation.get("service") == "auth"
        and method == "POST"
        and _action_noncreating_contract_matches(operation)
    ):
        return False
    if _document_read_rpc(operation) or _auth_noncreating_rpc(operation):
        return False
    writes = _bulk_writes(operation)
    if writes is not None and all(_existing_transform(write) for write in writes):
        return False
    return (
        body is not None
        or operation.get("bodyRef") is not None
        or (method == "PATCH" and path.endswith("?currentDocument.exists=false"))
        or (method == "POST" and path.endswith((":batchWrite", ":commit")))
    )


def _check_creates_declarations(plan):
    for job in plan["jobs"].values():
        schedule = job_schedule(job)
        if schedule is None:
            continue
        for entry in schedule:
            if entry.get("creates", True) is False and can_create(
                job[entry["phase"]][entry["index"]]
            ):
                raise ValueError(
                    "a slot whose request can create cannot declare creates false"
                )


def ownership_marker(plan):
    """How a created document proves it belongs to this campaign's owned namespace.

    The `shared-local-v2` convention is that a document names itself in
    `_sharedOwner`. A campaign whose documents are sized to the byte cannot add a
    field to carry that shape, so it may declare its own marker instead: a field
    and whether the value binds the resource name or the campaign nonce. A plan
    that declares nothing keeps the convention its contract implies.

    A nonce binding is weaker than a self-naming one: it proves the document came
    from this campaign, not that it is the document the request named. It is
    adequate only because the resource must also be in the job's assigned
    resources and under the nonce-scoped path, and that is worth a reviewer's
    attention rather than an assumption.
    """
    declared = plan.get("ownershipMarker")
    if declared is None:
        if plan["contract"] == "shared-local-v2":
            return "_sharedOwner", "resource-name"
        return None
    return declared["field"], declared["binding"]


def _nonce_scoped(plan):
    """Every assigned resource must carry the nonce that the marker binds to.

    The nonce binding proves a document came from this campaign, not that it is
    the document the request named. It is adequate only because the resource is
    also under the nonce-scoped path, so that part is checked rather than
    assumed.
    """
    marker = ownership_marker(plan)
    if marker is None or marker[1] != "nonce":
        return True
    segment = "/" + plan["nonce"] + "/"
    return all(
        isinstance(name, str) and segment in "/" + name + "/"
        for job in plan["jobs"].values()
        for name in job["resources"]
    )


def _valid_marker(plan):
    if "ownershipMarker" not in plan:
        return True
    declared = plan["ownershipMarker"]
    return (
        isinstance(declared, dict)
        and set(declared) == {"field", "binding"}
        and isinstance(declared["field"], str)
        and bool(declared["field"])
        and declared["binding"] in MARKER_BINDINGS
        and (declared["binding"] != "nonce" or isinstance(plan.get("nonce"), str))
    )


def resolve_version_source(operations, index, source):
    """The capture index a recovery slot reads its version from.

    A numeric `versionFrom` is canonical and names the slot directly. A named one
    is an alias for the kind of the earlier slot that captured the version,
    resolved within the same resource, so a campaign with one ownership read per
    document does not hard-code an index per document. It must resolve to exactly
    one earlier slot of that kind for that resource, or the plan is refused.
    """
    if source is None or type(source) is int:
        return source
    resource = operations[index].get("resource")
    if not isinstance(source, str) or not source or not isinstance(resource, str):
        raise ValueError("version source alias must name a kind and a resource")
    matches = [
        position
        for position, candidate in enumerate(operations[:index])
        if candidate.get("kind") == source and candidate.get("resource") == resource
    ]
    if len(matches) != 1:
        raise ValueError("version source alias must resolve to exactly one slot")
    return matches[0]


def _resolve_all_aliases(plan):
    for job in plan["jobs"].values():
        operations = job["recovery"]
        for index, operation in enumerate(operations):
            if isinstance(operation, dict):
                resolve_version_source(operations, index, operation.get("versionFrom"))


def _creation_proofs(operation, status, body, job, plan):
    """Only exact conditional-create acknowledgements grant destructive authority."""
    if status != 200 or operation["service"] != "firestore":
        return []
    if isinstance(body, dict) and "error" in body:
        raise ValueError("success response contains an API error")
    request = operation.get("body")
    candidates = []
    if operation["method"] == "PATCH" and operation["path"].endswith(
        "?currentDocument.exists=false"
    ):
        name = operation["path"].split("?", 1)[0].removeprefix("/v1/")
        if not isinstance(body, dict) or body.get("name") != name:
            raise ValueError("conditional creation identity mismatch")
        fields = request.get("fields") if isinstance(request, dict) else None
        if digest(body.get("fields")) != digest(fields):
            raise ValueError("conditional creation fields mismatch")
        candidates.append((name, fields, body.get("updateTime")))
    elif operation["method"] == "POST" and operation["path"].endswith(":commit"):
        # A Commit is atomic: a 200 means every write in it applied, so there is
        # no per-write status to read, only one update version per write.
        writes = request.get("writes", []) if isinstance(request, dict) else []
        conditional = [
            write
            for write in writes
            if isinstance(write, dict)
            and write.get("currentDocument") == {"exists": False}
        ]
        if not conditional:
            return []
        results = body.get("writeResults") if isinstance(body, dict) else None
        if not isinstance(results, list) or len(results) != len(writes):
            raise ValueError("conditional commit acknowledgement incomplete")
        for write, result in zip(writes, results, strict=True):
            if (
                not isinstance(write, dict)
                or write.get("currentDocument", {}).get("exists") is not False
                or digest(write.get("currentDocument")) != digest({"exists": False})
            ):
                continue
            update = write.get("update", {})
            if not isinstance(update, dict) or not isinstance(result, dict):
                raise ValueError("conditional commit creation body mismatch")  # noqa: TRY004 -- Gate admission uses ValueError.
            candidates.append(
                (update.get("name"), update.get("fields"), result.get("updateTime"))
            )
    elif operation["method"] == "POST" and operation["path"].endswith(":batchWrite"):
        writes = request.get("writes", []) if isinstance(request, dict) else []
        conditional = [
            write
            for write in writes
            if isinstance(write, dict)
            and write.get("currentDocument") == {"exists": False}
            and write["currentDocument"]["exists"] is False
        ]
        if not conditional:
            return []
        statuses = body.get("status") if isinstance(body, dict) else None
        results = body.get("writeResults") if isinstance(body, dict) else None
        if (
            not isinstance(statuses, list)
            or not isinstance(results, list)
            or len(statuses) != len(writes)
            or len(results) != len(writes)
        ):
            raise ValueError("conditional batch creation acknowledgement incomplete")
        for write, result, entry in zip(writes, results, statuses, strict=True):
            # google.rpc.Status omits its protobuf-default zero on production success.
            if not isinstance(entry, dict) or type(entry.get("code", 0)) is not int:
                raise ValueError("typed conditional batch status required")
            if (
                not isinstance(write, dict)
                or write.get("currentDocument", {}).get("exists") is not False
                or digest(write.get("currentDocument")) != digest({"exists": False})
                or entry.get("code", 0) != 0
            ):
                continue
            update = write.get("update", {})
            if not isinstance(update, dict) or not isinstance(result, dict):
                raise ValueError("conditional batch creation body mismatch")  # noqa: TRY004 -- Gate admission uses ValueError.
            candidates.append(
                (update.get("name"), update.get("fields"), result.get("updateTime"))
            )
    proofs = []
    for name, fields, version in candidates:
        if (
            name not in job["resources"]
            or not isinstance(fields, dict)
            or not isinstance(version, str)
            or not re.fullmatch(
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z", version
            )
        ):
            raise ValueError("typed conditional creation resource/version required")
        datetime.fromisoformat(version)
        marker = ownership_marker(plan)
        if marker is not None:
            field, binding = marker
            expected = (
                {"referenceValue": name}
                if binding == "resource-name"
                else {"stringValue": plan["nonce"]}
            )
            if fields.get(field) != expected:
                raise ValueError("conditional creation namespace marker required")
        proofs.append(
            {
                "name": name,
                "updateTime": version,
                "fieldsDigest": digest(fields),
                "requestDigest": digest(operation),
                "responseDigest": digest(body),
            }
        )
    return proofs


def _typed_create_refusal(status, body):
    """Whether a completed create response proves that no write was applied.

    A transport-level status is not a write outcome.  In particular, a 500 or
    504 can be returned after the server has committed the write.  The shared
    Gate only treats the narrow, typed request rejection used by the reviewed
    boundary campaigns as a refusal; every other response remains recoverable
    as an outcome-unknown create.
    """
    return _typed_firestore_error(status, body, 400, "INVALID_ARGUMENT")


def _creation_outcome(operation, status, body, proofs):
    """Settle a request only when every potentially creating write is accounted for.

    A successful prefix is not an acknowledgement of a BatchWrite's suffix.
    Keep partial creation proofs for conditional cleanup, but retain uncertain
    ownership if any other write has an ambiguous outcome or no creation proof.
    The accepted per-item refusals are INVALID_ARGUMENT (3) and ALREADY_EXISTS
    (6) for an exact exists=false conditional create. An ALREADY_EXISTS result
    cannot authorize deletion of that resource: it provides no creation proof.
    """
    if _typed_create_refusal(status, body):
        return "refused"
    if status != 200 or (isinstance(body, dict) and "error" in body):
        return "unknown"
    if operation["method"] == "PATCH":
        return "created" if proofs else "unknown"
    writes = _bulk_writes(operation)
    if writes is None or not isinstance(body, dict):
        return "unknown"
    batch = operation["path"].endswith(":batchWrite")
    statuses = body.get("status") if batch else None
    results = body.get("writeResults")
    if batch and (
        not isinstance(statuses, list)
        or len(statuses) != len(writes)
        or not isinstance(results, list)
        or len(results) != len(writes)
    ):
        return "unknown"
    outstanding = {proof["name"] for proof in proofs}
    if len(outstanding) != len(proofs):
        return "unknown"
    creates = 0
    for index, write in enumerate(writes):
        if _existing_transform(write):
            continue
        if batch and write == {}:
            # An empty write names no document and cannot create one. It is
            # accounted for only when the server refused it per item with the
            # typed INVALID_ARGUMENT code and the empty result slot; any other
            # answer for it leaves the request unknown.
            entry = statuses[index]
            if (
                isinstance(entry, dict)
                and entry.get("code") == 3
                and isinstance(results[index], dict)
                and not results[index]
            ):
                continue
            return "unknown"
        if (
            not isinstance(write, dict)
            or not {"update", "currentDocument"}
            <= set(write)
            <= {"update", "currentDocument", "updateMask", "updateTransforms"}
            or not isinstance(write["update"], dict)
            or not isinstance(write["update"].get("name"), str)
            or not isinstance(write["currentDocument"], dict)
            or set(write["currentDocument"]) != {"exists"}
            or write["currentDocument"]["exists"] is not False
        ):
            return "unknown"
        creates += 1
        if batch:
            entry = statuses[index]
            if not isinstance(entry, dict) or type(entry.get("code", 0)) is not int:
                return "unknown"
            code = entry.get("code", 0)
            if code in {3, 6}:
                # A refusal cannot also acknowledge a successful write. Only
                # the empty typed result slot settles this narrow contract.
                if not isinstance(results[index], dict) or results[index]:
                    return "unknown"
                continue
            if code != 0:
                return "unknown"
        name = write["update"]["name"]
        if name not in outstanding:
            return "unknown"
        outstanding.remove(name)
    if outstanding or not creates:
        return "unknown"
    return "created" if proofs else "refused"


def _management_receipt_valid(result, slot_id):
    """Accept bounded evidence only; raw tokeninfo is never an admissible body."""
    if not isinstance(result, dict) or set(result) != {
        "status",
        "complete",
        "workerReaped",
        "bodyKind",
        "body",
    }:
        return False
    try:
        if len(json.dumps(result, allow_nan=False).encode()) > 256 * 1024:
            return False
    except (ValueError, TypeError):
        return False
    status = result["status"]
    if (
        type(result["complete"]) is not bool
        or type(result["workerReaped"]) is not bool
        or result["bodyKind"] not in ("json", "non-json", "empty", None)
    ):
        return False
    if status is None:
        # No HTTP status at all is admissible only as a reaped, incomplete
        # failure; it is charged and stops the campaign, never validated.
        if result["complete"] is not False or result["workerReaped"] is not True:
            return False
    elif type(status) is not int or not 100 <= status <= 599:
        return False
    if slot_id != "oauth-tokeninfo":
        return True
    body = result["body"]
    if body is None:
        return result["complete"] is False
    if not isinstance(body, dict) or set(body) != {
        "kind",
        "principalDigest",
        "requiredScopeVerified",
        "identityMode",
        "identityVerified",
        "oauthClientVerified",
        "expiresInSeconds",
        "remainingSecondsAtVerification",
        "requiredSeconds",
        "complete",
        "workerReaped",
    }:
        return False
    return (
        body["kind"] == "request-byte-token-attestation-v1"
        and isinstance(body["principalDigest"], str)
        and re.fullmatch(r"[a-f0-9]{64}", body["principalDigest"]) is not None
        and body["identityMode"] in ("subject", "verified-email")
        and all(
            body[key] is True
            for key in (
                "requiredScopeVerified",
                "identityVerified",
                "oauthClientVerified",
                "complete",
                "workerReaped",
            )
        )
        and type(body["expiresInSeconds"]) is int
        and 2 <= body["expiresInSeconds"] <= 3600
        and all(
            type(body[key]) in (int, float)
            and math.isfinite(body[key])
            and body[key] > 0
            for key in ("remainingSecondsAtVerification", "requiredSeconds")
        )
        and body["remainingSecondsAtVerification"] >= body["requiredSeconds"]
    )


def _management_journal_digest(state):
    return digest(
        {
            "events": state.get("events", []),
            "jobs": state.get("jobs", {}),
            "coordinatorDone": state.get("coordinatorDone"),
        }
    )


def _management_derived_pre_values(state, marker):
    prefix_length = len(marker["prefix"])
    recovery_count = len(state.get("managementUsed", [])) - prefix_length
    prefix_events = state.get("managementEvents", [])[:prefix_length]
    if not prefix_events or "started" not in prefix_events[-1]:
        raise ValueError("forged management abort marker")
    cost = state["plan"]["requestCostMicrousd"]
    return {
        "total": state["total"] - recovery_count,
        "observation": state["observation"],
        "recovery": state["recovery"] - recovery_count,
        "costMicrousd": state["costMicrousd"] - recovery_count * cost,
        "reservedRecovery": state["reservedRecovery"] + recovery_count,
        "lastSent": prefix_events[-1]["started"],
        "coordinatorInflight": False,
    }


def _management_abort_projection(state, marker, *, skipped):
    projection = dict(state)
    prefix = marker["prefix"]
    projection["managementUsed"] = list(prefix)
    projection["managementEvents"] = list(
        state.get("managementEvents", [])[: len(prefix)]
    )
    values = _management_derived_pre_values(state, marker)
    for key, value in values.items():
        projection[key] = value
    projection["managementSkipped"] = list(marker["skipped"] if skipped else [])
    projection["managementAbort"] = None
    return projection


def _management_cancel_prefix_valid(state, *, prefix_len=None):
    """Require the closed limits lifecycle apply and its registered suffix."""
    observation = state["plan"].get("management", {}).get("observation", [])
    identities = ["observation:" + entry.get("id", "") for entry in observation]
    apply_id = "observation:index-lifecycle-apply"
    apply_indexes = [
        index for index, identity in enumerate(identities) if identity == apply_id
    ]
    used = state.get("managementUsed", [])
    if prefix_len is not None:
        used = used[:prefix_len]
    if len(apply_indexes) != 1:
        return False
    apply_index = apply_indexes[0]
    if len(used) <= apply_index:
        return False
    if used[apply_index] != apply_id:
        return False
    # A collector may fail after the complete limits preflight, whose final
    # metadata checks follow the index lifecycle. Only the fully settled,
    # source-declared sequence can take this branch; partial cancellation
    # retains the original lifecycle-only suffix rule below.
    events = state.get("managementEvents", [])[:len(used)]
    if (
        used == identities
        and len(events) == len(used)
        and identities == [
            "observation:" + slot for slot in (
                "oauth-tokeninfo", "project", "database",
                "index-lifecycle-before", "index-lifecycle-apply",
                "index-lifecycle-poll", "index-lifecycle-after",
                "index-exemption", "auth",
            )
        ]
        and [event.get("id") for event in events] == identities
        and all(
            event.get("completed") is True
            and event.get("workerReaped") is True
            and type(event.get("status")) is int
            and 200 <= event["status"] < 300
            for event in events
        )
    ):
        return True
    lifecycle_ids = {
        apply_id,
        "observation:index-lifecycle-poll",
        "observation:index-lifecycle-after",
    }
    return all(
        identity in lifecycle_ids
        for identity in used[apply_index:]
    )


def _management_cancel_events_valid(state, *, prefix_len=None):
    """Allow a completed prefix and one reaped unknown terminal lifecycle slot."""
    events = state.get("managementEvents", [])
    if prefix_len is not None:
        events = events[:prefix_len]
    if not events:
        return False
    terminal = events[-1]
    if all(
        event.get("completed") is True and event.get("workerReaped") is True
        for event in events
    ):
        return True
    return (
        terminal.get("id")
        in {
            "observation:index-lifecycle-poll",
            "observation:index-lifecycle-after",
        }
        and terminal.get("completed") is False
        and terminal.get("workerReaped") is True
        and all(
            event.get("completed") is True and event.get("workerReaped") is True
            for event in events[:-1]
        )
    )


def _validate_management_abort_marker(state):
    marker = state.get("managementAbort")
    if marker is None:
        return
    required = {
        "version",
        "planDigest",
        "nonceDigest",
        "prefix",
        "prefixDigest",
        "prefixEventsDigest",
        "journalDigest",
        "preGateDigest",
        "preValues",
        "skipped",
        "coordinatorPid",
        "applyOutcome",
        "recoveryPrerequisite",
        "postGateDigest",
    }
    if not isinstance(marker, dict) or set(marker) != required:
        raise ValueError("forged management abort marker")
    if state.get("coordinatorPid") != marker["coordinatorPid"]:
        raise ValueError("management abort coordinator ownership mismatch")
    prefix = marker["prefix"]
    skipped = marker["skipped"]
    if (
        not isinstance(prefix, list)
        or not isinstance(skipped, list)
        or not isinstance(marker["preValues"], dict)
        or set(marker["preValues"]) != {
            "total",
            "observation",
            "recovery",
            "costMicrousd",
            "reservedRecovery",
            "lastSent",
            "coordinatorInflight",
        }
    ):
        raise ValueError("forged management abort marker")
    values = _management_derived_pre_values(state, marker)
    if (
        marker["version"] != 2
        or marker["planDigest"] != state["planDigest"]
        or marker["nonceDigest"] != digest(state["plan"].get("nonce"))
        or marker["prefixDigest"] != digest(prefix)
        or marker["journalDigest"] != _management_journal_digest(state)
        or marker["applyOutcome"] not in ("may-have-landed", "coordinator-cancelled")
        or marker["recoveryPrerequisite"] is not True
        or marker["preValues"] != values
        or marker["prefixEventsDigest"]
        != digest(state.get("managementEvents", [])[: len(prefix)])
    ):
        raise ValueError("forged management abort marker")
    if digest(_management_abort_projection(state, marker, skipped=False)) != marker[
        "preGateDigest"
    ]:
        raise ValueError("forged management abort marker")
    post_projection = _management_abort_projection(state, marker, skipped=True)
    if digest(post_projection) != marker["postGateDigest"]:
        raise ValueError("forged management abort marker")

    management = state["plan"].get("management", {})
    declared = [
        (phase, entry)
        for phase in PHASES
        for entry in management.get(phase, [])
    ]
    identities = [phase + ":" + entry["id"] for phase, entry in declared]
    observation_ids = [identity for identity in identities if identity.startswith("observation:")]
    skipped_ids = [entry.get("id") for entry in skipped]
    used = state.get("managementUsed", [])
    prefix_len = len(prefix)
    recovery_used = used[prefix_len:]
    consumed = prefix + skipped_ids + recovery_used
    if (
        prefix != identities[:prefix_len]
        or consumed != identities[: len(consumed)]
        or [event.get("id") for event in state.get("managementEvents", [])]
        != used
        or skipped_ids != observation_ids[prefix_len:]
        or any(
            entry.get("phase") != "observation"
            or entry.get("reason") != MANAGEMENT_SKIP_REASON
            for entry in skipped
        )
        or state.get("coordinatorInflight") is not False
        or state["total"] != values["total"] + len(recovery_used)
        or state["observation"] != values["observation"]
        or state["recovery"] != values["recovery"] + len(recovery_used)
        or state["costMicrousd"]
        != values["costMicrousd"]
        + len(recovery_used) * state["plan"]["requestCostMicrousd"]
        or state["reservedRecovery"]
        != values["reservedRecovery"] - len(recovery_used)
        or (
            marker["applyOutcome"] == "may-have-landed"
            and any(
                event.get("completed") is not True
                or event.get("workerReaped") is not True
                for event in state.get("managementEvents", [])[prefix_len:]
            )
        )
        or (
            marker["applyOutcome"] == "coordinator-cancelled"
            and not _management_cancel_events_valid(
                state, prefix_len=prefix_len
            )
        )
        or (
            marker["applyOutcome"] == "coordinator-cancelled"
            and not _management_cancel_prefix_valid(
                state, prefix_len=prefix_len
            )
        )
        or (
            marker["applyOutcome"] == "coordinator-cancelled"
            and any(
                event.get("completed") is not True
                or event.get("workerReaped") is not True
                for event in state.get("managementEvents", [])[prefix_len:]
            )
        )
    ):
        raise ValueError("forged management abort marker")


class Gate:
    def __init__(self, path, job):
        self.path, self.job = Path(path), job
        self.plan_digest = self.snapshot()["planDigest"]

    @contextlib.contextmanager
    def locked(self):
        # Never recreate missing state/lock: no unmanaged fallback or reset.
        if self.path.stat().st_mode & 0o077 or any(
            (self.path / name).is_symlink() for name in ("lock", "state.json")
        ):
            raise ValueError("private regular gate files required")
        with (self.path / "lock").open("r+") as stream:
            wait_until = time.monotonic() + 15
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= wait_until:
                        raise ValueError("gate lock deadline") from None
                    time.sleep(0.01)
            state = json.loads((self.path / "state.json").read_bytes())
            if digest(state["plan"]) != state["planDigest"] or state[
                "planDigest"
            ] != getattr(self, "plan_digest", state["planDigest"]):
                raise ValueError("shared plan changed")
            if _rules_management(state["plan"]):
                _validate_rules_state(state, terminal=any(job["complete"] for job in state["jobs"].values()))
            yield state

    def snapshot(self):
        with self.locked() as state:
            return state

    def rules_management_ownership(self):
        """Return an immutable replay projection, never caller-owned authority."""
        state = self.snapshot()
        if not _rules_management(state["plan"]):
            raise ValueError("canonical Rules management plan required")

        def freeze(value):
            if isinstance(value, dict):
                return types.MappingProxyType(
                    {key: freeze(item) for key, item in value.items()}
                )
            if isinstance(value, list):
                return tuple(freeze(item) for item in value)
            return value

        return freeze(_rules_subject_states(state))

    def coordinator_call(self, index, send):
        """Two prepaid local ownership-control calls, before worker claims."""
        with self.locked() as state:
            if (
                state.get("noDataAbort") is not None
                or state["coordinatorPid"] != os.getpid()
                or state["coordinatorInflight"]
                or index != state["coordinatorDone"]
                or index >= state["plan"].get("coordinatorRequests", 0)
                or any(job["pid"] is not None for job in state["jobs"].values())
            ):
                raise ValueError("coordinator admission")
            delay = max(
                0,
                state["lastSent"] + state["plan"]["intervalSeconds"] - time.monotonic(),
            )
            time.sleep(delay)
            if (
                time.monotonic() + REQUEST_SECONDS
                > state["started"]
                + state["plan"]["wallSeconds"]
                - state["plan"]["recoverySeconds"]
            ):
                raise ValueError("coordinator deadline")
            state["coordinatorInflight"] = True
            _save(self.path, state)
            try:
                result = send()
            except BaseException:
                state["stopped"] = True
                _save(self.path, state)
                raise
            state["coordinatorInflight"] = False
            state["coordinatorDone"] += 1
            state["lastSent"] = time.monotonic()
            state.setdefault("coordinatorResults", []).append(
                {"index": index, "status": result[0], "ended": state["lastSent"]}
            )
            _save(self.path, state)
            return result

    def management_dispatch(self, phase, slot_id, send):
        """Debit one closed management slot before invoking its bounded transport.

        The callback is a trusted, capability-bound coordinator closure, never a
        caller assertion of a charge. It receives the absolute deadline and must
        enforce it after its own admission waits and in its transport worker.
        """
        with self.locked() as state:
            plan = state["plan"]
            management = plan.get("management", {})
            expires = plan.get("permissionExpiresAt")
            if (
                management.get("dispatchKind") != "closed-v1"
                or phase not in PHASES
                or type(expires) not in (int, float)
                or not math.isfinite(expires)
                or state["coordinatorPid"] != os.getpid()
                or state["coordinatorInflight"]
                or state.get("credentialRejected")
                or state.get("noDataAbort") is not None
                or any(job["inflight"] for job in state["jobs"].values())
                or (phase == "observation" and (state["stopped"] or state["events"]))
            ):
                raise ValueError("closed management admission")
            if state.get("managementAbort") is not None and not _rules_management(plan):
                _validate_management_abort_marker(state)
            declared = [(p, entry) for p in PHASES for entry in management.get(p, [])]
            identities = [p + ":" + entry["id"] for p, entry in declared]
            used = state["managementUsed"]
            skipped = state.get("managementSkipped", [])
            if _rules_management(plan):
                _, cursor = _rules_cursor(state)
                consumed = identities[:cursor]
            elif skipped:
                observation_count = sum(
                    identity.startswith("observation:") for identity in used
                )
                consumed = (
                    used[:observation_count]
                    + [entry.get("id") for entry in skipped]
                    + used[observation_count:]
                )
            else:
                consumed = used
            if (
                len(set(identities)) != len(identities)
                or consumed != identities[: len(consumed)]
                or len(consumed) >= len(declared)
                or (phase, slot_id)
                != (declared[len(consumed)][0], declared[len(consumed)][1]["id"])
                or (
                    phase == "recovery"
                    and state.get("managementAbort") is None
                    and any(
                        job["recovery"] != len(plan["jobs"][key]["recovery"])
                        for key, job in state["jobs"].items()
                    )
                )
            ):
                raise ValueError("closed management sequence")
            entry = declared[len(consumed)][1]
            if _rules_management(plan):
                _rules_dispatch_dependency(state, phase, entry)
            seconds = entry.get("timeout")
            if (
                type(seconds) not in (int, float)
                or not math.isfinite(seconds)
                or not 0 < seconds <= WALL_CAP_SECONDS
            ):
                raise ValueError("bounded management reservation required")
            phase_deadline = (
                state["started"]
                + plan["wallSeconds"]
                - (plan["recoverySeconds"] if phase == "observation" else 0)
            )
            delay = max(
                0, state["lastSent"] + plan["intervalSeconds"] - time.monotonic()
            )
            remaining = state["reservedRecovery"] - int(phase == "recovery")
            cost = plan["requestCostMicrousd"]
            if (
                remaining < 0
                or time.monotonic() + delay + seconds > phase_deadline
                or time.time() + delay + seconds > expires
                or (
                    phase == "observation"
                    and state[phase] >= plan["observationRequests"]
                )
                or state["costMicrousd"] + cost * (1 + remaining) > plan["costMicrousd"]
            ):
                raise ValueError("management capacity/deadline")
            time.sleep(delay)
            now = time.monotonic()
            if now + seconds > phase_deadline or time.time() + seconds > expires:
                raise ValueError("management deadline after wait")
            deadline = min(now + seconds, phase_deadline, now + expires - time.time())
            event = {
                "id": phase + ":" + slot_id,
                "started": now,
                "durationReserved": seconds,
                "deadline": deadline,
                "completed": False,
            }
            state["managementUsed"].append(event["id"])
            state["managementEvents"].append(event)
            state["total"] += 1
            state[phase] += 1
            state["costMicrousd"] += cost
            state["reservedRecovery"] = remaining
            state["lastSent"] = now
            state["coordinatorInflight"] = True
            _save(self.path, state)
            try:
                result = send(deadline)
                if not isinstance(result, dict):
                    raise TypeError("bounded management receipt required")
                status = result.get("status")
                if type(status) is int and status in (401, 403) and not (
                    _rules_management(plan) and _rules_data_slot(plan, phase, entry)
                ):
                    state["credentialRejected"] = True
                    state["stopped"] = True
                if not _management_receipt_valid(result, slot_id):
                    raise ValueError("bounded management receipt required")
                if plan.get("transport") == LIMITS_PREPARATION_TRANSPORT:
                    validate_limits_preparation_response(slot_id, result)
                if _rules_management(plan):
                    _validate_rules_receipt(plan, phase, entry, result)
                    event["rulesReceipt"] = result
                event.update(
                    {
                        "status": status,
                        "complete": result["complete"],
                        "workerReaped": result["workerReaped"],
                        "bodyKind": result.get("bodyKind"),
                        "responseDigest": digest(result),
                        "bodyDigest": digest(result.get("body")),
                        "ended": time.monotonic(),
                    }
                )
                event["completed"] = bool(
                    result["complete"]
                    and result["workerReaped"]
                    and event["ended"] <= deadline
                )
                # An unreaped worker remains an uncertain in-flight operation.
                state["coordinatorInflight"] = not result["workerReaped"]
                if not event["completed"]:
                    state["stopped"] = True
                _save(self.path, state)
                return result
            except BaseException as error:
                event["failure"] = type(error).__name__[:80]
                event["ended"] = time.monotonic()
                state["stopped"] = True
                _save(self.path, state)
                raise

    def claim(self):
        with self.locked() as state:
            job = state["jobs"][self.job]
            if (
                state.get("noDataAbort") is not None
                or job["pid"] is not None
                or job["complete"]
            ):
                raise ValueError("job already claimed; ownership retained")
            job["pid"] = os.getpid()
            _save(self.path, state)

    def skip_management_recovery(self, slot_id, *, expected_plan_digest, expected_prefix_digest):
        """Consume only the next compiled Rules dependency, without a wire debit."""
        with self.locked() as state:
            if not _rules_management(state["plan"]) or state["coordinatorPid"] != os.getpid():
                raise ValueError("Rules coordinator ownership required")
            _rules_settled(state)
            declared, count = _rules_cursor(state)
            prefix_digest = digest({"used": state["managementUsed"], "skipped": state["managementSkipped"]})
            if (expected_plan_digest != state["planDigest"] or expected_prefix_digest != prefix_digest
                    or count >= len(declared) or declared[count][:2] != ("recovery:" + slot_id, "recovery")):
                raise ValueError("Rules next recovery slot binding mismatch")
            dependency = declared[count][2]["dependency"]
            reason = _rules_skip_reason(_rules_subject_states(state)[dependency["subject"]], dependency)
            state["managementSkipped"].append({"id": "recovery:" + slot_id, "phase": "recovery",
                                               "reason": reason, "prefixDigest": prefix_digest,
                                               "eventsDigest": digest(state["managementEvents"])})
            state["reservedRecovery"] -= 1
            _validate_rules_state(state)
            _save(self.path, state)
            return state

    def hold_management_recovery(
        self,
        subject_id,
        *,
        expected_plan_digest,
        expected_prefix_digest,
        failure,
    ):
        """Record a Gate-owned held disposition before skipping its recovery suffix.

        A local identity-proof failure is not a recovery wire fact and therefore
        cannot be represented as a synthetic response.  This operation records
        that bounded disposition in the Gate journal.  The normal recovery skip
        path consumes the subject's reserved slots after the durable held state
        is replayed.
        """
        with self.locked() as state:
            if not _rules_management(state["plan"]) or state["coordinatorPid"] != os.getpid():
                raise ValueError("Rules coordinator ownership required")
            _rules_settled(state)
            declared, _count = _rules_cursor(state)
            prefix_digest = digest(
                {"used": state["managementUsed"], "skipped": state["managementSkipped"]}
            )
            if expected_plan_digest != state["planDigest"] or expected_prefix_digest != prefix_digest:
                raise ValueError("Rules recovery hold binding mismatch")
            if not isinstance(subject_id, str) or not subject_id.startswith("account/"):
                raise ValueError("Rules identity-proof hold requires an account")
            dependencies = [
                entry[2]["dependency"]
                for entry in declared
                if entry[1] == "recovery"
                and entry[2]["dependency"]["subject"] == subject_id
                and entry[2]["dependency"]["step"] == "read"
            ]
            if len(dependencies) != 1:
                raise ValueError("Rules held disposition subject is not canonical")
            read_identity = next(
                identity
                for identity, phase, slot in declared
                if phase == "recovery"
                and slot["dependency"] == dependencies[0]
            )
            used = set(state["managementUsed"])
            skipped = {item["id"] for item in state["managementSkipped"]}
            if read_identity in used or read_identity in skipped:
                raise ValueError("Rules held recovery subject already entered recovery")
            before_holds = dict(state)
            before_holds["rulesRecoveryHeld"] = {}
            current = _rules_subject_states(before_holds)[subject_id]
            if current["status"] not in {"owned", "verified"}:
                raise ValueError("Rules held disposition requires acknowledged ownership")
            if not isinstance(failure, str) or not failure or len(failure) > 80:
                raise ValueError("bounded identity proof failure required")
            held = dict(state.get("rulesRecoveryHeld", {}))
            held[subject_id] = {
                "kind": "identity-proof-unavailable-v1",
                "failure": failure,
            }
            state["rulesRecoveryHeld"] = held
            _validate_rules_state(state)
            _save(self.path, state)
            return state

    def abort_management_observation(
        self,
        *,
        expected_plan_digest=None,
        expected_nonce_digest=None,
        expected_management_prefix_digest=None,
        expected_journal_digest=None,
    ):
        """Close an OBS suffix after a reaped, unknown outcome."""
        return self._close_management_observation(
            mode="may-have-landed",
            expected_plan_digest=expected_plan_digest,
            expected_nonce_digest=expected_nonce_digest,
            expected_management_prefix_digest=expected_management_prefix_digest,
            expected_journal_digest=expected_journal_digest,
        )

    def cancel_management_observation(
        self,
        *,
        expected_plan_digest=None,
        expected_nonce_digest=None,
        expected_management_prefix_digest=None,
        expected_journal_digest=None,
    ):
        """Cancel the remaining OBS suffix after completed, reaped applies."""
        return self._close_management_observation(
            mode="coordinator-cancelled",
            expected_plan_digest=expected_plan_digest,
            expected_nonce_digest=expected_nonce_digest,
            expected_management_prefix_digest=expected_management_prefix_digest,
            expected_journal_digest=expected_journal_digest,
        )

    def _close_management_observation(
        self,
        *,
        mode,
        expected_plan_digest=None,
        expected_nonce_digest=None,
        expected_management_prefix_digest=None,
        expected_journal_digest=None,
    ):
        """Close an OBS management suffix under one typed coordinator mode.

        All authority is derived from the locked Gate journal. Optional expected
        digests are consistency checks only; they cannot assert worker exit,
        cursor state, or a no-data result.
        """
        with self.locked() as state:
            if state.get("coordinatorPid") != os.getpid():
                raise ValueError("management abort coordinator ownership mismatch")
            if _rules_management(state["plan"]):
                _rules_settled(state)
                if any(identity.startswith("recovery:") for identity in state["managementUsed"]) or any(item["phase"] == "recovery" for item in state["managementSkipped"]):
                    raise ValueError("Rules cancellation must precede recovery")
                prefix = state["managementUsed"]
                if any(value is not None and value != actual for value, actual in (
                    (expected_plan_digest, state["planDigest"]),
                    (expected_nonce_digest, digest(state["plan"]["nonce"])),
                    (expected_management_prefix_digest, digest(prefix)),
                    (expected_journal_digest, _management_journal_digest(state)),
                )):
                    raise ValueError("Rules cancellation binding mismatch")
                marker = {"version": "rules-cancel-v1", "planDigest": state["planDigest"],
                          "nonceDigest": digest(state["plan"]["nonce"]), "prefix": list(prefix),
                          "prefixEventsDigest": digest(state["managementEvents"]),
                          "coordinatorPid": state["coordinatorPid"]}
                state["managementAbort"] = marker
                state["managementSkipped"] = [{"id": "observation:" + slot["id"], "phase": "observation", "reason": MANAGEMENT_SKIP_REASON}
                                              for slot in state["plan"]["management"]["observation"][len(prefix):]]
                state["stopped"] = True
                _validate_rules_state(state)
                _save(self.path, state)
                return state
            existing = state.get("managementAbort")
            if existing is not None:
                _validate_management_abort_marker(state)
                if existing["applyOutcome"] != mode:
                    raise ValueError("management abort mode mismatch")
                if any(
                    value is not None
                    and value != existing[key]
                    for value, key in (
                        (expected_plan_digest, "planDigest"),
                        (expected_nonce_digest, "nonceDigest"),
                        (expected_management_prefix_digest, "prefixDigest"),
                        (expected_journal_digest, "journalDigest"),
                    )
                ):
                    raise ValueError("management abort binding mismatch")
                return state

            plan = state["plan"]
            management = plan.get("management", {})
            declared = [
                (phase, entry)
                for phase in PHASES
                for entry in management.get(phase, [])
            ]
            observation_declared = [
                entry for phase, entry in declared if phase == "observation"
            ]
            identities = [phase + ":" + entry["id"] for phase, entry in declared]
            used = state.get("managementUsed", [])
            events = state.get("managementEvents", [])
            prefix_digest = digest(used)
            nonce_digest = digest(plan.get("nonce"))
            journal_projection = {
                "events": state.get("events", []),
                "jobs": state.get("jobs", {}),
                "coordinatorDone": state.get("coordinatorDone"),
            }
            journal_digest = digest(journal_projection)
            if any(
                value is not None and value != expected
                for value, expected in (
                    (expected_plan_digest, state["planDigest"]),
                    (expected_nonce_digest, nonce_digest),
                    (expected_management_prefix_digest, prefix_digest),
                    (expected_journal_digest, journal_digest),
                )
            ):
                raise ValueError("management abort binding mismatch")

            if mode == "coordinator-cancelled" and not _management_cancel_prefix_valid(
                state
            ):
                raise ValueError(
                    "management cancellation requires declared apply lifecycle"
                )
            completed_prefix = _management_cancel_events_valid(state)
            if (
                management.get("dispatchKind") != "closed-v1"
                or not used
                or used != identities[: len(used)]
                or (
                    mode == "may-have-landed"
                    and len(used) >= len(observation_declared)
                )
                or any(not identity.startswith("observation:") for identity in used)
                or state.get("managementSkipped")
                or [event.get("id") for event in events] != used
                or state.get("coordinatorInflight") is not False
                or (mode == "may-have-landed" and state.get("stopped") is not True)
                or state.get("events")
                or state.get("coordinatorDone") != 0
                or state.get("observation") != len(used)
                or state.get("recovery") != 0
                or any(
                    job.get("pid") not in (None, os.getpid())
                    or any(
                        job.get(key) not in (0, None, False, {}, [])
                        for key in (
                            "observation",
                            "recovery",
                            "inflight",
                            "owned",
                            "creationProofs",
                            "absent",
                            "captures",
                            "complete",
                            "stopped",
                            "scheduleDone",
                        )
                    )
                    for job in state["jobs"].values()
                )
                or (
                    (mode == "may-have-landed")
                    and (
                        not events[-1].get("workerReaped")
                        or events[-1].get("completed") is not False
                    )
                )
                or (mode == "coordinator-cancelled" and not completed_prefix)
                or (
                    mode == "coordinator-cancelled"
                    and not _management_cancel_prefix_valid(state)
                )
            ):
                if mode == "may-have-landed":
                    raise ValueError(
                        "management abort requires reaped uncertain pre-data state"
                    )
                raise ValueError("management close requires an admissible state")

            suffix = [
                {
                    "id": identities[index],
                    "phase": "observation",
                    "index": index,
                    "reason": MANAGEMENT_SKIP_REASON,
                }
                for index in range(len(used), len(observation_declared))
            ]
            if len(suffix) != len(observation_declared) - len(used):
                raise ValueError("management abort requires an observation suffix")
            if mode == "coordinator-cancelled":
                state["stopped"] = True
            pre_gate_digest = digest(state)
            state["managementSkipped"] = suffix
            marker = {
                "version": 2,
                "planDigest": state["planDigest"],
                "nonceDigest": nonce_digest,
                "prefix": list(used),
                "prefixDigest": prefix_digest,
                "prefixEventsDigest": digest(events),
                "journalDigest": journal_digest,
                "preGateDigest": pre_gate_digest,
                "preValues": {
                    key: state[key]
                    for key in (
                        "total",
                        "observation",
                        "recovery",
                        "costMicrousd",
                        "reservedRecovery",
                        "lastSent",
                        "coordinatorInflight",
                    )
                },
                "skipped": list(suffix),
                "coordinatorPid": state["coordinatorPid"],
                "applyOutcome": mode,
                "recoveryPrerequisite": True,
            }
            state["managementAbort"] = marker
            post_projection = dict(state)
            post_projection["managementAbort"] = None
            marker["postGateDigest"] = digest(post_projection)
            _save(self.path, state)
            return state

    def skip_scheduled_slot(self, operation, recovery, reason):
        """Consume the next scheduled slot without a wire send.

        A campaign whose creating request was refused has nothing to delete, and
        its collector sends nothing for those slots by design. The Gate keeps its
        own cursor, so without this the schedule stalls behind the slot that will
        never be sent and every later request is refused as out of order.

        Admitted only when the slot itself cannot have written, when the resource
        it names has no creation proof, and when no earlier request that could
        have written is still unconfirmed. Those are facts the Gate holds, so the
        skip is checkable rather than taken on the caller's word.
        """
        if not isinstance(reason, str) or not 0 < len(reason) <= MAX_STOP_REASON:
            raise ValueError("bounded skip reason required")
        with self.locked() as state:
            job, plan = state["jobs"][self.job], state["plan"]
            phase = "recovery" if recovery else "observation"
            schedule = job_schedule(plan["jobs"][self.job])
            if (
                job["pid"] != os.getpid()
                or job["complete"]
                or job["inflight"]
                or state.get("noDataAbort") is not None
            ):
                raise ValueError("job or environment stopped/uncertain")
            if schedule is None:
                raise ValueError("a declared schedule is required to skip a slot")
            if unconfirmed_creates(state, self.job):
                # Checked before the cursor moves, so a refused skip changes
                # nothing.
                raise ValueError("an unconfirmed write is outstanding")
            index = job[phase]
            cursor = job["scheduleDone"]
            if job.get("stopReason") is not None:
                while (
                    cursor < len(schedule)
                    and schedule[cursor]["phase"] == "observation"
                ):
                    cursor += 1
                    job["skippedByStop"] += 1
                job["scheduleDone"] = cursor
            slot = schedule[cursor] if cursor < len(schedule) else None
            if (
                slot is None
                or slot["phase"] != phase
                or slot["index"] != index
                or index >= len(plan["jobs"][self.job][phase])
            ):
                raise ValueError("dispatch outside the frozen execution schedule")
            if slot.get("creates", True) is not False:
                raise ValueError("a slot that could have written cannot be skipped")
            expected = dict(plan["jobs"][self.job][phase][index])
            expected.pop("versionFrom", None)
            if digest(operation) != digest(expected):
                raise ValueError("request outside closed scenario")
            resource = _operation_resource(operation)
            if resource in job.get("creationProofs", {}):
                raise ValueError("a created resource must be cleaned, not skipped")
            job["scheduleDone"] += 1
            job[phase] += 1
            if recovery:
                state["reservedRecovery"] -= 1
            state.setdefault("skips", []).append(
                {
                    "job": self.job,
                    "index": index,
                    "reason": ZERO_WIRE_REASON,
                    "note": reason,
                }
            )
            _save(self.path, state)
            return (None, {"skipped": ZERO_WIRE_REASON})

    def abandon_observation(self, reason):
        """End this job's observation early and open its scheduled cleanup.

        With a declared schedule a dispatch is admitted only in its frozen order,
        so a job that stops part way through observation could not reach its own
        recovery slots at all: every cleanup request was refused as outside the
        schedule, and a probe that had created documents had no admissible way to
        delete them. This is the transition that says the observation is over.

        It does not weaken the cleanup rules. Recovery still runs in its declared
        order, and a resource with no creation proof is still never deleted: its
        slots become zero-wire skips rather than refusals, so the ones that can
        be cleaned are still reachable behind them.
        """
        if not isinstance(reason, str) or not 0 < len(reason) <= MAX_STOP_REASON:
            raise ValueError("bounded stop reason required")
        with self.locked() as state:
            job = state["jobs"][self.job]
            if state.get("noDataAbort") is not None or job["complete"]:
                raise ValueError("terminal Gate abort")
            if job_schedule(state["plan"]["jobs"][self.job]) is None:
                raise ValueError("a declared schedule is required to abandon")
            if job.get("stopReason") is not None:
                raise ValueError("observation already abandoned")
            if job["inflight"]:
                raise ValueError("in-flight request; ownership retained")
            job["stopReason"] = reason
            job["stopped"] = True
            _save(self.path, state)

    def stop(self, *, environment=False):
        with self.locked() as state:
            if state.get("noDataAbort") is not None:
                raise ValueError("terminal Gate abort")
            state["jobs"][self.job]["stopped"] = True
            if environment:
                state["stopped"] = True
            _save(self.path, state)

    def _validate_cleanup_ownership(self, operation, recovery, resource, source, job):
        """Validate the immutable creation proof for a conditional cleanup."""
        proof = job.get("creationProofs", {}).get(resource)
        capture = job["captures"].get(str(source), {})
        if (
            not recovery
            or proof is None
            or capture.get("name") != resource
            or capture.get("fieldsDigest") != proof["fieldsDigest"]
            or operation["path"]
            != "/v1/"
            + resource
            + "?currentDocument.updateTime="
            + quote(proof["updateTime"], safe="")
        ):
            raise ValueError("cleanup requires journaled creation ownership/version")

    def _record_response(self, state, operation, recovery, event, status, body):
        """Extension point for a closed local facade; called under the journal lock.

        The default adds no authority. A facade must validate its own frozen
        contract before settling an otherwise unknown creation acknowledgement.
        """

    def _allow_observation_auth_delete(self, state, job, operation, index):
        """Closed extension point; the base Gate never permits Auth observation deletes."""
        return False

    def _validate_finish_evidence(self, state):
        """Validate protocol-specific terminal evidence while the lock is held."""
        if _stream_policy(state["plan"]):
            validate_absence_proofs(state, self.job)

    def _recovery_capture(self, operation, status, body):
        """Return the bounded default recovery read receipt."""
        return {
            "status": status,
            "name": body.get("name") if isinstance(body, dict) else None,
            "fieldsDigest": digest(body.get("fields"))
            if isinstance(body, dict)
            else None,
            "updateTime": body.get("updateTime") if isinstance(body, dict) else None,
        }

    def dispatch(self, operation, recovery, send):
        with self.locked() as state:
            job, plan = state["jobs"][self.job], state["plan"]
            phase = "recovery" if recovery else "observation"
            if (
                job["pid"] != os.getpid()
                or job["complete"]
                or state["coordinatorInflight"]
                or state.get("credentialRejected")
                or state["coordinatorDone"] != plan.get("coordinatorRequests", 0)
                or any(j["inflight"] for j in state["jobs"].values())
                or state.get("noDataAbort") is not None
                or (not recovery and (job["stopped"] or state["stopped"]))
            ):
                raise ValueError("job or environment stopped/uncertain")
            management = plan.get("management", {})
            if management.get("dispatchKind") == "closed-v1":
                expected_management = [
                    "observation:" + entry["id"]
                    for entry in management.get("observation", [])
                ]
                events = state["managementEvents"][: len(expected_management)]
                if (
                    state["managementUsed"][: len(expected_management)]
                    != expected_management
                    or len(events) != len(expected_management)
                    or any(
                        event.get("completed") is not True
                        or type(event.get("status")) is not int
                        or not 200 <= event["status"] < 300
                        for event in events
                    )
                    or any(
                        identity.startswith("recovery:")
                        for identity in state["managementUsed"]
                    )
                ):
                    raise ValueError(
                        "closed management preflight incomplete or postflight begun"
                    )
            operations = plan["jobs"][self.job][phase]
            index = job[phase]
            if index >= len(operations):
                raise ValueError("scenario request capacity")
            schedule = job_schedule(plan["jobs"][self.job])
            if schedule is not None:
                cursor = job["scheduleDone"]
                if job.get("stopReason") is not None:
                    # The abandoned observation slots are consumed without a wire
                    # call, so the cleanup behind them becomes reachable.
                    while (
                        cursor < len(schedule)
                        and schedule[cursor]["phase"] == "observation"
                    ):
                        cursor += 1
                        job["skippedByStop"] += 1
                    job["scheduleDone"] = cursor
                slot = schedule[cursor] if cursor < len(schedule) else None
                if slot is None or slot["phase"] != phase or slot["index"] != index:
                    raise ValueError("dispatch outside the frozen execution schedule")
            policy = _stream_policy(plan)
            seconds = request_seconds(plan, policy)
            if schedule is not None:
                seconds = slot_seconds(slot, seconds)
            if policy:
                expected, resource, skip = policy.resolve(state, self.job, recovery)
                source = "stream-guard" if skip else None
                valid_version = False
                if digest(operation) != digest(expected):
                    raise ValueError("request outside closed stream scenario")
            else:
                expected = dict(operations[index])
                source = resolve_version_source(
                    operations, index, expected.pop("versionFrom", None)
                )
                reference = expected.pop("bodyRef", None)
                if reference is not None:
                    # Verify the buffer that was handed in, and let the caller
                    # send that same object: the Gate never re-reads a body from
                    # a path, so there is exactly one copy of these bytes.
                    encoded = canonical_body_bytes(operation.get("body"))
                    if (
                        len(encoded) != reference["bytes"]
                        or hashlib.sha256(encoded).hexdigest() != reference["sha256"]
                    ):
                        raise ValueError(
                            "request body differs from its frozen reference"
                        )
                    expected["body"] = operation.get("body")
                valid_version = False
                if source is not None:
                    capture = job["captures"].get(str(source))
                    valid_version = bool(
                        capture
                        and type(capture["status"]) is int
                        and capture["status"] == 200
                        and isinstance(capture.get("updateTime"), str)
                        and capture["updateTime"]
                    )
                    if valid_version:
                        version = capture.get("updateTime")
                        expected["path"] += "?currentDocument.updateTime=" + quote(
                            version, safe=""
                        )
                if digest(operation) != digest(expected):
                    raise ValueError("request outside closed scenario")
                resource = _operation_resource(operation)
                if recovery and resource not in job["resources"]:
                    raise ValueError("cleanup target outside assigned resources")
                if (
                    _auth_operation(operation)
                    and operation.get("method") == "POST"
                    and operation.get("path", "").endswith("/accounts:delete")
                    and not recovery
                    and not self._allow_observation_auth_delete(state, job, operation, index)
                ):
                    raise ValueError("destructive Auth delete is recovery-only")
                if (
                    recovery
                    and _auth_operation(operation)
                    and operation.get("method") == "POST"
                    and operation["path"].endswith("/accounts:delete")
                    and not _auth_creation_ownership(state, job, operation)
                ):
                    raise ValueError("Auth delete requires creation ownership")
                if operation["method"] == "DELETE" and (
                    source is None or valid_version
                ):
                    self._validate_cleanup_ownership(
                        operation, recovery, resource, source, job
                    )
            skip_reason = None
            if (
                recovery
                and schedule is not None
                and not unconfirmed_creates(state, self.job)
                and resource not in job.get("creationProofs", {})
            ):
                outcome = creating_outcome(state, self.job)
                if job.get("stopReason") is not None and outcome != "unsettled":
                    # The run is over, so no slot of an uncreated resource is
                    # worth a request.
                    skip_reason = (
                        NEVER_DISPATCHED_REASON
                        if outcome == "none"
                        else REFUSED_CREATE_REASON
                    )
                elif outcome == "refused" and source is not None:
                    # The normal path: the create was refused, so this delete has
                    # no version to bind and nothing to remove. The readbacks
                    # around it still run, because absence is what they prove.
                    skip_reason = REFUSED_CREATE_REASON
            if skip_reason is not None:
                # Nothing was created here, so there is nothing to clean and no
                # request to spend; the slot is consumed so the next one is
                # reachable.
                # `skippedByStop` counts only the observation slots the stop
                # passed over; a skipped recovery slot is already counted in
                # `job["recovery"]`, so counting it twice would break the
                # cursor invariant the no-data contract checks.
                job["scheduleDone"] += 1
                job[phase] += 1
                state["reservedRecovery"] -= 1
                state.setdefault("skips", []).append(
                    {"job": self.job, "index": index, "reason": skip_reason}
                )
                _save(self.path, state)
                return (None, {"skipped": skip_reason})
            if recovery and schedule is None:
                # Without a declared schedule, recovery is a one-way transition.
                # A scheduled campaign returns to observation by its own order,
                # which the cursor above is what admits.
                job["stopped"] = True
            if source is not None and not valid_version:
                job[phase] += 1
                if schedule is not None:
                    job["scheduleDone"] += 1
                state["reservedRecovery"] -= 1
                state.setdefault("skips", []).append(
                    {
                        "job": self.job,
                        "index": index,
                        "reason": "absent-or-unavailable-cleanup-read",
                    }
                )
                _save(self.path, state)
                return (
                    {"skipped": skip}
                    if policy
                    else (None, {"skipped": "absent-or-unavailable-cleanup-read"})
                )
            now = time.monotonic()
            delay = max(0, state["lastSent"] + plan["intervalSeconds"] - now)
            deadline = (
                state["started"]
                + plan["wallSeconds"]
                - (0 if recovery else plan["recoverySeconds"])
            )
            cost = plan["requestCostMicrousd"]
            remaining = state["reservedRecovery"] - (1 if recovery else 0)
            if (
                now + delay + seconds > deadline
                or (
                    not recovery and state["observation"] >= plan["observationRequests"]
                )
                or state["costMicrousd"] + cost * (1 + remaining) > plan["costMicrousd"]
            ):
                raise ValueError("global phase/time/cost capacity")
            time.sleep(delay)
            if time.monotonic() + seconds > deadline:
                raise ValueError("deadline after rate wait")
            if policy:
                policy.debit(state, job, operation)
            state["lastSent"] = time.monotonic()
            state["total"] += 1
            state[phase] += 1
            state["reservedRecovery"] = remaining
            state["costMicrousd"] += cost
            job[phase] += 1
            if schedule is not None:
                job["scheduleDone"] += 1
            if recovery and resource in job["absent"] and not (
                _auth_operation(operation)
                and isinstance(operation.get("body"), dict)
                and "email" in operation["body"]
            ):
                job["absent"].remove(resource)
            if recovery and not (
                _auth_operation(operation)
                and isinstance(operation.get("body"), dict)
                and "email" in operation["body"]
            ):
                job.setdefault("absenceProofs", {}).pop(resource, None)
            job["inflight"] = True
            event = {
                "job": self.job,
                "phase": phase,
                "index": index,
                "started": state["lastSent"],
                "requestDigest": digest(operation),
                "service": operation["service"],
                "method": operation["method"],
                "completed": False,
            }
            if not recovery and index in (creating_slots(plan, self.job) or ()):
                # Keep this pending until the response body has been checked.
                # A complete HTTP response alone does not settle a conditional
                # create: the server may have applied it before a 5xx or a
                # malformed acknowledgement was returned.
                event["creationOutcome"] = "pending"
            state["events"].append(event)
            _save(
                self.path, state
            )  # crash spends capacity and retains uncertain ownership
            try:
                result = send()
            except Exception as error:
                job["stopped"] = True
                event["failure"] = type(error).__name__
                raise
            else:
                if policy:
                    policy.record(state, self.job, operation, result, event)
                    return result
                status, body = result
                event.update(status=status, responseDigest=digest(body), completed=True)
                if type(status) is not int:
                    if not recovery and "creationOutcome" in event:
                        event["creationOutcome"] = "unknown"
                    job["stopped"] = True
                    raise ValueError("typed HTTP status required")
                if not recovery:
                    try:
                        proofs = _creation_proofs(operation, status, body, job, plan)
                    except ValueError:
                        if "creationOutcome" in event:
                            event["creationOutcome"] = "unknown"
                        job["stopped"] = True
                        raise
                    if "creationOutcome" in event:
                        event["creationOutcome"] = _creation_outcome(
                            operation, status, body, proofs
                        )
                    for proof in proofs:
                        # Never replace a creation version with a later read or write.
                        job["creationProofs"].setdefault(proof["name"], proof)
                        if proof["name"] not in job["owned"]:
                            job["owned"].append(proof["name"])
                if operation["method"] == "GET" and resource in job["resources"]:
                    if status == 404:
                        if not typed_absence(status, body):
                            job["stopped"] = True
                            raise ValueError("typed Firestore absence required")
                        if recovery:
                            if resource not in job["absent"]:
                                job["absent"].append(resource)
                            job.setdefault("absenceProofs", {})[resource] = {
                                "eventIndex": len(state["events"]) - 1,
                                "body": body,
                            }
                    elif status == 200 and (
                        not isinstance(body, dict)
                        or "error" in body
                        or body.get("name") != resource
                        or not isinstance(body.get("fields"), dict)
                    ):
                        job["stopped"] = True
                        raise ValueError("readback identity/body mismatch")
                if (
                    recovery
                    and _auth_operation(operation)
                    and resource in job["resources"]
                    and operation["path"].endswith("/accounts:lookup")
                    and _auth_uid_absence_operation_valid(operation, plan.get("project"))
                ):
                    if auth_typed_absence(status, body):
                        if resource not in job["absent"]:
                            job["absent"].append(resource)
                        job.setdefault("absenceProofs", {})[resource] = {
                            "eventIndex": len(state["events"]) - 1,
                            "body": body,
                        }
                    elif status == 200:
                        job["stopped"] = True
                        raise ValueError("typed Auth absence required")
                self._record_response(state, operation, recovery, event, status, body)
                if recovery:
                    job["captures"][str(index)] = self._recovery_capture(
                        operation, status, body
                    )
                return result
            finally:
                # Normal exception paths have returned from bounded transport. A killed
                # process never reaches here: its marker blocks every successor dispatch.
                interruption = sys.exc_info()[0]
                job["inflight"] = interruption is not None and (
                    policy is not None or not issubclass(interruption, Exception)
                )
                event["ended"] = time.monotonic()
                state["lastSent"] = event["ended"]
                _save(self.path, state)

    def finish(self):
        with self.locked() as state:
            if _rules_management(state["plan"]):
                _validate_rules_state(state, terminal=True)
                job = state["jobs"][self.job]
                if job["pid"] != os.getpid() or job["inflight"]:
                    raise ValueError("Rules finish worker ownership mismatch")
                job["complete"] = True
                _save(self.path, state)
                return
            if state["plan"].get("transport") == LIMITS_PREPARATION_TRANSPORT:
                validate_limits_preparation_success(state)
            job = state["jobs"][self.job]
            if (
                state.get("noDataAbort") is not None
                or state.get("managementAbort") is not None
                or job["pid"] != os.getpid()
                or job["inflight"]
                or unconfirmed_creates(state, self.job)
                or job["recovery"] != len(state["plan"]["jobs"][self.job]["recovery"])
                or set(job["absent"]) != set(job["resources"])
            ):
                raise ValueError("cleanup incomplete; ownership retained")
            self._validate_finish_evidence(state)
            job["complete"] = True
            _save(self.path, state)

    def abort_no_data(self, plan_digest, pre_gate_digest, record_digest):
        """Stop all Gate paths after a bound, empty data journal is verified."""
        with self.locked() as state:
            existing = state.get("noDataAbort")
            if existing is not None:
                if existing != {
                    "preGateDigest": pre_gate_digest,
                    "recordDigest": record_digest,
                }:
                    raise ValueError("different Gate abort proof")
                return state
            if digest(state) != pre_gate_digest or state["planDigest"] != plan_digest:
                raise ValueError("Gate abort snapshot changed")
            dispatched = non_creating_dispatches(state)
            if (
                state["coordinatorInflight"] is not False
                or dispatched is None
                or len(state["events"]) != dispatched
                or any(
                    skip.get("reason") not in GATE_SKIP_REASONS
                    for skip in state.get("skips", [])
                )
                or state.get("managementUsed")
                != [
                    "observation:" + operation["id"]
                    for operation in state["plan"]
                    .get("management", {})
                    .get("observation", [])
                ][: len(state.get("managementUsed", []))]
                or [event.get("id") for event in state.get("managementEvents", [])]
                != state.get("managementUsed", [])
                or state["total"] != len(state.get("managementUsed", [])) + dispatched
                or state["observation"] != state["total"]
                or state["observation"] > state["plan"]["observationRequests"]
                or state["costMicrousd"]
                != state["plan"].get("fixedCostMicrousd", 0)
                + state["total"] * state["plan"]["requestCostMicrousd"]
                or state["recovery"] != 0
                or state["coordinatorDone"] != 0
                or any(
                    type(job[key]) is not int
                    for job in state["jobs"].values()
                    for key in ("observation", "recovery")
                )
                or any(
                    job.get("scheduleDone", 0)
                    != job["observation"]
                    + job["recovery"]
                    + job.get("skippedByStop", 0)
                    for job in state["jobs"].values()
                )
                or any(
                    job["inflight"] is not False
                    or job["owned"] != []
                    or job["creationProofs"] != {}
                    or job["absent"] != []
                    or job["captures"] != {}
                    or job["complete"] is not False
                    for job in state["jobs"].values()
                )
            ):
                raise ValueError("positive or uncertain data Gate evidence")
            pids = [
                state["coordinatorPid"],
                *[job["pid"] for job in state["jobs"].values()],
            ]
            for pid in pids:
                if type(pid) is not int or pid <= 0:
                    raise ValueError("recorded worker identity required")
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                raise ValueError("worker exit not proven")
            state["stopped"] = True
            for job in state["jobs"].values():
                job["stopped"] = True
            state["noDataAbort"] = {
                "preGateDigest": pre_gate_digest,
                "recordDigest": record_digest,
            }
            _save(self.path, state)
            return state

    def adapter_request(self, adapter, operation, send):
        if not adapter.local:
            raise ValueError("shared gate is local-only; production permission absent")

        plan = self.snapshot()["plan"]
        from batch_adapter import observer_digest

        if (
            adapter.local != plan.get("localOrigins")
            or adapter.nonce != plan.get("nonce")
            or observer_digest() != plan.get("observerSha256")
        ):
            raise ValueError("adapter origin/nonce/observer binding mismatch")

        def admitted():
            adapter._shared_dispatch = True
            try:
                return send()
            finally:
                adapter._shared_dispatch = False

        return self.dispatch(operation, adapter.budget.recovery, admitted)
