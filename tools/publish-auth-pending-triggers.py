"""Validate and publish a redacted production-only receipt for one AUTH-U04 trigger.

Each trigger is its own slice, receipt, page and (later) approval. The observation was
recorded with the recorder at one commit and re-evaluated with the contract at
publication; both are named and never conflated. Only allowlisted fields are projected.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-pending-triggers"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from triggers_contract import (
    CASES,
    DIAGNOSTIC,
    TRIGGERS,
    classified,
    complete,
    corpus,
    require,
    validate_row,
)
from triggers_recorder import digest

EVID = ROOT / "spec/compatibility/evidence"
TRIGGER_TRANSITION = {
    "client-password-change": "the account's own session accounts:update sets a new password",
    "admin-password-update": "a privileged accounts:update sets a new password",
    "password-reset": "an admin PASSWORD_RESET OOB link is issued and resetPassword sets a new password",
    "provider-unlink": "a federated identity linked administratively before the held credential is removed by the session accounts:update deleteProvider",
}
RECORDER_FILES = (
    "tools/auth-pending-triggers/triggers_contract.py",
    "tools/auth-pending-triggers/triggers_recorder.py",
    "tools/auth-pending-revocation/revocation_recorder.py",
    "tools/auth-password-maximum/maximum_contract.py",
    "tools/auth-password-maximum/maximum_recorder.py",
)
PROJECTED = (
    "target",
    "recordedAt",
    "probeSourceCommit",
    "committedCheckout",
    "trigger",
    "cases",
    "setup",
    "providerLinked",
    "cleanup",
    "configRestored",
    "configRestoredReadback",
    "configDigestMatches",
)
CONFIGURATION_KEYS = (
    "sha256",
    "emailEnabled",
    "passwordRequired",
    "improvedEmailPrivacy",
    "blockingTriggersAbsent",
    "adminPasswordPolicyAbsent",
)
RESTORED_KEYS = ("mfa", "phoneNumber", "smsRegionConfig")


def scope(trigger):
    return (
        f"Seven sequential REST observations in production only for the {trigger} trigger: a "
        "fresh phone MFA completion (control) whose session is reused; a pending credential "
        "and SMS session are held; then, as the one transition, "
        f"{TRIGGER_TRANSITION[trigger]}; the held credential is presented to mfaSignIn:start "
        "and :finalize on the session opened before the transition, with lookup and refresh "
        "of any returned tokens; a fresh completion (control) closes the run. Phone MFA with "
        "one test phone number, no tenant, no blocking function, one run. For provider-unlink "
        "the federated identity is linked administratively as a precondition before the held "
        "credential (a refused link aborts the run). The oracle configuration was changed for "
        "the run and restored with a digest comparison. Admin is used for owned account setup, "
        "readback and cleanup. No human approval, no local artifact comparison, and no claim "
        "about other triggers, tenants, SDK or Rules; the held rows are the observation, not a "
        "rule about revocation."
    )


def bundle(trigger):
    return EVID / f"auth-pending-trigger-{trigger}/receipt.json"


def review_path(trigger):
    return EVID / f"auth-pending-trigger-{trigger}/source-review.json"


def page_path(trigger):
    return ROOT / f"docs/compatibility/auth-pending-trigger-{trigger}.md"


def hex_value(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    )


def publication_contract_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def working_tree_sha256(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def exact_keys(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys))
    return {key: value[key] for key in keys}


def git_blob_sha256(commit, path):
    blob = subprocess.check_output(
        ["git", "show", f"{commit}:{path}"], cwd=ROOT, stderr=subprocess.DEVNULL
    )
    return hashlib.sha256(blob).hexdigest()


def recorded_with(report, recorder_commit):
    hex_value(report["probeSourceCommit"], 40)
    hex_value(recorder_commit, 40)
    inputs = {path: report["probeInputs"][path] for path in RECORDER_FILES}
    for path, value in inputs.items():
        hex_value(value)
        require(git_blob_sha256(recorder_commit, path) == value)
    return {
        "probeSourceCommit": report["probeSourceCommit"],
        "recorderCommit": recorder_commit,
        "recorderInputs": inputs,
    }


def reevaluated_with():
    return {
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "contractSha256": working_tree_sha256(RECORDER_FILES[0]),
    }


def project(report, trigger, recorder_commit):
    require(
        type(report["schemaVersion"]) is int
        and report["schemaVersion"] == 1
        and report["acceptance"] == "candidate"
        and report["target"] == "production"
        and report["trigger"] == trigger
        and report["project"] == "fireemu-35fe6"
        and report["projectNumber"] == "592603257417"
        and digest(report["corpus"]) == digest(corpus(trigger))
        and complete(report)
    )
    out = {key: report[key] for key in PROJECTED}
    out["configRestoredReadback"] = exact_keys(
        report["configRestoredReadback"], RESTORED_KEYS
    )
    out["configuration"] = exact_keys(report["configReadback"], CONFIGURATION_KEYS)
    out["privateReceiptSha256"] = digest(report)
    out["recordedWith"] = recorded_with(report, recorder_commit)
    out["reevaluatedWith"] = reevaluated_with()
    validate_production(out, trigger)
    return out


def validate(value, trigger):
    require(
        set(value)
        == {
            "schemaVersion",
            "acceptance",
            "scope",
            "corpus",
            "sourceReviewSha256",
            "publicationContractSha256",
            "production",
        }
    )
    require(
        type(value["schemaVersion"]) is int
        and value["schemaVersion"] == 1
        and value["acceptance"] == "candidate"
        and value["scope"] == scope(trigger)
        and digest(value["corpus"]) == digest(corpus(trigger))
    )
    review = json.loads(review_path(trigger).read_bytes())
    require(value["publicationContractSha256"] == publication_contract_sha())
    require(value["sourceReviewSha256"] == digest(review))
    require([row["case"] for row in review["obligations"]] == list(CASES))
    require(
        review["executionApproval"] == "not-granted" and review["trigger"] == trigger
    )
    validate_production(value["production"], trigger)


def validate_production(report, trigger):
    require(
        set(report)
        == set(PROJECTED)
        | {"configuration", "privateReceiptSha256", "recordedWith", "reevaluatedWith"}
    )
    require(
        report["target"] == "production"
        and report["trigger"] == trigger
        and isinstance(report["recordedAt"], str)
        and re.fullmatch(r"[0-9T:.+\-]+", report["recordedAt"])
    )
    require(complete({**report, "status": "observed"}))
    hex_value(report["privateReceiptSha256"])
    for row, name in zip(report["cases"], CASES, strict=True):
        validate_row(row, name, trigger)
        require(classified(row))
    require(report["committedCheckout"] is True)
    config = exact_keys(report["configuration"], CONFIGURATION_KEYS)
    require(all(config[key] is True for key in config if key != "sha256"))
    hex_value(config["sha256"])
    restored = exact_keys(report["configRestoredReadback"], RESTORED_KEYS)
    require(
        restored["mfa"] == {"state": "DISABLED"}
        and restored["phoneNumber"] == {}
        and restored["smsRegionConfig"] == {"allowlistOnly": {}}
    )
    recorded = exact_keys(
        report["recordedWith"],
        ("probeSourceCommit", "recorderCommit", "recorderInputs"),
    )
    require(recorded["probeSourceCommit"] == report["probeSourceCommit"])
    recorded_with(
        {
            "probeSourceCommit": recorded["probeSourceCommit"],
            "probeInputs": exact_keys(recorded["recorderInputs"], RECORDER_FILES),
        },
        recorded["recorderCommit"],
    )
    reevaluated = exact_keys(report["reevaluatedWith"], ("commit", "contractSha256"))
    hex_value(reevaluated["commit"], 40)
    hex_value(reevaluated["contractSha256"])
    require(
        git_blob_sha256(reevaluated["commit"], RECORDER_FILES[0])
        == reevaluated["contractSha256"]
    )
    require(working_tree_sha256(RECORDER_FILES[0]) == reevaluated["contractSha256"])


def outcome(row):
    return f"{row['outcome']} / {row['observedError'] or 'none'}"


def render(value, trigger):
    validate(value, trigger)
    report = value["production"]
    rows = {row["id"]: row for row in report["cases"]}
    recorded, reevaluated = report["recordedWith"], report["reevaluatedWith"]
    lines = [
        f"# Held MFA pending credential across {trigger}",
        "",
        "Status: candidate, not approved. Seven redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus in this record; the local behavior is recorded separately in `tools/auth-pending-triggers/README.md`.",
        "",
        scope(trigger),
        "",
        "| Case | Basis | Outcome / error | Checks | Elapsed ms |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["cases"]:
        basis = "diagnostic" if row["id"] in DIAGNOSTIC else "control"
        checks = (
            ", ".join(f"{k}={v}" for k, v in sorted(row["checks"].items()))
            if row["checks"]
            else "none"
        )
        lines.append(
            f"| {row['id']} | {basis} | {outcome(row)} | {checks} | {row['elapsedMs']} |"
        )
    lines.extend(
        [
            "",
            f"Transition (`trigger`): **{outcome(rows['trigger'])}**. Held credential after the transition: start {outcome(rows['held-start'])}, finalize {outcome(rows['held-finalize'])}. Provider linked as a precondition: {report['providerLinked']}.",
            "",
            f"Review subject (unapproved): `{digest(value)}`.",
            "",
            "The held credential and SMS session were created before the transition and presented afterwards on the same session, so the held rows show the transition's effect on the pre-existing credential. The held rows are diagnostic: accepted and refused are both valid observations, and lookup and refresh run only when the held finalize was accepted. Elapsed milliseconds are cumulative from the recorder's measurement origin, sampled when each row is recorded; they are excluded from semantic equality.",
            "",
            "The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, one test phone number with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored before the account was deleted; the readback matched and the whole-configuration digest equaled the pre-run digest. The account was deleted with UID and email absence confirmation. The run started from a committed checkout.",
            "",
            f"Recorded with the recorder files at commit `{recorded['recorderCommit']}` while the repository was at `{recorded['probeSourceCommit']}`. Re-evaluated at publication with the contract at commit `{reevaluated['commit']}`. The observation itself was not re-run.",
            "",
            "This does not show what other triggers do, and does not generalize to tenants, blocking functions, SDK or Rules.",
            "",
            f"[Receipt](../../spec/compatibility/evidence/auth-pending-trigger-{trigger}/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-pending-trigger-{trigger}/source-review.json). All earlier evidence and approvals remain unchanged.",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trigger", required=True, choices=TRIGGERS)
    parser.add_argument("--production", type=Path)
    parser.add_argument("--recorder-commit")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    trigger = args.trigger
    if args.production:
        require(
            bool(args.recorder_commit)
            and not args.check
            and not bundle(trigger).exists()
        )
        value = {
            "schemaVersion": 1,
            "acceptance": "candidate",
            "scope": scope(trigger),
            "corpus": corpus(trigger),
            "sourceReviewSha256": digest(json.loads(review_path(trigger).read_bytes())),
            "publicationContractSha256": publication_contract_sha(),
            "production": project(
                json.loads(args.production.read_bytes()), trigger, args.recorder_commit
            ),
        }
        validate(value, trigger)
        bundle(trigger).parent.mkdir(parents=True, exist_ok=True)
        bundle(trigger).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    value = json.loads(bundle(trigger).read_bytes())
    page = render(value, trigger)
    if args.check:
        require(page_path(trigger).read_text() == page)
    else:
        page_path(trigger).write_text(page)
    print(f"Auth pending trigger {trigger} candidate checked; subject " + digest(value))
