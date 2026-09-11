"""Validate and publish the redacted production-only created-then-disabled receipt (revision 2).

The observation was recorded with the recorder at one commit and is re-evaluated with the
contract at publication time; both are named in the receipt and never conflated. Only
allowlisted fields of the private report are projected.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-blocking-create-disable"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from create_contract import (
    CASES,
    DIAGNOSTIC,
    complete,
    require,
    validate_row,
)
from create_recorder import digest

BUNDLE = ROOT / "spec/compatibility/evidence/auth-blocking-create-disable/receipt.json"
REVIEW = (
    ROOT / "spec/compatibility/evidence/auth-blocking-create-disable/source-review.json"
)
PAGE = ROOT / "docs/compatibility/auth-blocking-create-disable.md"
SCOPE = "Ten sequential REST observations in production only with a first-generation beforeSignIn function deployed for the run that answers disabled: true when the signing-in email's local part starts with a dedicated prefix. Target T signs up with that prefix, so the request that creates the account is the request the function disables; control C signs up with a random local part. Whether T's sign-up is accepted or refused, whether tokens are returned and serve lookup and refresh, whether a record for T exists afterwards and is disabled, what T's own sign-in and a second sign-up do, and C's sign-up, sign-in and photo URL readback are recorded. The function was removed and the trigger registration restored with a digest comparison; accounts were deleted with absence confirmation (or, for a refused creation with no record, the email re-read as absent). No MFA, phone or SMS configuration was touched. No human approval and no local artifact comparison in this record."
CORPUS = {"slice": "auth-blocking-create-disable", "revision": 2, "cases": list(CASES)}
# Fields of the private report that may appear in the receipt, and nothing else.
PROJECTED = (
    "target",
    "recordedAt",
    "probeSourceCommit",
    "cases",
    "setup",
    "hook",
    "cleanup",
    "targetRecordExists",
    "functionRemoved",
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
RECORDER_FILES = (
    "tools/auth-blocking-create-disable/create_contract.py",
    "tools/auth-blocking-create-disable/create_recorder.py",
    "tools/auth-blocking-create-disable/function/index.js",
    "tools/auth-blocking-create-disable/function/package.json",
    "tools/auth-blocking-create-disable/function/firebase.json",
)


def hex_value(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value)
    )


def publication_contract_sha():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def working_tree_sha256(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def exact_keys(value, keys):
    """A published object carries exactly the allowlisted keys, never more."""
    require(isinstance(value, dict) and set(value) == set(keys))
    return {key: value[key] for key in keys}


RESTORED_KEYS = ("mfa", "phoneNumber", "smsRegionConfig", "blockingFunctions")


def git_blob_sha256(commit, path):
    blob = subprocess.check_output(
        ["git", "show", f"{commit}:{path}"], cwd=ROOT, stderr=subprocess.DEVNULL
    )
    return hashlib.sha256(blob).hexdigest()


def recorded_with(report, recorder_commit):
    """The recorder that produced the observation: the files it hashed must be exactly
    the files at `recorder_commit`, which may differ from the commit it ran on."""
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
    """The contract applied at publication, which may be stricter than the recorder's."""
    return {
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "contractSha256": working_tree_sha256(RECORDER_FILES[0]),
    }


def project(report, recorder_commit):
    require(
        type(report["schemaVersion"]) is int
        and report["schemaVersion"] == 1
        and report["acceptance"] == "candidate"
        and report["target"] == "production"
        and report["project"] == "fireemu-35fe6"
        and report["projectNumber"] == "592603257417"
        and digest(report["corpus"]) == digest(CORPUS)
        and complete(report)
    )
    out = {key: report[key] for key in PROJECTED}
    # Nested objects are projected too: an unexpected key inside them refuses the input
    # rather than being copied through.
    out["configRestoredReadback"] = exact_keys(
        report["configRestoredReadback"], RESTORED_KEYS
    )
    out["configuration"] = exact_keys(report["configReadback"], CONFIGURATION_KEYS)
    out["privateReceiptSha256"] = digest(report)
    out["recordedWith"] = recorded_with(report, recorder_commit)
    out["reevaluatedWith"] = reevaluated_with()
    validate_production(out)
    return out


def validate(value):
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
        and value["scope"] == SCOPE
        and digest(value["corpus"]) == digest(CORPUS)
    )
    review = json.loads(REVIEW.read_bytes())
    require(value["publicationContractSha256"] == publication_contract_sha())
    require(value["sourceReviewSha256"] == digest(review))
    require([row["case"] for row in review["obligations"]] == list(CASES))
    require(review["executionApproval"] == "not-granted")
    validate_production(value["production"])


def validate_production(report):
    require(
        set(report)
        == set(PROJECTED)
        | {"configuration", "privateReceiptSha256", "recordedWith", "reevaluatedWith"}
    )
    require(
        report["target"] == "production"
        and isinstance(report["recordedAt"], str)
        and re.fullmatch(r"[0-9T:.+\-]+", report["recordedAt"])
    )
    require(complete({**report, "status": "observed"}))
    hex_value(report["privateReceiptSha256"])
    for row, name in zip(report["cases"], CASES, strict=True):
        validate_row(row, name)
    config = exact_keys(report["configuration"], CONFIGURATION_KEYS)
    require(all(config[key] is True for key in config if key != "sha256"))
    hex_value(config["sha256"])
    restored = exact_keys(report["configRestoredReadback"], RESTORED_KEYS)
    require(
        restored["mfa"] == {"state": "DISABLED"}
        and restored["phoneNumber"] == {}
        and restored["smsRegionConfig"] == {"allowlistOnly": {}}
        and restored["blockingFunctions"] == {"forwardInboundCredentials": {}}
    )
    cleanup = exact_keys(report["cleanup"], ("c", "t"))
    for account in cleanup.values():
        require(
            account
            in (
                {"uidAbsent": True, "emailAbsent": True},
                {"recordNeverCreated": True, "emailAbsent": True},
            )
        )
    require(type(report["targetRecordExists"]) is bool)
    require(report["functionRemoved"] is True)
    require(report["hook"] == {"deployed": True, "triggerReadback": True})
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
    # The re-evaluation names a commit and a contract digest: the contract at that commit
    # and the contract this validation just ran must both have that content.
    reevaluated = exact_keys(report["reevaluatedWith"], ("commit", "contractSha256"))
    hex_value(reevaluated["commit"], 40)
    hex_value(reevaluated["contractSha256"])
    require(
        git_blob_sha256(reevaluated["commit"], RECORDER_FILES[0])
        == reevaluated["contractSha256"]
    )
    require(working_tree_sha256(RECORDER_FILES[0]) == reevaluated["contractSha256"])


def render(value):
    validate(value)
    report = value["production"]
    rows = {row["id"]: row for row in report["cases"]}
    lines = [
        "# Blocking function on the creating request (revision 2)",
        "",
        "Status: candidate, not approved. Ten redacted production observations, not raw token responses or independent signature verification. No local artifact comparison is part of this record.",
        "",
        SCOPE,
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
            f"| {row['id']} | {basis} | {row['outcome']} / {row['observedError'] or 'none'} | {checks} | {row['elapsedMs']} |"
        )
    recorded, reevaluated = report["recordedWith"], report["reevaluatedWith"]
    lines.extend(
        [
            "",
            f"Control sign-up photo URL persisted: **{rows['control-c-signup-readback']['checks']['photoUrlPersisted']}**. Target sign-up: {rows['target-t-signup']['outcome']}; record exists afterwards: {rows['target-t-record-readback']['checks']['recordExists']}, disabled: {rows['target-t-record-readback']['checks']['disabledPersisted']}.",
            "",
            f"Review subject (unapproved): `{digest(value)}`.",
            "",
            "The target rows are approved-as-recorded candidates for what a beforeSignIn disable does to the account the same request creates. Refused rows carry the HTTP status and classified error only; the record readback and the second sign-up are the state evidence. The control readback keeps observing that sign-up does not persist a photo URL (revision 1).",
            "",
            f"Recorded with the recorder and function files at commit `{recorded['recorderCommit']}` while the repository was at `{recorded['probeSourceCommit']}`. Re-evaluated at publication with the contract at commit `{reevaluated['commit']}`. Elapsed milliseconds are cumulative from the recorder's measurement origin and excluded from semantic equality.",
            "",
            "[Receipt](../../spec/compatibility/evidence/auth-blocking-create-disable/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-blocking-create-disable/source-review.json). All earlier evidence and approvals remain unchanged.",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production", type=Path)
    parser.add_argument("--recorder-commit")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.production:
        require(bool(args.recorder_commit) and not args.check and not BUNDLE.exists())
        value = {
            "schemaVersion": 1,
            "acceptance": "candidate",
            "scope": SCOPE,
            "corpus": CORPUS,
            "sourceReviewSha256": digest(json.loads(REVIEW.read_bytes())),
            "publicationContractSha256": publication_contract_sha(),
            "production": project(
                json.loads(args.production.read_bytes()), args.recorder_commit
            ),
        }
        validate(value)
        BUNDLE.parent.mkdir(parents=True, exist_ok=True)
        BUNDLE.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    value = json.loads(BUNDLE.read_bytes())
    page = render(value)
    if args.check:
        require(PAGE.read_text() == page)
    else:
        PAGE.write_text(page)
    print(
        "Auth blocking create-disable revision 1 candidate checked; subject "
        + digest(value)
    )
