"""Validate and publish the redacted production-only auth-mfa-start-disabled receipt.

The observation was recorded with the recorder at one commit and re-evaluated with the
contract at publication; both are named and never conflated. Only allowlisted fields are
projected, and the full execution-dependency set is bound to the recorder commit.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/auth-mfa-start-disabled"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from start_disabled_contract import (
    CASES,
    DIAGNOSTIC,
    classified,
    complete,
    require,
    validate_row,
)
from start_disabled_recorder import digest

BUNDLE = ROOT / "spec/compatibility/evidence/auth-mfa-start-disabled/receipt.json"
REVIEW = ROOT / "spec/compatibility/evidence/auth-mfa-start-disabled/source-review.json"
PAGE = ROOT / "docs/compatibility/auth-mfa-start-disabled.md"
SCOPE = "Six sequential REST observations in production only: a fresh phone MFA completion (control) while enabled; the account is disabled through privileged accounts:update and read back; the pending credential obtained before the disable is presented to mfaSignIn:start, and its session finalized if one was returned; the account is re-enabled and read back and the same pending credential is started and finalized; a fresh completion (control) closes the run. Phone MFA with one test phone number, no tenant, no blocking function, one run; the pending credential is obtained before the disable. The oracle configuration was changed for the run and restored with a digest comparison. No human approval, no local artifact comparison, no claim about tenants, SDK, Rules or the credential's expiry; the held rows are the observation, not a rule."
CORPUS = {"slice": "auth-mfa-start-disabled", "revision": 1, "cases": list(CASES)}
RECORDER_FILES = (
    "tools/auth-mfa-start-disabled/start_disabled_contract.py",
    "tools/auth-mfa-start-disabled/start_disabled_recorder.py",
    "tools/auth-pending-revocation/revocation_recorder.py",
    "tools/auth-pending-revocation/revocation_contract.py",
    "tools/auth-password-maximum/maximum_contract.py",
    "tools/auth-password-maximum/maximum_recorder.py",
)
PROJECTED = (
    "target",
    "recordedAt",
    "probeSourceCommit",
    "committedCheckout",
    "cases",
    "setup",
    "heldPendingBeforeDisable",
    "transitions",
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


def render(value):
    validate(value)
    report = value["production"]
    rows = {row["id"]: row for row in report["cases"]}
    recorded, reevaluated = report["recordedWith"], report["reevaluatedWith"]
    lines = [
        "# mfaSignIn:start on a disabled account",
        "",
        "Status: candidate, not approved. Six redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus in this record; the local behavior is recorded separately in `tools/auth-mfa-start-disabled/README.md`.",
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
            f"| {row['id']} | {basis} | {outcome(row)} | {checks} | {row['elapsedMs']} |"
        )
    lines.extend(
        [
            "",
            f"mfaSignIn:start on the disabled account: **{outcome(rows['disabled-start'])}**; its finalize: {outcome(rows['disabled-finalize'])}. After re-enablement the same pending credential: start {outcome(rows['reenabled-start'])}, finalize {outcome(rows['reenabled-finalize'])}.",
            "",
            f"Review subject (unapproved): `{digest(value)}`.",
            "",
            "The pending credential was obtained while the account was enabled, then the account was disabled through privileged accounts:update and read back. The held rows are diagnostic: accepted and refused are both valid observations, and each finalize runs only when its own start returned a session. Elapsed milliseconds are cumulative from the recorder's measurement origin, sampled when each row is recorded; they are excluded from semantic equality.",
            "",
            "The oracle project had MFA disabled, no phone sign-in and an empty SMS region allowlist. For the run, phone MFA, one test phone number with a fixed code (no SMS is sent) and the allow-by-default SMS region policy were enabled, and after a wait for enforcement the flow ran. The recorded values were restored before the account was deleted; the readback matched and the whole-configuration digest equaled the pre-run digest. The account was deleted with UID and email absence confirmation. The run started from a committed checkout.",
            "",
            f"Recorded with the recorder files at commit `{recorded['recorderCommit']}` while the repository was at `{recorded['probeSourceCommit']}`. Re-evaluated at publication with the contract at commit `{reevaluated['commit']}`. The observation itself was not re-run.",
            "",
            "This does not generalize to tenants, blocking functions, SDK, Rules or the credential's own expiry.",
            "",
            "[Receipt](../../spec/compatibility/evidence/auth-mfa-start-disabled/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-mfa-start-disabled/source-review.json). All earlier evidence and approvals remain unchanged.",
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
    print("Auth mfa-start-disabled candidate checked; subject " + digest(value))
