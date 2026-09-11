"""Validate and publish the redacted production-only disabled-account administrative update receipt.

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
sys.path.insert(0, str(ROOT / "tools/auth-disabled-admin-update"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from admin_update_contract import (
    CASES,
    DIAGNOSTIC,
    complete,
    require,
    validate_row,
)
from admin_update_recorder import PASSWORD_POLICY, digest

BUNDLE = ROOT / "spec/compatibility/evidence/auth-disabled-admin-update/receipt.json"
REVIEW = (
    ROOT / "spec/compatibility/evidence/auth-disabled-admin-update/source-review.json"
)
PAGE = ROOT / "docs/compatibility/auth-disabled-admin-update.md"
SCOPE = "Ten sequential REST observations in production only: password sign-ins of target A and control B, then A is disabled through privileged accounts:update and read back; while disabled, an administrative password replacement and an administrative photo update are attempted on A (whether tokens are returned is the observation; any returned tokens are tried for lookup and refresh), A signs in with the new password, B signs in; A is re-enabled and read back, and both sign in again. No tenant, no configuration change (the configuration and the recorded password policy are read before and after and must be unchanged), a single run. Admin is used for owned account setup, the disable and re-enable transitions, the two updates, readback and cleanup. No human approval, no local artifact comparison, and no claim about other update fields, tenants, SDK or Rules."
CORPUS = {"slice": "auth-disabled-admin-update", "revision": 1, "cases": list(CASES)}
# Fields of the private report that may appear in the receipt, and nothing else.
PROJECTED = (
    "target",
    "recordedAt",
    "probeSourceCommit",
    "cases",
    "setup",
    "transitions",
    "cleanup",
    "configurationUnchanged",
)
CONFIGURATION_KEYS = (
    "sha256",
    "emailEnabled",
    "passwordRequired",
    "improvedEmailPrivacy",
    "blockingTriggersAbsent",
    "adminPasswordPolicyAbsent",
    "passwordPolicy",
)
RECORDER_FILES = (
    "tools/auth-disabled-admin-update/admin_update_contract.py",
    "tools/auth-disabled-admin-update/admin_update_recorder.py",
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
    require(
        all(
            config[key] is True
            for key in config
            if key not in {"sha256", "passwordPolicy"}
        )
    )
    require(digest(config["passwordPolicy"]) == digest(PASSWORD_POLICY))
    hex_value(config["sha256"])
    require(report["configurationUnchanged"] is True)
    require(
        report["transitions"]
        == [
            {"disabled": True, "targetReadback": True, "controlUnchanged": True},
            {"disabled": False, "targetReadback": True, "controlUnchanged": True},
        ]
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
        "# Administrative updates to a disabled account",
        "",
        "Status: candidate, not approved. Ten redacted production observations, not raw token responses or independent signature verification. No local artifact was run against this corpus; the local behavior is pinned separately by the `pending_retry` regressions.",
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
    update, photo = rows["disabled-a-password-update"], rows["disabled-a-photo-update"]
    recorded, reevaluated = report["recordedWith"], report["reevaluatedWith"]
    lines.extend(
        [
            "",
            f"Administrative password replacement of the disabled account: **{update['outcome']}** ({update['observedError'] or 'no error'}), tokens returned: {update['checks'].get('tokensReturned')}. Administrative photo update: **{photo['outcome']}** ({photo['observedError'] or 'no error'}), tokens returned: {photo['checks'].get('tokensReturned')}. The disabled account's own sign-in with the new password: {rows['disabled-a-signin']['outcome']} / {rows['disabled-a-signin']['observedError'] or 'none'}; after re-enablement: {rows['reenabled-a-signin']['outcome']}.",
            "",
            f"Review subject (unapproved): `{digest(value)}`.",
            "",
            "The two administrative updates carry `readbackApplied`, which requires the update to be visible through privileged lookup with the account still disabled and (for the password update) the selected non-photo fields unchanged. `tokensReturned` records whether the update response carried an ID token; the token rows run exactly when it did. Elapsed milliseconds are cumulative time from the recorder's measurement origin (set before account setup), sampled when each row is recorded after its checks; they are neither request latency nor time since the disable, and are excluded from semantic equality.",
            "",
            f"Recorded with the recorder files at commit `{recorded['recorderCommit']}` while the repository was at `{recorded['probeSourceCommit']}`; the receipt names the file digests the recorder hashed. Re-evaluated at publication with the contract at commit `{reevaluated['commit']}`. The observation itself was not re-run.",
            "",
            "This does not show what other update fields do on a disabled account, what a self-service update by a disabled user does, tenant behavior, or SDK and Rules behavior.",
            "",
            "[Receipt](../../spec/compatibility/evidence/auth-disabled-admin-update/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-disabled-admin-update/source-review.json). All earlier evidence and approvals remain unchanged.",
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
    print("Auth disabled admin update candidate checked; subject " + digest(value))
