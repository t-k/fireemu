"""Validate and publish the redacted production-only readback-timing receipt.

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
sys.path.insert(0, str(ROOT / "tools/auth-blocking-readback"))
sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
from readback_contract import (
    CASES,
    DIAGNOSTIC,
    complete,
    require,
    validate_row,
)
from readback_recorder import digest

BUNDLE = ROOT / "spec/compatibility/evidence/auth-blocking-readback/receipt.json"
REVIEW = ROOT / "spec/compatibility/evidence/auth-blocking-readback/source-review.json"
PAGE = ROOT / "docs/compatibility/auth-blocking-readback.md"
SCOPE = "Eleven sequential REST observations in production only with the disabling beforeSignIn function (the one recorded in auth-blocking-disable) deployed for the run. Two claimed accounts X and Y are refused on sign-in; the disabled flag is read back through privileged lookup for X before, immediately after, five and thirty seconds after the refusal, and for Y only after thirty seconds with no earlier read; a control Z signs in first and last. Readback rows record the flag as seen with the seconds since the refusal. The function was removed and the trigger registration restored with a digest comparison; the three accounts were deleted with absence confirmation. No MFA, phone or SMS configuration was touched. No human approval, no local artifact comparison in this record, and no claim beyond these points on one run's time axis."
CORPUS = {"slice": "auth-blocking-readback", "revision": 1, "cases": list(CASES)}
# Fields of the private report that may appear in the receipt, and nothing else.
PROJECTED = (
    "target",
    "recordedAt",
    "probeSourceCommit",
    "cases",
    "setup",
    "hook",
    "cleanup",
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
    "tools/auth-blocking-readback/readback_contract.py",
    "tools/auth-blocking-readback/readback_recorder.py",
    "tools/auth-blocking-disable/function/index.js",
    "tools/auth-blocking-disable/function/package.json",
    "tools/auth-blocking-disable/function/firebase.json",
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
        "# Hook-applied disable: readback timing",
        "",
        "Status: candidate, not approved. Eleven redacted production observations on one run's time axis. No local artifact comparison is part of this record.",
        "",
        SCOPE,
        "",
        "| Case | Basis | Outcome / error | Checks | Elapsed ms |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["cases"]:
        basis = (
            "diagnostic"
            if row["id"] in DIAGNOSTIC
            else ("readback" if "-readback-" in row["id"] else "control")
        )
        checks = (
            ", ".join(f"{k}={v}" for k, v in sorted(row["checks"].items()))
            if row["checks"]
            else "none"
        )
        lines.append(
            f"| {row['id']} | {basis} | {row['outcome']} / {row['observedError'] or 'none'} | {checks} | {row['elapsedMs']} |"
        )
    seen = {name: rows[name]["checks"] for name in rows if "-readback-" in name}
    recorded, reevaluated = report["recordedWith"], report["reevaluatedWith"]
    lines.extend(
        [
            "",
            "Disabled flag as read back: "
            + "; ".join(
                f"{name}: {c['disabledPersisted']} at {c['secondsSinceRefusal']}s"
                for name, c in seen.items()
            )
            + ".",
            "",
            f"Review subject (unapproved): `{digest(value)}`.",
            "",
            "The seconds are measured by the recorder between the refused sign-in's response and the readback request; they are not server-side propagation measurements. A readback that reads false is a fact about that moment on that account, not a rule; the gap ledger (GAP-AUTH-001) names what follows from the pattern across the five points.",
            "",
            f"Recorded with the recorder and function files at commit `{recorded['recorderCommit']}` while the repository was at `{recorded['probeSourceCommit']}`. Re-evaluated at publication with the contract at commit `{reevaluated['commit']}`. Elapsed milliseconds are cumulative from the recorder's measurement origin and excluded from semantic equality, as are the measured seconds.",
            "",
            "[Receipt](../../spec/compatibility/evidence/auth-blocking-readback/receipt.json) · [Source mapping](../../spec/compatibility/evidence/auth-blocking-readback/source-review.json). All earlier evidence and approvals remain unchanged.",
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
    print("Auth blocking readback candidate checked; subject " + digest(value))
